from __future__ import annotations

import os
import secrets
from typing import Any, Literal
from urllib.parse import urlencode, urlparse, urlunparse

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.utils import timezone
from ninja import Query, Router, Schema
from ninja.errors import HttpError

from core.security import require_internal_signature
from updspaceid.audit import enqueue_outbox, record_audit
from updspaceid.emailing import build_magic_link_url, send_magic_link_email
from updspaceid.enums import MembershipStatus
from updspaceid.errors import error_payload
from updspaceid.http import require_context
from updspaceid.models import TenantMembership
from updspaceid.services import (
    SESSION_TTL,
    consume_magic_link,
    ensure_tenant,
    request_magic_link,
)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


DEV_AUTH_MODE = _env_flag("DEV_AUTH_MODE", False)


class MagicLinkRequestIn(Schema):
    email: str
    redirect_to: str | None = None


class MagicLinkRequestOut(Schema):
    ok: Literal[True] = True
    sent: bool
    dev_magic_link: str | None = None


class MagicLinkConsumeIn(Schema):
    token: str


class MagicLinkConsumeOut(Schema):
    ok: Literal[True] = True
    user_id: str
    session_token: str


class ExchangeIn(Schema):
    code: str


class ExchangeOut(Schema):
    ok: Literal[True] = True
    user_id: str
    master_flags: dict[str, Any]
    ttl_seconds: int


router_magic_link = Router(tags=["MagicLink"])


_MAGIC_LINK_RATE_WINDOW = 15 * 60
_MAGIC_LINK_RATE_MAX = 5


def _cache_key(code: str) -> str:
    return f"usid:exchange:{code}"


def _build_redirect(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    q = parsed.query
    extra = urlencode(params)
    query = q + ("&" if q else "") + extra
    return urlunparse(parsed._replace(query=query))


@router_magic_link.post(
    "/magic-link/request",
    response={200: MagicLinkRequestOut},
    operation_id="auth_magic_link_request",
)
def magic_link_request(request, payload: MagicLinkRequestIn):
    ctx = require_context(request)
    ip = request.META.get("REMOTE_ADDR", "")
    ua = request.headers.get("User-Agent", "")

    key = f"usid:ml:rl:{payload.email.lower().strip()}:{ip}"
    count = int(cache.get(key) or 0)
    if count >= _MAGIC_LINK_RATE_MAX:
        raise HttpError(429, error_payload("RATE_LIMITED", "Too many requests"))
    cache.set(key, count + 1, timeout=_MAGIC_LINK_RATE_WINDOW)

    token = request_magic_link(email=payload.email, ip=ip, ua=ua)
    redirect_to = str(payload.redirect_to or "").strip()

    # Ensure tenant exists + membership exists (for later checks)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    if token:
        TenantMembership.objects.get_or_create(
            user=token.user,
            tenant=tenant,
            defaults={"status": MembershipStatus.ACTIVE, "base_role": "member"},
        )

    if token:
        record_audit(
            action="magic_link.requested",
            actor_user=token.user,
            target_type="user",
            target_id=str(token.user_id),
            tenant=tenant,
            meta={
                "expires_at": token.expires_at.isoformat()
                if token.expires_at
                else None,
            },
        )
        enqueue_outbox(
            event_type="magic_link.requested",
            tenant=tenant,
            payload={
                "user_id": str(token.user_id),
                "tenant_id": str(tenant.id),
                "tenant_slug": tenant.slug,
                "expires_at": token.expires_at.isoformat()
                if token.expires_at
                else None,
            },
        )

    if DEV_AUTH_MODE:
        if not redirect_to:
            raise HttpError(
                400,
                error_payload(
                    "BAD_REQUEST",
                    "redirect_to is required in DEV_AUTH_MODE",
                ),
            )

        dev_magic_link = None
        if token:
            dev_magic_link = build_magic_link_url(
                token=token.raw_token,
                redirect_to=redirect_to,
            )
        return {"ok": True, "sent": True, "dev_magic_link": dev_magic_link}

    if token:
        if not redirect_to:
            redirect_to = str(
                getattr(settings, "MAGIC_LINK_DEFAULT_REDIRECT", "") or ""
            ).strip()
        if redirect_to:
            magic_link = build_magic_link_url(
                token=token.raw_token,
                redirect_to=redirect_to,
            )
            send_magic_link_email(
                email=token.user.email,
                link=magic_link,
                expires_at=token.expires_at,
            )
    return {"ok": True, "sent": True, "dev_magic_link": None}


@router_magic_link.get(
    "/magic-link/consume",
    operation_id="auth_magic_link_consume_redirect",
)
def magic_link_consume_redirect(
    request,
    token: str = Query(...),
    redirect_to: str = Query(...),
):
    # Browser click: no internal signature.
    ctx = require_context(request)

    ip = request.META.get("REMOTE_ADDR", "")
    ua = request.headers.get("User-Agent", "")

    user, session = consume_magic_link(token=token, ip=ip, ua=ua)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    record_audit(
        action="magic_link.consumed",
        actor_user=user,
        target_type="user",
        target_id=str(user.user_id),
        tenant=tenant,
        meta={"session_expires_at": session.expires_at.isoformat()},
    )
    enqueue_outbox(
        event_type="session.created",
        tenant=tenant,
        payload={
            "user_id": str(user.user_id),
            "tenant_id": str(tenant.id),
            "tenant_slug": tenant.slug,
            "method": "magic_link",
        },
    )

    # Mint short-lived exchange code for BFF.
    code = secrets.token_urlsafe(24)

    master_flags: dict[str, Any] = {
        "email_verified": bool(user.email_verified),
        "system_admin": bool(user.system_admin),
    }

    ttl_seconds = int(SESSION_TTL.total_seconds())
    cache.set(
        _cache_key(code),
        {
            "user_id": str(user.user_id),
            "master_flags": master_flags,
            "ttl_seconds": ttl_seconds,
            "issued_at": timezone.now().isoformat(),
        },
        timeout=60,
    )

    return HttpResponseRedirect(_build_redirect(redirect_to, {"code": code}))


@router_magic_link.post(
    "/magic-link/consume",
    response={200: MagicLinkConsumeOut},
    operation_id="auth_magic_link_consume",
)
def magic_link_consume(request, payload: MagicLinkConsumeIn):
    request._error_envelope = True
    ctx = require_context(request)

    ip = request.META.get("REMOTE_ADDR", "")
    ua = request.headers.get("User-Agent", "")

    user, session = consume_magic_link(token=payload.token, ip=ip, ua=ua)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    record_audit(
        action="magic_link.consumed",
        actor_user=user,
        target_type="user",
        target_id=str(user.user_id),
        tenant=tenant,
        meta={"session_expires_at": session.expires_at.isoformat()},
    )
    enqueue_outbox(
        event_type="session.created",
        tenant=tenant,
        payload={
            "user_id": str(user.user_id),
            "tenant_id": str(tenant.id),
            "tenant_slug": tenant.slug,
            "method": "magic_link",
        },
    )
    return {
        "ok": True,
        "user_id": str(user.user_id),
        "session_token": session.token,
    }


@router_magic_link.post(
    "/exchange",
    response={200: ExchangeOut},
    operation_id="auth_exchange",
)
def exchange(request, payload: ExchangeIn):
    # Only BFF should be able to exchange codes.
    require_internal_signature(request)

    raw = cache.get(_cache_key(payload.code))
    if not raw:
        raise HttpError(
            401,
            error_payload("UNAUTHORIZED", "Invalid or expired code"),
        )

    cache.delete(_cache_key(payload.code))

    user_id = str(raw.get("user_id") or "")
    ttl_seconds = int(
        raw.get("ttl_seconds")
        or int(SESSION_TTL.total_seconds())
    )
    master_flags = raw.get("master_flags")
    if not isinstance(master_flags, dict):
        master_flags = {}

    if not user_id:
        raise HttpError(
            500,
            error_payload("SERVER_ERROR", "Malformed exchange payload"),
        )

    return {
        "ok": True,
        "user_id": user_id,
        "master_flags": master_flags,
        "ttl_seconds": ttl_seconds,
    }


__all__ = ["router_magic_link"]
