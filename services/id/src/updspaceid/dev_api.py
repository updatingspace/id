from __future__ import annotations

import os
from typing import Any, Literal

from ninja import Body, Router, Schema
from ninja.errors import HttpError

from updspaceid.enums import MembershipStatus, UserStatus
from updspaceid.errors import error_payload
from updspaceid.http import require_context
from updspaceid.models import Tenant, TenantMembership, User
from updspaceid.services import ensure_tenant


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


DEV_AUTH_MODE = _env_flag("DEV_AUTH_MODE", False)


dev_router = Router(tags=["Dev"])
REQUIRED_BODY = Body(...)


def _require_dev_mode():
    if not DEV_AUTH_MODE:
        raise HttpError(
            404,
            error_payload("NOT_FOUND", "Dev endpoints are disabled"),
        )


class DevSeedIn(Schema):
    email: str = "dev@aef.local"
    username: str = "dev"
    display_name: str = "Dev User"
    system_admin: bool = True


class DevSeedOut(Schema):
    ok: Literal[True] = True
    tenant: dict[str, Any]
    user: dict[str, Any]


class DevLoginIn(Schema):
    email: str = "dev@aef.local"


class DevLoginOut(Schema):
    ok: Literal[True] = True
    session_token: str
    user_id: str


@dev_router.get("/tenants", operation_id="dev_tenants")
def list_tenants(request):
    _require_dev_mode()
    tenants = Tenant.objects.all()[:50]
    return [{"tenant_slug": t.slug, "id": str(t.id)} for t in tenants]


@dev_router.get("/users", operation_id="dev_users")
def list_users(request, tenant_slug: str | None = None):
    _require_dev_mode()
    qs = User.objects.filter(status=UserStatus.ACTIVE)
    if tenant_slug:
        qs = qs.filter(
            memberships__tenant__slug=tenant_slug,
            memberships__status=MembershipStatus.ACTIVE,
        )
    users = qs.distinct()[:100]
    return [
        {
            "id": str(u.user_id),
            "username": u.username,
            "email": u.email,
            "system_admin": bool(u.system_admin),
        }
        for u in users
    ]


@dev_router.get("/user/{user_id}", operation_id="dev_user_detail")
def get_user(request, user_id: str, tenant_slug: str | None = None):
    _require_dev_mode()
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        raise HttpError(404, error_payload("NOT_FOUND", "User not found"))

    return {
        "id": str(user.user_id),
        "username": user.username,
        "email": user.email,
        "system_admin": bool(user.system_admin),
    }


@dev_router.post("/seed", response={200: DevSeedOut}, operation_id="dev_seed")
def seed(request, payload: DevSeedIn = REQUIRED_BODY):
    _require_dev_mode()

    from django.contrib.auth import get_user_model
    DjangoUser = get_user_model()

    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)

    email = str(payload.email).lower().strip()
    
    # Create updspaceid.User (multi-tenant identity)
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={
            "username": payload.username,
            "display_name": payload.display_name,
            "status": UserStatus.ACTIVE,
            "email_verified": True,
            "system_admin": bool(payload.system_admin),
        },
    )

    # If user already existed, make sure it is usable in dev.
    updated = False
    if user.status != UserStatus.ACTIVE:
        user.status = UserStatus.ACTIVE
        updated = True
    if not user.email_verified:
        user.email_verified = True
        updated = True
    if bool(payload.system_admin) and not user.system_admin:
        user.system_admin = True
        updated = True
    if updated:
        user.save(update_fields=["status", "email_verified", "system_admin"])

    TenantMembership.objects.get_or_create(
        user=user,
        tenant=tenant,
        defaults={
            "status": MembershipStatus.ACTIVE,
            "base_role": "admin" if user.system_admin else "member",
        },
    )

    # Also create Django auth.User for allauth sessions (with random password)
    dj_user, created = DjangoUser.objects.get_or_create(
        email=email,
        defaults={
            "username": payload.username or email.split("@")[0],
        },
    )
    if created:
        # Set unusable password - dev login bypasses password
        dj_user.set_unusable_password()
        dj_user.save()

    return {
        "ok": True,
        "tenant": {"id": str(tenant.id), "slug": tenant.slug},
        "user": {
            "id": str(user.user_id),
            "email": user.email,
            "system_admin": bool(user.system_admin),
        },
    }


@dev_router.post("/login", response={200: DevLoginOut}, operation_id="dev_login")
def dev_login(request, payload: DevLoginIn = REQUIRED_BODY):
    """
    Dev-only endpoint to create a session for a user without password.
    Returns a session token that can be used with X-Session-Token header.
    Works with ID frontend which uses allauth headless sessions.
    """
    _require_dev_mode()

    from django.contrib.auth import get_user_model
    from django.contrib.sessions.backends.db import SessionStore
    from allauth.headless.tokens.sessions import SessionTokenStrategy
    from core.models import UserSessionMeta

    DjangoUser = get_user_model()
    email = str(payload.email).lower().strip()
    
    # Check updspaceid.User exists
    try:
        usid_user = User.objects.get(email=email, status=UserStatus.ACTIVE)
    except User.DoesNotExist:
        raise HttpError(404, error_payload("NOT_FOUND", f"User {email} not found. Run /dev/seed first."))

    # Get or create Django auth.User (for allauth sessions)
    dj_user, created = DjangoUser.objects.get_or_create(
        email=email,
        defaults={"username": email.split("@")[0]},
    )
    if created:
        dj_user.set_unusable_password()
        dj_user.save()

    # Create Django session manually (bypassing login signal that tries to update last_login)
    session = SessionStore()
    session.create()
    session["_auth_user_id"] = str(dj_user.pk)
    session["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
    session["_auth_user_hash"] = ""
    session.save()
    
    # Create UserSessionMeta for allauth headless session token
    existing_meta = UserSessionMeta.objects.filter(
        user=dj_user,
        session_key=session.session_key,
    ).first()
    if not existing_meta:
        existing_meta = UserSessionMeta.objects.create(
            user=dj_user,
            session_key=session.session_key,
            session_token=None,
        )
    
    # Create session token using allauth strategy
    request.session = session
    request.user = dj_user
    strategy = SessionTokenStrategy()
    session_token = strategy.create_session_token(request)

    return {
        "ok": True,
        "session_token": session_token,
        "user_id": str(usid_user.user_id),
    }


__all__ = ["dev_router"]
