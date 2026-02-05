from __future__ import annotations

import logging
import uuid
from urllib.parse import urlparse, urlunparse
from datetime import timedelta

from django.conf import settings
from django.db.models import QuerySet
from django.utils import timezone
from ninja import NinjaAPI, Router
from ninja.errors import HttpError
from functools import wraps

from core.security import require_internal_signature
from updspaceid.enums import ApplicationStatus, ExternalProvider, OAuthPurpose
from updspaceid.errors import error_payload
from updspaceid.http import require_context
from updspaceid.models import Application, Tenant, TenantMembership, User
from updspaceid.audit import enqueue_outbox, record_audit
from updspaceid.emailing import send_activation_email
from updspaceid.providers import build_authorization_url, exchange_code_for_subject
from updspaceid.schemas import (
    ActivateIn,
    ActivateOut,
    ApplicationCreateIn,
    ApplicationListOut,
    ApplicationOut,
    ApproveOut,
    ClaimTokenOut,
    ErrorEnvelopeOut,
    MeOut,
    MigrationImportIn,
    MigrationImportOut,
    OAuthCallbackIn,
    OAuthStartIn,
    OAuthLoginOut,
    OAuthStartOut,
    OkOut,
    RejectOut,
)
from updspaceid.services import (
    COOKIE_NAME,
    activate_account,
    approve_application,
    create_application,
    ensure_tenant,
    get_session_user,
    issue_activation_token,
    oauth_consume_state,
    oauth_login_only_if_linked,
    oauth_start,
    revoke_session,
)

api_v1 = NinjaAPI(title="UpdSpaceID", version="1.0.0", urls_namespace="updspaceid_v1")
logger = logging.getLogger(__name__)


def _error_envelope_response(request, exc: HttpError):
    status = getattr(exc, "status_code", 500)
    raw = getattr(exc, "message", None)
    if raw is None:
        raw = str(exc)
    if not isinstance(raw, dict):
        raw = {"code": "HTTP_ERROR", "message": str(raw)}

    request_id = request.headers.get("X-Request-Id") or ""
    payload = {
        "error": {
            "code": str(
                raw.get("code") or ("SERVER_ERROR" if status >= 500 else "HTTP_ERROR")
            ),
            "message": str(raw.get("message") or "Error"),
            "details": raw.get("details"),
            "request_id": str(request_id),
        }
    }
    return api_v1.create_response(request, payload, status=status)


def _with_error_envelope(fn):
    @wraps(fn)
    def wrapper(request, *args, **kwargs):
        request._error_envelope = True
        try:
            return fn(request, *args, **kwargs)
        except HttpError as exc:
            return _error_envelope_response(request, exc)

    return wrapper


@api_v1.exception_handler(HttpError)
def on_http_error(request, exc: HttpError):  # noqa: N802
    return _error_envelope_response(request, exc)


def _as_application_out(obj: Application) -> ApplicationOut:
    return ApplicationOut(
        id=obj.id,
        tenant_slug=obj.tenant_slug,
        payload_json=obj.payload_json,
        status=obj.status,
        created_at=obj.created_at,
    )


def _require_session_user(request) -> User:
    ctx = require_context(request)
    token = request.COOKIES.get(COOKIE_NAME)
    if not token:
        raise HttpError(401, error_payload("UNAUTHORIZED", "Missing session"))
    user = get_session_user(token)
    # Tenant isolation: user must have membership in current tenant
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    if not TenantMembership.objects.filter(user=user, tenant=tenant, status="active").exists():
        raise HttpError(403, error_payload("TENANT_FORBIDDEN", "No access to tenant"))
    return user


def _has_internal_signature(request) -> bool:
    return bool(
        request.headers.get("X-Updspace-Timestamp")
        and request.headers.get("X-Updspace-Signature")
    )


def _require_internal_user(request) -> User:
    require_internal_signature(request)
    user_id = request.headers.get("X-User-Id") or ""
    if not user_id:
        raise HttpError(401, error_payload("UNAUTHORIZED", "X-User-Id is required"))
    try:
        uuid.UUID(str(user_id))
    except Exception as exc:
        raise HttpError(
            400,
            error_payload("INVALID_USER_ID", "X-User-Id must be a UUID"),
        ) from exc

    user = User.objects.filter(user_id=user_id).first()
    if not user:
        raise HttpError(401, error_payload("UNAUTHORIZED", "User not found"))

    ctx = require_context(request)
    tenant = Tenant.objects.filter(slug=ctx.tenant_slug).first()
    if not tenant:
        tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)

    if not TenantMembership.objects.filter(
        user=user, tenant=tenant, status="active"
    ).exists():
        raise HttpError(403, error_payload("TENANT_FORBIDDEN", "No access to tenant"))

    return user


def _require_admin(request) -> User:
    if _has_internal_signature(request):
        user = _require_internal_user(request)
    else:
        user = _require_session_user(request)
    if not user.system_admin:
        raise HttpError(403, error_payload("FORBIDDEN", "Admin required"))
    return user


router = Router(tags=["UpdSpaceID"])


@router.post(
    "/applications",
    response={201: ApplicationOut, 400: ErrorEnvelopeOut, 409: ErrorEnvelopeOut},
    operation_id="applications_create",
)
@_with_error_envelope
def applications_create(request, payload: ApplicationCreateIn):
    ctx = require_context(request)
    if payload.tenant_slug != ctx.tenant_slug:
        raise HttpError(409, error_payload("TENANT_MISMATCH", "tenant_slug mismatch"))
    app = create_application(payload.tenant_slug, payload.payload_json)
    return api_v1.create_response(request, _as_application_out(app), status=201)


@router.get(
    "/applications",
    response={200: ApplicationListOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut},
    operation_id="applications_list",
)
@_with_error_envelope
def applications_list(request, status: str | None = None):
    _require_admin(request)
    ctx = require_context(request)
    qs: QuerySet[Application] = Application.objects.filter(tenant_slug=ctx.tenant_slug)
    if status:
        qs = qs.filter(status=status)
    items = [_as_application_out(a) for a in qs.order_by("-created_at")[:200]]
    return {"items": items}


@router.post(
    "/applications/{application_id}/approve",
    response={200: ApproveOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 409: ErrorEnvelopeOut},
    operation_id="applications_approve",
)
@_with_error_envelope
def applications_approve(request, application_id: int):
    admin = _require_admin(request)
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    try:
        application = Application.objects.get(id=application_id)
    except Application.DoesNotExist as exc:
        raise HttpError(404, error_payload("NOT_FOUND", "Application not found")) from exc

    activation = approve_application(
        application,
        reviewer_user_id=str(admin.user_id),
        tenant=tenant,
    )
    raw_token = getattr(activation, "raw_token", activation.token)
    try:
        send_activation_email(
            email=activation.user.email,
            tenant_slug=tenant.slug,
            token=raw_token,
            expires_at=activation.expires_at,
        )
    except Exception:
        logger.warning(
            "Failed to send activation email",
            extra={"user_id": str(activation.user_id)},
            exc_info=True,
        )
    return {
        "activation_token": raw_token,
        "activation_expires_at": activation.expires_at,
    }


@router.post(
    "/applications/{application_id}/reject",
    response={200: RejectOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 409: ErrorEnvelopeOut},
    operation_id="applications_reject",
)
@_with_error_envelope
def applications_reject(request, application_id: int):
    admin = _require_admin(request)
    try:
        application = Application.objects.get(id=application_id)
    except Application.DoesNotExist as exc:
        raise HttpError(404, error_payload("NOT_FOUND", "Application not found")) from exc

    from updspaceid.services import reject_application

    reject_application(application, reviewer_user_id=str(admin.user_id))
    return {"ok": True}


@router.post(
    "/auth/activate",
    response={200: ActivateOut, 400: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 409: ErrorEnvelopeOut, 410: ErrorEnvelopeOut},
    operation_id="auth_activate",
)
@_with_error_envelope
def auth_activate(request, payload: ActivateIn):
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    user = activate_account(payload.token, tenant=tenant)
    return {"ok": True, "user_id": user.user_id}


@router.post(
    "/auth/logout",
    response={200: OkOut, 401: ErrorEnvelopeOut},
    operation_id="auth_logout",
)
@_with_error_envelope
def auth_logout(request):
    require_context(request)
    token = request.COOKIES.get(COOKIE_NAME)
    if not token:
        raise HttpError(401, error_payload("UNAUTHORIZED", "Missing session"))
    revoke_session(token)
    resp = api_v1.create_response(request, {"ok": True}, status=200)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@router.get(
    "/me",
    response={200: MeOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut},
    operation_id="me",
)
@_with_error_envelope
def me(request):
    ctx = require_context(request)
    if _has_internal_signature(request):
        user = _require_internal_user(request)
    else:
        user = _require_session_user(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    memberships = TenantMembership.objects.filter(user=user, tenant=tenant)
    account_profile = None
    try:
        from django.contrib.auth import get_user_model
        from accounts.services.auth import AuthService

        account_user = get_user_model().objects.filter(email=user.email).first()
        if account_user:
            account_profile = AuthService.profile(account_user, request=request)
    except Exception:
        account_profile = None
    avatar_url = None
    if account_profile:
        avatar_url = getattr(account_profile, "avatar_url", None)
        if avatar_url:
            public_base = str(
                getattr(settings, "OIDC_PUBLIC_BASE_URL", "")
                or getattr(settings, "ID_ACTIVATION_BASE_URL", "")
                or ""
            ).rstrip("/")
            if public_base:
                try:
                    parsed_url = urlparse(avatar_url)
                    parsed_base = urlparse(public_base)
                    if parsed_base.scheme and parsed_base.netloc:
                        if parsed_url.netloc != parsed_base.netloc:
                            avatar_url = urlunparse(
                                (
                                    parsed_base.scheme,
                                    parsed_base.netloc,
                                    parsed_url.path,
                                    parsed_url.params,
                                    parsed_url.query,
                                    parsed_url.fragment,
                                )
                            )
                except Exception:
                    pass
    return {
        "user": {
            "user_id": str(user.user_id),
            "username": user.username,
            "display_name": user.display_name,
            "email": user.email,
            "email_verified": user.email_verified,
            "status": user.status,
            "system_admin": user.system_admin,
            "created_at": user.created_at,
            "first_name": getattr(account_profile, "first_name", None),
            "last_name": getattr(account_profile, "last_name", None),
            "phone_number": getattr(account_profile, "phone_number", None),
            "phone_verified": getattr(account_profile, "phone_verified", None),
            "birth_date": getattr(account_profile, "birth_date", None),
            "language": getattr(account_profile, "language", None),
            "timezone": getattr(account_profile, "timezone", None),
            "avatar_url": avatar_url,
            "avatar_source": getattr(account_profile, "avatar_source", None),
            "avatar_gravatar_enabled": getattr(account_profile, "avatar_gravatar_enabled", None),
        },
        "memberships": [
            {
                "tenant_id": tenant.id,
                "tenant_slug": tenant.slug,
                "status": m.status,
                "base_role": m.base_role,
            }
            for m in memberships
        ],
    }


def _validate_provider(provider: str) -> str:
    provider = str(provider)
    if provider not in {ExternalProvider.GITHUB, ExternalProvider.DISCORD, ExternalProvider.STEAM}:
        raise HttpError(404, error_payload("PROVIDER_NOT_SUPPORTED", "Provider not supported"))
    return provider


@router.post(
    "/external-identities/{provider}/link/start",
    response={200: OAuthStartOut, 400: ErrorEnvelopeOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 501: ErrorEnvelopeOut},
    operation_id="external_identities_link_start",
)
@_with_error_envelope
def external_identities_link_start(request, provider: str, payload: OAuthStartIn):
    user = _require_session_user(request)
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    provider = _validate_provider(provider)
    redirect_uri = payload.redirect_uri.strip()
    st = oauth_start(
        provider=provider,
        purpose=OAuthPurpose.LINK,
        tenant=tenant,
        user=user,
        redirect_uri=redirect_uri,
    )
    try:
        authorization_url = build_authorization_url(
            provider=provider,
            state=st.state,
            nonce=st.nonce,
            redirect_uri=redirect_uri,
        )
    except HttpError:
        st.delete()
        raise
    return {
        "authorization_url": authorization_url,
        "state": st.state,
        "nonce": st.nonce,
    }


@router.post(
    "/external-identities/{provider}/link/callback",
    response={200: OkOut, 400: ErrorEnvelopeOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 409: ErrorEnvelopeOut, 410: ErrorEnvelopeOut, 501: ErrorEnvelopeOut, 502: ErrorEnvelopeOut},
    operation_id="external_identities_link_callback",
)
@_with_error_envelope
def external_identities_link_callback(request, provider: str, payload: OAuthCallbackIn):
    user = _require_session_user(request)
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    provider = _validate_provider(provider)
    st = oauth_consume_state(
        state_value=payload.state,
        provider=provider,
        purpose=OAuthPurpose.LINK,
        tenant=tenant,
    )
    subject = exchange_code_for_subject(
        provider=provider,
        code=payload.code,
        claimed_id=payload.claimed_id,
        redirect_uri=st.redirect_uri,
        openid_params=payload.openid_params,
        expected_state=payload.state,
    )
    from updspaceid.services import link_external_identity

    link_external_identity(
        user=user,
        provider=provider,
        subject=subject,
        tenant=tenant,
    )
    return {"ok": True}


@router.post(
    "/oauth/{provider}/login/start",
    response={200: OAuthStartOut, 400: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 501: ErrorEnvelopeOut},
    operation_id="oauth_login_start",
)
@_with_error_envelope
def oauth_login_start(request, provider: str, payload: OAuthStartIn):
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    provider = _validate_provider(provider)
    redirect_uri = payload.redirect_uri.strip()
    st = oauth_start(
        provider=provider,
        purpose=OAuthPurpose.LOGIN,
        tenant=tenant,
        user=None,
        redirect_uri=redirect_uri,
    )
    try:
        authorization_url = build_authorization_url(
            provider=provider,
            state=st.state,
            nonce=st.nonce,
            redirect_uri=redirect_uri,
        )
    except HttpError:
        st.delete()
        raise
    return {
        "authorization_url": authorization_url,
        "state": st.state,
        "nonce": st.nonce,
    }


@router.post(
    "/oauth/{provider}/login/callback",
    response={200: OAuthLoginOut, 400: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut, 409: ErrorEnvelopeOut, 410: ErrorEnvelopeOut, 501: ErrorEnvelopeOut, 502: ErrorEnvelopeOut},
    operation_id="oauth_login_callback",
)
@_with_error_envelope
def oauth_login_callback(request, provider: str, payload: OAuthCallbackIn):
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    provider = _validate_provider(provider)
    st = oauth_consume_state(
        state_value=payload.state,
        provider=provider,
        purpose=OAuthPurpose.LOGIN,
        tenant=tenant,
    )
    subject = exchange_code_for_subject(
        provider=provider,
        code=payload.code,
        claimed_id=payload.claimed_id,
        redirect_uri=st.redirect_uri,
        openid_params=payload.openid_params,
        expected_state=payload.state,
    )
    user = oauth_login_only_if_linked(provider=provider, subject=subject)

    # issue session cookie as result of OAuth login
    from updspaceid.models import IdSession

    session = IdSession.objects.create(
        user=user,
        expires_at=timezone.now() + timedelta(days=14),
    )
    record_audit(
        action="auth.oauth_login",
        actor_user=user,
        target_type="user",
        target_id=str(user.user_id),
        tenant=tenant,
        meta={
            "provider": provider,
            "session_expires_at": session.expires_at.isoformat(),
        },
    )
    enqueue_outbox(
        event_type="session.created",
        tenant=tenant,
        payload={
            "user_id": str(user.user_id),
            "tenant_id": str(tenant.id),
            "tenant_slug": tenant.slug,
            "method": "oauth",
            "provider": provider,
        },
    )
    return {"ok": True, "user_id": user.user_id, "session_token": session.token}


@router.post(
    "/migrations/aefvote/import",
    response={200: MigrationImportOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut},
    operation_id="migrations_aefvote_import",
)
@_with_error_envelope
def migrations_aefvote_import(request, payload: MigrationImportIn):
    _require_admin(request)
    from updspaceid.enums import UserStatus
    from updspaceid.models import MigrationMap

    imported = 0
    for item in payload.items:
        old_user_id = str(item.get("old_user_id") or "").strip()
        email = str(item.get("email") or "").strip().lower()
        if not old_user_id or not email:
            continue
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "username": str(item.get("username") or ""),
                "display_name": str(item.get("display_name") or ""),
                "status": UserStatus.MIGRATED_UNCLAIMED,
                "email_verified": False,
            },
        )
        MigrationMap.objects.get_or_create(old_system="aefvote", old_user_id=old_user_id, defaults={"user": user})
        if created:
            imported += 1
    return {"imported": imported}


@router.post(
    "/migrations/aefvote/claim-token/{user_id}",
    response={200: ClaimTokenOut, 401: ErrorEnvelopeOut, 403: ErrorEnvelopeOut, 404: ErrorEnvelopeOut},
    operation_id="migrations_aefvote_claim_token",
)
@_with_error_envelope
def migrations_aefvote_claim_token(request, user_id: str):
    _require_admin(request)
    ctx = require_context(request)
    tenant = ensure_tenant(ctx.tenant_id, ctx.tenant_slug)
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist as exc:
        raise HttpError(404, error_payload("NOT_FOUND", "User not found")) from exc

    activation, raw_token = issue_activation_token(
        user=user,
        tenant=tenant,
        expires_at=timezone.now() + timedelta(hours=24),
    )
    return {
        "activation_token": raw_token,
        "activation_expires_at": activation.expires_at,
    }
