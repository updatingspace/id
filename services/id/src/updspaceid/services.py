from __future__ import annotations

# ruff: noqa: E501

import hashlib
import hmac
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from ninja.errors import HttpError

from updspaceid.enums import ApplicationStatus, MembershipStatus, UserStatus
from updspaceid.errors import error_payload
from updspaceid.models import (
    ActivationToken,
    Application,
    ExternalIdentity,
    IdSession,
    MagicLinkToken,
    OAuthState,
    Tenant,
    TenantMembership,
    User,
    generate_token_urlsafe,
)
from updspaceid.audit import enqueue_outbox, record_audit


ACTIVATION_TTL = timedelta(hours=24)
MAGIC_LINK_TTL = timedelta(minutes=15)
SESSION_TTL = timedelta(days=14)
OAUTH_STATE_TTL = timedelta(minutes=10)

COOKIE_NAME = "updspace_session"


def _hash_value(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_secret() -> str:
    return str(getattr(settings, "ID_TOKEN_HASH_SECRET", settings.SECRET_KEY))


def _hash_token(raw: str) -> str:
    secret = _token_secret().encode("utf-8")
    return hmac.new(secret, raw.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()


def _context_matches(stored: str, current: str) -> bool:
    if not stored:
        return True
    if not current:
        return False
    return hmac.compare_digest(stored, current)


def issue_activation_token(
    *,
    user: User,
    tenant: Tenant,
    expires_at: timezone.datetime | None = None,
) -> tuple[ActivationToken, str]:
    raw_token = generate_token_urlsafe()
    activation = ActivationToken.objects.create(
        token=_hash_token(raw_token),
        user=user,
        tenant=tenant,
        expires_at=expires_at or (timezone.now() + ACTIVATION_TTL),
    )
    return activation, raw_token


def ensure_tenant(tenant_id: str, tenant_slug: str) -> Tenant:
    tenant = Tenant.objects.filter(slug=tenant_slug).first()
    if tenant:
        if str(tenant.id) != str(tenant_id):
            # In dev mode we allow slug to be authoritative to avoid cross-service
            # tenant id mismatches breaking internal calls.
            if getattr(settings, "DEBUG", False) or getattr(settings, "DEV_AUTH_MODE", False):
                return tenant
            raise HttpError(
                409,
                error_payload(
                    "TENANT_MISMATCH",
                    "Tenant slug does not match tenant id",
                    details={
                        "tenant_id": str(tenant.id),
                        "tenant_slug": tenant.slug,
                    },
                ),
            )
        return tenant

    tenant = Tenant.objects.create(id=tenant_id, slug=tenant_slug)
    return tenant


def require_active_user(user: User) -> None:
    if user.status == UserStatus.SUSPENDED:
        raise HttpError(
            403,
            error_payload("ACCOUNT_SUSPENDED", "Account is suspended"),
        )
    if user.status == UserStatus.BANNED:
        raise HttpError(
            403,
            error_payload("ACCOUNT_BANNED", "Account is banned"),
        )


def create_application(tenant_slug: str, payload_json: dict) -> Application:
    return Application.objects.create(
        tenant_slug=tenant_slug,
        payload_json=payload_json,
    )


@transaction.atomic
def approve_application(
    application: Application,
    *,
    reviewer_user_id: str | None,
    tenant: Tenant,
) -> ActivationToken:
    if application.status != ApplicationStatus.PENDING:
        raise HttpError(
            409,
            error_payload(
                "INVALID_APPLICATION_STATUS",
                "Application is not pending",
            ),
        )

    email = (application.payload_json or {}).get("email")
    if not email:
        raise HttpError(
            400,
            error_payload("MISSING_EMAIL", "payload_json.email is required"),
        )

    user, created = User.objects.get_or_create(
        email=str(email).lower().strip(),
        defaults={
            "username": (application.payload_json or {}).get("username", ""),
            "display_name": (application.payload_json or {}).get(
                "display_name",
                "",
            ),
            "status": UserStatus.MIGRATED_UNCLAIMED,
            "email_verified": False,
        },
    )
    if not created:
        # If user exists but is banned/suspended, keep application rejected
        # in spirit.
        if user.status in {UserStatus.SUSPENDED, UserStatus.BANNED}:
            raise HttpError(
                403,
                error_payload("USER_NOT_ELIGIBLE", "User is not eligible"),
            )

    TenantMembership.objects.get_or_create(
        user=user,
        tenant=tenant,
        defaults={"status": MembershipStatus.ACTIVE, "base_role": "member"},
    )

    application.status = ApplicationStatus.APPROVED
    application.reviewed_by_user_id = reviewer_user_id
    application.reviewed_at = timezone.now()
    application.save(
        update_fields=["status", "reviewed_by_user_id", "reviewed_at"]
    )

    activation, raw_token = issue_activation_token(
        user=user,
        tenant=tenant,
        expires_at=timezone.now() + ACTIVATION_TTL,
    )
    activation.raw_token = raw_token
    actor = (
        User.objects.filter(user_id=reviewer_user_id).first()
        if reviewer_user_id
        else None
    )
    record_audit(
        action="application.approved",
        actor_user=actor,
        target_type="application",
        target_id=application.id,
        tenant=tenant,
        meta={
            "user_id": str(user.user_id),
            "application_id": application.id,
        },
    )
    if created:
        enqueue_outbox(
            event_type="user.created",
            tenant=tenant,
            payload={
                "user_id": str(user.user_id),
                "email": user.email,
                "tenant_id": str(tenant.id),
                "tenant_slug": tenant.slug,
            },
        )
    enqueue_outbox(
        event_type="application.approved",
        tenant=tenant,
        payload={
            "application_id": application.id,
            "user_id": str(user.user_id),
            "tenant_id": str(tenant.id),
            "tenant_slug": tenant.slug,
        },
    )
    return activation


@transaction.atomic
def reject_application(
    application: Application,
    *,
    reviewer_user_id: str | None,
) -> None:
    if application.status != ApplicationStatus.PENDING:
        raise HttpError(
            409,
            error_payload(
                "INVALID_APPLICATION_STATUS",
                "Application is not pending",
            ),
        )
    application.status = ApplicationStatus.REJECTED
    application.reviewed_by_user_id = reviewer_user_id
    application.reviewed_at = timezone.now()
    application.save(
        update_fields=["status", "reviewed_by_user_id", "reviewed_at"]
    )
    actor = (
        User.objects.filter(user_id=reviewer_user_id).first()
        if reviewer_user_id
        else None
    )
    tenant = Tenant.objects.filter(slug=application.tenant_slug).first()
    record_audit(
        action="application.rejected",
        actor_user=actor,
        target_type="application",
        target_id=application.id,
        tenant=tenant,
        meta={"application_id": application.id},
    )
    if tenant:
        enqueue_outbox(
            event_type="application.rejected",
            tenant=tenant,
            payload={
                "application_id": application.id,
                "tenant_id": str(tenant.id),
                "tenant_slug": tenant.slug,
            },
        )


@transaction.atomic
def activate_account(token: str, *, tenant: Tenant) -> User:
    token_hash = _hash_token(token)
    try:
        activation = (
            ActivationToken.objects.select_for_update()
            .select_related("user", "tenant")
            .get(token=token_hash)
        )
    except ActivationToken.DoesNotExist:
        try:
            activation = (
                ActivationToken.objects.select_for_update()
                .select_related("user", "tenant")
                .get(token=token)
            )
        except ActivationToken.DoesNotExist as exc:
            raise HttpError(
                404,
                error_payload("TOKEN_NOT_FOUND", "Activation token not found"),
            ) from exc

    if activation.tenant_id != tenant.id:
        raise HttpError(
            403,
            error_payload(
                "TENANT_FORBIDDEN",
                "Token belongs to different tenant",
            ),
        )

    if activation.used_at is not None:
        raise HttpError(409, error_payload("TOKEN_USED", "Token already used"))
    if activation.expires_at <= timezone.now():
        raise HttpError(410, error_payload("TOKEN_EXPIRED", "Token expired"))

    user = activation.user
    if user.status in {UserStatus.SUSPENDED, UserStatus.BANNED}:
        raise HttpError(
            403,
            error_payload("ACCOUNT_NOT_ELIGIBLE", "Account is not eligible"),
        )

    user.status = UserStatus.ACTIVE
    user.email_verified = True
    user.save(update_fields=["status", "email_verified"])

    activation.used_at = timezone.now()
    activation.save(update_fields=["used_at"])
    record_audit(
        action="account.activated",
        actor_user=user,
        target_type="user",
        target_id=str(user.user_id),
        tenant=tenant,
        meta={"tenant_id": str(tenant.id), "tenant_slug": tenant.slug},
    )
    enqueue_outbox(
        event_type="user.activated",
        tenant=tenant,
        payload={
            "user_id": str(user.user_id),
            "tenant_id": str(tenant.id),
            "tenant_slug": tenant.slug,
        },
    )
    return user


def request_magic_link(
    *,
    email: str,
    ip: str,
    ua: str,
    skip_context_validation: bool = False,
) -> MagicLinkToken | None:
    try:
        user = User.objects.get(email=str(email).lower().strip())
    except User.DoesNotExist:
        return None

    try:
        require_active_user(user)
        if not user.email_verified:
            raise HttpError(
                403,
                error_payload("EMAIL_NOT_VERIFIED", "Email is not verified"),
            )
    except HttpError:
        return None

    raw_token = generate_token_urlsafe()
    token = MagicLinkToken.objects.create(
        token=_hash_token(raw_token),
        user=user,
        expires_at=timezone.now() + MAGIC_LINK_TTL,
        ip_hash="" if skip_context_validation else _hash_value(ip),
        ua_hash="" if skip_context_validation else _hash_value(ua),
        skip_context_validation=skip_context_validation,
    )
    token.raw_token = raw_token
    return token


@transaction.atomic
def consume_magic_link(
    *,
    token: str,
    ip: str,
    ua: str,
) -> tuple[User, IdSession]:
    token_hash = _hash_token(token)
    try:
        mlt = (
            MagicLinkToken.objects.select_for_update()
            .select_related("user")
            .get(token=token_hash)
        )
    except MagicLinkToken.DoesNotExist:
        try:
            mlt = (
                MagicLinkToken.objects.select_for_update()
                .select_related("user")
                .get(token=token)
            )
        except MagicLinkToken.DoesNotExist as exc:
            raise HttpError(
                404,
                error_payload("TOKEN_NOT_FOUND", "Magic link token not found"),
            ) from exc

    if mlt.used_at is not None:
        raise HttpError(409, error_payload("TOKEN_USED", "Token already used"))
    if mlt.expires_at <= timezone.now():
        raise HttpError(410, error_payload("TOKEN_EXPIRED", "Token expired"))

    if not mlt.skip_context_validation:
        if not _context_matches(mlt.ip_hash, _hash_value(ip)) or not _context_matches(
            mlt.ua_hash, _hash_value(ua)
        ):
            raise HttpError(
                403,
                error_payload("TOKEN_CONTEXT_MISMATCH", "Magic link context mismatch"),
            )

    user = mlt.user
    require_active_user(user)
    if not user.email_verified:
        raise HttpError(
            403,
            error_payload("EMAIL_NOT_VERIFIED", "Email is not verified"),
        )

    mlt.used_at = timezone.now()
    mlt.save(update_fields=["used_at"])

    session = IdSession.objects.create(
        user=user,
        expires_at=timezone.now() + SESSION_TTL,
        ip_hash=_hash_value(ip),
        ua_hash=_hash_value(ua),
    )
    return user, session


def get_session_user(session_token: str) -> User:
    try:
        session = IdSession.objects.select_related("user").get(
            token=session_token
        )
    except IdSession.DoesNotExist as exc:
        raise HttpError(
            401,
            error_payload("UNAUTHORIZED", "Invalid session"),
        ) from exc

    if session.revoked_at is not None or session.expires_at <= timezone.now():
        raise HttpError(401, error_payload("UNAUTHORIZED", "Session expired"))

    user = session.user
    require_active_user(user)
    return user


def revoke_session(session_token: str) -> None:
    if not session_token:
        return
    IdSession.objects.filter(
        token=session_token,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())


@transaction.atomic
def oauth_start(
    *,
    provider: str,
    purpose: str,
    tenant: Tenant,
    user: User | None,
    redirect_uri: str,
) -> OAuthState:
    state = OAuthState.objects.create(
        provider=provider,
        purpose=purpose,
        tenant=tenant,
        user=user,
        redirect_uri=redirect_uri,
        expires_at=timezone.now() + OAUTH_STATE_TTL,
    )
    return state


@transaction.atomic
def oauth_consume_state(
    *,
    state_value: str,
    provider: str,
    purpose: str,
    tenant: Tenant,
) -> OAuthState:
    try:
        st = OAuthState.objects.select_for_update().get(state=state_value)
    except OAuthState.DoesNotExist as exc:
        raise HttpError(
            404,
            error_payload("STATE_NOT_FOUND", "state not found"),
        ) from exc

    if st.tenant_id != tenant.id:
        raise HttpError(
            403,
            error_payload(
                "TENANT_FORBIDDEN",
                "state belongs to different tenant",
            ),
        )
    if st.provider != provider or st.purpose != purpose:
        raise HttpError(
            400,
            error_payload(
                "INVALID_STATE",
                "state does not match provider/purpose",
            ),
        )
    if st.used_at is not None:
        raise HttpError(
            409,
            error_payload("CALLBACK_ALREADY_USED", "callback already used"),
        )
    if st.expires_at <= timezone.now():
        raise HttpError(410, error_payload("STATE_EXPIRED", "state expired"))

    st.used_at = timezone.now()
    st.save(update_fields=["used_at"])
    return st


def oauth_login_only_if_linked(*, provider: str, subject: str) -> User:
    try:
        ext = ExternalIdentity.objects.select_related("user").get(
            provider=provider,
            subject=subject,
        )
    except ExternalIdentity.DoesNotExist as exc:
        raise HttpError(
            403,
            error_payload("ACCOUNT_NOT_LINKED", "External account not linked"),
        ) from exc

    user = ext.user
    require_active_user(user)
    if not user.email_verified:
        raise HttpError(
            403,
            error_payload("EMAIL_NOT_VERIFIED", "Email is not verified"),
        )
    ext.last_used_at = timezone.now()
    ext.save(update_fields=["last_used_at"])
    return user


@transaction.atomic
def link_external_identity(
    *,
    user: User,
    provider: str,
    subject: str,
    tenant: Tenant,
) -> ExternalIdentity:
    require_active_user(user)
    ext, created = ExternalIdentity.objects.get_or_create(
        user=user,
        provider=provider,
        defaults={"subject": subject},
    )
    if ext.subject != subject:
        # user already linked to another subject
        raise HttpError(
            409,
            error_payload(
                "IDENTITY_CONFLICT",
                "Provider already linked to different account",
            ),
        )
    if created:
        record_audit(
            action="external_identity.linked",
            actor_user=user,
            target_type="external_identity",
            target_id=f"{provider}:{subject}",
            tenant=tenant,
            meta={"provider": provider},
        )
        enqueue_outbox(
            event_type="external_identity.linked",
            tenant=tenant,
            payload={
                "user_id": str(user.user_id),
                "provider": provider,
                "subject": subject,
                "tenant_id": str(tenant.id),
                "tenant_slug": tenant.slug,
            },
        )
    return ext
