from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from allauth.account.forms import SignupForm
from allauth.account.internal.flows.login import record_authentication
from allauth.account.models import EmailAddress
from allauth.account.utils import perform_login
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as dj_login
from django.db import transaction
from django.utils import timezone
from django.utils.module_loading import import_string
from ninja.errors import HttpError

from updspaceid.enums import MembershipStatus, UserStatus
from updspaceid.http import require_tenant_headers
from updspaceid.models import TenantMembership, User as UpdspaceIdUser
from updspaceid.services import ensure_tenant

from accounts.services.activity import ActivityService
from accounts.services.preferences import ConsentService, PreferencesService
from accounts.services.mfa import MfaService
from accounts.services.profile import ProfileService
from accounts.models import UserConsent

logger = logging.getLogger(__name__)


def _hash_email(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


@dataclass(slots=True)
class HeadlessService:
    @staticmethod
    def issue_session_token(request) -> str:
        Strategy = import_string(
            getattr(
                settings,
                "HEADLESS_TOKEN_STRATEGY",
                "allauth.headless.tokens.sessions.SessionTokenStrategy",
            )
        )
        return Strategy().create_session_token(request)

    @staticmethod
    def login(
        request,
        email: str,
        password: str,
        *,
        mfa_code: str | None = None,
        recovery_code: str | None = None,
    ) -> dict:
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user_obj = User.objects.filter(email__iexact=email.strip()).first()
        if not user_obj:
            logger.warning(
                "Headless login failed: user not found",
                extra={"email_hash": _hash_email(email)},
            )
            raise HttpError(
                401,
                {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Неверный логин или пароль",
                },
            )
        user = authenticate(
            request,
            username=getattr(user_obj, "username", ""),
            password=password,
        )
        if not user:
            logger.warning(
                "Headless login failed: invalid password",
                extra={
                    "user_id": getattr(user_obj, "id", None),
                },
            )
            ActivityService.record_login(
                request,
                user=user_obj,
                success=False,
                reason="invalid_password",
            )
            raise HttpError(
                401,
                {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Неверный логин или пароль",
                },
            )
        record_authentication(request, user, method="password", email=email.strip())

        mfa_enabled = False
        mfa_used: str | None = None
        if "allauth.mfa" in getattr(settings, "INSTALLED_APPS", []):
            try:
                from allauth.mfa.adapter import get_adapter as get_mfa_adapter

                mfa_enabled = bool(get_mfa_adapter().is_mfa_enabled(user))
            except Exception:
                mfa_enabled = False

        if mfa_enabled:
            from allauth.mfa.models import Authenticator
            from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
            from allauth.mfa.totp.internal.auth import TOTP

            code = (mfa_code or recovery_code or "").strip().replace(" ", "")
            if not code:
                logger.info(
                    "Headless login requires MFA code",
                    extra={
                        "user_id": getattr(user, "id", None),
                        "mfa_enabled": True,
                    },
                )
                ActivityService.record_login(
                    request, user=user, success=False, reason="mfa_required"
                )
                raise HttpError(
                    401,
                    {"code": "MFA_REQUIRED", "message": "Требуется код MFA"},
                )
            totp_auth = Authenticator.objects.filter(
                user=user, type=Authenticator.Type.TOTP
            ).first()
            rc_auth = Authenticator.objects.filter(
                user=user, type=Authenticator.Type.RECOVERY_CODES
            ).first()
            validated = False
            if totp_auth and TOTP(totp_auth).validate_code(code):
                validated = True
                mfa_used = "totp"
                record_authentication(
                    request, user, method="mfa", type="totp", passwordless=False
                )
            elif rc_auth and RecoveryCodes(rc_auth).validate_code(code):
                validated = True
                mfa_used = "recovery_code"
                record_authentication(request, user, method="mfa", type="recovery_codes")
            if not validated:
                logger.warning(
                    "Headless login failed: invalid MFA code",
                    extra={
                        "user_id": getattr(user, "id", None),
                        "mfa_enabled": True,
                    },
                )
                ActivityService.record_login(
                    request, user=user, success=False, reason="invalid_mfa"
                )
                raise HttpError(
                    401,
                    {
                        "code": "INVALID_CREDENTIALS",
                        "message": "Неверный код подтверждения",
                    },
                )

        # Bypass allauth stage controller to stay headless and avoid redirects.
        dj_login(
            request,
            user,
            backend=user.backend if hasattr(user, "backend") else None,
        )
        recovery_codes = None
        if mfa_used == "recovery_code":
            try:
                recovery_codes = MfaService.rotate_recovery_codes(user)
            except Exception:
                logger.warning(
                    "Failed to rotate recovery codes",
                    extra={"user_id": getattr(user, "id", None)},
                    exc_info=True,
                )
        ActivityService.record_login(
            request,
            user=user,
            success=True,
            meta={"mfa_enabled": mfa_enabled, "mfa_method": mfa_used or ""},
        )
        logger.info(
            "Headless login succeeded",
            extra={
                "user_id": getattr(user, "id", None),
                "mfa_enabled": mfa_enabled,
                "mfa_method": mfa_used,
            },
        )
        _sync_updspace_identity(request, user)
        return {
            "session_token": HeadlessService.issue_session_token(request),
            "recovery_codes": recovery_codes,
        }

    @staticmethod
    def signup(
        request,
        username: str | None,
        email: str | None,
        password: str,
        *,
        language: str | None = None,
        timezone_name: str | None = None,
        consent_data_processing: bool = False,
        consent_marketing: bool = False,
        is_minor: bool = False,
        guardian_email: str | None = None,
        guardian_consent: bool = False,
        birth_date=None,
    ) -> str:
        from django.contrib.auth import get_user_model

        User = get_user_model()
        if not consent_data_processing:
            logger.info(
                "Signup rejected: data processing consent required",
                extra={"email_hash": _hash_email(email or "")},
            )
            raise HttpError(
                400,
                {
                    "code": "CONSENT_REQUIRED",
                    "message": "Требуется согласие на обработку персональных данных",
                },
            )
        minor = bool(is_minor)
        if birth_date:
            try:
                today = timezone.now().date()
                age = (
                    today.year
                    - birth_date.year
                    - ((today.month, today.day) < (birth_date.month, birth_date.day))
                )
                if age < 18:
                    minor = True
            except Exception:
                minor = bool(is_minor)
        if minor and not guardian_consent:
            raise HttpError(
                400,
                {
                    "code": "PARENTAL_CONSENT_REQUIRED",
                    "message": "Для пользователей младше 18 требуется согласие родителя/опекуна",
                },
            )
        if minor and not guardian_email:
            raise HttpError(
                400,
                {
                    "code": "GUARDIAN_EMAIL_REQUIRED",
                    "message": "Укажите email родителя/опекуна",
                },
            )
        if email and User.objects.filter(email__iexact=email.strip()).exists():
            logger.info(
                "Signup rejected: email already exists",
                extra={
                    "username": username,
                    "email_hash": _hash_email(email),
                },
            )
            raise HttpError(
                409,
                {
                    "code": "EMAIL_ALREADY_EXISTS",
                    "message": ("Пользователь с таким e-mail уже зарегистрирован"),
                },
            )
        form = SignupForm(
            data={
                "username": username or (email or "user"),
                "email": email or "",
                "password1": password,
                "password2": password,
            }
        )
        if not form.is_valid():
            logger.info(
                "Signup rejected due to validation errors",
                extra={
                    "username": username,
                    "email_hash": _hash_email(email or ""),
                    "errors": form.errors,
                },
            )
            raise HttpError(400, form.errors.as_json())
        user = form.save(request)
        record_authentication(
            request,
            user,
            method="password",
            username=(username or "").strip(),
        )
        perform_login(request, user)
        try:
            ProfileService.maybe_refresh_gravatar(user, force=True)
        except Exception:
            logger.warning(
                "Gravatar prefetch failed after signup",
                extra={"user_id": getattr(user, "id", None)},
                exc_info=True,
            )
        ProfileService.update_profile_fields(
            user,
            birth_date=birth_date,
        )
        PreferencesService.update(
            user,
            language=language,
            timezone_name=timezone_name,
            marketing_opt_in=bool(consent_marketing),
            source="signup",
        )
        ConsentService.grant(
            user,
            kind=UserConsent.Kind.DATA_PROCESSING,
            version=ConsentService.data_processing_version(),
            source="signup",
        )
        if consent_marketing:
            ConsentService.grant(
                user,
                kind=UserConsent.Kind.MARKETING,
                version=ConsentService.marketing_version(),
                source="signup",
            )
        if minor:
            ConsentService.grant(
                user,
                kind=UserConsent.Kind.PARENTAL,
                version=ConsentService.parental_version(),
                source="signup",
                meta={"guardian_email": guardian_email or ""},
            )
        logger.info(
            "Headless signup succeeded",
            extra={
                "user_id": getattr(user, "id", None),
                "username": username,
                "email_hash": _hash_email(email or ""),
            },
        )
        _sync_updspace_identity(request, user)
        return HeadlessService.issue_session_token(request)


def _sync_updspace_identity(request, user) -> None:
    email = (getattr(user, "email", "") or "").strip().lower()
    if not email:
        logger.debug(
            "Skipping UpdSpace identity sync: missing email",
            extra={"user_id": getattr(user, "id", None)},
        )
        return

    try:
        tenant_id, tenant_slug = require_tenant_headers(request)
    except HttpError:
        logger.debug(
            "Skipping UpdSpace identity sync: tenant headers unavailable",
            extra={"user_id": getattr(user, "id", None)},
        )
        return

    display_name = (
        f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}"
    ).strip()
    if not display_name:
        display_name = getattr(user, "username", "") or email.split("@")[0]
    is_verified = EmailAddress.objects.filter(user=user, verified=True).exists()
    is_admin = bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
    try:
        tenant = ensure_tenant(tenant_id, tenant_slug)
        with transaction.atomic():
            identity, created = UpdspaceIdUser.objects.get_or_create(
                email=email,
                defaults={
                    "username": getattr(user, "username", "") or email.split("@")[0],
                    "display_name": display_name,
                    "status": UserStatus.ACTIVE,
                    "email_verified": is_verified,
                    "system_admin": is_admin,
                },
            )
            if created:
                logger.info(
                    "Created UpdSpace identity",
                    extra={
                        "user_id": getattr(user, "id", None),
                        "updspace_user_id": str(identity.user_id),
                    },
                )
            else:
                updated_fields: list[str] = []
                if is_admin and not identity.system_admin:
                    identity.system_admin = True
                    updated_fields.append("system_admin")
                if identity.status != UserStatus.ACTIVE:
                    identity.status = UserStatus.ACTIVE
                    updated_fields.append("status")
                if is_verified and not identity.email_verified:
                    identity.email_verified = True
                    updated_fields.append("email_verified")
                if display_name and identity.display_name != display_name:
                    identity.display_name = display_name
                    updated_fields.append("display_name")
                username = getattr(user, "username", "")
                if username and identity.username != username:
                    identity.username = username
                    updated_fields.append("username")
                if updated_fields:
                    identity.save(update_fields=updated_fields)

            membership, _ = TenantMembership.objects.get_or_create(
                user=identity,
                tenant=tenant,
                defaults={
                    "status": MembershipStatus.ACTIVE,
                    "base_role": "admin" if is_admin else "member",
                },
            )
            membership_updates: list[str] = []
            if membership.status != MembershipStatus.ACTIVE:
                membership.status = MembershipStatus.ACTIVE
                membership_updates.append("status")
            if is_admin and membership.base_role != "admin":
                membership.base_role = "admin"
                membership_updates.append("base_role")
            if membership_updates:
                membership.save(update_fields=membership_updates)
    except Exception:
        logger.exception(
            "Failed to sync UpdSpace identity",
            extra={"user_id": getattr(user, "id", None)},
        )
