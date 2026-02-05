from __future__ import annotations

# isort: skip_file

import logging
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone

from accounts.services.preferences import PreferencesService
from accounts.services.profile import ProfileService
from accounts.transport.schemas import (
    ProfileOut,
    TokenPairOut,
    TokenRefreshIn,
    TokenRefreshOut,
)
from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount
from core.models import UserSessionMeta, UserSessionToken
from django.conf import settings
from django.contrib.auth import get_user_model, logout as dj_logout
from django.utils import timezone
from ninja.errors import HttpError
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()
logger = logging.getLogger(__name__)

UNAUTHORIZED_PAYLOAD: dict[str, str] = {
    "code": "UNAUTHORIZED",
    "message": "Требуется авторизация",
}
INVALID_TOKEN_PAYLOAD: dict[str, str] = {
    "code": "INVALID_OR_EXPIRED_TOKEN",
    "message": "Сессия недействительна, пожалуйста, войдите заново",
}


def _http_error(status: int, payload: dict[str, str]) -> HttpError:
    return HttpError(status, payload)  # type: ignore[arg-type]


def _has_mfa_enabled(user) -> bool:
    if "allauth.mfa" not in getattr(settings, "INSTALLED_APPS", []):
        return False
    try:
        from allauth.mfa.adapter import get_adapter as get_mfa_adapter

        return bool(get_mfa_adapter().is_mfa_enabled(user))
    except Exception:
        return False


@dataclass(slots=True)
class AuthService:
    @staticmethod
    def issue_pair_for_session(request, user) -> TokenPairOut:
        if not getattr(user, "is_authenticated", False):
            raise _http_error(401, UNAUTHORIZED_PAYLOAD)
        token = request.headers.get("X-Session-Token") or ""
        dj_key = request.session.session_key or ""

        meta = (
            UserSessionMeta.objects.filter(user=user, session_token=token).first()
            or UserSessionMeta.objects.filter(user=user, session_key=dj_key).first()
        )
        if not meta:
            meta = UserSessionMeta.objects.create(
                user=user,
                session_key=dj_key or token,
                session_token=token or None,
            )
        if dj_key and meta.session_key != dj_key:
            meta.session_key = dj_key
            meta.save(update_fields=["session_key"])

        rt = RefreshToken.for_user(user)
        at = rt.access_token  # type: ignore[attr-defined]
        rt["session_key"] = meta.session_key

        expires_at = datetime.fromtimestamp(float(rt["exp"]), tz=dt_timezone.utc)
        OutstandingToken.objects.update_or_create(
            user=user,
            jti=str(rt["jti"]),
            defaults={"token": str(rt), "expires_at": expires_at},
        )

        UserSessionToken.objects.get_or_create(
            user=user, session_key=meta.session_key, refresh_jti=str(rt["jti"])
        )
        logger.info(
            "Issued JWT pair for session",
            extra={
                "user_id": getattr(user, "id", None),
                "session_key": meta.session_key,
                "has_header_session_token": bool(token),
            },
        )
        return TokenPairOut(access=str(at), refresh=str(rt))

    @staticmethod
    def logout_current(request) -> None:
        dj_logout(request)
        logger.info(
            "User logged out",
            extra={"user_id": getattr(getattr(request, "user", None), "id", None)},
        )

    @staticmethod
    def profile(user, request=None) -> ProfileOut:
        if not user or not getattr(user, "is_authenticated", False):
            raise HttpError(401, "Not authenticated")
        ProfileService.maybe_refresh_gravatar(user)
        avatar = ProfileService.avatar_state(user, request=request)
        has_2fa = _has_mfa_enabled(user)
        profile = getattr(user, "profile", None) or ProfileService._ensure_profile(user)
        prefs = PreferencesService.get(user)
        providers_qs = SocialAccount.objects.filter(user=user).values_list(
            "provider", flat=True
        )
        providers = list(providers_qs)
        primary = EmailAddress.objects.filter(user=user, primary=True).first()
        return ProfileOut(
            username=user.username,
            email=user.email,
            has_2fa=has_2fa,
            oauth_providers=providers,
            is_staff=bool(getattr(user, "is_staff", False)),
            is_superuser=bool(getattr(user, "is_superuser", False)),
            first_name=getattr(user, "first_name", None) or None,
            last_name=getattr(user, "last_name", None) or None,
            phone_number=getattr(profile, "phone_number", None),
            phone_verified=getattr(profile, "phone_verified", None),
            birth_date=(
                getattr(profile, "birth_date", None).isoformat()
                if getattr(profile, "birth_date", None)
                else None
            ),
            language=prefs.get("language"),
            timezone=prefs.get("timezone"),
            avatar_url=avatar.url,
            avatar_source=avatar.source,
            avatar_gravatar_enabled=avatar.gravatar_enabled,
            email_verified=bool(primary and primary.verified),
        )

    @staticmethod
    def change_password(user, current: str, new: str) -> None:
        from django.contrib.auth.password_validation import validate_password
        from django.core.exceptions import ValidationError

        if not user.check_password(current):
            logger.warning(
                "Password change rejected: wrong current password",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise HttpError(400, "wrong current password")
        if not (new and new.strip()):
            logger.info(
                "Password change rejected: empty new password",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise HttpError(400, "new password cannot be empty")
        if current == new:
            logger.info(
                "Password change rejected: new password equals current",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise HttpError(400, "new password must differ from current")
        try:
            validate_password(new, user=user)
        except ValidationError as e:
            logger.info(
                "Password change rejected: validation failed",
                extra={
                    "user_id": getattr(user, "id", None),
                    "errors": e.messages,
                },
            )
            raise HttpError(400, "; ".join(e.messages)) from e
        user.set_password(new)
        user.save(update_fields=["password"])
        logger.info(
            "Password changed successfully",
            extra={"user_id": getattr(user, "id", None)},
        )

    @staticmethod
    def refresh_pair(payload: TokenRefreshIn) -> TokenRefreshOut:
        try:
            rt = RefreshToken(payload.refresh)
        except Exception as err:
            logger.warning("Refresh token rejected: invalid token structure")
            raise _http_error(401, INVALID_TOKEN_PAYLOAD) from err

        user = User.objects.filter(pk=rt.get("user_id")).first()
        if not user:
            logger.warning("Refresh token rejected: unknown user")
            raise _http_error(401, INVALID_TOKEN_PAYLOAD)

        jti = str(rt["jti"])
        expires_at = datetime.fromtimestamp(float(rt["exp"]), tz=dt_timezone.utc)
        outstanding, _ = OutstandingToken.objects.update_or_create(
            user=user,
            jti=jti,
            defaults={"token": str(rt), "expires_at": expires_at},
        )

        if BlacklistedToken.objects.filter(token=outstanding).exists():
            logger.warning(
                "Refresh token rejected: blacklisted",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise _http_error(401, INVALID_TOKEN_PAYLOAD)

        mapping = UserSessionToken.objects.filter(
            user=user, refresh_jti=jti, revoked_at__isnull=True
        ).first()
        if not mapping:
            logger.warning(
                "Refresh token rejected: session mapping missing",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise _http_error(401, INVALID_TOKEN_PAYLOAD)

        meta = UserSessionMeta.objects.filter(
            user=user, session_key=mapping.session_key
        ).first()
        if meta and meta.revoked_at:
            logger.warning(
                "Refresh token rejected: session revoked",
                extra={
                    "user_id": getattr(user, "id", None),
                    "session_key": mapping.session_key,
                },
            )
            raise _http_error(401, INVALID_TOKEN_PAYLOAD)

        # Blacklist the incoming refresh token and retire its mapping
        BlacklistedToken.objects.get_or_create(token=outstanding)
        now = timezone.now()
        if not mapping.revoked_at:
            mapping.revoked_at = now
            mapping.save(update_fields=["revoked_at"])

        new_refresh = RefreshToken.for_user(user)
        new_refresh["session_key"] = mapping.session_key
        new_rt_jti = str(new_refresh["jti"])
        new_expires_at = datetime.fromtimestamp(
            float(new_refresh["exp"]), tz=dt_timezone.utc
        )
        OutstandingToken.objects.update_or_create(
            user=user,
            jti=new_rt_jti,
            defaults={"token": str(new_refresh), "expires_at": new_expires_at},
        )
        UserSessionToken.objects.get_or_create(
            user=user,
            session_key=mapping.session_key,
            refresh_jti=new_rt_jti,
        )

        logger.info(
            "Issued new token pair from refresh",
            extra={
                "user_id": getattr(user, "id", None),
                "session_key": mapping.session_key,
            },
        )
        access_token = new_refresh.access_token  # type: ignore[attr-defined]
        access_str = str(access_token)
        return TokenRefreshOut(refresh=str(new_refresh), access=access_str)
