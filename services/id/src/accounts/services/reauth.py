from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from ninja.errors import HttpError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ReauthService:
    @staticmethod
    def verify(user, *, password: str, mfa_code: str | None = None, recovery_code: str | None = None) -> None:
        if not user.check_password(password):
            logger.info(
                "Reauth failed: invalid password",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise HttpError(
                400,
                {
                    "code": "INVALID_PASSWORD",
                    "message": "Неверный текущий пароль",
                },
            )

        if "allauth.mfa" not in getattr(settings, "INSTALLED_APPS", []):
            return

        try:
            from allauth.mfa.adapter import get_adapter as get_mfa_adapter
            from allauth.mfa.models import Authenticator
            from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
            from allauth.mfa.totp.internal.auth import TOTP

            if not get_mfa_adapter().is_mfa_enabled(user):
                return

            code = (mfa_code or recovery_code or "").strip().replace(" ", "")
            if not code:
                raise HttpError(
                    400,
                    {"code": "MFA_REQUIRED", "message": "Требуется код MFA"},
                )
            totp_auth = Authenticator.objects.filter(
                user=user, type=Authenticator.Type.TOTP
            ).first()
            rc_auth = Authenticator.objects.filter(
                user=user, type=Authenticator.Type.RECOVERY_CODES
            ).first()
            if totp_auth and TOTP(totp_auth).validate_code(code):
                return
            if rc_auth and RecoveryCodes(rc_auth).validate_code(code):
                return
            raise HttpError(
                400,
                {
                    "code": "INVALID_MFA_CODE",
                    "message": "Неверный код MFA",
                },
            )
        except HttpError:
            raise
        except Exception as exc:
            logger.warning(
                "Reauth failed: MFA validation error",
                extra={"user_id": getattr(user, "id", None)},
                exc_info=exc,
            )
            raise HttpError(
                400,
                {
                    "code": "MFA_VALIDATION_FAILED",
                    "message": "Не удалось проверить код MFA",
                },
            ) from exc
