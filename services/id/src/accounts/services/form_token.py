from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass

from django.core.cache import cache
from django.core import signing
from ninja.errors import HttpError

logger = logging.getLogger(__name__)

TOKEN_TTL_SEC = 15 * 60
PREFIX = "formtoken"
SIGNING_SALT = "accounts.form_token"
INVALID_FORM_TOKEN_PAYLOAD = {
    "code": "INVALID_FORM_TOKEN",
    "message": "Неверный или просроченный токен формы",
}


def _invalid_token_error() -> HttpError:
    return HttpError(400, INVALID_FORM_TOKEN_PAYLOAD)  # type: ignore[arg-type]


@dataclass(slots=True)
class IssuedFormToken:
    token: str
    expires_in: int
    expires_at: int


class FormTokenPurpose:
    LOGIN = "login"
    REGISTER = "register"

    @classmethod
    def is_allowed(cls, value: str) -> bool:
        return value in {cls.LOGIN, cls.REGISTER}


class FormTokenService:
    """Single-use form tokens to prevent bot/CSRF-style submissions."""

    @staticmethod
    def _key(token: str) -> str:
        return f"{PREFIX}:{token}"

    @staticmethod
    def issue(
        *,
        purpose: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedFormToken:
        if not FormTokenPurpose.is_allowed(purpose):
            raise ValueError(f"Unsupported form token purpose: {purpose}")
        token = signing.dumps(
            {
                "purpose": purpose,
                "nonce": secrets.token_urlsafe(32),
            },
            salt=SIGNING_SALT,
        )
        now = int(time.time())
        expires_at = now + TOKEN_TTL_SEC
        cache.set(
            FormTokenService._key(token),
            {
                "purpose": purpose,
                "issued_at": now,
                "expires_at": expires_at,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "used": False,
            },
            TOKEN_TTL_SEC,
        )
        logger.debug(
            "Issued form token",
            extra={
                "purpose": purpose,
                "client_ip": client_ip,
                "user_agent": user_agent,
            },
        )
        return IssuedFormToken(
            token=token, expires_in=TOKEN_TTL_SEC, expires_at=expires_at
        )

    @staticmethod
    def consume(
        token: str | None, *, purpose: str, client_ip: str | None = None
    ) -> None:
        if not token:
            raise _invalid_token_error()
        stored = cache.get(FormTokenService._key(token))
        if not stored:
            FormTokenService._consume_signed(token, purpose=purpose, client_ip=client_ip)
            return
        if stored.get("purpose") != purpose:
            logger.info(
                "Form token rejected",
                extra={
                    "reason": "missing_or_mismatched",
                    "purpose": purpose,
                    "client_ip": client_ip,
                },
            )
            raise _invalid_token_error()
        now = int(time.time())
        if stored.get("expires_at", 0) < now:
            cache.delete(FormTokenService._key(token))
            logger.info(
                "Form token expired",
                extra={"purpose": purpose, "client_ip": client_ip},
            )
            raise _invalid_token_error()
        if stored.get("used"):
            cache.delete(FormTokenService._key(token))
            logger.info(
                "Form token reused",
                extra={"purpose": purpose, "client_ip": client_ip},
            )
            raise _invalid_token_error()
        cache.set(
            FormTokenService._key(token),
            {**stored, "used": True},
            max(stored.get("expires_at", now) - now, 1),
        )
        logger.debug(
            "Form token consumed",
            extra={"purpose": purpose, "client_ip": client_ip},
        )

    @staticmethod
    def _consume_signed(token: str, *, purpose: str, client_ip: str | None = None) -> None:
        try:
            payload = signing.loads(
                token,
                salt=SIGNING_SALT,
                max_age=TOKEN_TTL_SEC,
            )
        except signing.SignatureExpired:
            logger.info(
                "Signed form token expired",
                extra={"purpose": purpose, "client_ip": client_ip},
            )
            raise _invalid_token_error()
        except signing.BadSignature:
            logger.info(
                "Signed form token rejected",
                extra={
                    "reason": "bad_signature",
                    "purpose": purpose,
                    "client_ip": client_ip,
                },
            )
            raise _invalid_token_error()

        if not isinstance(payload, dict) or payload.get("purpose") != purpose:
            logger.info(
                "Signed form token rejected",
                extra={
                    "reason": "mismatched_purpose",
                    "purpose": purpose,
                    "client_ip": client_ip,
                },
            )
            raise _invalid_token_error()

        logger.debug(
            "Signed form token consumed",
            extra={"purpose": purpose, "client_ip": client_ip},
        )
