from __future__ import annotations

import logging

from allauth.account.internal.flows.login import (
    AUTHENTICATION_METHODS_SESSION_KEY,
    record_authentication,
)
from allauth.headless.internal.sessionkit import (
    authenticate_by_x_session_token,
)
from ninja.errors import HttpError
from ninja.security.base import AuthBase

logger = logging.getLogger(__name__)


def _record_session_authentication_best_effort(request, user) -> None:
    try:
        record_authentication(request, user, method="session")
    except Exception:
        logger.warning(
            "Failed to record session authentication",
            extra={"user_id": getattr(user, "id", None)},
            exc_info=True,
        )


class SessionTokenAuth(AuthBase):
    """
    Custom X-Session-Token auth that also wires the underlying Django session
    onto the request so downstream allauth flows (reauth/MFA) can read
    authentication records.
    """

    openapi_type = "apiKey"

    def __call__(self, request):
        fallback_user = getattr(request, "user", None)
        raw_auth = request.headers.get("Authorization") or ""
        token = None
        if raw_auth.lower().startswith("bearer "):
            token = raw_auth.split(" ", 1)[1].strip()
        if not token:
            token = request.headers.get("X-Session-Token")
        if not token:
            if getattr(fallback_user, "is_authenticated", False):
                request.auth = fallback_user
                return fallback_user
            # No token -> anonymous
            request.user = None
            return None
        user_session = authenticate_by_x_session_token(token)
        if not user_session:
            if getattr(fallback_user, "is_authenticated", False):
                request.auth = fallback_user
                return fallback_user
            raise HttpError(
                401,
                {
                    "code": "INVALID_OR_EXPIRED_TOKEN",
                    "message": ("Сессия недействительна, пожалуйста, войдите заново"),
                },
            )
        user, session = user_session
        try:
            request._session = session
            request.session = session
        except Exception:
            request._session = session
        request.user = user
        request.auth = user
        if not session.get(AUTHENTICATION_METHODS_SESSION_KEY):
            _record_session_authentication_best_effort(request, user)
        return user


session_token_auth = SessionTokenAuth()


def authenticate_optional(request):
    """Authenticate only when a token is present; otherwise return None."""
    fallback_user = getattr(request, "user", None)
    raw_auth = request.headers.get("Authorization") or ""
    token = None
    if raw_auth.lower().startswith("bearer "):
        token = raw_auth.split(" ", 1)[1].strip()
    if not token:
        token = request.headers.get("X-Session-Token")
    if not token:
        if getattr(fallback_user, "is_authenticated", False):
            request.auth = fallback_user
            return fallback_user
        request.user = None
        request.auth = None
        return None

    user_session = authenticate_by_x_session_token(token)
    if not user_session:
        if getattr(fallback_user, "is_authenticated", False):
            request.auth = fallback_user
            return fallback_user
        raise HttpError(
            401,
            {
                "code": "INVALID_OR_EXPIRED_TOKEN",
                "message": ("Сессия недействительна, пожалуйста, войдите заново"),
            },
        )
    user, session = user_session
    try:
        request._session = session
        request.session = session
    except Exception:
        request._session = session
    request.user = user
    request.auth = user
    if not session.get(AUTHENTICATION_METHODS_SESSION_KEY):
        _record_session_authentication_best_effort(request, user)
    return user
