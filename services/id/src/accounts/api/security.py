from __future__ import annotations

from allauth.account.internal.flows.login import (
    AUTHENTICATION_METHODS_SESSION_KEY,
    record_authentication,
)
from allauth.headless.internal.sessionkit import (
    authenticate_by_x_session_token,
)
from ninja.errors import HttpError
from ninja.security.base import AuthBase


class SessionTokenAuth(AuthBase):
    """
    Custom X-Session-Token auth that also wires the underlying Django session
    onto the request so downstream allauth flows (reauth/MFA) can read
    authentication records.
    """

    openapi_type = "apiKey"

    def __call__(self, request):
        raw_auth = request.headers.get("Authorization") or ""
        token = None
        if raw_auth.lower().startswith("bearer "):
            token = raw_auth.split(" ", 1)[1].strip()
        if not token:
            token = request.headers.get("X-Session-Token")
        if not token:
            # No token -> anonymous
            request.user = None
            return None
        user_session = authenticate_by_x_session_token(token)
        if not user_session:
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
            record_authentication(request, user, method="session")
        return user


session_token_auth = SessionTokenAuth()


def authenticate_optional(request):
    """Authenticate only when a token is present; otherwise return None."""
    raw_auth = request.headers.get("Authorization") or ""
    token = None
    if raw_auth.lower().startswith("bearer "):
        token = raw_auth.split(" ", 1)[1].strip()
    if not token:
        token = request.headers.get("X-Session-Token")
    if not token:
        request.user = None
        request.auth = None
        return None

    user_session = authenticate_by_x_session_token(token)
    if not user_session:
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
        record_authentication(request, user, method="session")
    return user
