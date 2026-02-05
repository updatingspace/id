from allauth.headless.contrib.ninja.security import x_session_token_auth
from ninja import Body, Router
from ninja.errors import HttpError

from accounts.api.security import authenticate_optional
from accounts.services.auth import AuthService
from accounts.transport.schemas import (
    ChangePasswordIn,
    CurrentUserOut,
    ErrorOut,
    OkOut,
    TokenPairOut,
    TokenRefreshIn,
    TokenRefreshOut,
)

auth_router = Router(tags=["Auth"])
REQUIRED_BODY = Body(...)


def _require_user(request):
    user = getattr(request, "auth", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(
            401,
            {"code": "UNAUTHORIZED", "message": "Требуется авторизация"},
        )
    return user


@auth_router.post(
    "/jwt/from_session",
    auth=[x_session_token_auth],
    response={200: TokenPairOut, 401: ErrorOut},
    summary="Issue JWT pair bound to current session",
    operation_id="auth_jwt_from_session",
)
def jwt_from_session(request):
    user = _require_user(request)
    return AuthService.issue_pair_for_session(request, user)


@auth_router.post(
    "/logout",
    auth=[x_session_token_auth],
    response={200: OkOut},
    summary="Logout current session",
    operation_id="auth_logout",
)
def logout_current(request):
    _require_user(request)
    AuthService.logout_current(request)
    return OkOut(ok=True, message="logged out")


@auth_router.get(
    "/me",
    auth=None,
    response={200: CurrentUserOut, 401: ErrorOut},
    summary="Get current user profile or guest",
    operation_id="auth_me",
)
def me(request):
    try:
        user = authenticate_optional(request)
    except HttpError:
        # authenticate_optional already raises structured 401
        raise
    if not user:
        return {"user": None}
    return {"user": AuthService.profile(user, request=request)}


@auth_router.post(
    "/change_password",
    auth=[x_session_token_auth],
    response={200: OkOut, 400: ErrorOut, 401: ErrorOut},
    summary="Change password (requires current password)",
    operation_id="auth_change_password",
)
def change_password(request, payload: ChangePasswordIn = REQUIRED_BODY):
    user = _require_user(request)
    AuthService.change_password(user, payload.current_password, payload.new_password)
    return OkOut(ok=True, message="password changed")


@auth_router.post(
    "/refresh",
    response={200: TokenRefreshOut, 401: ErrorOut},
    summary="Refresh JWT pair",
    operation_id="auth_refresh",
)
def refresh_pair(request, payload: TokenRefreshIn = REQUIRED_BODY):
    return AuthService.refresh_pair(payload)
