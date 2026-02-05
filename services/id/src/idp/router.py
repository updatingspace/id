from __future__ import annotations

import logging

from ninja import Body, Router
from ninja.errors import HttpError
from ninja.responses import Response

from accounts.api.security import session_token_auth
from accounts.services.rate_limit import get_client_ip, RateLimitService
from accounts.transport.schemas import ErrorOut, OkOut
from core.monitoring import track_oidc_event, track_rate_limit
from idp.models import OidcAuthorizationRequest
from idp.schemas import (
    AuthorizationApproveIn,
    AuthorizationDenyIn,
    AuthorizationDecisionOut,
    AuthorizationPrepareOut,
    RevokeIn,
    TokenRequestIn,
    TokenResponseOut,
)
from idp.services import OidcService

logger = logging.getLogger(__name__)
oidc_router = Router(tags=["OIDC"])
REQUIRED_BODY = Body(...)
NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _check_rate_limit(request, scope: str, **kwargs) -> None:
    """Check rate limit and raise 429 if exceeded."""
    ip = get_client_ip(request)

    if scope == "token":
        decision = RateLimitService.oidc_token_attempt(
            ip=ip, client_id=kwargs.get("client_id")
        )
    elif scope == "userinfo":
        decision = RateLimitService.oidc_userinfo_attempt(ip=ip)
    elif scope == "authorize":
        user = getattr(request, "auth", None)
        user_id = str(user.pk) if user and hasattr(user, "pk") else None
        decision = RateLimitService.oidc_authorize_attempt(ip=ip, user_id=user_id)
    else:
        return

    if decision.blocked:
        track_rate_limit(scope, "ip" if ip else "unknown")
        logger.warning(
            "OIDC rate limit exceeded",
            extra={"scope": scope, "ip": ip, "retry_after": decision.retry_after},
        )
        raise HttpError(
            429,
            {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": f"Too many requests. Retry after {decision.retry_after} seconds.",
                "retry_after": decision.retry_after,
            },
        )


def _require_user(request):
    user = getattr(request, "auth", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(
            401,
            {"code": "UNAUTHORIZED", "message": "Требуется авторизация"},
        )
    request.user = user
    return user


@oidc_router.get(
    "/authorize/prepare",
    auth=[session_token_auth],
    response={
        200: AuthorizationPrepareOut,
        400: ErrorOut,
        401: ErrorOut,
        404: ErrorOut,
        429: ErrorOut,
    },
    operation_id="oidc_authorize_prepare",
)
def authorize_prepare(
    request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str | None = None,
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    prompt: str | None = None,
):
    _check_rate_limit(request, "authorize")
    user = _require_user(request)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope or "",
        "state": state or "",
        "nonce": nonce or "",
        "code_challenge": code_challenge or "",
        "code_challenge_method": code_challenge_method or "",
        "prompt": prompt or "",
    }
    track_oidc_event("authorization_prepare", client_id=client_id)
    return OidcService.prepare_authorization(user, params)


@oidc_router.post(
    "/authorize/approve",
    auth=[session_token_auth],
    response={
        200: AuthorizationDecisionOut,
        400: ErrorOut,
        401: ErrorOut,
        429: ErrorOut,
    },
    operation_id="oidc_authorize_approve",
)
def authorize_approve(request, payload: AuthorizationApproveIn = REQUIRED_BODY):
    _check_rate_limit(request, "authorize")
    user = _require_user(request)

    # Get client_id for metrics before approving
    auth_req = OidcAuthorizationRequest.objects.filter(
        request_id=payload.request_id
    ).first()
    client_id = auth_req.client.client_id if auth_req else None

    redirect_uri = OidcService.approve_authorization(
        user,
        request_id=payload.request_id,
        approved_scopes=payload.scopes or None,
        remember=payload.remember,
    )
    track_oidc_event("authorization_approved", client_id=client_id)
    return Response(
        {"redirect_uri": redirect_uri},
        headers=NO_STORE_HEADERS,
    )


@oidc_router.post(
    "/authorize/deny",
    auth=[session_token_auth],
    response={
        200: AuthorizationDecisionOut,
        400: ErrorOut,
        401: ErrorOut,
        429: ErrorOut,
    },
    operation_id="oidc_authorize_deny",
)
def authorize_deny(request, payload: AuthorizationDenyIn = REQUIRED_BODY):
    _check_rate_limit(request, "authorize")
    user = _require_user(request)
    auth_req = OidcAuthorizationRequest.objects.filter(
        request_id=payload.request_id
    ).first()
    client_id = auth_req.client.client_id if auth_req else None

    redirect_uri = OidcService.deny_authorization(user, request_id=payload.request_id)
    track_oidc_event("authorization_denied", client_id=client_id)
    return Response(
        {"redirect_uri": redirect_uri},
        headers=NO_STORE_HEADERS,
    )


@oidc_router.post(
    "/token",
    response={200: TokenResponseOut, 400: ErrorOut, 401: ErrorOut, 429: ErrorOut},
    operation_id="oidc_token",
)
def token(request, payload: TokenRequestIn = REQUIRED_BODY):
    data = payload.dict() if payload else {}
    if request.POST:
        for key, value in request.POST.items():
            if value is not None:
                data[key] = value

    client_id = str(data.get("client_id") or "")
    _check_rate_limit(request, "token", client_id=client_id)

    grant_type = str(data.get("grant_type") or "")
    if grant_type == "authorization_code":
        result = OidcService.exchange_code(data, request=request)
        track_oidc_event("token_issued", client_id=client_id, grant_type=grant_type)
        return Response(result, headers=NO_STORE_HEADERS)
    if grant_type == "refresh_token":
        result = OidcService.refresh_tokens(data, request=request)
        track_oidc_event("token_refresh", client_id=client_id, grant_type=grant_type)
        return Response(result, headers=NO_STORE_HEADERS)
    raise HttpError(
        400,
        {"code": "UNSUPPORTED_GRANT_TYPE", "message": "unsupported grant_type"},
    )


@oidc_router.get(
    "/userinfo",
    response={200: dict, 401: ErrorOut, 429: ErrorOut},
    operation_id="oidc_userinfo",
)
def userinfo(request):
    _check_rate_limit(request, "userinfo")
    auth = request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HttpError(
            401,
            {"code": "UNAUTHORIZED", "message": "Missing bearer token"},
        )
    token_str = auth.split(" ", 1)[1].strip()
    result = OidcService.userinfo(token_str, request=request)
    track_oidc_event("userinfo")
    return Response(result, headers=NO_STORE_HEADERS)


@oidc_router.get(
    "/jwks",
    response={200: dict},
    operation_id="oidc_jwks",
)
def jwks(request):
    return OidcService.jwks()


@oidc_router.post(
    "/revoke",
    response={200: OkOut, 400: ErrorOut},
    operation_id="oidc_revoke",
)
def revoke(request, payload: RevokeIn = REQUIRED_BODY):
    if not payload.token:
        raise HttpError(
            400,
            {"code": "INVALID_REQUEST", "message": "token required"},
        )
    OidcService.revoke_token(payload.token)
    return Response(
        {"ok": True, "message": "revoked"},
        headers=NO_STORE_HEADERS,
    )
