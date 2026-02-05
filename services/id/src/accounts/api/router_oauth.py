from allauth.headless.contrib.ninja.security import x_session_token_auth
from ninja import Router
from ninja.errors import HttpError

from accounts.services.oauth import OAuthService
from accounts.transport.schemas import ErrorOut, OAuthLinkOut, OAuthUnlinkIn, OkOut, ProvidersOut
from updspaceid.services import require_active_user

router_oauth = Router(tags=["OAuth"], auth=[x_session_token_auth])


def _ensure_active_user(user) -> None:
    if hasattr(user, "status"):
        require_active_user(user)
        return
    if hasattr(user, "is_active") and not user.is_active:
        raise HttpError(
            403,
            {"code": "ACCOUNT_INACTIVE", "message": "Аккаунт не активен"},
        )


@router_oauth.get(
    "/providers",
    auth=None,
    response={200: ProvidersOut},
    summary="List configured OAuth providers",
    operation_id="oauth_list_providers",
)
def list_providers(request):
    return ProvidersOut(providers=OAuthService.list_providers())


@router_oauth.get(
    "/login/{provider}",
    auth=None,
    response={200: OAuthLinkOut, 404: ErrorOut},
    summary="Get authorize URL for provider login",
    operation_id="oauth_login_provider",
)
def login_provider(request, provider: str, next: str = "/"):
    data = OAuthService.login_provider(provider, next_path=next)
    return OAuthLinkOut(**data)


@router_oauth.get(
    "/link/{provider}",
    response={200: OAuthLinkOut, 401: ErrorOut, 404: ErrorOut},
    summary="Get authorize URL for linking provider",
    operation_id="oauth_link_provider",
)
def link_provider(request, provider: str, next: str = "/account/security"):
    user = getattr(request, "auth", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(
            401,
            {"code": "UNAUTHORIZED", "message": "Требуется авторизация"},
        )
    _ensure_active_user(user)
    data = OAuthService.link_provider(provider, next_path=next)
    return OAuthLinkOut(**data)


@router_oauth.post(
    "/unlink",
    response={200: OkOut, 401: ErrorOut, 404: ErrorOut},
    summary="Unlink provider from account",
    operation_id="oauth_unlink_provider",
)
def unlink_provider(request, payload: OAuthUnlinkIn):
    user = getattr(request, "auth", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(
            401,
            {"code": "UNAUTHORIZED", "message": "Требуется авторизация"},
        )
    _ensure_active_user(user)
    OAuthService.unlink_provider(user, payload.provider)
    return OkOut(ok=True, message="Провайдер отключён")
