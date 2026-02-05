from ninja import NinjaAPI, Router

from accounts.api.exception_handlers import install_http_error_handler
from accounts.api.router import account_router
from accounts.api.router_auth import auth_router
from accounts.api.router_headless import headless_router
from accounts.api.router_oauth import router_oauth
from accounts.api.router_magic_link import router_magic_link

router = Router()
router.add_router("", headless_router)
router.add_router("", auth_router)
router.add_router("", router_magic_link)
router.add_router("", account_router)
router.add_router("/oauth", router_oauth)


def install(api: NinjaAPI) -> None:
    install_http_error_handler(api)


__all__ = ["router", "install"]
