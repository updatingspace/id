from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include, re_path
from django.views.static import serve
from ninja import NinjaAPI
from ninja.errors import HttpError
from allauth.account import views as allauth_account_views
from accounts.api import router as auth_router
from accounts.api import install as install_accounts_api
from updspaceid.dev_api import dev_router
from updspaceid.api import router as updspaceid_router
from idp.router import oidc_router
from idp.views import jwks, openid_configuration
from core.health import liveness_view, readiness_view, health_view, set_service_start_time
from core.monitoring import prometheus_metrics_view
from core.logging_config import configure_logging

# Initialize production logging
configure_logging()

# Track service startup time
set_service_start_time()

api = NinjaAPI(
    title="UpdSpace ID API",
    version="1",
    urls_namespace="api",
    docs_url="/docs" if settings.DEBUG else None,  # Swagger docs only in debug
    openapi_url="/openapi.json",  # Always expose OpenAPI spec
)
api.add_router("/auth", auth_router)
api.add_router("/dev", dev_router)
# updspaceid_router contains /applications and other top-level routes
api.add_router("", updspaceid_router)
install_accounts_api(api)

oidc_api = NinjaAPI(title="UpdSpace ID OIDC", version="1", urls_namespace="oidc")
oidc_api.add_router("", oidc_router)


@oidc_api.exception_handler(HttpError)
def oidc_http_error(request, exc):
    payload = exc.message
    if payload is None:
        payload = {"code": "HTTP_ERROR", "message": "Error"}
    elif not isinstance(payload, dict):
        payload = {"code": "HTTP_ERROR", "message": str(payload)}
    return oidc_api.create_response(request, payload, status=exc.status_code)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", api.urls),
    path("oauth/", oidc_api.urls),
    path(".well-known/openid-configuration", openid_configuration),
    path(".well-known/jwks.json", jwks),
    # Health check endpoints (Kubernetes probes)
    path("health", health_view),  # Detailed health status
    path("healthz", liveness_view),  # Liveness probe
    path("readyz", readiness_view),  # Readiness probe
    # Prometheus metrics endpoint
    path("metrics", prometheus_metrics_view),
    path("accounts/", include("allauth.urls")),
    re_path(
        r"^accounts/confirm-email/(?P<key>[-:\w]+)/$",
        allauth_account_views.confirm_email,
        name="account_confirm_email",
    ),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += [
        re_path(r"^avatars/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT}),
    ]
