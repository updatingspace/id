from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse

from idp.scopes import SCOPES
from idp.services import OidcService


def openid_configuration(request):
    issuer = str(getattr(settings, "OIDC_ISSUER", "https://id.localhost")).rstrip("/")
    public_base = str(getattr(settings, "OIDC_PUBLIC_BASE_URL", issuer)).rstrip("/")
    cfg = {
        "issuer": issuer,
        "authorization_endpoint": getattr(
            settings, "OIDC_AUTHORIZATION_ENDPOINT", f"{public_base}/oauth/authorize"
        ),
        "token_endpoint": getattr(
            settings, "OIDC_TOKEN_ENDPOINT", f"{public_base}/oauth/token"
        ),
        "userinfo_endpoint": getattr(
            settings, "OIDC_USERINFO_ENDPOINT", f"{public_base}/oauth/userinfo"
        ),
        "jwks_uri": getattr(
            settings, "OIDC_JWKS_URI", f"{issuer}/.well-known/jwks.json"
        ),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": list(SCOPES.keys()),
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "revocation_endpoint": getattr(
            settings, "OIDC_REVOCATION_ENDPOINT", f"{public_base}/oauth/revoke"
        ),
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": sorted(
            {claim for scope in SCOPES.values() for claim in scope.claims}
        ),
    }
    return JsonResponse(cfg)


def jwks(request):
    return JsonResponse(OidcService.jwks())
