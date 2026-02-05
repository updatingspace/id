from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from django.conf import settings
from ninja.errors import HttpError

from core.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
)
from updspaceid.errors import error_payload

logger = logging.getLogger(__name__)

STEAM_CLAIMED_ID_RE = re.compile(r"^https?://steamcommunity\.com/openid/id/(\d+)$")
STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"
STEAM_OPENID_NS = "http://specs.openid.net/auth/2.0"
STEAM_OPENID_IDENTIFIER = "http://specs.openid.net/auth/2.0/identifier_select"

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

DISCORD_AUTHORIZE_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_USER_URL = "https://discord.com/api/users/@me"

# Circuit breakers for external OAuth providers
_circuit_config = CircuitBreakerConfig(
    failure_threshold=3,
    success_threshold=2,
    timeout_seconds=60.0,
)
_github_circuit = CircuitBreaker.get("github_oauth", _circuit_config)
_discord_circuit = CircuitBreaker.get("discord_oauth", _circuit_config)
_steam_circuit = CircuitBreaker.get("steam_oauth", _circuit_config)


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    client_id: str | None
    client_secret: str | None
    authorize_url: str
    token_url: str | None
    user_url: str | None
    scopes: list[str]
    redirect_uris: list[str]


def _get_provider_config(provider: str) -> ProviderConfig:
    provider = str(provider)
    if provider == "github":
        return ProviderConfig(
            provider=provider,
            client_id=str(getattr(settings, "GITHUB_CLIENT_ID", "") or ""),
            client_secret=str(getattr(settings, "GITHUB_CLIENT_SECRET", "") or ""),
            authorize_url=GITHUB_AUTHORIZE_URL,
            token_url=GITHUB_TOKEN_URL,
            user_url=GITHUB_USER_URL,
            scopes=list(
                getattr(settings, "GITHUB_SCOPES", ["read:user"]) or ["read:user"]
            ),
            redirect_uris=list(getattr(settings, "GITHUB_REDIRECT_URIS", []) or []),
        )
    if provider == "discord":
        return ProviderConfig(
            provider=provider,
            client_id=str(getattr(settings, "DISCORD_CLIENT_ID", "") or ""),
            client_secret=str(getattr(settings, "DISCORD_CLIENT_SECRET", "") or ""),
            authorize_url=DISCORD_AUTHORIZE_URL,
            token_url=DISCORD_TOKEN_URL,
            user_url=DISCORD_USER_URL,
            scopes=list(
                getattr(settings, "DISCORD_SCOPES", ["identify"]) or ["identify"]
            ),
            redirect_uris=list(getattr(settings, "DISCORD_REDIRECT_URIS", []) or []),
        )
    if provider == "steam":
        return ProviderConfig(
            provider=provider,
            client_id=None,
            client_secret=None,
            authorize_url=STEAM_OPENID_URL,
            token_url=None,
            user_url=None,
            scopes=[],
            redirect_uris=list(getattr(settings, "STEAM_REDIRECT_URIS", []) or []),
        )
    raise HttpError(
        404, error_payload("PROVIDER_NOT_SUPPORTED", "Provider not supported")
    )


def _require_oauth_config(cfg: ProviderConfig) -> None:
    if cfg.provider == "steam":
        return
    if not cfg.client_id or not cfg.client_secret:
        raise HttpError(
            501,
            error_payload(
                "PROVIDER_NOT_CONFIGURED",
                "Provider integration is not configured in this environment",
                details={"provider": cfg.provider},
            ),
        )


def _normalize_redirect_uri(cfg: ProviderConfig, redirect_uri: str | None) -> str:
    uri = (redirect_uri or "").strip()
    if not uri:
        raise HttpError(
            400,
            error_payload("MISSING_REDIRECT_URI", "redirect_uri is required"),
        )
    parsed = urlparse(uri)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HttpError(
            400,
            error_payload(
                "INVALID_REDIRECT_URI",
                "redirect_uri must be an absolute http(s) URL",
            ),
        )
    if cfg.redirect_uris and uri not in cfg.redirect_uris:
        raise HttpError(
            400,
            error_payload(
                "INVALID_REDIRECT_URI",
                "redirect_uri is not allowed",
                details={"redirect_uri": uri, "provider": cfg.provider},
            ),
        )
    if not cfg.redirect_uris:
        logger.info(
            "OAuth redirect allowlist is empty; accepting redirect_uri",
            extra={"provider": cfg.provider, "redirect_uri": uri},
        )
    return uri


def _append_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = parsed.query
    extra = urlencode(params)
    combined = query + ("&" if query else "") + extra
    return urlunparse(parsed._replace(query=combined))


def build_authorization_url(
    *,
    provider: str,
    state: str,
    nonce: str,
    redirect_uri: str,
) -> str:
    cfg = _get_provider_config(provider)
    _require_oauth_config(cfg)
    redirect_uri = _normalize_redirect_uri(cfg, redirect_uri)

    if cfg.provider == "github":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(cfg.scopes),
            "state": state,
        }
        return f"{cfg.authorize_url}?{urlencode(params)}"

    if cfg.provider == "discord":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(cfg.scopes),
            "state": state,
        }
        return f"{cfg.authorize_url}?{urlencode(params)}"

    if cfg.provider == "steam":
        return_to = _append_query(redirect_uri, {"state": state})
        realm = f"{urlparse(return_to).scheme}://{urlparse(return_to).netloc}"
        params = {
            "openid.ns": STEAM_OPENID_NS,
            "openid.mode": "checkid_setup",
            "openid.return_to": return_to,
            "openid.realm": realm,
            "openid.identity": STEAM_OPENID_IDENTIFIER,
            "openid.claimed_id": STEAM_OPENID_IDENTIFIER,
        }
        return f"{cfg.authorize_url}?{urlencode(params)}"

    raise HttpError(
        404, error_payload("PROVIDER_NOT_SUPPORTED", "Provider not supported")
    )


def _get_circuit_for_provider(provider: str) -> CircuitBreaker:
    """Get the appropriate circuit breaker for a provider."""
    if provider == "github":
        return _github_circuit
    elif provider == "discord":
        return _discord_circuit
    elif provider == "steam":
        return _steam_circuit
    return CircuitBreaker.get(f"{provider}_oauth", _circuit_config)


def _request_json_internal(
    *,
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    provider: str,
) -> dict:
    """Internal function that makes the actual HTTP request."""
    req = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=10) as resp:  # noqa: S310 - controlled OAuth URLs
            raw = resp.read() or b"{}"
    except HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        logger.warning(
            "OAuth provider request failed",
            extra={"provider": provider, "status": exc.code},
        )
        raise HttpError(
            400,
            error_payload(
                "OAUTH_EXCHANGE_FAILED",
                "OAuth provider rejected the request",
                details={
                    "provider": provider,
                    "status": exc.code,
                    "body": body[:200].decode("utf-8", "ignore"),
                },
            ),
        ) from exc
    except URLError as exc:
        logger.warning(
            "OAuth provider unavailable",
            extra={"provider": provider},
        )
        raise HttpError(
            502,
            error_payload(
                "PROVIDER_UNAVAILABLE",
                "OAuth provider is unavailable",
                details={"provider": provider},
            ),
        ) from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.warning(
            "OAuth provider returned invalid JSON",
            extra={"provider": provider},
        )
        raise HttpError(
            502,
            error_payload(
                "PROVIDER_ERROR",
                "OAuth provider returned invalid response",
                details={"provider": provider},
            ),
        ) from exc


def _request_json(
    *,
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    provider: str,
) -> dict:
    """Make HTTP request with circuit breaker protection."""
    circuit = _get_circuit_for_provider(provider)
    try:
        return circuit(
            lambda: _request_json_internal(
                url=url, method=method, data=data, headers=headers, provider=provider
            )
        )()
    except CircuitBreakerOpenError:
        logger.warning(
            "OAuth circuit breaker open, rejecting request",
            extra={"provider": provider},
        )
        raise HttpError(
            503,
            error_payload(
                "PROVIDER_CIRCUIT_OPEN",
                "OAuth provider is temporarily unavailable due to repeated failures",
                details={"provider": provider, "retry_after": 60},
            ),
        )


def _request_form_internal(
    *,
    url: str,
    data: bytes,
    provider: str,
) -> str:
    """Internal function for form-encoded requests."""
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, timeout=10) as resp:  # noqa: S310 - controlled OAuth URLs
            return (resp.read() or b"").decode("utf-8", "ignore")
    except HTTPError as exc:
        logger.warning(
            "OAuth provider request failed",
            extra={"provider": provider, "status": exc.code},
        )
        raise HttpError(
            400,
            error_payload(
                "OAUTH_EXCHANGE_FAILED",
                "OAuth provider rejected the request",
                details={"provider": provider, "status": exc.code},
            ),
        ) from exc
    except URLError as exc:
        logger.warning(
            "OAuth provider unavailable",
            extra={"provider": provider},
        )
        raise HttpError(
            502,
            error_payload(
                "PROVIDER_UNAVAILABLE",
                "OAuth provider is unavailable",
                details={"provider": provider},
            ),
        ) from exc


def _request_form(
    *,
    url: str,
    data: bytes,
    provider: str,
) -> str:
    """Make form-encoded request with circuit breaker protection."""
    circuit = _get_circuit_for_provider(provider)
    try:
        return circuit(
            lambda: _request_form_internal(url=url, data=data, provider=provider)
        )()
    except CircuitBreakerOpenError:
        logger.warning(
            "OAuth circuit breaker open, rejecting request",
            extra={"provider": provider},
        )
        raise HttpError(
            503,
            error_payload(
                "PROVIDER_CIRCUIT_OPEN",
                "OAuth provider is temporarily unavailable due to repeated failures",
                details={"provider": provider, "retry_after": 60},
            ),
        )


def _exchange_github_code(cfg: ProviderConfig, code: str, redirect_uri: str) -> str:
    payload = urlencode(
        {
            "client_id": cfg.client_id or "",
            "client_secret": cfg.client_secret or "",
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("utf-8")
    data = _request_json(
        url=cfg.token_url or "",
        method="POST",
        data=payload,
        headers={"Accept": "application/json"},
        provider=cfg.provider,
    )
    token = str(data.get("access_token") or "")
    if not token:
        raise HttpError(
            400,
            error_payload(
                "OAUTH_EXCHANGE_FAILED",
                "OAuth provider did not return access_token",
                details={"provider": cfg.provider},
            ),
        )
    return token


def _exchange_discord_code(cfg: ProviderConfig, code: str, redirect_uri: str) -> str:
    payload = urlencode(
        {
            "client_id": cfg.client_id or "",
            "client_secret": cfg.client_secret or "",
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("utf-8")
    data = _request_json(
        url=cfg.token_url or "",
        method="POST",
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        provider=cfg.provider,
    )
    token = str(data.get("access_token") or "")
    if not token:
        raise HttpError(
            400,
            error_payload(
                "OAUTH_EXCHANGE_FAILED",
                "OAuth provider did not return access_token",
                details={"provider": cfg.provider},
            ),
        )
    return token


def _fetch_user_subject(cfg: ProviderConfig, token: str) -> str:
    data = _request_json(
        url=cfg.user_url or "",
        headers={"Authorization": f"Bearer {token}"},
        provider=cfg.provider,
    )
    subject = str(data.get("id") or "")
    if not subject:
        raise HttpError(
            502,
            error_payload(
                "PROVIDER_ERROR",
                "OAuth provider did not return subject",
                details={"provider": cfg.provider},
            ),
        )
    return subject


def _steam_subject_from_claimed_id(claimed_id: str) -> str:
    m = STEAM_CLAIMED_ID_RE.match(str(claimed_id))
    if not m:
        raise HttpError(
            400, error_payload("INVALID_CLAIMED_ID", "Invalid steam claimed_id")
        )
    return m.group(1)


def _steam_verify_openid(
    openid_params: dict[str, str], expected_state: str | None
) -> str:
    if not openid_params:
        raise HttpError(
            400,
            error_payload(
                "MISSING_OPENID_PARAMS", "openid_params are required for steam"
            ),
        )
    return_to = openid_params.get("openid.return_to") or ""
    if expected_state:
        parsed = urlparse(return_to)
        state_values = parse_qs(parsed.query).get("state") or []
        if not state_values or state_values[0] != expected_state:
            raise HttpError(
                400,
                error_payload("INVALID_STATE", "state does not match return_to"),
            )
    claimed_id = (
        openid_params.get("openid.claimed_id")
        or openid_params.get("openid.identity")
        or ""
    )
    if not claimed_id:
        raise HttpError(
            400, error_payload("MISSING_CLAIMED_ID", "claimed_id is required for steam")
        )
    payload = {k: v for k, v in openid_params.items() if k.startswith("openid.")}
    payload["openid.mode"] = "check_authentication"
    body = _request_form(
        url=STEAM_OPENID_URL,
        data=urlencode(payload).encode("utf-8"),
        provider="steam",
    )
    if "is_valid:true" not in body:
        raise HttpError(
            400, error_payload("INVALID_OPENID", "Steam OpenID validation failed")
        )
    return _steam_subject_from_claimed_id(claimed_id)


def exchange_code_for_subject(
    *,
    provider: str,
    code: str | None,
    claimed_id: str | None,
    redirect_uri: str | None,
    openid_params: dict[str, str] | None = None,
    expected_state: str | None = None,
) -> str:
    """Return provider subject."""
    provider = str(provider)
    cfg = _get_provider_config(provider)
    _require_oauth_config(cfg)

    if provider == "steam":
        if openid_params:
            return _steam_verify_openid(openid_params, expected_state)
        if not claimed_id:
            raise HttpError(
                400,
                error_payload("MISSING_CLAIMED_ID", "claimed_id is required for steam"),
            )
        return _steam_subject_from_claimed_id(claimed_id)

    redirect_uri = _normalize_redirect_uri(cfg, redirect_uri)
    if not code:
        raise HttpError(
            400, error_payload("MISSING_CODE", "code is required for oauth provider")
        )

    if provider == "github":
        token = _exchange_github_code(cfg, code, redirect_uri)
        return _fetch_user_subject(cfg, token)

    if provider == "discord":
        token = _exchange_discord_code(cfg, code, redirect_uri)
        return _fetch_user_subject(cfg, token)

    raise HttpError(
        404, error_payload("PROVIDER_NOT_SUPPORTED", "Provider not supported")
    )
