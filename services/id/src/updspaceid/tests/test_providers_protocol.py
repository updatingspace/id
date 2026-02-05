from __future__ import annotations

from io import BytesIO
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse

from django.test import SimpleTestCase, override_settings
from ninja.errors import HttpError

from core.resilience import CircuitBreakerOpenError
from updspaceid.providers import (
    ProviderConfig,
    _append_query,
    _exchange_discord_code,
    _exchange_github_code,
    _fetch_user_subject,
    _get_circuit_for_provider,
    _get_provider_config,
    _normalize_redirect_uri,
    _request_form,
    _request_form_internal,
    _request_json,
    _request_json_internal,
    _steam_subject_from_claimed_id,
    _steam_verify_openid,
    build_authorization_url,
    exchange_code_for_subject,
)


class _DummyResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class _OpenCircuit:
    def __call__(self, _func):
        def wrapper():
            raise CircuitBreakerOpenError("open", circuit_name="oauth")

        return wrapper


@override_settings(
    GITHUB_CLIENT_ID="gh-id",
    GITHUB_CLIENT_SECRET="gh-secret",
    GITHUB_REDIRECT_URIS=["https://app.example.com/oauth/callback"],
    DISCORD_CLIENT_ID="discord-id",
    DISCORD_CLIENT_SECRET="discord-secret",
    DISCORD_REDIRECT_URIS=["https://app.example.com/oauth/discord"],
    STEAM_REDIRECT_URIS=["https://app.example.com/oauth/steam"],
)
class ProviderProtocolTests(SimpleTestCase):
    def test_append_query_merges_existing_params(self):
        result = _append_query("https://a.example/path?x=1", {"state": "s1"})
        parsed = urlparse(result)
        params = parse_qs(parsed.query)
        self.assertEqual(params["x"], ["1"])
        self.assertEqual(params["state"], ["s1"])

    def test_get_provider_config_supports_known_and_unknown_providers(self):
        self.assertEqual(_get_provider_config("github").provider, "github")
        self.assertEqual(_get_provider_config("discord").provider, "discord")
        self.assertEqual(_get_provider_config("steam").provider, "steam")
        with self.assertRaises(HttpError) as exc:
            _get_provider_config("unknown")
        self.assertEqual(exc.exception.status_code, 404)
        self.assertEqual(exc.exception.message["code"], "PROVIDER_NOT_SUPPORTED")

    def test_normalize_redirect_uri_requires_value_and_supports_empty_allowlist(self):
        cfg = ProviderConfig(
            provider="github",
            client_id="id",
            client_secret="secret",
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            user_url="https://api.github.com/user",
            scopes=["read:user"],
            redirect_uris=[],
        )
        with self.assertRaises(HttpError) as exc:
            _normalize_redirect_uri(cfg, "")
        self.assertEqual(exc.exception.message["code"], "MISSING_REDIRECT_URI")
        normalized = _normalize_redirect_uri(cfg, "https://allowed.example/callback")
        self.assertEqual(normalized, "https://allowed.example/callback")

    def test_steam_subject_from_claimed_id_validation(self):
        self.assertEqual(
            _steam_subject_from_claimed_id(
                "https://steamcommunity.com/openid/id/76561198000000000"
            ),
            "76561198000000000",
        )
        with self.assertRaises(HttpError) as exc:
            _steam_subject_from_claimed_id("https://example.com/not-steam")
        self.assertEqual(exc.exception.message["code"], "INVALID_CLAIMED_ID")

    def test_steam_verify_openid_requires_state_match(self):
        with self.assertRaises(HttpError) as exc:
            _steam_verify_openid(
                {
                    "openid.return_to": "https://app.example.com/cb?state=wrong",
                    "openid.claimed_id": "https://steamcommunity.com/openid/id/1",
                },
                expected_state="expected",
            )
        self.assertEqual(exc.exception.message["code"], "INVALID_STATE")

    def test_steam_verify_openid_rejects_invalid_provider_validation(self):
        params = {
            "openid.return_to": "https://app.example.com/cb?state=expected",
            "openid.claimed_id": "https://steamcommunity.com/openid/id/76561198000000000",
            "openid.mode": "id_res",
        }
        with self.assertRaises(HttpError) as exc:
            with self.settings():
                from unittest.mock import patch

                with patch(
                    "updspaceid.providers._request_form", return_value="is_valid:false"
                ):
                    _steam_verify_openid(params, "expected")
        self.assertEqual(exc.exception.message["code"], "INVALID_OPENID")

    def test_steam_verify_openid_success(self):
        params = {
            "openid.return_to": "https://app.example.com/cb?state=expected",
            "openid.claimed_id": "https://steamcommunity.com/openid/id/76561198000000000",
            "openid.mode": "id_res",
        }
        from unittest.mock import patch

        with patch("updspaceid.providers._request_form", return_value="is_valid:true"):
            subject = _steam_verify_openid(params, "expected")
        self.assertEqual(subject, "76561198000000000")

    def test_exchange_code_for_subject_requires_code_for_oauth_providers(self):
        with self.assertRaises(HttpError) as exc:
            exchange_code_for_subject(
                provider="github",
                code=None,
                claimed_id=None,
                redirect_uri="https://app.example.com/oauth/callback",
            )
        self.assertEqual(exc.exception.message["code"], "MISSING_CODE")

    def test_exchange_code_for_subject_steam_via_claimed_id(self):
        subject = exchange_code_for_subject(
            provider="steam",
            code=None,
            claimed_id="https://steamcommunity.com/openid/id/76561198000000001",
            redirect_uri=None,
        )
        self.assertEqual(subject, "76561198000000001")

    def test_exchange_code_for_subject_steam_via_openid_params(self):
        from unittest.mock import patch

        with patch(
            "updspaceid.providers._steam_verify_openid",
            return_value="76561198000000002",
        ):
            subject = exchange_code_for_subject(
                provider="steam",
                code=None,
                claimed_id=None,
                redirect_uri=None,
                openid_params={
                    "openid.return_to": "https://app.example.com/cb?state=s1",
                    "openid.claimed_id": "https://steamcommunity.com/openid/id/76561198000000002",
                },
                expected_state="s1",
            )
        self.assertEqual(subject, "76561198000000002")

    def test_exchange_code_for_subject_github_success(self):
        from unittest.mock import patch

        with (
            patch("updspaceid.providers._exchange_github_code", return_value="token-1"),
            patch("updspaceid.providers._fetch_user_subject", return_value="subject-1"),
        ):
            subject = exchange_code_for_subject(
                provider="github",
                code="code-1",
                claimed_id=None,
                redirect_uri="https://app.example.com/oauth/callback",
            )
        self.assertEqual(subject, "subject-1")

    def test_request_json_internal_success(self):
        from unittest.mock import patch

        with patch(
            "updspaceid.providers.urlopen",
            return_value=_DummyResponse(b'{"id":"subject-1"}'),
        ):
            data = _request_json_internal(
                url="https://api.example.com/me",
                provider="github",
            )
        self.assertEqual(data["id"], "subject-1")

    def test_request_json_internal_handles_http_error(self):
        from unittest.mock import patch

        error = HTTPError(
            url="https://api.example.com/me",
            code=400,
            msg="bad",
            hdrs=None,
            fp=BytesIO(b'{"error":"bad"}'),
        )
        with patch("updspaceid.providers.urlopen", side_effect=error):
            with self.assertRaises(HttpError) as exc:
                _request_json_internal(
                    url="https://api.example.com/me", provider="github"
                )
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "OAUTH_EXCHANGE_FAILED")

    def test_request_json_internal_handles_url_error(self):
        from unittest.mock import patch

        with patch("updspaceid.providers.urlopen", side_effect=URLError("down")):
            with self.assertRaises(HttpError) as exc:
                _request_json_internal(
                    url="https://api.example.com/me", provider="github"
                )
        self.assertEqual(exc.exception.status_code, 502)
        self.assertEqual(exc.exception.message["code"], "PROVIDER_UNAVAILABLE")

    def test_request_json_internal_handles_invalid_json(self):
        from unittest.mock import patch

        with patch(
            "updspaceid.providers.urlopen",
            return_value=_DummyResponse(b"not-json"),
        ):
            with self.assertRaises(HttpError) as exc:
                _request_json_internal(
                    url="https://api.example.com/me", provider="github"
                )
        self.assertEqual(exc.exception.status_code, 502)
        self.assertEqual(exc.exception.message["code"], "PROVIDER_ERROR")

    def test_request_form_internal_success(self):
        from unittest.mock import patch

        with patch(
            "updspaceid.providers.urlopen",
            return_value=_DummyResponse(b"is_valid:true"),
        ):
            body = _request_form_internal(
                url="https://steamcommunity.com/openid/login",
                data=b"payload",
                provider="steam",
            )
        self.assertEqual(body, "is_valid:true")

    def test_request_form_internal_handles_http_and_url_errors(self):
        from unittest.mock import patch

        error = HTTPError(
            url="https://steamcommunity.com/openid/login",
            code=400,
            msg="bad",
            hdrs=None,
            fp=BytesIO(b""),
        )
        with patch("updspaceid.providers.urlopen", side_effect=error):
            with self.assertRaises(HttpError) as http_exc:
                _request_form_internal(
                    url="https://steamcommunity.com/openid/login",
                    data=b"payload",
                    provider="steam",
                )
        self.assertEqual(http_exc.exception.status_code, 400)
        self.assertEqual(http_exc.exception.message["code"], "OAUTH_EXCHANGE_FAILED")

        with patch("updspaceid.providers.urlopen", side_effect=URLError("down")):
            with self.assertRaises(HttpError) as url_exc:
                _request_form_internal(
                    url="https://steamcommunity.com/openid/login",
                    data=b"payload",
                    provider="steam",
                )
        self.assertEqual(url_exc.exception.status_code, 502)
        self.assertEqual(url_exc.exception.message["code"], "PROVIDER_UNAVAILABLE")

    def test_request_json_and_form_handle_open_circuit(self):
        from unittest.mock import patch

        with patch(
            "updspaceid.providers._get_circuit_for_provider",
            return_value=_OpenCircuit(),
        ):
            with self.assertRaises(HttpError) as json_exc:
                _request_json(url="https://api.example.com/me", provider="github")
            self.assertEqual(json_exc.exception.status_code, 503)
            self.assertEqual(
                json_exc.exception.message["code"], "PROVIDER_CIRCUIT_OPEN"
            )

            with self.assertRaises(HttpError) as form_exc:
                _request_form(
                    url="https://api.example.com/token",
                    data=b"payload",
                    provider="github",
                )
            self.assertEqual(form_exc.exception.status_code, 503)
            self.assertEqual(
                form_exc.exception.message["code"], "PROVIDER_CIRCUIT_OPEN"
            )

    def test_exchange_helpers_require_access_token_and_subject(self):
        cfg = ProviderConfig(
            provider="github",
            client_id="id",
            client_secret="secret",
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            user_url="https://api.github.com/user",
            scopes=["read:user"],
            redirect_uris=["https://app.example.com/oauth/callback"],
        )
        from unittest.mock import patch

        with patch("updspaceid.providers._request_json", return_value={}):
            with self.assertRaises(HttpError) as exc1:
                _exchange_github_code(
                    cfg,
                    code="code",
                    redirect_uri="https://app.example.com/oauth/callback",
                )
        self.assertEqual(exc1.exception.message["code"], "OAUTH_EXCHANGE_FAILED")

        with patch("updspaceid.providers._request_json", return_value={"id": ""}):
            with self.assertRaises(HttpError) as exc2:
                _fetch_user_subject(cfg, token="token")
        self.assertEqual(exc2.exception.message["code"], "PROVIDER_ERROR")

        cfg_discord = ProviderConfig(
            provider="discord",
            client_id="id",
            client_secret="secret",
            authorize_url="https://discord.com/api/oauth2/authorize",
            token_url="https://discord.com/api/oauth2/token",
            user_url="https://discord.com/api/users/@me",
            scopes=["identify"],
            redirect_uris=["https://app.example.com/oauth/discord"],
        )
        with patch("updspaceid.providers._request_json", return_value={}):
            with self.assertRaises(HttpError) as exc3:
                _exchange_discord_code(
                    cfg_discord,
                    code="code",
                    redirect_uri="https://app.example.com/oauth/discord",
                )
        self.assertEqual(exc3.exception.message["code"], "OAUTH_EXCHANGE_FAILED")

    def test_exchange_helpers_return_token_and_subject_on_success(self):
        cfg = ProviderConfig(
            provider="github",
            client_id="id",
            client_secret="secret",
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            user_url="https://api.github.com/user",
            scopes=["read:user"],
            redirect_uris=["https://app.example.com/oauth/callback"],
        )
        from unittest.mock import patch

        with patch(
            "updspaceid.providers._request_json", return_value={"access_token": "at-1"}
        ):
            token = _exchange_github_code(
                cfg, code="code", redirect_uri="https://app.example.com/oauth/callback"
            )
        self.assertEqual(token, "at-1")

        cfg_discord = ProviderConfig(
            provider="discord",
            client_id="id",
            client_secret="secret",
            authorize_url="https://discord.com/api/oauth2/authorize",
            token_url="https://discord.com/api/oauth2/token",
            user_url="https://discord.com/api/users/@me",
            scopes=["identify"],
            redirect_uris=["https://app.example.com/oauth/discord"],
        )
        with patch(
            "updspaceid.providers._request_json", return_value={"access_token": "at-2"}
        ):
            token2 = _exchange_discord_code(
                cfg_discord,
                code="code",
                redirect_uri="https://app.example.com/oauth/discord",
            )
        self.assertEqual(token2, "at-2")

        with patch(
            "updspaceid.providers._request_json", return_value={"id": "subject-2"}
        ):
            subject = _fetch_user_subject(cfg, token="at-1")
        self.assertEqual(subject, "subject-2")

    def test_get_circuit_for_provider_known_and_unknown(self):
        self.assertIsNotNone(_get_circuit_for_provider("github"))
        self.assertIsNotNone(_get_circuit_for_provider("discord"))
        self.assertIsNotNone(_get_circuit_for_provider("steam"))
        self.assertIsNotNone(_get_circuit_for_provider("custom"))

    def test_build_authorization_url_for_discord_and_steam(self):
        discord_url = build_authorization_url(
            provider="discord",
            state="state-1",
            nonce="nonce-1",
            redirect_uri="https://app.example.com/oauth/discord",
        )
        discord_params = parse_qs(urlparse(discord_url).query)
        self.assertEqual(discord_params["response_type"], ["code"])
        self.assertEqual(discord_params["state"], ["state-1"])

        steam_url = build_authorization_url(
            provider="steam",
            state="state-2",
            nonce="nonce-2",
            redirect_uri="https://app.example.com/oauth/steam",
        )
        steam_params = parse_qs(urlparse(steam_url).query)
        self.assertEqual(steam_params["openid.mode"], ["checkid_setup"])
        self.assertIn("openid.return_to", steam_params)
