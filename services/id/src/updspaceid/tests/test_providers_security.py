from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from django.test import SimpleTestCase, override_settings
from ninja.errors import HttpError

from updspaceid.providers import (
    _get_provider_config,
    _normalize_redirect_uri,
    build_authorization_url,
)


@override_settings(
    GITHUB_CLIENT_ID="github-client",
    GITHUB_CLIENT_SECRET="github-secret",
    GITHUB_REDIRECT_URIS=["https://app.example.com/oauth/callback"],
)
class ProviderSecurityTests(SimpleTestCase):
    def test_normalize_redirect_uri_requires_absolute_https_url(self):
        cfg = _get_provider_config("github")
        with self.assertRaises(HttpError) as exc:
            _normalize_redirect_uri(cfg, "/oauth/callback")
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "INVALID_REDIRECT_URI")

    def test_normalize_redirect_uri_rejects_unlisted_uri(self):
        cfg = _get_provider_config("github")
        with self.assertRaises(HttpError) as exc:
            _normalize_redirect_uri(cfg, "https://evil.example.com/cb")
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "INVALID_REDIRECT_URI")

    def test_normalize_redirect_uri_accepts_allowlisted_uri(self):
        cfg = _get_provider_config("github")
        normalized = _normalize_redirect_uri(
            cfg,
            "https://app.example.com/oauth/callback",
        )
        self.assertEqual(normalized, "https://app.example.com/oauth/callback")

    def test_build_authorization_url_includes_state_and_redirect_uri(self):
        url = build_authorization_url(
            provider="github",
            state="state-123",
            nonce="nonce-123",
            redirect_uri="https://app.example.com/oauth/callback",
        )
        parsed = urlparse(url)
        self.assertEqual(parsed.netloc, "github.com")
        params = parse_qs(parsed.query)
        self.assertEqual(params.get("state"), ["state-123"])
        self.assertEqual(
            params.get("redirect_uri"),
            ["https://app.example.com/oauth/callback"],
        )

    @override_settings(GITHUB_CLIENT_SECRET="")
    def test_build_authorization_url_fails_when_provider_not_configured(self):
        with self.assertRaises(HttpError) as exc:
            build_authorization_url(
                provider="github",
                state="state-1",
                nonce="nonce-1",
                redirect_uri="https://app.example.com/oauth/callback",
            )
        self.assertEqual(exc.exception.status_code, 501)
        self.assertEqual(exc.exception.message["code"], "PROVIDER_NOT_CONFIGURED")
