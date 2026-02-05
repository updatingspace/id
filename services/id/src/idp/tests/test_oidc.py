"""
Tests for OIDC provider endpoints and setup_portal_client command.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from ninja.errors import HttpError
from unittest.mock import patch
from jwt import InvalidTokenError

from accounts.services.rate_limit import RateLimitDecision
from idp.keys import _generate_keypair, clear_key_cache_for_tests
from idp.models import OidcAuthorizationRequest, OidcClient
from idp.router import (
    _check_rate_limit,
    _require_user,
    authorize_approve,
    authorize_deny,
    authorize_prepare,
    jwks,
    revoke,
    token,
    userinfo,
)
from idp.services import (
    OidcService,
    _apply_privacy_prefs,
    _build_redirect,
    _claims_for_scopes,
    _decode_jwt_token,
    _normalize_scope_request,
    _resolve_token_public_key,
    _verify_pkce,
)
from updspaceid.enums import UserStatus
from updspaceid.models import User as UpdspaceUser


class SetupPortalClientCommandTests(TestCase):
    """Tests for the setup_portal_client management command."""

    def test_creates_portal_client(self):
        """Command should create a new OIDC client for portal."""
        out = StringIO()
        call_command("setup_portal_client", stdout=out)

        output = out.getvalue()
        self.assertIn("Created OIDC client", output)
        self.assertIn("AEF Portal", output)

        # Verify client was created
        client = OidcClient.objects.filter(name="AEF Portal").first()
        self.assertIsNotNone(client)
        self.assertEqual(client.client_id, "portal-dev-client")
        self.assertTrue(client.is_first_party)
        self.assertIn("openid", client.allowed_scopes)
        self.assertIn("profile", client.allowed_scopes)

    def test_updates_existing_client(self):
        """Command should update existing client without changing secret."""
        # Create initial client
        call_command("setup_portal_client")
        client = OidcClient.objects.get(name="AEF Portal")
        original_client_id = client.client_id
        original_secret_hash = client.client_secret_hash

        # Run command again
        out = StringIO()
        call_command("setup_portal_client", stdout=out)

        output = out.getvalue()
        self.assertIn("Updated OIDC client", output)

        # Verify client_id unchanged, secret unchanged
        client.refresh_from_db()
        self.assertEqual(client.client_id, original_client_id)
        self.assertEqual(client.client_secret_hash, original_secret_hash)

    def test_reset_secret_generates_new_secret(self):
        """Command with --reset-secret should generate new secret."""
        call_command("setup_portal_client")
        client = OidcClient.objects.get(name="AEF Portal")
        original_secret_hash = client.client_secret_hash

        out = StringIO()
        call_command("setup_portal_client", "--reset-secret", stdout=out)

        client.refresh_from_db()
        self.assertNotEqual(client.client_secret_hash, original_secret_hash)

    def test_show_secret_displays_secret(self):
        """Command with --show-secret should display client secret."""
        out = StringIO()
        call_command("setup_portal_client", "--show-secret", stdout=out)

        output = out.getvalue()
        self.assertIn("Client Secret:", output)
        self.assertIn("Save this secret", output)

    def test_redirect_uris_include_auth_callback(self):
        """Client should have /api/v1/auth/callback in redirect_uris."""
        call_command("setup_portal_client")
        client = OidcClient.objects.get(name="AEF Portal")

        # Check for new auth callback URIs
        has_callback = any(
            "/api/v1/auth/callback" in uri for uri in client.redirect_uris
        )
        self.assertTrue(
            has_callback,
            f"Expected /api/v1/auth/callback in {client.redirect_uris}",
        )


class OidcClientModelTests(TestCase):
    """Tests for OidcClient model."""

    def test_generate_client_id(self):
        """client_id should be auto-generated."""
        client = OidcClient.objects.create(
            name="Test Client",
            redirect_uris=["http://localhost/callback"],
        )
        self.assertIsNotNone(client.client_id)
        self.assertGreater(len(client.client_id), 10)

    def test_set_and_check_secret(self):
        """set_secret and check_secret should work correctly."""
        client = OidcClient.objects.create(
            name="Test Client",
            redirect_uris=["http://localhost/callback"],
            is_public=False,
        )

        secret = client.set_secret()
        client.save()

        self.assertTrue(client.check_secret(secret))
        self.assertFalse(client.check_secret("wrong-secret"))
        self.assertFalse(client.check_secret(None))

    def test_public_client_skips_secret_check(self):
        """Public clients should pass secret check with any value."""
        client = OidcClient.objects.create(
            name="Public Client",
            redirect_uris=["http://localhost/callback"],
            is_public=True,
        )

        self.assertTrue(client.check_secret(None))
        self.assertTrue(client.check_secret("anything"))


class OidcEndpointTests(TestCase):
    """Tests for OIDC API endpoints."""

    def setUp(self):
        self.client_http = Client()
        self.oidc_client = OidcClient.objects.create(
            name="Test App",
            redirect_uris=[
                "http://localhost:5173/callback",
                "http://aef.localhost/api/v1/auth/callback",
            ],
            allowed_scopes=["openid", "profile", "email"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=False,
            is_first_party=True,
        )
        self.oidc_client.set_secret("test-secret")
        self.oidc_client.save()

    def test_openid_configuration_endpoint(self):
        """/.well-known/openid-configuration should return OIDC metadata."""
        resp = self.client_http.get("/.well-known/openid-configuration")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("issuer", data)
        self.assertIn("authorization_endpoint", data)
        self.assertIn("token_endpoint", data)
        self.assertIn("userinfo_endpoint", data)
        self.assertIn("jwks_uri", data)
        self.assertEqual(data["response_types_supported"], ["code"])
        self.assertEqual(
            data.get("jwks_uri"), "https://id.localhost/.well-known/jwks.json"
        )

    def test_openid_configuration_includes_revocation_and_refresh(self):
        resp = self.client_http.get("/.well-known/openid-configuration")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(
            data.get("grant_types_supported"),
            ["authorization_code", "refresh_token"],
        )
        self.assertIn("revocation_endpoint", data)
        self.assertEqual(
            data.get("token_endpoint_auth_methods_supported"),
            ["client_secret_basic", "client_secret_post"],
        )
        self.assertEqual(
            data.get("code_challenge_methods_supported"),
            ["S256"],
        )

    def test_jwks_endpoint(self):
        """JWKS endpoint should return signing keys."""
        resp = self.client_http.get("/oauth/jwks")

        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("keys", data)

    def test_well_known_jwks_endpoint(self):
        resp = self.client_http.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), self.client_http.get("/oauth/jwks").json())

    @override_settings(OIDC_ISSUER="http://id.localhost")
    def test_token_endpoint_requires_grant_type(self):
        """Token endpoint should require grant_type parameter."""
        resp = self.client_http.post(
            "/oauth/token",
            data=json.dumps({}),
            content_type="application/json",
        )

        self.assertEqual(resp.status_code, 400)

    def test_userinfo_requires_bearer_token(self):
        """Userinfo endpoint should require Bearer token."""
        resp = self.client_http.get("/oauth/userinfo")

        self.assertEqual(resp.status_code, 401)
        data = resp.json()
        self.assertIn("UNAUTHORIZED", str(data))

    def test_oidc_errors_use_safe_envelope(self):
        resp = self.client_http.post(
            "/oauth/token",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        payload = resp.json()
        self.assertIn("error", payload)
        self.assertIn("request_id", payload["error"])


class OidcDiscoveryTests(TestCase):
    """Ensure JWKS reflects the configured key set."""

    def setUp(self):
        self.client_http = Client()
        clear_key_cache_for_tests()

    def test_jwks_endpoint_returns_all_configured_keys(self):
        primary = _generate_keypair()
        secondary = _generate_keypair()
        key_config = [
            {
                "private_key_pem": primary.private_key_pem,
                "public_key_pem": primary.public_key_pem,
                "kid": primary.kid,
                "active": True,
            },
            {
                "private_key_pem": secondary.private_key_pem,
                "public_key_pem": secondary.public_key_pem,
                "kid": secondary.kid,
                "active": False,
            },
        ]
        with override_settings(OIDC_KEY_PAIRS=key_config):
            clear_key_cache_for_tests()
            resp = self.client_http.get("/oauth/jwks")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            kids = {key["kid"] for key in data.get("keys", [])}
            self.assertIn(primary.kid, kids)
            self.assertIn(secondary.kid, kids)


class OidcTokenLifecycleTests(TestCase):
    """Tests for refresh and revoke flows."""

    def setUp(self):
        self.client_http = Client()
        clear_key_cache_for_tests()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="token-user", email="tokenuser@example.com", password="secret"
        )
        self.upd_user = UpdspaceUser.objects.create(
            email=self.user.email,
            username="token-user",
            display_name="Token User",
            status=UserStatus.ACTIVE,
            email_verified=True,
        )
        self.oidc_client = OidcClient.objects.create(
            name="Lifecycle App",
            redirect_uris=["http://localhost/callback"],
            allowed_scopes=["openid", "email"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            is_public=False,
            is_first_party=True,
        )
        self.oidc_client.set_secret("test-secret")
        self.oidc_client.save()

    def _issue_tokens(self) -> dict:
        tokens = OidcService._issue_tokens(
            user=self.user,
            client=self.oidc_client,
            scope="openid offline_access",
            nonce="",
        )
        self.assertIn("refresh_token", tokens)
        return tokens

    def _refresh(self, refresh_token: str):
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.oidc_client.client_id,
            "client_secret": "test-secret",
        }
        return self.client_http.post(
            "/oauth/token",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def _error_code(self, resp):
        body = resp.json()
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                return error.get("code")
            return body.get("code")
        return None

    def test_refresh_invalidates_previous_token(self):
        tokens = self._issue_tokens()
        resp = self._refresh(tokens["refresh_token"])
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Cache-Control"), "no-store")
        self.assertTrue(resp.json()["refresh_token"])
        reuse_response = self._refresh(tokens["refresh_token"])
        self.assertEqual(reuse_response.status_code, 400)
        self.assertEqual(self._error_code(reuse_response), "INVALID_REFRESH_TOKEN")

    def test_refresh_rejects_banned_user(self):
        tokens = self._issue_tokens()
        resp = self._refresh(tokens["refresh_token"])
        self.assertEqual(resp.status_code, 200)
        new_refresh = resp.json()["refresh_token"]
        self.upd_user.status = UserStatus.BANNED
        self.upd_user.save()
        resp = self._refresh(new_refresh)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self._error_code(resp), "ACCOUNT_BANNED")

    def test_revoke_prevents_refresh(self):
        tokens = self._issue_tokens()
        resp = self.client_http.post(
            "/oauth/revoke",
            data=json.dumps({"token": tokens["refresh_token"]}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        refresh_resp = self._refresh(tokens["refresh_token"])
        self.assertEqual(refresh_resp.status_code, 400)
        self.assertEqual(self._error_code(refresh_resp), "INVALID_REFRESH_TOKEN")

    def test_userinfo_accepts_tokens_signed_with_retired_key(self):
        primary = _generate_keypair()
        secondary = _generate_keypair()
        initial_config = [
            {
                "kid": primary.kid,
                "private_key_pem": primary.private_key_pem,
                "public_key_pem": primary.public_key_pem,
                "active": True,
            },
            {
                "kid": secondary.kid,
                "private_key_pem": secondary.private_key_pem,
                "public_key_pem": secondary.public_key_pem,
                "active": False,
            },
        ]
        rotated_config = [
            {
                "kid": primary.kid,
                "private_key_pem": primary.private_key_pem,
                "public_key_pem": primary.public_key_pem,
                "active": False,
            },
            {
                "kid": secondary.kid,
                "private_key_pem": secondary.private_key_pem,
                "public_key_pem": secondary.public_key_pem,
                "active": True,
            },
        ]
        with override_settings(OIDC_KEY_PAIRS=initial_config):
            clear_key_cache_for_tests()
            tokens = self._issue_tokens()
        with override_settings(OIDC_KEY_PAIRS=rotated_config):
            clear_key_cache_for_tests()
            resp = self.client_http.get(
                "/oauth/userinfo",
                HTTP_AUTHORIZATION=f"Bearer {tokens['access_token']}",
            )
        clear_key_cache_for_tests()
        self.assertEqual(resp.status_code, 200)


class OidcAuthorizePrepareTests(TestCase):
    """Tests for OIDC authorize/prepare endpoint."""

    def setUp(self):
        self.client_http = Client()
        self.oidc_client = OidcClient.objects.create(
            name="Portal App",
            redirect_uris=[
                "http://aef.localhost/api/v1/auth/callback",
            ],
            allowed_scopes=["openid", "profile"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=False,
            is_first_party=True,
        )

    def test_prepare_requires_authentication(self):
        """authorize/prepare should require authenticated user."""
        resp = self.client_http.get(
            "/oauth/authorize/prepare",
            {
                "client_id": self.oidc_client.client_id,
                "redirect_uri": "http://aef.localhost/api/v1/auth/callback",
                "response_type": "code",
                "scope": "openid profile",
            },
        )

        self.assertEqual(resp.status_code, 401)


class OidcSubjectTests(TestCase):
    """Ensure OIDC subjects use UpdSpace UUIDs when available."""

    def test_sub_uses_updspace_uuid(self):
        User = get_user_model()
        django_user = User.objects.create_user(
            username="uuid-user",
            email="uuid-user@example.com",
            password="secret",
        )
        upd_user = UpdspaceUser.objects.create(
            email=django_user.email,
            username="uuid-user",
            display_name="UUID User",
            status=UserStatus.ACTIVE,
            email_verified=True,
        )
        claims = _claims_for_scopes(django_user, ["openid"])
        self.assertEqual(claims["sub"], str(upd_user.user_id))
        self.assertEqual(claims["user_id"], str(upd_user.user_id))

    def test_sub_falls_back_to_auth_user_id(self):
        User = get_user_model()
        django_user = User.objects.create_user(
            username="fallback-user",
            email="fallback@example.com",
            password="secret",
        )
        claims = _claims_for_scopes(django_user, ["openid"])
        self.assertEqual(claims["sub"], str(django_user.id))
        self.assertEqual(claims["user_id"], str(django_user.id))

    def test_claims_include_master_flags_from_updspace_user(self):
        User = get_user_model()
        django_user = User.objects.create_user(
            username="admin-user",
            email="admin@example.com",
            password="secret",
        )
        upd_user = UpdspaceUser.objects.create(
            email=django_user.email,
            username="admin-user",
            display_name="Admin User",
            status=UserStatus.SUSPENDED,
            email_verified=True,
            system_admin=True,
        )
        claims = _claims_for_scopes(django_user, ["openid"])
        master_flags = claims.get("master_flags")
        self.assertIsInstance(master_flags, dict)
        self.assertTrue(master_flags.get("system_admin"))
        self.assertTrue(master_flags.get("suspended"))
        self.assertFalse(master_flags.get("banned"))
        self.assertEqual(master_flags.get("status"), upd_user.status)


class OidcProtocolComplianceTests(TestCase):
    """Protocol-level invariants for OIDC/OAuth2 flows."""

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="protocol-user",
            email="protocol@example.com",
            password="secret",
        )
        self.private_client = OidcClient.objects.create(
            name="Private Client",
            redirect_uris=["http://localhost/callback"],
            allowed_scopes=["openid", "profile"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=False,
            is_first_party=True,
        )
        self.private_client.set_secret("private-secret")
        self.private_client.save()

        self.public_client = OidcClient.objects.create(
            name="Public Client",
            redirect_uris=["http://localhost/public-callback"],
            allowed_scopes=["openid", "profile"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=True,
            is_first_party=True,
        )

    def test_public_client_requires_pkce(self):
        with self.assertRaises(HttpError) as exc:
            OidcService.prepare_authorization(
                self.user,
                {
                    "client_id": self.public_client.client_id,
                    "redirect_uri": "http://localhost/public-callback",
                    "response_type": "code",
                    "scope": "openid profile",
                    "state": "s1",
                    "code_challenge": "",
                    "code_challenge_method": "",
                },
            )
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message.get("code"), "PKCE_REQUIRED")

    def test_public_client_requires_s256_pkce(self):
        with self.assertRaises(HttpError) as exc:
            OidcService.prepare_authorization(
                self.user,
                {
                    "client_id": self.public_client.client_id,
                    "redirect_uri": "http://localhost/public-callback",
                    "response_type": "code",
                    "scope": "openid profile",
                    "state": "s2",
                    "code_challenge": "abc123",
                    "code_challenge_method": "plain",
                },
            )
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message.get("code"), "INVALID_PKCE_METHOD")

    def test_private_client_rejects_plain_pkce_method(self):
        with self.assertRaises(HttpError) as exc:
            OidcService.prepare_authorization(
                self.user,
                {
                    "client_id": self.private_client.client_id,
                    "redirect_uri": "http://localhost/callback",
                    "response_type": "code",
                    "scope": "openid profile",
                    "state": "s3",
                    "code_challenge": "abc123",
                    "code_challenge_method": "plain",
                },
            )
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message.get("code"), "INVALID_PKCE_METHOD")

    def test_exchange_code_rejects_invalid_pkce_verifier(self):
        code_verifier = "verifier-1234567890"
        hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(hashed).rstrip(b"=").decode("ascii")

        auth_req = OidcAuthorizationRequest.objects.create(
            request_id="req-proto-1",
            client=self.private_client,
            user=self.user,
            redirect_uri="http://localhost/callback",
            scope="openid profile",
            state="state-1",
            code_challenge=challenge,
            code_challenge_method="S256",
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        redirect = OidcService.approve_authorization(
            self.user, request_id=auth_req.request_id
        )
        code = parse_qs(urlparse(redirect).query)["code"][0]

        with self.assertRaises(HttpError) as exc:
            OidcService.exchange_code(
                {
                    "client_id": self.private_client.client_id,
                    "client_secret": "private-secret",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost/callback",
                    "code": code,
                    "code_verifier": "wrong-verifier",
                },
                request=SimpleNamespace(headers={}),
            )
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message.get("code"), "INVALID_PKCE")

    def test_exchange_code_rejects_plain_pkce_method(self):
        auth_req = OidcAuthorizationRequest.objects.create(
            request_id="req-proto-plain",
            client=self.private_client,
            user=self.user,
            redirect_uri="http://localhost/callback",
            scope="openid profile",
            state="state-plain",
            code_challenge="plain-verifier",
            code_challenge_method="plain",
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        redirect = OidcService.approve_authorization(
            self.user, request_id=auth_req.request_id
        )
        code = parse_qs(urlparse(redirect).query)["code"][0]

        with self.assertRaises(HttpError) as exc:
            OidcService.exchange_code(
                {
                    "client_id": self.private_client.client_id,
                    "client_secret": "private-secret",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost/callback",
                    "code": code,
                    "code_verifier": "plain-verifier",
                },
                request=SimpleNamespace(headers={}),
            )
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message.get("code"), "INVALID_PKCE_METHOD")

    def test_approve_authorization_never_escalates_scope(self):
        prepared = OidcService.prepare_authorization(
            self.user,
            {
                "client_id": self.private_client.client_id,
                "redirect_uri": "http://localhost/callback",
                "response_type": "code",
                "scope": "openid profile",
                "state": "state-2",
                "code_challenge": "",
                "code_challenge_method": "",
            },
        )

        redirect = OidcService.approve_authorization(
            self.user,
            request_id=prepared["request_id"],
            approved_scopes=["openid", "profile", "email"],
            remember=False,
        )
        code = parse_qs(urlparse(redirect).query)["code"][0]

        token_resp = OidcService.exchange_code(
            {
                "client_id": self.private_client.client_id,
                "client_secret": "private-secret",
                "grant_type": "authorization_code",
                "redirect_uri": "http://localhost/callback",
                "code": code,
            },
            request=SimpleNamespace(headers={}),
        )
        self.assertEqual(token_resp["scope"], "openid profile")

    def test_exchange_code_rejects_redirect_mismatch(self):
        prepared = OidcService.prepare_authorization(
            self.user,
            {
                "client_id": self.private_client.client_id,
                "redirect_uri": "http://localhost/callback",
                "response_type": "code",
                "scope": "openid profile",
                "state": "state-3",
                "code_challenge": "",
                "code_challenge_method": "",
            },
        )
        redirect = OidcService.approve_authorization(
            self.user,
            request_id=prepared["request_id"],
            remember=False,
        )
        code = parse_qs(urlparse(redirect).query)["code"][0]
        with self.assertRaises(HttpError) as exc:
            OidcService.exchange_code(
                {
                    "client_id": self.private_client.client_id,
                    "client_secret": "private-secret",
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost/other",
                    "code": code,
                },
                request=SimpleNamespace(headers={}),
            )
        self.assertEqual(exc.exception.message["code"], "INVALID_REDIRECT_URI")

    def test_refresh_rejects_client_without_refresh_grant(self):
        self.private_client.grant_types = ["authorization_code"]
        self.private_client.save(update_fields=["grant_types"])
        with self.assertRaises(HttpError) as exc:
            OidcService.refresh_tokens(
                {
                    "client_id": self.private_client.client_id,
                    "client_secret": "private-secret",
                    "refresh_token": "unknown",
                },
                request=SimpleNamespace(headers={}),
            )
        self.assertEqual(exc.exception.message["code"], "UNSUPPORTED_GRANT_TYPE")


class OidcHelperTests(TestCase):
    def test_verify_pkce_requires_s256(self):
        verifier = "verifier-1234567890"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        self.assertTrue(_verify_pkce(verifier, challenge, "S256"))
        self.assertFalse(_verify_pkce(verifier, challenge, "plain"))
        self.assertFalse(_verify_pkce("", challenge, "S256"))
        self.assertFalse(_verify_pkce(verifier, "", "S256"))

    def test_build_redirect_preserves_existing_query(self):
        redirected = _build_redirect("https://app.example/cb?foo=bar", {"state": "s1"})
        parsed = urlparse(redirected)
        params = parse_qs(parsed.query)
        self.assertEqual(params["foo"], ["bar"])
        self.assertEqual(params["state"], ["s1"])

    def test_normalize_scope_request_includes_openid(self):
        client = OidcClient.objects.create(
            name="Scope Client",
            redirect_uris=["https://app.example/cb"],
            allowed_scopes=["profile"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=True,
            is_first_party=True,
        )
        scopes = _normalize_scope_request("profile unknown", client)
        self.assertEqual(scopes, ["openid", "profile"])

    def test_apply_privacy_prefs_filters_denied_scopes(self):
        result = _apply_privacy_prefs(
            ["openid", "profile", "email"],
            {"privacy_scope_defaults": {"email": "deny"}},
        )
        self.assertEqual(result, ["openid", "profile"])

    def test_apply_privacy_prefs_reinserts_openid_when_all_denied(self):
        result = _apply_privacy_prefs(
            ["openid", "email"],
            {"privacy_scope_defaults": {"openid": "deny", "email": "deny"}},
        )
        self.assertEqual(result, ["openid"])

    def test_normalize_scope_request_defaults_to_catalog_when_allowlist_empty(self):
        client = OidcClient.objects.create(
            name="Wide Scope Client",
            redirect_uris=["https://app.example/cb"],
            allowed_scopes=[],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=True,
            is_first_party=True,
        )
        scopes = _normalize_scope_request("unknown email", client)
        self.assertEqual(scopes, ["openid", "email"])

    def test_prepare_authorization_validation_errors(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username="prepare-user",
            email="prepare@example.com",
            password="secret",
        )

        with self.assertRaises(HttpError) as unsupported:
            OidcService.prepare_authorization(
                user,
                {
                    "client_id": "missing",
                    "redirect_uri": "https://app.example/cb",
                    "response_type": "token",
                },
            )
        self.assertEqual(
            unsupported.exception.message["code"], "UNSUPPORTED_RESPONSE_TYPE"
        )

        with self.assertRaises(HttpError) as missing_client:
            OidcService.prepare_authorization(
                user,
                {
                    "client_id": "missing",
                    "redirect_uri": "https://app.example/cb",
                    "response_type": "code",
                },
            )
        self.assertEqual(missing_client.exception.message["code"], "CLIENT_NOT_FOUND")

        client = OidcClient.objects.create(
            name="Prepare Client",
            redirect_uris=["https://allowed.example/cb"],
            allowed_scopes=["openid", "profile"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=False,
            is_first_party=True,
        )
        client.set_secret("secret")
        client.save()

        with self.assertRaises(HttpError) as bad_redirect:
            OidcService.prepare_authorization(
                user,
                {
                    "client_id": client.client_id,
                    "redirect_uri": "https://evil.example/cb",
                    "response_type": "code",
                },
            )
        self.assertEqual(bad_redirect.exception.message["code"], "INVALID_REDIRECT_URI")

        client.response_types = ["id_token"]
        client.save(update_fields=["response_types"])
        with self.assertRaises(HttpError) as not_allowed:
            OidcService.prepare_authorization(
                user,
                {
                    "client_id": client.client_id,
                    "redirect_uri": "https://allowed.example/cb",
                    "response_type": "code",
                },
            )
        self.assertEqual(
            not_allowed.exception.message["code"], "UNSUPPORTED_RESPONSE_TYPE"
        )

    def test_prepare_authorization_requires_challenge_with_method(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(
            username="prepare-user-2",
            email="prepare2@example.com",
            password="secret",
        )
        client = OidcClient.objects.create(
            name="Prepare Client 2",
            redirect_uris=["https://allowed.example/cb2"],
            allowed_scopes=["openid"],
            grant_types=["authorization_code"],
            response_types=["code"],
            is_public=False,
            is_first_party=True,
        )
        client.set_secret("secret")
        client.save()

        with self.assertRaises(HttpError) as exc:
            OidcService.prepare_authorization(
                user,
                {
                    "client_id": client.client_id,
                    "redirect_uri": "https://allowed.example/cb2",
                    "response_type": "code",
                    "code_challenge": "",
                    "code_challenge_method": "S256",
                },
            )
        self.assertEqual(exc.exception.message["code"], "INVALID_PKCE_METHOD")

    def test_authenticate_client_rejects_invalid_basic_auth(self):
        request = SimpleNamespace(headers={"Authorization": "Basic not-base64"})
        with self.assertRaises(HttpError) as exc:
            OidcService.authenticate_client(request, {})
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "INVALID_CLIENT")

    def test_resolve_token_public_key_rejects_unknown_kid(self):
        with (
            patch(
                "idp.services.jwt.get_unverified_header", return_value={"kid": "k-1"}
            ),
            patch("idp.services.public_key_for_kid", return_value=None),
        ):
            with self.assertRaises(HttpError) as exc:
                _resolve_token_public_key("token")
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "UNKNOWN_KEY")

    def test_decode_jwt_token_rejects_invalid_signature(self):
        with (
            patch("idp.services._resolve_token_public_key", return_value="public-key"),
            patch("idp.services.jwt.decode", side_effect=InvalidTokenError("invalid")),
        ):
            with self.assertRaises(HttpError) as exc:
                _decode_jwt_token("token")
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "INVALID_TOKEN")


class OidcRouterBehaviorTests(TestCase):
    def setUp(self):
        self.client_http = Client()

    def test_require_user_rejects_unauthenticated(self):
        request = SimpleNamespace(auth=None)
        with self.assertRaises(HttpError) as exc:
            _require_user(request)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "UNAUTHORIZED")

    def test_check_rate_limit_raises_429_when_blocked(self):
        request = SimpleNamespace(auth=None, headers={}, META={})
        blocked = RateLimitDecision(blocked=True, retry_after=17, remaining=0, limit=1)
        with (
            patch("idp.router.get_client_ip", return_value="127.0.0.1"),
            patch(
                "idp.router.RateLimitService.oidc_token_attempt", return_value=blocked
            ),
            patch("idp.router.track_rate_limit") as track_mock,
            self.assertRaises(HttpError) as exc,
        ):
            _check_rate_limit(request, "token", client_id="portal")

        self.assertEqual(exc.exception.status_code, 429)
        self.assertEqual(exc.exception.message["code"], "RATE_LIMIT_EXCEEDED")
        track_mock.assert_called_once_with("token", "ip")

    def test_check_rate_limit_ignores_unknown_scope(self):
        request = SimpleNamespace(auth=None, headers={}, META={})
        _check_rate_limit(request, "custom-scope")

    def test_check_rate_limit_authorize_scope_uses_user_id(self):
        request = SimpleNamespace(
            auth=SimpleNamespace(pk=777),
            headers={},
            META={},
        )
        allowed = RateLimitDecision(
            blocked=False,
            retry_after=None,
            remaining=10,
            limit=30,
        )
        with (
            patch("idp.router.get_client_ip", return_value="127.0.0.9"),
            patch(
                "idp.router.RateLimitService.oidc_authorize_attempt",
                return_value=allowed,
            ) as authorize_attempt,
        ):
            _check_rate_limit(request, "authorize")
        authorize_attempt.assert_called_once_with(ip="127.0.0.9", user_id="777")

    def test_require_user_accepts_authenticated_request(self):
        request = SimpleNamespace(auth=SimpleNamespace(is_authenticated=True, pk=1))
        user = _require_user(request)
        self.assertIs(user, request.auth)
        self.assertIs(request.user, request.auth)

    def test_token_endpoint_rejects_unsupported_grant_type(self):
        response = self.client_http.post(
            "/oauth/token",
            data=json.dumps(
                {
                    "grant_type": "client_credentials",
                    "client_id": "x",
                    "client_secret": "y",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertEqual(payload["error"]["code"], "UNSUPPORTED_GRANT_TYPE")

    def test_revoke_endpoint_requires_token(self):
        response = self.client_http.post(
            "/oauth/revoke",
            data=json.dumps({"token": ""}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertEqual(payload["error"]["code"], "INVALID_REQUEST")

    def test_authorize_prepare_calls_service_with_normalized_params(self):
        request = SimpleNamespace(
            auth=SimpleNamespace(is_authenticated=True, pk=10),
            headers={},
            META={},
            path="/oauth/authorize/prepare",
            method="GET",
        )
        prepared = {"request_id": "req-1"}
        with (
            patch("idp.router._check_rate_limit"),
            patch(
                "idp.router.OidcService.prepare_authorization", return_value=prepared
            ) as prepare_mock,
            patch("idp.router.track_oidc_event") as track_mock,
        ):
            response = authorize_prepare(
                request,
                client_id="portal",
                redirect_uri="https://app.example/cb",
                response_type="code",
                scope=None,
                state=None,
                nonce=None,
                code_challenge=None,
                code_challenge_method=None,
                prompt=None,
            )
        self.assertEqual(response, prepared)
        args = prepare_mock.call_args.args
        self.assertEqual(args[1]["scope"], "")
        self.assertEqual(args[1]["state"], "")
        track_mock.assert_called_once_with("authorization_prepare", client_id="portal")

    def test_authorize_approve_and_deny_return_no_store_headers(self):
        request = SimpleNamespace(
            auth=SimpleNamespace(is_authenticated=True, pk=10),
            headers={},
            META={},
            path="/oauth/authorize/approve",
            method="POST",
        )
        payload = SimpleNamespace(request_id="req-2", scopes=["openid"], remember=True)
        auth_req = SimpleNamespace(client=SimpleNamespace(client_id="portal"))
        query_result = SimpleNamespace(first=lambda: auth_req)
        with (
            patch("idp.router._check_rate_limit"),
            patch(
                "idp.router.OidcAuthorizationRequest.objects.filter",
                return_value=query_result,
            ),
            patch(
                "idp.router.OidcService.approve_authorization",
                return_value="https://app.example/cb?code=1",
            ),
            patch("idp.router.track_oidc_event"),
        ):
            approved = authorize_approve(request, payload)
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved["Cache-Control"], "no-store")

        deny_payload = SimpleNamespace(request_id="req-3")
        with (
            patch("idp.router._check_rate_limit"),
            patch(
                "idp.router.OidcAuthorizationRequest.objects.filter",
                return_value=SimpleNamespace(first=lambda: None),
            ),
            patch(
                "idp.router.OidcService.deny_authorization",
                return_value="https://app.example/cb?error=access_denied",
            ),
            patch("idp.router.track_oidc_event"),
        ):
            denied = authorize_deny(request, deny_payload)
        self.assertEqual(denied.status_code, 200)
        self.assertEqual(denied["Cache-Control"], "no-store")

    def test_token_router_supports_both_grants_and_post_override(self):
        request = SimpleNamespace(
            POST={
                "grant_type": "refresh_token",
                "client_id": "from-post",
                "ignored": None,
            },
            headers={},
            META={},
        )
        payload = SimpleNamespace(
            dict=lambda: {
                "grant_type": "authorization_code",
                "client_id": "from-json",
                "code": "c1",
            }
        )
        with (
            patch("idp.router._check_rate_limit"),
            patch(
                "idp.router.OidcService.refresh_tokens",
                return_value={"access_token": "a", "token_type": "Bearer"},
            ) as refresh_mock,
            patch("idp.router.track_oidc_event") as track_mock,
        ):
            refresh_response = token(request, payload)
        self.assertEqual(refresh_response.status_code, 200)
        self.assertEqual(refresh_response["Cache-Control"], "no-store")
        refresh_mock.assert_called_once()
        track_mock.assert_called_once_with(
            "token_refresh",
            client_id="from-post",
            grant_type="refresh_token",
        )

        request2 = SimpleNamespace(POST={}, headers={}, META={})
        payload2 = SimpleNamespace(
            dict=lambda: {
                "grant_type": "authorization_code",
                "client_id": "from-json",
                "code": "c2",
            }
        )
        with (
            patch("idp.router._check_rate_limit"),
            patch(
                "idp.router.OidcService.exchange_code",
                return_value={"access_token": "a2", "token_type": "Bearer"},
            ) as exchange_mock,
            patch("idp.router.track_oidc_event"),
        ):
            code_response = token(request2, payload2)
        self.assertEqual(code_response.status_code, 200)
        self.assertEqual(code_response["Cache-Control"], "no-store")
        exchange_mock.assert_called_once()

    def test_userinfo_jwks_and_revoke_success_paths(self):
        request = SimpleNamespace(
            headers={"Authorization": "Bearer access-1"},
            META={},
        )
        with (
            patch("idp.router._check_rate_limit"),
            patch(
                "idp.router.OidcService.userinfo",
                return_value={"sub": "user-1"},
            ) as userinfo_mock,
            patch("idp.router.track_oidc_event"),
        ):
            userinfo_response = userinfo(request)
        self.assertEqual(userinfo_response.status_code, 200)
        self.assertEqual(userinfo_response["Cache-Control"], "no-store")
        userinfo_mock.assert_called_once_with("access-1", request=request)

        with patch(
            "idp.router.OidcService.jwks", return_value={"keys": []}
        ) as jwks_mock:
            jwks_response = jwks(SimpleNamespace())
        self.assertEqual(jwks_response, {"keys": []})
        jwks_mock.assert_called_once()

        with patch("idp.router.OidcService.revoke_token") as revoke_mock:
            revoke_response = revoke(SimpleNamespace(), SimpleNamespace(token="rt-1"))
        self.assertEqual(revoke_response.status_code, 200)
        self.assertEqual(revoke_response["Cache-Control"], "no-store")
        revoke_mock.assert_called_once_with("rt-1")
