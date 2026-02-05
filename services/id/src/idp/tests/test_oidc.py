"""
Tests for OIDC provider endpoints and setup_portal_client command.
"""

from __future__ import annotations

import json
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings

from idp.keys import _generate_keypair, clear_key_cache_for_tests
from idp.models import OidcClient
from idp.services import OidcService, _claims_for_scopes
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
            ["plain", "S256"],
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
        self.user = User.objects.create_user(username="token-user", email="tokenuser@example.com", password="secret")
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
        new_refresh = resp.json()["refresh_token"]
        reuse_response = self._refresh(tokens["refresh_token"])
        self.assertEqual(reuse_response.status_code, 400)
        self.assertEqual(
            self._error_code(reuse_response), "INVALID_REFRESH_TOKEN"
        )

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
        self.assertEqual(
            self._error_code(refresh_resp), "INVALID_REFRESH_TOKEN"
        )

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
