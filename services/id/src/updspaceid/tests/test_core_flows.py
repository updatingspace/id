from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import timedelta
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from updspaceid.enums import MembershipStatus, UserStatus
from updspaceid.models import (
    ActivationToken,
    MagicLinkToken,
    Tenant,
    TenantMembership,
    User,
)
from updspaceid.services import _hash_token


def post_json(client: Client, path: str, payload: dict, headers: dict[str, str]):
    return client.post(
        path,
        data=json.dumps(payload),
        content_type="application/json",
        **headers,
    )


class UpdSpaceIdFlowsTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.tenant = Tenant.objects.create(slug="aef")
        self.headers = {
            "HTTP_X_REQUEST_ID": "test-req-1",
            "HTTP_X_TENANT_ID": str(self.tenant.id),
            "HTTP_X_TENANT_SLUG": self.tenant.slug,
        }

    def test_activation_token_one_time(self):
        user = User.objects.create(
            email="migrated@example.com",
            status=UserStatus.MIGRATED_UNCLAIMED,
            email_verified=False,
        )
        raw_token = "activation-raw-token"
        ActivationToken.objects.create(
            token=_hash_token(raw_token),
            user=user,
            tenant=self.tenant,
            expires_at=timezone.now() + timedelta(hours=1),
        )

        resp1 = post_json(
            self.client,
            "/api/v1/auth/activate",
            {"token": raw_token},
            self.headers,
        )
        self.assertEqual(resp1.status_code, 200)
        self.assertTrue(resp1.json()["ok"])

        resp2 = post_json(
            self.client,
            "/api/v1/auth/activate",
            {"token": raw_token},
            self.headers,
        )
        self.assertEqual(resp2.status_code, 409)
        self.assertEqual(resp2.json()["error"]["code"], "TOKEN_USED")

    @override_settings(
        GITHUB_CLIENT_ID="test",
        GITHUB_CLIENT_SECRET="test-secret",
        GITHUB_REDIRECT_URIS=["https://app.localhost/oauth/callback"],
    )
    def test_oauth_login_without_link_is_forbidden(self):
        # Start flow to create state
        resp_start = post_json(
            self.client,
            "/api/v1/oauth/github/login/start",
            {"redirect_uri": "https://app.localhost/oauth/callback"},
            self.headers,
        )
        self.assertEqual(resp_start.status_code, 200)
        state = resp_start.json()["state"]

        with patch("updspaceid.api.exchange_code_for_subject", return_value="123"):
            resp_cb = post_json(
                self.client,
                "/api/v1/oauth/github/login/callback",
                {"state": state, "code": "any"},
                self.headers,
            )

        self.assertEqual(resp_cb.status_code, 403)
        self.assertEqual(resp_cb.json()["error"]["code"], "ACCOUNT_NOT_LINKED")

    @override_settings(
        GITHUB_CLIENT_ID="test",
        GITHUB_CLIENT_SECRET="test-secret",
        GITHUB_REDIRECT_URIS=["https://app.localhost/oauth/callback"],
    )
    def test_oauth_start_rejects_unlisted_redirect_uri(self):
        resp = post_json(
            self.client,
            "/api/v1/oauth/github/login/start",
            {"redirect_uri": "https://evil.example.com/callback"},
            self.headers,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], "INVALID_REDIRECT_URI")

    def test_suspended_user_denied(self):
        user = User.objects.create(
            email="suspended@example.com",
            status=UserStatus.SUSPENDED,
            email_verified=True,
        )
        raw_token = "magic-raw-token"
        MagicLinkToken.objects.create(
            token=_hash_token(raw_token),
            user=user,
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        resp = post_json(
            self.client,
            "/api/v1/auth/magic-link/consume",
            {"token": raw_token},
            self.headers,
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"]["code"], "ACCOUNT_SUSPENDED")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="test-hmac")
    def test_applications_list_allows_internal_admin(self):
        tenant = self.tenant
        user = User.objects.create(
            email="admin@example.com",
            status=UserStatus.ACTIVE,
            email_verified=True,
            system_admin=True,
        )
        TenantMembership.objects.create(
            user=user,
            tenant=tenant,
            status=MembershipStatus.ACTIVE,
            base_role="admin",
        )

        request_id = "req-app-list-1"
        ts = str(int(time.time()))
        path = "/api/v1/applications"
        body = b""
        msg = "\n".join(
            [
                "GET",
                path,
                hashlib.sha256(body).hexdigest(),
                request_id,
                ts,
            ]
        ).encode("utf-8")
        sig = hmac.new(
            b"test-hmac",
            msg,
            digestmod=hashlib.sha256,
        ).hexdigest()

        resp = self.client.get(
            "/api/v1/applications",
            HTTP_X_REQUEST_ID=request_id,
            HTTP_X_TENANT_ID=str(tenant.id),
            HTTP_X_TENANT_SLUG=tenant.slug,
            HTTP_X_USER_ID=str(user.user_id),
            HTTP_X_UPDSPACE_TIMESTAMP=ts,
            HTTP_X_UPDSPACE_SIGNATURE=sig,
        )

        self.assertEqual(resp.status_code, 200)

    @override_settings(
        BFF_INTERNAL_HMAC_SECRET="test-hmac", GRAVATAR_AUTOLOAD_ENABLED=False
    )
    def test_me_internal_includes_account_profile(self):
        tenant = self.tenant
        user = User.objects.create(
            email="admin@example.com",
            status=UserStatus.ACTIVE,
            email_verified=True,
            system_admin=True,
        )
        TenantMembership.objects.create(
            user=user,
            tenant=tenant,
            status=MembershipStatus.ACTIVE,
            base_role="admin",
        )

        from django.contrib.auth import get_user_model
        from accounts.models import UserProfile

        auth_user = get_user_model().objects.create_user(
            username="admin",
            email="admin@example.com",
            password="test-pass",
        )
        UserProfile.objects.get_or_create(user=auth_user)

        request_id = "req-me-1"
        ts = str(int(time.time()))
        path = "/api/v1/me"
        body = b""
        msg = "\n".join(
            [
                "GET",
                path,
                hashlib.sha256(body).hexdigest(),
                request_id,
                ts,
            ]
        ).encode("utf-8")
        sig = hmac.new(
            b"test-hmac",
            msg,
            digestmod=hashlib.sha256,
        ).hexdigest()

        resp = self.client.get(
            "/api/v1/me",
            HTTP_X_REQUEST_ID=request_id,
            HTTP_X_TENANT_ID=str(tenant.id),
            HTTP_X_TENANT_SLUG=tenant.slug,
            HTTP_X_USER_ID=str(user.user_id),
            HTTP_X_UPDSPACE_TIMESTAMP=ts,
            HTTP_X_UPDSPACE_SIGNATURE=sig,
        )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        user_payload = payload["user"]
        self.assertIn("avatar_url", user_payload)
        self.assertIn("avatar_source", user_payload)
        self.assertIn("avatar_gravatar_enabled", user_payload)
