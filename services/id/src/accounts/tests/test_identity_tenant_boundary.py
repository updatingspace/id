"""Only authenticated internal callers may activate the explicit tenant bridge."""

import json
import time
import uuid

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings

from accounts.models import AccountIdentity
from core.tests.test_internal_signature import _make_signature
from updspaceid.enums import MembershipStatus
from updspaceid.models import Tenant, TenantMembership


@override_settings(
    ID_GLOBAL_IDENTITY_PROVISIONING=True,
    BFF_INTERNAL_HMAC_SECRET="synthetic-bridge-secret",
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class IdentityTenantBoundaryTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = get_user_model().objects.create_user(
            username="tenant-boundary",
            email="tenant-boundary@example.test",
            password="Synthetic-password-123!",
        )
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=True
        )
        self.tenant_id = uuid.uuid4()

    def login(self, signature_kind):
        form = self.client.get("/api/v1/auth/form_token", {"purpose": "login"}).json()
        path = "/api/v1/auth/login"
        body = json.dumps(
            {
                "email": self.user.email,
                "password": "Synthetic-password-123!",
                "form_token": form["form_token"],
            }
        ).encode()
        headers = {
            "HTTP_X_TENANT_ID": str(self.tenant_id),
            "HTTP_X_TENANT_SLUG": "forged-or-internal",
            "HTTP_X_REQUEST_ID": "synthetic-bridge-request",
        }
        if signature_kind != "missing":
            timestamp = int(time.time()) - (301 if signature_kind == "expired" else 0)
            signature = _make_signature(
                secret="synthetic-bridge-secret",
                method="POST",
                path=path,
                body=body,
                request_id=headers["HTTP_X_REQUEST_ID"],
                timestamp=timestamp,
            )
            headers["HTTP_X_UPDSPACE_TIMESTAMP"] = str(timestamp)
            headers["HTTP_X_UPDSPACE_SIGNATURE"] = (
                "invalid" if signature_kind == "bad" else signature
            )
        response = self.client.post(
            path, body, content_type="application/json", **headers
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(str(self.user.pk), self.client.session["_auth_user_id"])
        self.assertIsNotNone(AccountIdentity.objects.get(user=self.user).identity_id)

    def test_unsigned_forged_tenant_headers_do_not_grant_membership(self):
        self.login("missing")
        self.assertFalse(Tenant.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())

    def test_bad_signature_does_not_grant_membership(self):
        self.login("bad")
        self.assertFalse(Tenant.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())

    def test_expired_signature_does_not_grant_membership(self):
        self.login("expired")
        self.assertFalse(Tenant.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())

    def test_signed_bridge_creates_membership_and_preserves_disabled_custom_role(self):
        self.login("valid")
        binding = AccountIdentity.objects.get(user=self.user)
        membership = TenantMembership.objects.get(
            user_id=binding.identity_id, tenant_id=self.tenant_id
        )
        self.assertEqual(membership.base_role, "member")
        self.assertEqual(membership.status, MembershipStatus.ACTIVE)
        membership.base_role = "auditor"
        membership.status = MembershipStatus.DISABLED
        membership.save(update_fields=["base_role", "status"])
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.login("valid")
        membership.refresh_from_db()
        self.assertEqual(membership.base_role, "auditor")
        self.assertEqual(membership.status, MembershipStatus.DISABLED)
        self.assertEqual(TenantMembership.objects.count(), 1)
