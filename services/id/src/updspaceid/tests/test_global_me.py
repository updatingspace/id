import hashlib
import hmac
import time
import uuid

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from accounts.models import AccountIdentity, UserPreferences, UserProfile
from updspaceid.enums import UserStatus
from updspaceid.models import Tenant, TenantMembership, User


@override_settings(
    BFF_INTERNAL_HMAC_SECRET="global-me-test", GRAVATAR_AUTOLOAD_ENABLED=False
)
class GlobalMeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            email="owner@example.com", status=UserStatus.ACTIVE
        )

    def headers(self, **extra):
        request_id = str(uuid.uuid4())
        timestamp = str(int(time.time()))
        message = "\n".join(
            [
                "GET",
                "/api/v1/me",
                hashlib.sha256(b"").hexdigest(),
                request_id,
                timestamp,
            ]
        )
        return {
            "HTTP_X_USER_ID": str(self.user.pk),
            "HTTP_X_REQUEST_ID": request_id,
            "HTTP_X_UPDSPACE_TIMESTAMP": timestamp,
            "HTTP_X_UPDSPACE_SIGNATURE": hmac.new(
                b"global-me-test", message.encode(), hashlib.sha256
            ).hexdigest(),
            **extra,
        }

    def test_standalone_profile_is_read_only_and_does_not_create_tenants(self):
        auth_user = get_user_model().objects.create_user(
            username="bound", email="changed@example.com", first_name="Bound"
        )
        AccountIdentity.objects.create(
            user=auth_user, identity=self.user, public_subject="opaque"
        )
        UserProfile.objects.filter(user=auth_user).delete()
        UserPreferences.objects.filter(user=auth_user).delete()
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get("/api/v1/me", **self.headers())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["user"]["email"], self.user.email)
        self.assertEqual(response.json()["user"]["first_name"], "Bound")
        self.assertEqual(response.json()["memberships"], [])
        self.assertFalse(Tenant.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())
        self.assertFalse(
            any(
                q["sql"].lstrip().startswith(("INSERT", "UPDATE", "DELETE"))
                for q in queries
            )
        )

    def test_only_own_active_memberships_are_returned_across_two_tenants(self):
        one = Tenant.objects.create(slug="one")
        two = Tenant.objects.create(slug="two")
        other = User.objects.create(email="other@example.com", status=UserStatus.ACTIVE)
        TenantMembership.objects.create(user=self.user, tenant=one, status="active")
        TenantMembership.objects.create(user=self.user, tenant=two, status="suspended")
        TenantMembership.objects.create(user=other, tenant=two, status="active")
        response = self.client.get("/api/v1/me", **self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [m["tenant_slug"] for m in response.json()["memberships"]], ["one"]
        )
        TenantMembership.objects.filter(user=self.user, tenant=two).update(
            status="active"
        )
        scoped = self.client.get(
            "/api/v1/me",
            **self.headers(HTTP_X_TENANT_ID=str(one.pk), HTTP_X_TENANT_SLUG=one.slug),
        )
        self.assertEqual(scoped.status_code, 200)
        self.assertEqual(
            [m["tenant_slug"] for m in scoped.json()["memberships"]], ["one"]
        )

    def test_missing_invalid_and_expired_signatures_are_rejected(self):
        self.assertEqual(self.client.get("/api/v1/me").status_code, 400)
        self.assertEqual(
            self.client.get(
                "/api/v1/me", HTTP_X_REQUEST_ID="missing-signature"
            ).status_code,
            401,
        )
        for headers in [
            self.headers(HTTP_X_UPDSPACE_SIGNATURE="bad"),
            self.headers(HTTP_X_UPDSPACE_TIMESTAMP="1"),
        ]:
            self.assertEqual(self.client.get("/api/v1/me", **headers).status_code, 401)

    def test_invalid_unknown_and_inactive_principals_are_rejected(self):
        self.assertEqual(
            self.client.get(
                "/api/v1/me", **self.headers(HTTP_X_USER_ID="not-uuid")
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.get(
                "/api/v1/me", **self.headers(HTTP_X_USER_ID=str(uuid.uuid4()))
            ).status_code,
            401,
        )
        for status in [UserStatus.SUSPENDED, UserStatus.BANNED]:
            self.user.status = status
            self.user.save(update_fields=["status"])
            self.assertEqual(
                self.client.get("/api/v1/me", **self.headers()).status_code, 403
            )

    def test_partial_tenant_headers_do_not_fall_back_to_global(self):
        for extra in [
            {"HTTP_X_TENANT_ID": str(uuid.uuid4())},
            {"HTTP_X_TENANT_SLUG": "one"},
            {"HTTP_X_TENANT_ID": "", "HTTP_X_TENANT_SLUG": ""},
        ]:
            self.assertEqual(
                self.client.get("/api/v1/me", **self.headers(**extra)).status_code, 400
            )

    def test_scoped_request_cannot_read_another_tenant(self):
        tenant = Tenant.objects.create(slug="not-a-member")
        response = self.client.get(
            "/api/v1/me",
            **self.headers(
                HTTP_X_TENANT_ID=str(tenant.pk), HTTP_X_TENANT_SLUG=tenant.slug
            ),
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(TenantMembership.objects.exists())

    def test_matching_email_does_not_attach_an_unbound_account_profile(self):
        get_user_model().objects.create_user(
            username="unbound", email=self.user.email, first_name="Not the owner"
        )
        response = self.client.get("/api/v1/me", **self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["user"]["first_name"])
        self.assertFalse(AccountIdentity.objects.exists())
