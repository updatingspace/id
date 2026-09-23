from __future__ import annotations

import json
import uuid
from unittest.mock import patch

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from ninja.errors import HttpError

from accounts.models import AccountIdentity
from accounts.services.identity import resolve_identity
from idp.services import _resolve_updspace_user
from updspaceid.enums import UserStatus
from updspaceid.models import Tenant, TenantMembership, User as Identity


@override_settings(
    ID_GLOBAL_IDENTITY_PROVISIONING=True,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    ACCOUNT_EMAIL_VERIFICATION="mandatory",
)
class GlobalIdentityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.password = "Synthetic-Password-123!"
        self.user = get_user_model().objects.create_user(
            username="standalone",
            email="standalone@example.com",
            password=self.password,
        )

    def verify(self):
        return EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=True
        )

    def login(self):
        token = self.client.get("/api/v1/auth/form_token", {"purpose": "login"}).json()[
            "form_token"
        ]
        return self.client.post(
            "/api/v1/auth/login",
            json.dumps(
                {
                    "email": self.user.email,
                    "password": self.password,
                    "form_token": token,
                }
            ),
            content_type="application/json",
        )

    def test_verified_standalone_password_login_has_global_uuid_without_tenant(self):
        self.verify()
        response = self.login()
        self.assertEqual(response.status_code, 200, response.content)
        binding = AccountIdentity.objects.get(user=self.user)
        self.assertIsInstance(binding.identity_id, uuid.UUID)
        self.assertEqual(binding.public_subject, str(self.user.pk))
        self.assertEqual(binding.identity.email, self.user.email)
        self.assertTrue(binding.identity.email_verified)
        self.assertFalse(Tenant.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())

    def test_oidc_resolver_provisions_verified_principal_without_membership(self):
        self.verify()
        tenant = Tenant.objects.create(slug="not-granted")
        identity = _resolve_updspace_user(self.user)
        self.assertIsInstance(identity.pk, uuid.UUID)
        self.assertEqual(identity.email, self.user.email)
        self.assertFalse(TenantMembership.objects.filter(tenant=tenant).exists())

    def test_late_provisioning_preserves_preexisting_opaque_subject(self):
        binding = AccountIdentity.objects.create(
            user=self.user, public_subject="legacy-opaque-18"
        )
        self.verify()
        resolved = resolve_identity(self.user)
        self.assertIsInstance(resolved.identity_id, uuid.UUID)
        self.assertEqual(resolved.public_subject, binding.public_subject)
        with CaptureQueriesContext(connection) as queries:
            again = resolve_identity(self.user)
        self.assertEqual(again.identity_id, resolved.identity_id)
        self.assertFalse(
            any(
                q["sql"].lstrip().startswith(("INSERT", "UPDATE", "DELETE"))
                for q in queries
            )
        )
        self.assertEqual(Identity.objects.count(), 1)
        self.assertFalse(TenantMembership.objects.exists())

    def test_unverified_primary_does_not_provision_global_identity(self):
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=False
        )
        binding = resolve_identity(self.user)
        self.assertIsNone(binding.identity_id)
        self.assertEqual(binding.public_subject, str(self.user.pk))
        self.assertFalse(Identity.objects.exists())
        self.assertEqual(self.login().status_code, 401)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_unverified_address_cannot_take_or_bypass_existing_banned_identity(self):
        identity = Identity.objects.create(
            email=self.user.email, status=UserStatus.BANNED
        )
        with self.assertRaises(HttpError) as error:
            resolve_identity(self.user)
        self.assertEqual(
            error.exception.message["code"], "IDENTITY_VERIFICATION_REQUIRED"
        )
        self.assertFalse(AccountIdentity.objects.filter(user=self.user).exists())
        identity.refresh_from_db()
        self.assertEqual(identity.status, UserStatus.BANNED)

    def test_banned_verified_master_blocks_password_before_session_creation(self):
        self.verify()
        identity = Identity.objects.create(
            email=self.user.email, status=UserStatus.BANNED
        )
        response = self.login()
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("X-Session-Token", response.headers)
        self.assertNotIn("access_token", response.json())
        self.assertNotIn("_auth_user_id", self.client.session)
        identity.refresh_from_db()
        self.assertEqual(identity.status, UserStatus.BANNED)
        self.assertFalse(TenantMembership.objects.exists())

    def test_late_matching_master_never_joins_an_established_null_binding(self):
        binding = resolve_identity(self.user)
        self.verify()
        foreign = Identity.objects.create(
            email=self.user.email, status=UserStatus.ACTIVE, system_admin=True
        )
        with self.assertRaises(HttpError) as error:
            resolve_identity(self.user)
        self.assertEqual(error.exception.message["code"], "IDENTITY_LINK_CONFLICT")
        binding.refresh_from_db()
        self.assertIsNone(binding.identity_id)
        self.assertEqual(Identity.objects.count(), 1)
        self.assertTrue(Identity.objects.get(pk=foreign.pk).system_admin)
        response = self.login()
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_ambiguous_verified_email_cannot_provision_or_authenticate(self):
        self.verify()
        get_user_model().objects.create_user(
            username="ambiguous", email=self.user.email.upper()
        )
        with self.assertRaises(HttpError):
            resolve_identity(self.user)
        self.assertFalse(Identity.objects.exists())
        self.assertFalse(AccountIdentity.objects.exists())

    def test_failed_binding_rolls_back_new_global_identity(self):
        self.verify()
        with patch(
            "accounts.services.identity.attach_identity",
            side_effect=HttpError(409, "synthetic conflict"),
        ):
            with self.assertRaises(HttpError):
                resolve_identity(self.user)
        self.assertFalse(Identity.objects.exists())
        self.assertFalse(AccountIdentity.objects.exists())

    def test_read_only_and_inactive_resolution_do_not_provision(self):
        self.verify()
        self.assertIsNone(resolve_identity(self.user, create=False))
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assertIsNone(resolve_identity(self.user).identity_id)
        self.assertFalse(Identity.objects.exists())
