"""Freeze subjects before enabling UUID provisioning or choosing a rollback target."""

from importlib import import_module
from types import SimpleNamespace

from allauth.account.models import EmailAddress
from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import RequestFactory, TestCase, override_settings
from ninja.errors import HttpError

from accounts.models import AccountIdentity
from accounts.services.headless import _sync_updspace_identity
from accounts.services.identity import backfill_identity_bindings, resolve_identity
from updspaceid.models import TenantMembership, User as Identity


class IdentityRolloutTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="rollout-owner", email="rollout@example.test"
        )
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=True
        )

    def legacy_subject(self):
        # Pre-hotfix binaries resolved the subject from a mutable email join.
        identity = Identity.objects.filter(
            email=self.user.email.strip().lower()
        ).first()
        return str(identity.pk) if identity else str(self.user.pk)

    def test_runtime_defaults_to_freeze_only(self):
        self.assertFalse(settings.ID_GLOBAL_IDENTITY_PROVISIONING)
        before = self.legacy_subject()
        binding = resolve_identity(self.user)
        self.assertEqual(binding.public_subject, before)
        self.assertIsNone(binding.identity_id)
        self.assertEqual(self.legacy_subject(), before)
        self.assertFalse(Identity.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())

    @override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=True)
    def test_backfill_never_provisions_even_when_runtime_flag_is_enabled(self):
        before = self.legacy_subject()
        result = backfill_identity_bindings()
        self.assertEqual(result["created"], 1)
        binding = AccountIdentity.objects.get(user=self.user)
        self.assertEqual(binding.public_subject, before)
        self.assertIsNone(binding.identity_id)
        self.assertEqual(self.legacy_subject(), before)
        self.assertFalse(Identity.objects.exists())
        self.assertEqual(backfill_identity_bindings()["existing"], 1)
        self.assertFalse(Identity.objects.exists())

    @override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False)
    def test_two_phase_activation_preserves_subject_and_disabling_keeps_identity(self):
        frozen = resolve_identity(self.user)
        self.assertIsNone(frozen.identity_id)
        with override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=True):
            enabled = resolve_identity(self.user)
        self.assertIsNotNone(enabled.identity_id)
        self.assertEqual(enabled.public_subject, frozen.public_subject)
        disabled = resolve_identity(self.user)
        self.assertEqual(disabled.identity_id, enabled.identity_id)
        self.assertEqual(disabled.public_subject, frozen.public_subject)
        self.assertFalse(TenantMembership.objects.exists())
        # Old binaries become an unsafe rollback target after phase two.
        self.assertNotEqual(self.legacy_subject(), frozen.public_subject)

    @override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False)
    def test_existing_legacy_uuid_is_frozen_without_creating_a_master(self):
        existing = Identity.objects.create(email=self.user.email, status="active")
        before = self.legacy_subject()
        backfill_identity_bindings()
        binding = resolve_identity(self.user)
        self.assertEqual(binding.identity_id, existing.pk)
        self.assertEqual(binding.public_subject, before)
        self.assertEqual(Identity.objects.count(), 1)

    @override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False)
    def test_disabled_provisioning_does_not_allow_late_foreign_identity_bypass(self):
        binding = resolve_identity(self.user)
        Identity.objects.create(email=self.user.email, status="banned")
        with self.assertRaises(HttpError):
            resolve_identity(self.user)
        binding.refresh_from_db()
        self.assertIsNone(binding.identity_id)

    @override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False)
    def test_tenant_headers_cannot_bypass_disabled_global_provisioning(self):
        request = RequestFactory().post(
            "/",
            HTTP_X_TENANT_ID="f4d2d83e-9bb4-46f0-a780-d81771e7a1d2",
            HTTP_X_TENANT_SLUG="explicit-tenant",
            HTTP_X_REQUEST_ID="rollout-test",
        )
        _sync_updspace_identity(request, self.user)
        binding = AccountIdentity.objects.get(user=self.user)
        self.assertEqual(binding.public_subject, str(self.user.pk))
        self.assertIsNone(binding.identity_id)
        self.assertFalse(Identity.objects.exists())
        self.assertFalse(TenantMembership.objects.exists())

    @override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False)
    def test_uppercase_legacy_master_links_without_changing_numeric_subject(self):
        identity = Identity.objects.create(
            email=self.user.email.upper(), status="active"
        )
        before = self.legacy_subject()
        self.assertEqual(before, str(self.user.pk))
        binding = resolve_identity(self.user)
        self.assertEqual(binding.identity_id, identity.pk)
        self.assertEqual(binding.public_subject, before)
        self.assertEqual(self.legacy_subject(), before)

    def test_sql_freeze_preserves_numeric_subject_for_uppercase_legacy_master(self):
        identity = Identity.objects.create(
            email=self.user.email.upper(), status="active"
        )
        before = self.legacy_subject()
        migration = import_module("accounts.migrations.0004_accountidentity")
        migration.freeze_existing_principals(
            apps, SimpleNamespace(connection=connection)
        )
        binding = AccountIdentity.objects.get(user=self.user)
        self.assertEqual(binding.identity_id, identity.pk)
        self.assertEqual(binding.public_subject, before)
        self.assertEqual(self.legacy_subject(), before)

    def test_exact_and_uppercase_master_candidates_remain_ambiguous(self):
        Identity.objects.create(email=self.user.email.upper(), status="active")
        exact = Identity.objects.create(email=self.user.email, status="active")
        self.assertEqual(self.legacy_subject(), str(exact.pk))
        with self.assertRaises(HttpError):
            resolve_identity(self.user)
        self.assertFalse(AccountIdentity.objects.filter(user=self.user).exists())
        self.assertEqual(self.legacy_subject(), str(exact.pk))
