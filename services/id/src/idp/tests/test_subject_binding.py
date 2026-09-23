"""Stable subject and principal ownership, including pre-migration token handling."""

from importlib import import_module
from types import SimpleNamespace

import jwt
from allauth.account.models import EmailAddress
from django.apps import apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from ninja.errors import HttpError

from accounts.models import AccountIdentity
from accounts.services.identity import (
    attach_identity,
    backfill_identity_bindings,
    resolve_identity,
)
from idp.keys import load_keypair
from idp.models import OidcClient, OidcToken
from idp.services import OidcService, _decode_jwt_token
from updspaceid.enums import UserStatus
from updspaceid.models import User as Identity


class SubjectBindingTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="subject-owner", email="owner@example.test"
        )
        self.client = OidcClient.objects.create(
            name="subject app",
            is_public=True,
            grant_types=["authorization_code", "refresh_token"],
        )

    def verify(self, user=None):
        user = user or self.user
        return EmailAddress.objects.create(
            user=user, email=user.email, verified=True, primary=True
        )

    def identity(self, **kwargs):
        return Identity.objects.create(
            email=kwargs.pop("email", self.user.email),
            status=UserStatus.ACTIVE,
            **kwargs,
        )

    def issue(self, user=None):
        return OidcService._issue_tokens(
            user=user or self.user,
            client=self.client,
            scope="openid offline_access",
            nonce="original",
        )

    def refresh(self, token):
        return OidcService.refresh_tokens(
            {"client_id": self.client.client_id, "refresh_token": token},
            request=SimpleNamespace(headers={}),
        )

    def assert_subject(self, tokens, expected):
        self.assertEqual(_decode_jwt_token(tokens["access_token"])["sub"], expected)
        self.assertEqual(_decode_jwt_token(tokens["id_token"])["sub"], expected)
        self.assertEqual(OidcService.userinfo(tokens["access_token"])["sub"], expected)
        row = OidcToken.objects.get(
            access_jti=_decode_jwt_token(tokens["access_token"])["jti"]
        )
        self.assertEqual(row.subject, expected)

    def test_verified_legacy_uuid_is_preserved_after_email_change_and_refresh(self):
        self.verify()
        identity = self.identity()
        tokens = self.issue()
        expected = str(identity.pk)
        self.assert_subject(tokens, expected)
        self.user.email = "changed@example.test"
        self.user.save(update_fields=["email"])
        self.identity(email=self.user.email, username="different-owner")
        self.assert_subject(self.refresh(tokens["refresh_token"]), expected)
        self.assert_subject(self.issue(), expected)
        self.assertEqual(resolve_identity(self.user).identity_id, identity.pk)

    def test_fallback_subject_stays_fixed_after_explicit_identity_attachment(self):
        tokens = self.issue()
        expected = str(self.user.pk)
        self.verify()
        identity = self.identity()
        binding = attach_identity(resolve_identity(self.user, create=False), identity)
        self.assertEqual(binding.public_subject, expected)
        self.assert_subject(self.refresh(tokens["refresh_token"]), expected)
        self.assert_subject(self.issue(), expected)

    def test_late_email_match_is_not_automatically_attached(self):
        tokens = self.issue()
        self.verify()
        self.identity(system_admin=True)
        binding = resolve_identity(self.user, create=False)
        self.assertIsNone(binding.identity_id)
        self.assertEqual(binding.public_subject, str(self.user.pk))
        with self.assertRaises(HttpError):
            self.refresh(tokens["refresh_token"])
        with self.assertRaises(HttpError):
            OidcService.userinfo(tokens["access_token"])
        self.assertIsNone(OidcToken.objects.get().revoked_at)

    def test_unverified_email_cannot_claim_or_bypass_existing_identity(self):
        identity = self.identity(system_admin=True)
        identity.status = UserStatus.BANNED
        identity.save(update_fields=["status"])
        with self.assertRaises(HttpError) as raised:
            self.issue()
        self.assertEqual(
            raised.exception.message["code"], "IDENTITY_VERIFICATION_REQUIRED"
        )
        self.assertFalse(AccountIdentity.objects.filter(user=self.user).exists())
        self.assertEqual(OidcToken.objects.count(), 0)

    def test_ambiguous_verified_email_fails_closed(self):
        self.verify()
        self.identity()
        get_user_model().objects.create_user(
            username="duplicate", email=self.user.email.upper()
        )
        with self.assertRaises(HttpError):
            resolve_identity(self.user)
        self.assertEqual(AccountIdentity.objects.count(), 0)

    def test_ambiguous_master_email_fails_closed(self):
        self.verify()
        self.identity()
        self.identity(email=self.user.email.upper())
        with self.assertRaises(HttpError):
            resolve_identity(self.user)
        self.assertEqual(AccountIdentity.objects.count(), 0)

    def test_bound_identity_cannot_be_taken_by_another_auth_principal(self):
        self.verify()
        identity = self.identity()
        binding = resolve_identity(self.user)
        identity.email = "other@example.test"
        identity.save(update_fields=["email"])
        other = get_user_model().objects.create_user(
            username="other", email=identity.email
        )
        self.verify(other)
        with self.assertRaises(HttpError):
            resolve_identity(other)
        self.assertEqual(
            AccountIdentity.objects.get(user=self.user).identity_id, binding.identity_id
        )
        self.assertFalse(AccountIdentity.objects.filter(user=other).exists())

    def test_subject_and_established_link_cannot_be_reassigned(self):
        self.verify()
        self.identity()
        binding = resolve_identity(self.user)
        original = binding.public_subject
        binding.public_subject = "replacement"
        with self.assertRaises(ValueError):
            binding.save(update_fields=["public_subject"])
        binding.refresh_from_db()
        different = self.identity(email="different@example.test")
        with self.assertRaises(HttpError):
            attach_identity(binding, different)
        self.assertEqual(
            AccountIdentity.objects.get(user=self.user).public_subject, original
        )

    def test_foreign_identity_cannot_be_attached_to_empty_binding(self):
        binding = resolve_identity(self.user)
        self.verify()
        with self.assertRaises(HttpError):
            attach_identity(binding, self.identity(email="not-owner@example.test"))
        self.assertIsNone(AccountIdentity.objects.get(user=self.user).identity_id)

    def test_unverified_attachment_is_rejected_and_existing_attachment_is_idempotent(
        self,
    ):
        binding = resolve_identity(self.user)
        identity = self.identity()
        with self.assertRaises(HttpError):
            attach_identity(binding, identity)
        self.verify()
        attached = attach_identity(binding, identity)
        again = attach_identity(binding, identity)
        self.assertEqual(attached.pk, again.pk)
        self.assertEqual(again.public_subject, str(self.user.pk))

    def test_read_only_resolution_does_not_create_a_binding(self):
        self.assertIsNone(resolve_identity(self.user, create=False))
        self.assertEqual(AccountIdentity.objects.count(), 0)

    def test_reserved_subject_collision_fails_without_binding_another_principal(self):
        other = get_user_model().objects.create_user(
            username="reserved-owner", email="reserved@example.test"
        )
        AccountIdentity.objects.create(user=other, public_subject=str(self.user.pk))
        with self.assertRaises(HttpError):
            resolve_identity(self.user)
        self.assertFalse(AccountIdentity.objects.filter(user=self.user).exists())

    def test_legacy_access_can_continue_but_opaque_refresh_requires_new_authorization(
        self,
    ):
        tokens = self.issue()
        OidcToken.objects.update(subject="")
        self.assertEqual(
            OidcService.userinfo(tokens["access_token"])["sub"], str(self.user.pk)
        )
        with self.assertRaises(HttpError) as raised:
            self.refresh(tokens["refresh_token"])
        self.assertEqual(raised.exception.message["code"], "INVALID_REFRESH_TOKEN")
        self.assertEqual(OidcToken.objects.count(), 1)
        self.assert_subject(self.issue(), str(self.user.pk))

    def test_signed_subject_mismatch_is_rejected_even_for_legacy_token(self):
        tokens = self.issue()
        payload = _decode_jwt_token(tokens["access_token"])
        payload["sub"] = "different-principal"
        key = load_keypair()
        altered = jwt.encode(
            payload, key.private_key_pem, algorithm="RS256", headers={"kid": key.kid}
        )
        for subject in (str(self.user.pk), ""):
            OidcToken.objects.update(subject=subject)
            with self.assertRaises(HttpError):
                OidcService.userinfo(altered)

    def test_token_cannot_be_moved_to_another_principal(self):
        tokens = self.issue()
        other = get_user_model().objects.create_user(
            username="other-principal", email="other@example.test"
        )
        OidcToken.objects.update(user=other)
        with self.assertRaises(HttpError):
            OidcService.userinfo(tokens["access_token"])
        with self.assertRaises(HttpError):
            self.refresh(tokens["refresh_token"])
        self.assertEqual(OidcToken.objects.count(), 1)

    def test_refresh_subject_snapshot_mismatch_does_not_consume_token(self):
        tokens = self.issue()
        OidcToken.objects.update(subject="foreign")
        with self.assertRaises(HttpError):
            self.refresh(tokens["refresh_token"])
        self.assertIsNone(OidcToken.objects.get().revoked_at)

    def test_explicit_issuance_subject_cannot_override_canonical_subject(self):
        with self.assertRaises(HttpError):
            OidcService._issue_tokens(
                user=self.user,
                client=self.client,
                scope="openid",
                nonce="",
                subject_id="foreign",
            )
        self.assertEqual(OidcToken.objects.count(), 0)

    def test_deleted_and_recreated_master_email_does_not_change_subject(self):
        self.verify()
        identity = self.identity()
        original = str(identity.pk)
        tokens = self.issue()
        identity.delete()
        self.identity()
        binding = resolve_identity(self.user, create=False)
        self.assertIsNone(binding.identity_id)
        self.assertEqual(binding.public_subject, original)
        with self.assertRaises(HttpError):
            self.refresh(tokens["refresh_token"])

    def test_backfill_is_resumable_and_does_not_rebind_changed_email(self):
        expected = str(self.user.pk)
        result = backfill_identity_bindings()
        self.assertEqual(
            result, {"created": 1, "existing": 0, "verification_required": 0}
        )
        self.verify()
        self.identity()
        result = backfill_identity_bindings()
        self.assertEqual(
            result, {"created": 0, "existing": 1, "verification_required": 0}
        )
        binding = resolve_identity(self.user, create=False)
        self.assertEqual(binding.public_subject, expected)
        self.assertIsNone(binding.identity_id)
        with self.assertRaises(HttpError):
            resolve_identity(self.user)

    def test_backfill_skips_unverified_match_but_stops_on_ambiguous_ownership(self):
        self.identity()
        result = backfill_identity_bindings()
        self.assertEqual(result["verification_required"], 1)
        self.assertEqual(AccountIdentity.objects.count(), 0)
        self.verify()
        get_user_model().objects.create_user(
            username="ambiguous", email=self.user.email
        )
        with self.assertRaises(HttpError):
            backfill_identity_bindings()
        self.assertEqual(AccountIdentity.objects.count(), 0)

    def test_data_migration_freezes_verified_uuid_and_skips_unverified_master(self):
        self.verify()
        identity = self.identity()
        unverified = get_user_model().objects.create_user(
            username="unverified-legacy", email="unverified@example.test"
        )
        self.identity(email=unverified.email)
        migration = import_module("accounts.migrations.0004_accountidentity")
        migration.freeze_existing_principals(
            apps, SimpleNamespace(connection=connection)
        )
        self.assertEqual(
            AccountIdentity.objects.get(user=self.user).public_subject, str(identity.pk)
        )
        self.assertFalse(AccountIdentity.objects.filter(user=unverified).exists())
