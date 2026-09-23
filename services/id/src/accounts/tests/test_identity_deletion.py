from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import AccountIdentity
from accounts.services.deletion import AccountDeletionService
from updspaceid.enums import UserStatus
from updspaceid.models import User as Identity


class IdentityDeletionTests(TestCase):
    def test_deletion_anonymizes_only_bound_identity_and_preserves_subject(self):
        user = get_user_model().objects.create_user(
            username="delete-owner", email="changed@example.com", password="secret"
        )
        identity = Identity.objects.create(
            email="old@example.com",
            username="original",
            display_name="Original",
            email_verified=True,
            system_admin=True,
            status=UserStatus.ACTIVE,
        )
        other = Identity.objects.create(
            email=user.email,
            username="other",
            status=UserStatus.ACTIVE,
        )
        binding = AccountIdentity.objects.create(
            user=user, identity=identity, public_subject="opaque-original-subject"
        )

        AccountDeletionService.delete_account(None, user)

        user.refresh_from_db()
        identity.refresh_from_db()
        other.refresh_from_db()
        binding.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertFalse(user.has_usable_password())
        self.assertEqual(identity.status, UserStatus.SUSPENDED)
        self.assertEqual(identity.email, user.email)
        self.assertTrue(identity.email.endswith("@deleted.local"))
        self.assertEqual(identity.username, user.username)
        self.assertEqual(identity.display_name, "")
        self.assertFalse(identity.email_verified)
        self.assertFalse(identity.system_admin)
        self.assertEqual(binding.identity_id, identity.pk)
        self.assertEqual(binding.public_subject, "opaque-original-subject")
        self.assertEqual(other.email, "changed@example.com")
        self.assertEqual(other.status, UserStatus.ACTIVE)

    def test_unbound_deletion_does_not_claim_matching_email_identity(self):
        user = get_user_model().objects.create_user(
            username="unbound-owner", email="same@example.com"
        )
        other = Identity.objects.create(email=user.email, status=UserStatus.ACTIVE)
        AccountDeletionService.delete_account(None, user)
        other.refresh_from_db()
        self.assertEqual(other.email, "same@example.com")
        self.assertEqual(other.status, UserStatus.ACTIVE)
        self.assertFalse(AccountIdentity.objects.filter(user=user).exists())
        self.assertEqual(Identity.objects.count(), 1)
