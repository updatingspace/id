"""Canonical internal identity is distinct from the immutable public subject."""

from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import AccountIdentity
from idp.models import OidcClient
from idp.services import OidcService, _decode_jwt_token
from updspaceid.models import User as Identity


class UserIdClaimTests(TestCase):
    def test_legacy_numeric_subject_keeps_separate_master_uuid(self):
        user = get_user_model().objects.create_user(
            username="legacy-subject", email="legacy@example.test"
        )
        EmailAddress.objects.create(
            user=user, email=user.email, primary=True, verified=True
        )
        master = Identity.objects.create(email=user.email, status="active")
        AccountIdentity.objects.create(
            user=user, identity=master, public_subject=str(user.pk)
        )
        client = OidcClient.objects.create(
            name="Internal client",
            is_public=True,
            grant_types=["authorization_code", "refresh_token"],
        )
        tokens = OidcService._issue_tokens(
            user=user, client=client, scope="openid", nonce=None
        )
        for claims in (
            _decode_jwt_token(tokens["id_token"]),
            OidcService.userinfo(tokens["access_token"]),
        ):
            self.assertEqual(claims["sub"], str(user.pk))
            self.assertEqual(claims["user_id"], str(master.pk))
            self.assertNotEqual(claims["sub"], claims["user_id"])
