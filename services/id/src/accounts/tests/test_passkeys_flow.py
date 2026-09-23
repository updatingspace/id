from allauth.account.models import EmailAddress
from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from accounts.tests.test_api import post_json
from accounts.tests.webauthn_helpers import VirtualPasskey
from accounts.models import AccountIdentity
from updspaceid.enums import UserStatus
from updspaceid.models import TenantMembership, User as Identity


@override_settings(
    ID_GLOBAL_IDENTITY_PROVISIONING=True,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    ACCOUNT_EMAIL_VERIFICATION="mandatory",
)
class PasskeyFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = get_user_model().objects.create_user(
            username="passkey-flow",
            email="passkey@example.com",
            password="Strong-Test-Password!123",
        )
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, verified=True, primary=True
        )
        token = self.client.get("/api/v1/auth/form_token", {"purpose": "login"}).json()[
            "form_token"
        ]
        response = post_json(
            self.client,
            "/api/v1/auth/login",
            {
                "email": self.user.email,
                "password": "Strong-Test-Password!123",
                "form_token": token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.token = response.json()["meta"]["session_token"]

    def begin(self):
        response = post_json(
            self.client,
            "/api/v1/auth/passkeys/begin",
            {"passwordless": True},
            token=self.token,
        )
        self.assertEqual(response.status_code, 200)
        options = response.json()["creation_options"]["publicKey"]
        self.assertTrue(options["challenge"])
        self.assertEqual(options["authenticatorSelection"]["residentKey"], "required")
        return options

    def complete(self, credential):
        return post_json(
            self.client,
            "/api/v1/auth/passkeys/complete",
            {
                "name": "Test passkey",
                "credential": credential,
            },
            token=self.token,
        )

    def test_registration_login_and_registration_replay(self):
        key = VirtualPasskey()
        credential = key.register(self.begin())
        response = self.complete(credential)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()["authenticator"]["is_passwordless"])
        self.assertTrue(response.json()["recovery_codes"])
        replay = self.complete(credential)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()["code"], "INVALID_PASSKEY")
        self.assertEqual(
            Authenticator.objects.filter(
                user=self.user, type=Authenticator.Type.WEBAUTHN
            ).count(),
            1,
        )

        anonymous = Client()
        begin = anonymous.post("/api/v1/auth/passkeys/login/begin")
        self.assertEqual(begin.status_code, 200)
        assertion = key.authenticate(begin.json()["request_options"]["publicKey"])
        response = post_json(
            anonymous, "/api/v1/auth/passkeys/login/complete", {"credential": assertion}
        )
        self.assertEqual(response.status_code, 200, response.content)
        session_token = response.json()["meta"]["session_token"]
        profile = anonymous.get("/api/v1/auth/me", HTTP_X_SESSION_TOKEN=session_token)
        self.assertEqual(profile.json()["user"]["email"], self.user.email)
        replay = post_json(
            Client(), "/api/v1/auth/passkeys/login/complete", {"credential": assertion}
        )
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json()["code"], "INVALID_PASSKEY")

    def test_passkey_cannot_login_to_inactive_account(self):
        key = VirtualPasskey()
        self.assertEqual(self.complete(key.register(self.begin())).status_code, 200)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        anonymous = Client()
        begin = anonymous.post("/api/v1/auth/passkeys/login/begin")
        assertion = key.authenticate(begin.json()["request_options"]["publicKey"])
        response = post_json(
            anonymous, "/api/v1/auth/passkeys/login/complete", {"credential": assertion}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "INVALID_PASSKEY")
        self.assertNotIn("X-Session-Token", response.headers)

    def test_legacy_passkey_login_provisions_global_identity_without_tenant_access(
        self,
    ):
        key = VirtualPasskey()
        self.assertEqual(self.complete(key.register(self.begin())).status_code, 200)
        binding = AccountIdentity.objects.get(user=self.user)
        identity_id = binding.identity_id
        subject = binding.public_subject
        # Legacy accounts could already have a passkey and opaque subject while
        # never having visited a tenant-aware login route.
        Identity.objects.filter(pk=identity_id).delete()
        binding.refresh_from_db()
        self.assertIsNone(binding.identity_id)
        anonymous = Client()
        begin = anonymous.post("/api/v1/auth/passkeys/login/begin")
        assertion = key.authenticate(begin.json()["request_options"]["publicKey"])
        response = post_json(
            anonymous, "/api/v1/auth/passkeys/login/complete", {"credential": assertion}
        )
        self.assertEqual(response.status_code, 200, response.content)
        binding.refresh_from_db()
        self.assertIsNotNone(binding.identity_id)
        self.assertNotEqual(binding.identity_id, identity_id)
        self.assertEqual(binding.public_subject, subject)
        self.assertFalse(TenantMembership.objects.exists())

    def test_passkey_cannot_login_to_banned_linked_identity(self):
        key = VirtualPasskey()
        self.assertEqual(self.complete(key.register(self.begin())).status_code, 200)
        binding = AccountIdentity.objects.get(user=self.user)
        Identity.objects.filter(pk=binding.identity_id).update(status=UserStatus.BANNED)
        anonymous = Client()
        begin = anonymous.post("/api/v1/auth/passkeys/login/begin")
        assertion = key.authenticate(begin.json()["request_options"]["publicKey"])
        response = post_json(
            anonymous, "/api/v1/auth/passkeys/login/complete", {"credential": assertion}
        )
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("X-Session-Token", response.headers)
        self.assertNotIn("_auth_user_id", anonymous.session)

    def test_registration_rejects_wrong_challenge_and_origin(self):
        for bad_part in ("challenge", "origin"):
            with self.subTest(bad_part=bad_part):
                options = self.begin()
                if bad_part == "challenge":
                    options["challenge"] = "d3JvbmctY2hhbGxlbmdl"
                origin = (
                    "https://wrong.example.com"
                    if bad_part == "origin"
                    else "https://testserver"
                )
                response = self.complete(
                    VirtualPasskey().register(options, origin=origin)
                )
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json()["code"], "INVALID_PASSKEY")
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())

    def test_registration_requires_begin_and_rejects_malformed_credential(self):
        response = self.complete({"rawId": "invalid"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "INVALID_PASSKEY")
        self.assertFalse(Authenticator.objects.filter(user=self.user).exists())
