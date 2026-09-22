from __future__ import annotations

import re
from datetime import timedelta
from smtplib import SMTPException
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from allauth.account.forms import default_token_generator
from allauth.account.models import EmailAddress, EmailConfirmationHMAC
from allauth.mfa.models import Authenticator
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from accounts.tests.test_api import post_json
from core.models import UserSessionMeta, UserSessionToken
from idp.models import (
    OidcClient,
    OidcToken,
    OidcAuthorizationCode,
    OidcAuthorizationRequest,
)

User = get_user_model()


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ID_FRONTEND_BASE_URL="https://id.example.com",
    DEFAULT_FROM_EMAIL="UpdSpace ID <account@updspace.com>",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    ACCOUNT_EMAIL_VERIFICATION="mandatory",
)
class RecoveryTests(TestCase):
    def setUp(self):
        cache.clear()
        self.password = "Previous-Strong-Password-123!"
        self.new_password = "Different-Strong-Password-456!"
        self.user = User.objects.create_user(
            username="recover", email="recover@example.com", password=self.password
        )
        self.address = EmailAddress.objects.create(
            user=self.user, email=self.user.email, verified=True, primary=True
        )

    def post(self, path, payload, client=None):
        with self.captureOnCommitCallbacks(execute=True):
            return post_json(client or self.client, f"/api/v1/auth/{path}", payload)

    def request_email(self, *, email=None, verification=False, client=None):
        client = client or self.client
        purpose = "email_verification" if verification else "password_reset"
        form_token = client.get("/api/v1/auth/form_token", {"purpose": purpose}).json()[
            "form_token"
        ]
        return self.post(
            "email/verification/request" if verification else "password/reset/request",
            {"email": email or self.user.email, "form_token": form_token},
            client,
        )

    def key_from_mail(self, index=-1):
        link = re.search(
            r"https://id\.example\.com/(?:reset-password|verify-email)#[^\s]+",
            mail.outbox[index].body,
        )
        self.assertIsNotNone(link)
        return parse_qs(urlsplit(link.group()).fragment)["key"][0]

    def login(self, client=None, password=None):
        client = client or self.client
        form_token = client.get("/api/v1/auth/form_token", {"purpose": "login"}).json()[
            "form_token"
        ]
        return self.post(
            "login",
            {
                "email": self.user.email,
                "password": password or self.password,
                "form_token": form_token,
            },
            client,
        )

    def test_reset_email_uses_configured_origin_and_sender_and_no_secrets(self):
        response = self.request_email(email="  RECOVER@example.com  ")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["recover@example.com"])
        self.assertEqual(msg.from_email, "UpdSpace ID <account@updspace.com>")
        self.assertIn("Восстановление пароля", msg.subject)
        self.assertTrue(msg.alternatives)
        self.assertNotIn(self.password, msg.body)
        self.assertNotIn(self.key_from_mail(), response.content.decode())
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_unknown_inactive_and_known_emails_have_same_public_response(self):
        known = self.request_email().json()
        mail.outbox.clear()
        unknown = self.request_email(email="unknown@example.com")
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        inactive = self.request_email()
        self.assertEqual(known, unknown.json())
        self.assertEqual(known, inactive.json())
        self.assertEqual(len(mail.outbox), 0)

    def test_form_token_is_required_purpose_bound_and_single_use(self):
        token = self.client.get("/api/v1/auth/form_token", {"purpose": "login"}).json()[
            "form_token"
        ]
        invalid = self.post(
            "password/reset/request", {"email": self.user.email, "form_token": token}
        )
        self.assertEqual(invalid.status_code, 400)
        token = self.client.get(
            "/api/v1/auth/form_token", {"purpose": "password_reset"}
        ).json()["form_token"]
        payload = {"email": self.user.email, "form_token": token}
        self.assertEqual(self.post("password/reset/request", payload).status_code, 200)
        self.assertEqual(self.post("password/reset/request", payload).status_code, 400)
        self.assertEqual(len(mail.outbox), 1)

    def test_requests_are_rate_limited_for_unknown_addresses_too(self):
        for _ in range(5):
            self.assertEqual(
                self.request_email(email="unknown@example.com").status_code, 200
            )
        self.assertEqual(
            self.request_email(email="unknown@example.com").status_code, 429
        )

    def test_password_validation_does_not_consume_key_and_reset_is_single_use(self):
        self.request_email()
        key = self.key_from_mail()
        invalid = self.post("password/reset/confirm", {"key": key, "password": "short"})
        self.assertEqual(invalid.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))
        self.assertEqual(len(mail.outbox), 1)
        response = self.post(
            "password/reset/confirm", {"key": key, "password": self.new_password}
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-Session-Token", response.headers)
        self.assertNotIn("access_token", response.json())
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertIn("Пароль восстановлен", mail.outbox[-1].subject)
        self.assertEqual(
            self.post(
                "password/reset/confirm", {"key": key, "password": self.password}
            ).status_code,
            400,
        )
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(self.login(password=self.new_password).status_code, 200)

    def test_invalid_expired_and_disabled_account_keys_are_rejected(self):
        self.request_email()
        key = self.key_from_mail()
        for value in ["broken", "!-bad", "zzzz-bad"]:
            self.assertEqual(
                self.post(
                    "password/reset/confirm",
                    {"key": value, "password": self.new_password},
                ).status_code,
                400,
            )
        with patch.object(
            default_token_generator,
            "_now",
            return_value=default_token_generator._now() + timedelta(hours=2),
        ):
            self.assertEqual(
                self.post(
                    "password/reset/confirm",
                    {"key": key, "password": self.new_password},
                ).status_code,
                400,
            )
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assertEqual(
            self.post(
                "password/reset/confirm", {"key": key, "password": self.new_password}
            ).status_code,
            400,
        )

    def test_reset_revokes_sessions_refresh_tokens_and_oidc_artifacts(self):
        login1 = self.login().json()
        login2 = self.login(client=Client()).json()
        oidc_client = OidcClient.objects.create(name="App")
        expires = timezone.now() + timedelta(hours=1)
        token = OidcToken.objects.create(
            user=self.user,
            client=oidc_client,
            access_jti="jti",
            access_expires_at=expires,
        )
        code = OidcAuthorizationCode.objects.create(
            code="code", user=self.user, client=oidc_client, expires_at=expires
        )
        OidcAuthorizationRequest.objects.create(
            request_id="pending", user=self.user, client=oidc_client, expires_at=expires
        )
        self.request_email()
        key = self.key_from_mail()
        self.assertEqual(
            self.post(
                "password/reset/confirm",
                {"key": key, "password": self.new_password},
                Client(),
            ).status_code,
            200,
        )
        for session in [login1, login2]:
            self.assertEqual(
                Client()
                .get(
                    "/api/v1/auth/me",
                    HTTP_X_SESSION_TOKEN=session["meta"]["session_token"],
                )
                .status_code,
                401,
            )
            self.assertEqual(
                self.post(
                    "refresh", {"refresh": session["refresh_token"]}, Client()
                ).status_code,
                401,
            )
        self.assertFalse(
            UserSessionMeta.objects.filter(
                user=self.user, revoked_at__isnull=True
            ).exists()
        )
        self.assertFalse(
            UserSessionToken.objects.filter(
                user=self.user, revoked_at__isnull=True
            ).exists()
        )
        token.refresh_from_db()
        code.refresh_from_db()
        self.assertIsNotNone(token.revoked_at)
        self.assertIsNotNone(code.used_at)
        self.assertFalse(
            OidcAuthorizationRequest.objects.filter(user=self.user).exists()
        )

    def test_reset_preserves_mfa_and_does_not_log_in(self):
        auth = Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP, data={"secret": "test-secret"}
        )
        self.request_email()
        key = self.key_from_mail()
        self.assertEqual(
            self.post(
                "password/reset/confirm", {"key": key, "password": self.new_password}
            ).status_code,
            200,
        )
        self.assertTrue(Authenticator.objects.filter(pk=auth.pk).exists())
        self.assertEqual(self.client.get("/api/v1/auth/me").json(), {"user": None})
        response = self.login(password=self.new_password)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["code"], "MFA_REQUIRED")

    def test_confirmation_and_resend_work_without_login(self):
        self.address.verified = False
        self.address.save()
        response = self.login()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["code"], "EMAIL_VERIFICATION_REQUIRED")
        self.assertEqual(self.request_email(verification=True).status_code, 200)
        key = self.key_from_mail()
        self.assertFalse(EmailAddress.objects.get(pk=self.address.pk).verified)
        response = self.post("email/verification/confirm", {"key": key}, Client())
        self.assertEqual(response.status_code, 200)
        self.address.refresh_from_db()
        self.assertTrue(self.address.verified)
        self.assertIn("Email подтверждён", mail.outbox[-1].subject)
        self.assertEqual(
            self.post("email/verification/confirm", {"key": key}).status_code, 400
        )
        self.assertEqual(self.login().status_code, 200)

    def test_signup_email_points_to_working_confirmation_page(self):
        token = self.client.get(
            "/api/v1/auth/form_token", {"purpose": "register"}
        ).json()["form_token"]
        response = self.post(
            "signup",
            {
                "email": "new@example.com",
                "password": self.password,
                "consent_data_processing": True,
                "form_token": token,
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["verification_required"])
        key = self.key_from_mail()
        self.assertEqual(
            self.post("email/verification/confirm", {"key": key}, Client()).status_code,
            200,
        )
        self.assertTrue(EmailAddress.objects.get(email="new@example.com").verified)

    def test_pending_secondary_email_cannot_be_used_for_password_reset(self):
        EmailAddress.objects.create(
            user=self.user, email="pending@example.com", verified=False, primary=False
        )
        response = self.request_email(email="pending@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_verification_rejects_expired_keys_and_inactive_accounts(self):
        self.address.verified = False
        self.address.save()
        with patch("django.core.signing.time.time", return_value=0):
            expired = EmailConfirmationHMAC(self.address).key
        self.assertEqual(
            self.post("email/verification/confirm", {"key": expired}).status_code, 400
        )
        key = EmailConfirmationHMAC(self.address).key
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assertEqual(
            self.post("email/verification/confirm", {"key": key}).status_code, 400
        )
        self.address.refresh_from_db()
        self.assertFalse(self.address.verified)
        self.assertEqual(len(mail.outbox), 0)

    def test_verified_unknown_and_invalid_addresses_cannot_trigger_confirmation_mail(
        self,
    ):
        self.assertEqual(self.request_email(verification=True).status_code, 200)
        self.assertEqual(
            self.request_email(
                email="unknown@example.com", verification=True
            ).status_code,
            200,
        )
        self.assertEqual(
            self.request_email(email="bad-email", verification=True).status_code, 400
        )
        self.assertEqual(len(mail.outbox), 0)

    def test_untracked_legacy_email_can_be_confirmed_without_login(self):
        self.address.delete()
        self.assertEqual(self.request_email(verification=True).status_code, 200)
        key = self.key_from_mail()
        self.assertEqual(
            self.post("email/verification/confirm", {"key": key}).status_code, 200
        )
        self.assertTrue(EmailAddress.objects.get(user=self.user).verified)

    def test_password_reset_rolls_back_if_session_revocation_fails(self):
        self.request_email()
        key = self.key_from_mail()
        with patch(
            "accounts.services.recovery.SessionService.revoke_all",
            side_effect=RuntimeError("revocation failed"),
        ):
            with self.assertRaises(RuntimeError):
                self.post(
                    "password/reset/confirm",
                    {"key": key, "password": self.new_password},
                )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            self.post(
                "password/reset/confirm", {"key": key, "password": self.new_password}
            ).status_code,
            200,
        )

    def test_password_change_sends_notification_and_invalidates_reset_link(self):
        token = self.login().json()["meta"]["session_token"]
        self.request_email()
        key = self.key_from_mail()
        with self.captureOnCommitCallbacks(execute=True):
            response = post_json(
                self.client,
                "/api/v1/auth/change_password",
                {"current_password": self.password, "new_password": self.new_password},
                token=token,
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Пароль изменён", mail.outbox[-1].subject)
        self.assertEqual(
            self.post(
                "password/reset/confirm",
                {"key": key, "password": self.password},
                Client(),
            ).status_code,
            400,
        )

    def test_delivery_errors_are_logged_without_disclosing_account_or_secrets(self):
        with patch(
            "django.core.mail.message.EmailMessage.send",
            side_effect=SMTPException("secret transport details"),
        ):
            with self.assertLogs("accounts.services.recovery", level="ERROR") as logs:
                known = self.request_email()
            unknown = self.request_email(email="unknown@example.com")
            self.assertEqual(known.json(), unknown.json())
            self.assertNotIn("secret transport details", " ".join(logs.output))
        self.request_email()
        key = self.key_from_mail()
        with patch(
            "django.core.mail.message.EmailMessage.send",
            side_effect=SMTPException("secret"),
        ):
            with self.assertLogs("accounts.adapter", level="ERROR"):
                response = self.post(
                    "password/reset/confirm",
                    {"key": key, "password": self.new_password},
                )
            self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
