from __future__ import annotations

import json
import shutil
import tempfile
import time
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

from allauth.account.models import EmailAddress
from allauth.mfa import app_settings as mfa_app_settings
from allauth.mfa.totp.internal import auth as totp_auth
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from ninja.errors import HttpError
from PIL import Image
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

from core.models import UserSessionMeta, UserSessionToken

User = get_user_model()


def post_json(client: Client, path: str, payload: dict, *, token: str | None = None):
    headers = {"content_type": "application/json"}
    if token:
        headers["HTTP_X_SESSION_TOKEN"] = token
    return client.post(path, data=json.dumps(payload), **headers)


def patch_json(client: Client, path: str, payload: dict, *, token: str | None = None):
    headers = {"content_type": "application/json"}
    if token:
        headers["HTTP_X_SESSION_TOKEN"] = token
    return client.patch(path, data=json.dumps(payload), **headers)


class AccountsApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.password = "StrongPass123!"
        self.user = self._create_user()
        cache.clear()
        self.media_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
        override = override_settings(
            MEDIA_ROOT=self.media_root,
            MEDIA_URL="/media/",
            GRAVATAR_AUTOLOAD_ENABLED=False,
        )
        override.enable()
        self.addCleanup(override.disable)

    def _create_user(
        self,
        username: str = "ivan",
        email: str = "ivan@example.com",
        password: str | None = None,
    ) -> User:
        return User.objects.create_user(
            username=username, email=email, password=password or self.password
        )

    def _ensure_email_verified(self):
        EmailAddress.objects.update_or_create(
            user=self.user,
            email=self.user.email,
            defaults={"verified": True, "primary": True},
        )

    def login_and_get_token(
        self,
        client: Client | None = None,
        email: str | None = None,
        password: str | None = None,
    ) -> str:
        client = client or self.client
        form_token = self._form_token(client, "login")
        resp = post_json(
            client,
            "/api/v1/auth/login",
            {
                "email": email or self.user.email,
                "password": password or self.password,
                "form_token": form_token,
            },
        )
        self.assertEqual(resp.status_code, 200)
        token = resp.headers.get("X-Session-Token")
        self.assertTrue(token)
        return str(token)

    def _form_token(self, client: Client, purpose: str) -> str:
        resp = client.get(f"/api/v1/auth/form_token?purpose={purpose}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        return data["form_token"]

    def _image_file(self, name: str = "avatar.png", size=(512, 640)):
        img = Image.new("RGB", size, color=(12, 34, 56))
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return SimpleUploadedFile(name, buf.getvalue(), content_type="image/png")

    def test_headless_login_and_profile_requires_auth(self):
        resp = self.client.get("/api/v1/auth/me")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"user": None})

        token = self.login_and_get_token()
        resp_ok = self.client.get("/api/v1/auth/me", HTTP_X_SESSION_TOKEN=token)
        self.assertEqual(resp_ok.status_code, 200)
        data = resp_ok.json()
        user = data["user"]
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], self.user.username)
        self.assertEqual(user["email"], self.user.email)
        self.assertFalse(user["has_2fa"])
        self.assertEqual(user["oauth_providers"], [])
        self.assertFalse(user["is_staff"])
        self.assertFalse(user["is_superuser"])
        self.assertIsNone(user["avatar_url"])
        self.assertEqual(user["avatar_source"], "none")
        self.assertTrue(user["avatar_gravatar_enabled"])

    def test_headless_login_rejects_invalid_credentials(self):
        form_token = self._form_token(self.client, "login")
        resp = post_json(
            self.client,
            "/api/v1/auth/login",
            {
                "email": self.user.email,
                "password": "wrong",
                "form_token": form_token,
            },
        )
        self.assertEqual(resp.status_code, 401)
        body = resp.json()
        self.assertEqual(body.get("code"), "INVALID_CREDENTIALS")

    def test_headless_login_requires_form_token(self):
        resp = post_json(
            self.client,
            "/api/v1/auth/login",
            {"email": self.user.email, "password": self.password},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data.get("code"), "INVALID_FORM_TOKEN")

    def test_headless_login_rate_limited(self):
        retry_code = None
        for i in range(6):
            form_token = self._form_token(self.client, "login")
            resp = post_json(
                self.client,
                "/api/v1/auth/login",
                {
                    "email": self.user.email,
                    "password": "wrong",
                    "form_token": form_token,
                },
            )
            if i < 5:
                self.assertEqual(resp.status_code, 401)
            else:
                self.assertEqual(resp.status_code, 429)
                data = resp.json()
                retry_code = data.get("code")
                self.assertEqual(retry_code, "LOGIN_RATE_LIMITED")
                self.assertIn("Retry-After", resp.headers)
        self.assertEqual(retry_code, "LOGIN_RATE_LIMITED")

    def test_form_token_single_use(self):
        form_token = self._form_token(self.client, "login")
        resp_ok = post_json(
            self.client,
            "/api/v1/auth/login",
            {
                "email": self.user.email,
                "password": self.password,
                "form_token": form_token,
            },
        )
        self.assertEqual(resp_ok.status_code, 200)
        # Reuse same token should fail
        resp_reuse = post_json(
            self.client,
            "/api/v1/auth/login",
            {
                "email": self.user.email,
                "password": self.password,
                "form_token": form_token,
            },
        )
        self.assertEqual(resp_reuse.status_code, 400)
        self.assertEqual(resp_reuse.json().get("code"), "INVALID_FORM_TOKEN")

    def test_issue_jwt_and_refresh(self):
        token = self.login_and_get_token()
        resp_pair = self.client.post(
            "/api/v1/auth/jwt/from_session", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_pair.status_code, 200)
        payload = resp_pair.json()
        self.assertIn("access", payload)
        self.assertIn("refresh", payload)
        self.assertTrue(
            UserSessionMeta.objects.filter(
                user=self.user, session_key=self.client.session.session_key
            ).exists()
        )
        self.assertTrue(UserSessionToken.objects.filter(user=self.user).exists())

        resp_refresh = post_json(
            self.client,
            "/api/v1/auth/refresh",
            {"refresh": payload["refresh"]},
        )
        self.assertEqual(resp_refresh.status_code, 200)
        refreshed = resp_refresh.json()
        self.assertIn("access", refreshed)
        self.assertIn("refresh", refreshed)

        # Second refresh should use rotated token, original one is blacklisted
        outstanding = OutstandingToken.objects.filter(
            token=payload["refresh"], user=self.user
        ).first()
        resp_refresh_again = post_json(
            self.client,
            "/api/v1/auth/refresh",
            {"refresh": payload["refresh"]},
        )
        self.assertEqual(resp_refresh_again.status_code, 401)
        self.assertTrue(outstanding)
        self.assertTrue(BlacklistedToken.objects.filter(token=outstanding).exists())

        resp_bad = post_json(
            self.client, "/api/v1/auth/refresh", {"refresh": "not-a-token"}
        )
        self.assertEqual(resp_bad.status_code, 401)

        stray = RefreshToken.for_user(self.user)
        self.user.delete()
        resp_missing_user = post_json(
            self.client,
            "/api/v1/auth/refresh",
            {"refresh": str(stray)},
        )
        self.assertEqual(resp_missing_user.status_code, 401)

    def test_refresh_rotation_tracks_session_and_blacklists_old(self):
        token = self.login_and_get_token()
        resp_pair = self.client.post(
            "/api/v1/auth/jwt/from_session", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_pair.status_code, 200)
        payload = resp_pair.json()

        refresh_token = payload["refresh"]
        old_outstanding = OutstandingToken.objects.filter(
            token=refresh_token, user=self.user
        ).first()
        self.assertIsNotNone(old_outstanding)
        old_jti = str(old_outstanding.jti)
        session_key = self.client.session.session_key

        resp_refresh = post_json(
            self.client,
            "/api/v1/auth/refresh",
            {"refresh": refresh_token},
        )
        self.assertEqual(resp_refresh.status_code, 200)
        refreshed = resp_refresh.json()

        new_outstanding = OutstandingToken.objects.filter(
            token=refreshed["refresh"], user=self.user
        ).first()
        self.assertIsNotNone(new_outstanding)
        new_jti = str(new_outstanding.jti)

        old_map = UserSessionToken.objects.get(refresh_jti=old_jti)
        new_map = UserSessionToken.objects.get(refresh_jti=new_jti)
        self.assertEqual(new_map.session_key, session_key)
        self.assertIsNone(new_map.revoked_at)
        self.assertIsNotNone(old_map.revoked_at)

        outstanding_old = OutstandingToken.objects.filter(
            user=self.user, jti=old_jti
        ).first()
        self.assertTrue(outstanding_old)
        self.assertTrue(BlacklistedToken.objects.filter(token=outstanding_old).exists())

    def test_refresh_rejected_after_session_revocation(self):
        token = self.login_and_get_token()
        resp_pair = self.client.post(
            "/api/v1/auth/jwt/from_session", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_pair.status_code, 200)
        refresh_token = resp_pair.json()["refresh"]

        session_key = self.client.session.session_key
        UserSessionMeta.objects.update_or_create(
            user=self.user,
            session_key=session_key,
            defaults={
                "session_token": token,
                "revoked_at": timezone.now(),
                "revoked_reason": "manual",
            },
        )

        resp_refresh = post_json(
            self.client,
            "/api/v1/auth/refresh",
            {"refresh": refresh_token},
        )
        self.assertEqual(resp_refresh.status_code, 401)

    def test_change_password_validations_and_success(self):
        token = self.login_and_get_token()

        wrong_cur = post_json(
            self.client,
            "/api/v1/auth/change_password",
            {"current_password": "nope", "new_password": "NewPass123!"},
            token=token,
        )
        self.assertEqual(wrong_cur.status_code, 400)

        empty_new = post_json(
            self.client,
            "/api/v1/auth/change_password",
            {"current_password": self.password, "new_password": ""},
            token=token,
        )
        self.assertEqual(empty_new.status_code, 400)

        same_new = post_json(
            self.client,
            "/api/v1/auth/change_password",
            {"current_password": self.password, "new_password": self.password},
            token=token,
        )
        self.assertEqual(same_new.status_code, 400)

        short_new = post_json(
            self.client,
            "/api/v1/auth/change_password",
            {"current_password": self.password, "new_password": "short"},
            token=token,
        )
        self.assertEqual(short_new.status_code, 400)

        ok = post_json(
            self.client,
            "/api/v1/auth/change_password",
            {
                "current_password": self.password,
                "new_password": "BetterPass123!",
            },
            token=token,
        )
        self.assertEqual(ok.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("BetterPass123!"))

    def test_profile_update_avatar_upload_and_delete(self):
        token = self.login_and_get_token()

        resp_update = patch_json(
            self.client,
            "/api/v1/auth/profile",
            {"first_name": "  Alice ", "last_name": "  Smith  "},
            token=token,
        )
        self.assertEqual(resp_update.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Alice")
        self.assertEqual(self.user.last_name, "Smith")

        resp_avatar = self.client.post(
            "/api/v1/auth/avatar",
            data={"avatar": self._image_file()},
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_avatar.status_code, 200)
        data = resp_avatar.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["avatar_source"], "upload")
        self.user.refresh_from_db()
        profile = self.user.profile
        profile.refresh_from_db()
        self.assertTrue(profile.avatar)
        self.assertEqual(profile.avatar_source, "upload")
        self.assertFalse(profile.gravatar_enabled)

        resp_delete = self.client.delete(
            "/api/v1/auth/avatar",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_delete.status_code, 200)
        deleted = resp_delete.json()
        self.assertTrue(deleted["ok"])
        self.assertIsNone(deleted["avatar_url"])
        self.assertEqual(deleted["avatar_source"], "none")
        self.assertFalse(deleted["avatar_gravatar_enabled"])
        profile.refresh_from_db()
        self.assertFalse(profile.avatar)
        self.assertEqual(profile.avatar_source, "none")

    def test_email_status_and_resend(self):
        token = self.login_and_get_token()
        mail.outbox.clear()
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=True
        )
        resp_status = self.client.get("/api/v1/auth/email", HTTP_X_SESSION_TOKEN=token)
        self.assertEqual(resp_status.status_code, 200)
        payload = resp_status.json()
        self.assertEqual(payload["email"], self.user.email)
        self.assertTrue(payload["verified"])

        resp_resend = self.client.post(
            "/api/v1/auth/email/resend", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_resend.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(ACCOUNT_UNIQUE_EMAIL=True)
    def test_change_email_rejects_invalid_and_duplicates(self):
        token = self.login_and_get_token()
        other = self._create_user(username="other", email="other@example.com")
        EmailAddress.objects.create(
            user=other, email="dup@example.com", primary=True, verified=True
        )

        invalid = post_json(
            self.client,
            "/api/v1/auth/email/change",
            {"new_email": "bad-email"},
            token=token,
        )
        self.assertEqual(invalid.status_code, 400)

        same = post_json(
            self.client,
            "/api/v1/auth/email/change",
            {"new_email": self.user.email},
            token=token,
        )
        self.assertEqual(same.status_code, 200)

        dup = post_json(
            self.client,
            "/api/v1/auth/email/change",
            {"new_email": "dup@example.com"},
            token=token,
        )
        self.assertEqual(dup.status_code, 400)

    def test_sessions_listing_and_revocation(self):
        token = self.login_and_get_token()
        resp_sessions = self.client.get(
            "/api/v1/auth/sessions", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_sessions.status_code, 200)
        sessions = resp_sessions.json()["sessions"]
        self.assertTrue(any(s["current"] for s in sessions))

        resp_missing = self.client.delete(
            "/api/v1/auth/sessions/unknown",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_missing.status_code, 404)

        # Создаём вторую сессию для массового отключения
        other_client = Client()
        token_other = self.login_and_get_token(
            other_client, self.user.email, self.password
        )
        other_client.get("/api/v1/auth/sessions", HTTP_X_SESSION_TOKEN=token_other)
        second_key = other_client.session.session_key

        bulk = post_json(
            self.client,
            "/api/v1/auth/sessions/bulk",
            {"all_except_current": True},
            token=token,
        )
        self.assertEqual(bulk.status_code, 200)
        body = bulk.json()
        self.assertIn(second_key, body.get("revoked_ids", []))
        self.assertEqual(body.get("current"), self.client.session.session_key)

    def test_revoked_session_is_blocked(self):
        token = self.login_and_get_token()
        session_key = self.client.session.session_key
        UserSessionMeta.objects.update_or_create(
            user=self.user,
            session_key=session_key,
            defaults={
                "session_token": token,
                "revoked_at": timezone.now(),
                "revoked_reason": "manual",
            },
        )
        resp = self.client.get("/api/v1/auth/sessions", HTTP_X_SESSION_TOKEN=token)
        self.assertEqual(resp.status_code, 401)

    def test_logout_and_session_cleanup(self):
        token = self.login_and_get_token()
        resp_logout = self.client.post(
            "/api/v1/auth/logout", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_logout.status_code, 200)
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    def test_oauth_link_requires_auth(self):
        # No session token -> should be rejected before provider logic
        resp = self.client.get("/api/v1/auth/oauth/link/dummy")
        self.assertEqual(resp.status_code, 401)

    def test_oauth_provider_helpers(self):
        token = self.login_and_get_token()

        with (
            patch(
                "accounts.services.oauth.OAuthService.configured_provider_ids",
                return_value={"dummy"},
            ),
            patch(
                "accounts.services.oauth.registry.as_choices",
                return_value=[("dummy", "Dummy")],
            ),
        ):
            resp_list = self.client.get(
                "/api/v1/auth/oauth/providers", HTTP_X_SESSION_TOKEN=token
            )
            self.assertEqual(resp_list.status_code, 200)
            providers = resp_list.json()["providers"]
            self.assertEqual(providers, [{"id": "dummy", "name": "Dummy"}])

        resp_unknown = self.client.get(
            "/api/v1/auth/oauth/link/missing", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_unknown.status_code, 404)

        with (
            patch(
                "accounts.services.oauth.OAuthService.configured_provider_ids",
                return_value={"dummy"},
            ),
            patch(
                "accounts.services.oauth.registry.as_choices",
                return_value=[("dummy", "Dummy")],
            ),
            patch("accounts.services.oauth.reverse", return_value="/dummy/login/"),
        ):
            resp_link = self.client.get(
                "/api/v1/auth/oauth/link/dummy", HTTP_X_SESSION_TOKEN=token
            )
        self.assertEqual(resp_link.status_code, 200)
        link = resp_link.json()
        self.assertIn("process=connect", link["authorize_url"])
        self.assertEqual(link["method"], "POST")

    def test_mfa_totp_requires_email_verified(self):
        token = self.login_and_get_token()
        resp_begin = self.client.post(
            "/api/v1/auth/mfa/totp/begin",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_begin.status_code, 400)
        payload = resp_begin.json()
        self.assertEqual(payload.get("code"), "EMAIL_VERIFICATION_REQUIRED")

    def test_mfa_totp_full_flow(self):
        token = self.login_and_get_token()
        self._ensure_email_verified()

        resp_status = self.client.get(
            "/api/v1/auth/mfa/status", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_status.status_code, 200)
        self.assertFalse(resp_status.json()["has_totp"])

        resp_begin = self.client.post(
            "/api/v1/auth/mfa/totp/begin",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_begin.status_code, 200)
        begin_payload = resp_begin.json()
        secret = begin_payload["secret"]
        counter = int(time.time()) // mfa_app_settings.TOTP_PERIOD
        code = totp_auth.format_hotp_value(totp_auth.hotp_value(secret, counter))

        resp_confirm = post_json(
            self.client,
            "/api/v1/auth/mfa/totp/confirm",
            {"code": code},
            token=token,
        )
        self.assertEqual(resp_confirm.status_code, 200)
        confirm_payload = resp_confirm.json()
        self.assertTrue(confirm_payload["ok"])
        self.assertTrue(confirm_payload["recovery_codes"])

        resp_status_after = self.client.get(
            "/api/v1/auth/mfa/status", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_status_after.status_code, 200)
        data_after = resp_status_after.json()
        self.assertTrue(data_after["has_totp"])
        self.assertGreaterEqual(data_after["recovery_codes_left"], 0)

        resp_disable = self.client.post(
            "/api/v1/auth/mfa/totp/disable",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_disable.status_code, 200)
        resp_status_final = self.client.get(
            "/api/v1/auth/mfa/status", HTTP_X_SESSION_TOKEN=token
        )
        self.assertEqual(resp_status_final.status_code, 200)
        self.assertFalse(resp_status_final.json()["has_totp"])

    def test_mfa_totp_invalid_code_returns_400(self):
        token = self.login_and_get_token()
        self._ensure_email_verified()
        resp_begin = self.client.post(
            "/api/v1/auth/mfa/totp/begin",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_begin.status_code, 200)

        resp_confirm = post_json(
            self.client,
            "/api/v1/auth/mfa/totp/confirm",
            {"code": "000000"},
            token=token,
        )
        self.assertEqual(resp_confirm.status_code, 400)
        data = resp_confirm.json()
        self.assertIn("code", data)

    def test_mfa_totp_confirm_without_begin(self):
        token = self.login_and_get_token()

        resp_confirm = post_json(
            self.client,
            "/api/v1/auth/mfa/totp/confirm",
            {"code": "000000"},
            token=token,
        )
        self.assertEqual(resp_confirm.status_code, 400)
        payload = resp_confirm.json()
        self.assertEqual(payload.get("code"), "TOTP_SETUP_REQUIRED")

    def test_regenerate_recovery_codes(self):
        token = self.login_and_get_token()
        self._ensure_email_verified()

        resp_begin = self.client.post(
            "/api/v1/auth/mfa/totp/begin",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_begin.status_code, 200)
        secret = resp_begin.json()["secret"]
        counter = int(time.time()) // mfa_app_settings.TOTP_PERIOD
        code = totp_auth.format_hotp_value(totp_auth.hotp_value(secret, counter))
        resp_confirm = post_json(
            self.client,
            "/api/v1/auth/mfa/totp/confirm",
            {"code": code},
            token=token,
        )
        self.assertEqual(resp_confirm.status_code, 200)

        resp_regen = self.client.post(
            "/api/v1/auth/mfa/recovery/regenerate",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_regen.status_code, 200)
        codes = resp_regen.json()["recovery_codes"]
        self.assertTrue(isinstance(codes, list) and len(codes) > 0)

    def test_regenerate_recovery_codes_requires_mfa(self):
        token = self.login_and_get_token()

        resp_regen = self.client.post(
            "/api/v1/auth/mfa/recovery/regenerate",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=token,
        )
        self.assertEqual(resp_regen.status_code, 400)
        self.assertEqual(resp_regen.json().get("code"), "MFA_REQUIRED")

    def test_passkeys_begin_respects_session_auth(self):
        token = self.login_and_get_token()

        resp_list = self.client.get("/api/v1/auth/passkeys", HTTP_X_SESSION_TOKEN=token)
        self.assertEqual(resp_list.status_code, 200)
        self.assertEqual(resp_list.json()["authenticators"], [])

        resp_begin = post_json(
            self.client,
            "/api/v1/auth/passkeys/begin",
            {"passwordless": True},
            token=token,
        )
        self.assertEqual(resp_begin.status_code, 200)
        body = resp_begin.json()
        self.assertIn("creation_options", body)
        self.assertIn("publicKey", body["creation_options"])

    def test_passkeys_complete_returns_recovery_codes(self):
        token = self.login_and_get_token()
        now = timezone.now()

        class DummyRc:
            class Type:
                RECOVERY_CODES = "rc"

            type = "rc"

        dummy_auth = SimpleNamespace(
            id="a1",
            data={"name": "MyPasskey"},
            created_at=now,
            last_used_at=None,
        )

        with (
            patch(
                "accounts.services.passkeys.PasskeyService.complete_registration",
                return_value=(dummy_auth, DummyRc()),
            ) as complete_mock,
            patch("allauth.mfa.recovery_codes.internal.auth.RecoveryCodes") as rc_mock,
        ):
            rc_mock.return_value.get_unused_codes.return_value = [
                "111111",
                "222222",
            ]
            resp = post_json(
                self.client,
                "/api/v1/auth/passkeys/complete",
                {"name": "MyPasskey", "credential": {"rawId": "abc"}},
                token=token,
            )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["authenticator"]["name"], "MyPasskey")
        self.assertEqual(payload["recovery_codes"], ["111111", "222222"])
        complete_mock.assert_called_once()
        rc_mock.return_value.get_unused_codes.assert_called_once()

    def test_passkeys_delete_requires_reauth(self):
        token = self.login_and_get_token()
        with patch(
            "accounts.services.passkeys.PasskeyService.delete",
            side_effect=HttpError(401, "reauth_required"),
        ):
            resp = post_json(
                self.client,
                "/api/v1/auth/passkeys/delete",
                {"ids": ["a1", "a2"]},
                token=token,
            )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("reauth_required", resp.json().get("detail", ""))

    def test_headless_passkey_login_complete_issues_session_token(self):
        user = self._create_user(username="passkey", email="pk@example.com")
        with (
            patch(
                "accounts.api.router_headless.PasskeyService.complete_login",
                return_value=(user, None),
            ),
            patch(
                "accounts.api.router_headless.HeadlessService.issue_session_token",
                return_value="headless-token",
            ),
            patch(
                "accounts.api.router_headless.AuthService.issue_pair_for_session",
                return_value=SimpleNamespace(
                    access="access-token", refresh="refresh-token"
                ),
            ),
            patch(
                "accounts.api.router_headless.AuthService.profile",
                return_value={"email": "pk@example.com"},
            ),
        ):
            resp = post_json(
                self.client,
                "/api/v1/auth/passkeys/login/complete",
                {"credential": {"rawId": "cred"}},
            )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Session-Token"), "headless-token")
        body = resp.json()
        self.assertEqual(body["meta"]["session_token"], "headless-token")
        self.assertEqual(body["access_token"], "access-token")
        self.assertEqual(body["refresh_token"], "refresh-token")
        self.assertEqual(body["user"]["email"], "pk@example.com")
