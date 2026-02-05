from __future__ import annotations

import datetime
import os
import shutil
import tempfile
from io import BytesIO
from unittest.mock import patch

from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from ninja.errors import HttpError
from PIL import Image

from accounts.models import UserProfile
from accounts.services import user_has_telegram_link
from accounts.services.auth import AuthService
from accounts.services.emailing import EmailService
from accounts.services.profile import ProfileService
from accounts.services.sessions import SessionService
from core.models import UserSessionMeta, UserSessionToken

User = get_user_model()


class UserHasTelegramLinkTests(TestCase):
    def test_returns_false_for_missing_or_anonymous(self):
        self.assertFalse(user_has_telegram_link(None))
        self.assertFalse(user_has_telegram_link(AnonymousUser()))

    def test_returns_true_when_social_account_present(self):
        user = User.objects.create_user(username="tg", email="tg@example.com")
        SocialAccount.objects.create(user=user, provider="telegram", uid="123")

        self.assertTrue(user_has_telegram_link(user))

    def test_returns_false_when_lookup_fails(self):
        user = User.objects.create_user(username="broken", email="broken@example.com")
        with patch(
            "accounts.services.SocialAccount.objects.filter",
            side_effect=RuntimeError("db down"),
        ):
            self.assertFalse(user_has_telegram_link(user))


class EmailServiceTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="ivan", email="ivan@example.com", password="123Strong!"
        )
        EmailAddress.objects.create(
            user=self.user, email=self.user.email, primary=True, verified=False
        )

    def test_status_uses_primary_and_verification_flag(self):
        primary = EmailAddress.objects.filter(user=self.user, primary=True).first()
        primary.verified = True
        primary.save(update_fields=["verified"])

        status = EmailService.status(self.user)

        self.assertEqual(status["email"], self.user.email)
        self.assertTrue(status["verified"])

    def test_request_change_rejects_invalid_email(self):
        request = self.factory.post("/fake")
        with self.assertRaises(HttpError):
            EmailService.request_change(request, self.user, new_email="not-an-email")

    def test_request_change_skips_when_email_matches(self):
        request = self.factory.post("/fake")
        with patch.object(EmailAddress, "send_confirmation") as send_mock:
            EmailService.request_change(
                request, self.user, new_email="Ivan@Example.com"
            )
        self.assertFalse(send_mock.called)
        self.assertEqual(
            EmailAddress.objects.filter(user=self.user, email=self.user.email).count(),
            1,
        )

    @override_settings(ACCOUNT_UNIQUE_EMAIL=True)
    def test_request_change_rejects_verified_duplicate(self):
        request = self.factory.post("/fake")
        other = User.objects.create_user(
            username="other", email="other@example.com", password="123Strong!"
        )
        EmailAddress.objects.create(
            user=other, email="dup@example.com", primary=True, verified=True
        )

        with self.assertRaises(HttpError):
            EmailService.request_change(request, self.user, new_email="dup@example.com")

    def test_request_change_creates_address_and_sends_confirmation(self):
        request = self.factory.post("/fake")
        with patch.object(EmailAddress, "send_confirmation") as send_mock:
            EmailService.request_change(request, self.user, new_email="new@example.com")

        addr = EmailAddress.objects.filter(
            user=self.user, email="new@example.com"
        ).first()
        self.assertIsNotNone(addr)
        self.assertTrue(send_mock.called)

    def test_resend_confirmation_returns_none_when_no_pending(self):
        request = self.factory.post("/fake")
        EmailAddress.objects.filter(user=self.user).update(verified=True)
        with patch.object(EmailAddress, "send_confirmation") as send_mock:
            EmailService.resend_confirmation(request, self.user)
        self.assertFalse(send_mock.called)

    def test_resend_confirmation_prefers_unverified_primary(self):
        request = self.factory.post("/fake")
        primary = EmailAddress.objects.filter(user=self.user, primary=True).first()
        primary.verified = False
        primary.save(update_fields=["verified"])

        with patch.object(
            EmailAddress, "send_confirmation", autospec=True
        ) as send_mock:
            EmailService.resend_confirmation(request, self.user)
        send_mock.assert_called_once()
        called_addr, called_request = send_mock.call_args[0][0:2]
        self.assertEqual(called_addr.pk, primary.pk)
        self.assertIs(called_request, request)

    def test_resend_confirmation_falls_back_to_recent_unverified(self):
        request = self.factory.post("/fake")
        EmailAddress.objects.filter(user=self.user).update(verified=True)
        EmailAddress.objects.create(
            user=self.user, email="alt1@example.com", verified=False
        )
        second = EmailAddress.objects.create(
            user=self.user, email="alt2@example.com", verified=False
        )

        with patch.object(
            EmailAddress, "send_confirmation", autospec=True
        ) as send_mock:
            EmailService.resend_confirmation(request, self.user)

        send_mock.assert_called_once()
        # Самый новый id должен быть выбран.
        called_addr, called_request = send_mock.call_args[0][0:2]
        self.assertEqual(called_addr.pk, second.pk)
        self.assertIs(called_request, request)


class ProfileServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="user", email="user@example.com", password="123Strong!"
        )
        self.media_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
        self._override = override_settings(
            MEDIA_ROOT=self.media_root, MEDIA_URL="/media/"
        )
        self._override.enable()

    def tearDown(self):
        self._override.disable()

    def _image_file(self, name="avatar.png", size=(640, 480)):
        image = Image.new("RGB", size, color=(32, 64, 96))
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)
        return SimpleUploadedFile(name, buffer.getvalue(), content_type="image/png")

    def test_update_name_trims_and_saves(self):
        with patch.object(self.user, "save", wraps=self.user.save) as save_mock:
            ProfileService.update_name(self.user, first="  Alice ", last="  Smith  ")
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Alice")
        self.assertEqual(self.user.last_name, "Smith")
        save_mock.assert_called_once()

    def test_update_name_skips_save_when_no_fields(self):
        with patch.object(self.user, "save", wraps=self.user.save) as save_mock:
            ProfileService.update_name(self.user)
        save_mock.assert_not_called()

    def test_save_avatar_processes_and_disables_gravatar(self):
        avatar_file = self._image_file()
        state = ProfileService.save_avatar(self.user, avatar_file)
        profile = self.user.profile
        self.assertEqual(state.source, UserProfile.AvatarSource.UPLOAD)
        self.assertFalse(state.gravatar_enabled)
        self.assertTrue(profile.avatar.name.endswith(".jpg"))
        with Image.open(profile.avatar.path) as img:
            self.assertEqual(
                img.size,
                (
                    ProfileService.AVATAR_SIZE,
                    ProfileService.AVATAR_SIZE,
                ),
            )

    def test_save_avatar_rejects_large_files(self):
        too_big = SimpleUploadedFile(
            "big.png",
            b"x" * (ProfileService.MAX_FILE_BYTES + 10),
            content_type="image/png",
        )
        with self.assertRaises(HttpError):
            ProfileService.save_avatar(self.user, too_big)

    def test_remove_avatar_disables_gravatar(self):
        ProfileService.save_avatar(self.user, self._image_file())
        state = ProfileService.remove_avatar(self.user)
        profile = self.user.profile
        self.assertFalse(profile.avatar)
        self.assertEqual(state.source, UserProfile.AvatarSource.NONE)
        self.assertFalse(state.gravatar_enabled)

    def test_gravatar_refresh_skips_when_disabled(self):
        profile = ProfileService._ensure_profile(self.user)
        profile.gravatar_enabled = False
        profile.save(update_fields=["gravatar_enabled"])
        with patch.object(ProfileService, "_fetch_gravatar") as fetch_mock:
            changed = ProfileService.maybe_refresh_gravatar(self.user, force=True)
        self.assertFalse(changed)
        fetch_mock.assert_not_called()

    def test_gravatar_refresh_updates_when_available(self):
        # Ensure TTL check passes
        profile = ProfileService._ensure_profile(self.user)
        profile.gravatar_checked_at = timezone.now() - datetime.timedelta(days=8)
        profile.save(update_fields=["gravatar_checked_at"])
        gravatar_bytes = self._image_file("grav.png", size=(300, 500)).read()
        with patch.object(
            ProfileService, "_fetch_gravatar", return_value=gravatar_bytes
        ):
            changed = ProfileService.maybe_refresh_gravatar(self.user, force=True)
        self.assertTrue(changed)
        profile.refresh_from_db()
        self.assertEqual(profile.avatar_source, UserProfile.AvatarSource.GRAVATAR)
        self.assertTrue(profile.gravatar_enabled)
        self.assertTrue(os.path.exists(profile.avatar.path))


class AuthServiceTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="u1", email="u1@example.com", password="123Strong!"
        )

    def _request_with_session(self, *, token: str | None = None, user=None):
        request = self.factory.get("/")
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        if token:
            request.META["HTTP_X_SESSION_TOKEN"] = token
        request.user = user or self.user
        return request

    def test_issue_pair_rejects_anonymous(self):
        request = self._request_with_session(user=AnonymousUser())
        with self.assertRaises(HttpError):
            AuthService.issue_pair_for_session(request, request.user)

    def test_issue_pair_creates_meta_and_tokens(self):
        request = self._request_with_session(token="header-token")
        pair = AuthService.issue_pair_for_session(request, request.user)

        meta = UserSessionMeta.objects.get(user=self.user)
        self.assertEqual(meta.session_key, request.session.session_key)
        self.assertEqual(meta.session_token, "header-token")
        self.assertIn("access", pair.model_dump())
        self.assertIn("refresh", pair.model_dump())
        self.assertTrue(
            UserSessionToken.objects.filter(
                user=self.user, session_key=meta.session_key
            ).exists()
        )

    def test_issue_pair_updates_existing_session_key(self):
        token = "persisted"
        meta = UserSessionMeta.objects.create(
            user=self.user, session_key="old-key", session_token=token
        )
        request = self._request_with_session(token=token)

        AuthService.issue_pair_for_session(request, request.user)

        meta.refresh_from_db()
        self.assertEqual(meta.session_key, request.session.session_key)


class SessionServiceTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="sess", email="sess@example.com", password="123Strong!"
        )

    def _request(self, *, token: str | None = None, with_session: bool = True):
        request = self.factory.get("/")
        if with_session:
            middleware = SessionMiddleware(lambda r: None)
            middleware.process_request(request)
            request.session.save()
        if token:
            request.META["HTTP_X_SESSION_TOKEN"] = token
        request.user = self.user
        return request

    def test_assert_session_allowed_blocks_revoked_token(self):
        request = self._request(token="t1")
        UserSessionMeta.objects.create(
            user=self.user,
            session_key="key1",
            session_token="t1",
            revoked_at=datetime.datetime.now(datetime.timezone.utc),
        )
        with self.assertRaises(HttpError):
            SessionService.assert_session_allowed(request)

    def test_assert_session_allowed_blocks_revoked_session_key(self):
        request = self._request()
        UserSessionMeta.objects.create(
            user=self.user,
            session_key=request.session.session_key,
            revoked_at=datetime.datetime.now(datetime.timezone.utc),
        )
        with self.assertRaises(HttpError):
            SessionService.assert_session_allowed(request)

    def test_assert_session_allowed_passes_for_active_session(self):
        request = self._request()
        UserSessionMeta.objects.create(
            user=self.user,
            session_key=request.session.session_key,
        )
        SessionService.assert_session_allowed(request)
