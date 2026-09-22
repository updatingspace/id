from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from urllib.error import URLError

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.models import UserProfile
from accounts.services.auth import AuthService
from accounts.services.profile import ProfileService

User = get_user_model()


class ProfilePerformanceTests(TestCase):
    def test_profile_returns_saved_avatar_without_remote_io(self):
        user = User.objects.create_user(
            username="saved-avatar", email="saved@example.com"
        )
        profile = UserProfile.objects.create(user=user, avatar="avatars/saved.jpg")
        with (
            patch.object(ProfileService, "_fetch_gravatar") as fetch,
            patch.object(profile.avatar.storage, "exists") as exists,
        ):
            result = AuthService.profile(user)
        self.assertTrue(result.avatar_url.endswith("avatars/saved.jpg"))
        fetch.assert_not_called()
        exists.assert_not_called()

    def test_cookie_without_header_token_is_still_a_guest(self):
        user = User.objects.create_user(username="cookie-only")
        self.client.force_login(user)
        response = self.client.get("/api/v1/auth/me")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"user": None})
        self.assertEqual(response["Cache-Control"], "private, no-store")

    def test_invalid_session_response_is_not_cacheable(self):
        response = self.client.get("/api/v1/auth/me", HTTP_X_SESSION_TOKEN="expired")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Cache-Control"], "private, no-store")


class RefreshGravatarsTests(TestCase):
    def profile(self, name, **fields):
        return UserProfile.objects.create(
            user=User.objects.create_user(username=name, email=f"{name}@example.com"),
            **fields,
        )

    def test_processes_only_due_opted_in_profiles(self):
        due = self.profile(
            "due", gravatar_checked_at=timezone.now() - timedelta(days=8)
        )
        never = self.profile("never")
        self.profile("fresh", gravatar_checked_at=timezone.now())
        self.profile("disabled", gravatar_enabled=False)
        self.profile("uploaded", avatar_source=UserProfile.AvatarSource.UPLOAD)
        output = StringIO()
        with patch.object(
            ProfileService, "maybe_refresh_gravatar", return_value=True
        ) as refresh:
            call_command("refresh_gravatars", stdout=output)
        self.assertEqual(
            {call.args[0].pk for call in refresh.call_args_list},
            {due.user_id, never.user_id},
        )
        self.assertIn("Checked 2; updated 2; failed 0", output.getvalue())

    def test_limits_batch_and_reports_failures(self):
        self.profile("one")
        self.profile("two")
        with patch.object(
            ProfileService,
            "maybe_refresh_gravatar",
            side_effect=RuntimeError("storage unavailable"),
        ) as refresh:
            with self.assertRaises(CommandError):
                call_command("refresh_gravatars", limit=1, stdout=StringIO())
        self.assertEqual(refresh.call_count, 1)

    @override_settings(GRAVATAR_AUTOLOAD_ENABLED=False)
    def test_disabled_job_does_not_touch_profiles(self):
        with patch.object(ProfileService, "maybe_refresh_gravatar") as refresh:
            call_command("refresh_gravatars", stdout=StringIO())
        refresh.assert_not_called()

    def test_rejects_invalid_limit(self):
        with self.assertRaises(CommandError):
            call_command("refresh_gravatars", limit=0)

    def test_network_failure_leaves_profile_due_for_retry(self):
        profile = self.profile("retry")
        with patch(
            "accounts.services.profile.urllib.request.urlopen",
            side_effect=URLError("offline"),
        ):
            with self.assertRaises(CommandError):
                call_command("refresh_gravatars", stdout=StringIO())
        profile.refresh_from_db()
        self.assertIsNone(profile.gravatar_checked_at)

    def test_does_not_overwrite_an_upload_made_during_fetch(self):
        profile = self.profile("upload-during-fetch")

        def uploaded(_email):
            UserProfile.objects.filter(pk=profile.pk).update(
                avatar_source=UserProfile.AvatarSource.UPLOAD,
                gravatar_enabled=False,
            )
            return b"downloaded image"

        with (
            patch.object(ProfileService, "_fetch_gravatar", side_effect=uploaded),
            patch.object(ProfileService, "_replace_avatar") as replace,
        ):
            call_command("refresh_gravatars", stdout=StringIO())
        replace.assert_not_called()
