from datetime import timedelta
from unittest.mock import patch

from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.usersessions.models import UserSession
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import RequestFactory, TestCase
from django.utils import timezone

from accounts.services.mfa import MfaService
from accounts.services.sessions import SessionService
from core.models import UserSessionMeta


class AccountReadQueryTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="query-owner", email="owner@example.invalid"
        )
        self.other = get_user_model().objects.create_user(
            username="query-other", email="other@example.invalid"
        )

    def test_session_listing_batches_expiry_and_preserves_revocation(self):
        request = RequestFactory().get("/")
        request.session = SessionStore(session_key="current-session-key")
        expiry = timezone.now() + timedelta(days=1)
        for index in range(12):
            key = f"session-{index:02}"
            Session.objects.create(session_key=key, session_data="", expire_date=expiry)
            UserSessionMeta.objects.create(user=self.user, session_key=key)
        Session.objects.create(
            session_key="current-session-key", session_data="", expire_date=expiry
        )
        UserSession.objects.create(
            user=self.user, session_key="current-session-key", ip="192.0.2.1"
        )
        UserSessionMeta.objects.create(
            user=self.user, session_key="current-session-key"
        )
        revoked_at = timezone.now()
        UserSessionMeta.objects.filter(session_key="session-00").update(
            revoked_at=revoked_at, revoked_reason="user_revoked"
        )
        UserSessionMeta.objects.create(user=self.user, session_key="missing-session")
        UserSessionMeta.objects.create(user=self.other, session_key="other-session")

        with self.assertNumQueries(3):
            rows = SessionService.list(request, self.user)

        by_key = {row.id: row for row in rows}
        self.assertEqual(len(rows), 14)
        self.assertNotIn("other-session", by_key)
        self.assertTrue(by_key["current-session-key"].current)
        self.assertFalse(by_key["current-session-key"].revoked)
        self.assertEqual(by_key["session-01"].expires, expiry)
        self.assertTrue(by_key["session-00"].revoked)
        self.assertEqual(by_key["session-00"].revoked_reason, "user_revoked")
        self.assertEqual(by_key["session-00"].revoked_at, revoked_at)
        self.assertTrue(by_key["missing-session"].revoked)
        self.assertIsNone(by_key["missing-session"].expires)

    def test_session_listing_without_sessions_needs_no_expiry_query(self):
        request = RequestFactory().get("/")
        request.session = SessionStore()
        with self.assertNumQueries(2):
            self.assertEqual(SessionService.list(request, self.user), [])

    def test_session_listing_marks_unpurged_expired_sessions_as_revoked(self):
        request = RequestFactory().get("/")
        request.session = SessionStore()
        now = timezone.now()
        for key, expiry in (
            ("expired", now - timedelta(seconds=1)),
            ("expires-now", now),
            ("active", now + timedelta(days=1)),
        ):
            Session.objects.create(session_key=key, session_data="", expire_date=expiry)
            UserSessionMeta.objects.create(user=self.user, session_key=key)

        with patch("accounts.services.sessions.timezone.now", return_value=now):
            with self.assertNumQueries(3):
                rows = SessionService.list(request, self.user)

        by_key = {row.id: row for row in rows}
        self.assertTrue(by_key["expired"].revoked)
        self.assertTrue(by_key["expires-now"].revoked)
        self.assertFalse(by_key["active"].revoked)
        self.assertEqual(by_key["expired"].expires, now - timedelta(seconds=1))

    def test_mfa_status_uses_one_query_and_counts_only_unused_codes(self):
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.TOTP, data={}
        )
        Authenticator.objects.create(
            user=self.user, type=Authenticator.Type.WEBAUTHN, data={}
        )
        recovery = RecoveryCodes.activate(self.user)
        codes = recovery.get_unused_codes()
        self.assertTrue(recovery.validate_code(codes[0]))

        with self.assertNumQueries(1):
            status = MfaService.status(self.user)
        self.assertTrue(status.has_totp)
        self.assertTrue(status.has_webauthn)
        self.assertTrue(status.has_recovery_codes)
        self.assertEqual(status.recovery_codes_left, len(codes) - 1)

        with self.assertNumQueries(1):
            other_status = MfaService.status(self.other)
        self.assertFalse(other_status.has_totp)
        self.assertFalse(other_status.has_webauthn)
        self.assertFalse(other_status.has_recovery_codes)
        self.assertEqual(other_status.recovery_codes_left, 0)
