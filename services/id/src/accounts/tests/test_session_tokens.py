from datetime import timedelta

from allauth.headless.internal.sessionkit import authenticate_by_x_session_token
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts.session_tokens import LoadedSessionTokenStrategy


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
class LoadedSessionTokenTests(TestCase):
    def setUp(self):
        self.strategy = LoadedSessionTokenStrategy()
        self.session = SessionStore()
        self.session["challenge"] = "synthetic-pending-passkey-challenge"
        self.session.save()

    def test_one_query_loads_session_and_preserves_preauth_state(self):
        with self.assertNumQueries(1):
            loaded = self.strategy.lookup_session(self.session.session_key)
            self.assertEqual(loaded["challenge"], self.session["challenge"])
            self.assertIsNone(loaded.get("_auth_user_id"))
        self.assertFalse(loaded.modified)

    def test_empty_live_session_remains_valid(self):
        self.session.clear()
        self.session.save()
        with self.assertNumQueries(1):
            self.assertIsNotNone(self.strategy.lookup_session(self.session.session_key))

    def test_deleted_session_is_not_cached_between_requests(self):
        self.assertIsNotNone(self.strategy.lookup_session(self.session.session_key))
        Session.objects.filter(session_key=self.session.session_key).delete()
        with self.assertNumQueries(1):
            self.assertIsNone(self.strategy.lookup_session(self.session.session_key))

    def test_expired_or_missing_session_is_rejected(self):
        Session.objects.filter(session_key=self.session.session_key).update(
            expire_date=timezone.now() - timedelta(seconds=1)
        )
        for token in (self.session.session_key, "nonexistentsession000000000000000"):
            with self.subTest(token=token), self.assertNumQueries(1):
                self.assertIsNone(self.strategy.lookup_session(token))
        self.assertIsNone(self.strategy.lookup_session("short"))

    def test_authentication_checks_active_user_and_uses_two_queries(self):
        user = get_user_model().objects.create_user(
            username="session-query-user", email="session@example.invalid"
        )
        self.session["_auth_user_id"] = str(user.pk)
        self.session.save()
        with self.assertNumQueries(2):
            result = authenticate_by_x_session_token(self.session.session_key)
            self.assertEqual(result[0].pk, user.pk)
        user.is_active = False
        user.save(update_fields=["is_active"])
        self.assertIsNone(authenticate_by_x_session_token(self.session.session_key))
