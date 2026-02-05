from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase
from ninja.errors import HttpError

from accounts.api.security import (
    AUTHENTICATION_METHODS_SESSION_KEY,
    SessionTokenAuth,
    session_token_auth,
)


class SessionTokenAuthTests(SimpleTestCase):
    def test_returns_none_without_token_or_when_invalid(self):
        auth = SessionTokenAuth()
        request = SimpleNamespace(headers={})

        self.assertIsNone(auth(request))

        with patch(
            "accounts.api.security.authenticate_by_x_session_token",
            return_value=None,
        ) as auth_mock:
            request.headers["X-Session-Token"] = "bad"
            with self.assertRaises(HttpError):
                auth(request)
            auth_mock.assert_called_once_with("bad")

    def test_attaches_user_and_records_authentication(self):
        user = SimpleNamespace(is_authenticated=True)
        session = {}
        request = SimpleNamespace(headers={"X-Session-Token": "ok"})

        with patch(
            "accounts.api.security.authenticate_by_x_session_token",
            return_value=(user, session),
        ) as auth_mock, patch(
            "accounts.api.security.record_authentication"
        ) as record_mock:
            result = session_token_auth(request)

        self.assertIs(result, user)
        self.assertIs(request.user, user)
        self.assertIs(request.session, session)
        auth_mock.assert_called_once_with("ok")
        record_mock.assert_called_once()

    def test_skips_record_when_methods_present(self):
        user = SimpleNamespace(is_authenticated=True)
        session = {AUTHENTICATION_METHODS_SESSION_KEY: ["session"]}
        request = SimpleNamespace(headers={"X-Session-Token": "ok2"})

        with patch(
            "accounts.api.security.authenticate_by_x_session_token",
            return_value=(user, session),
        ), patch("accounts.api.security.record_authentication") as record_mock:
            result = session_token_auth(request)

        self.assertIs(result, user)
        record_mock.assert_not_called()
