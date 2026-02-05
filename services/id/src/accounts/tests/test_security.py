from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase
from ninja.errors import HttpError

from accounts.api.security import (
    AUTHENTICATION_METHODS_SESSION_KEY,
    SessionTokenAuth,
    authenticate_optional,
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

        with (
            patch(
                "accounts.api.security.authenticate_by_x_session_token",
                return_value=(user, session),
            ) as auth_mock,
            patch("accounts.api.security.record_authentication") as record_mock,
        ):
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

        with (
            patch(
                "accounts.api.security.authenticate_by_x_session_token",
                return_value=(user, session),
            ),
            patch("accounts.api.security.record_authentication") as record_mock,
        ):
            result = session_token_auth(request)

        self.assertIs(result, user)
        record_mock.assert_not_called()

    def test_accepts_bearer_authorization_header(self):
        user = SimpleNamespace(is_authenticated=True)
        session = {}
        request = SimpleNamespace(headers={"Authorization": "Bearer token-1"})

        with (
            patch(
                "accounts.api.security.authenticate_by_x_session_token",
                return_value=(user, session),
            ) as auth_mock,
            patch("accounts.api.security.record_authentication"),
        ):
            result = session_token_auth(request)

        self.assertIs(result, user)
        auth_mock.assert_called_once_with("token-1")

    def test_session_token_auth_falls_back_when_request_session_is_read_only(self):
        class RequestWithReadOnlySession:
            def __init__(self):
                self.headers = {"X-Session-Token": "token-ro"}
                self.user = None
                self.auth = None

            @property
            def session(self):
                return None

            @session.setter
            def session(self, _value):
                raise RuntimeError("read-only")

        user = SimpleNamespace(is_authenticated=True)
        session = {}
        request = RequestWithReadOnlySession()

        with (
            patch(
                "accounts.api.security.authenticate_by_x_session_token",
                return_value=(user, session),
            ),
            patch("accounts.api.security.record_authentication"),
        ):
            result = session_token_auth(request)

        self.assertIs(result, user)
        self.assertIs(request._session, session)


class AuthenticateOptionalTests(SimpleTestCase):
    def test_returns_none_and_clears_context_without_token(self):
        request = SimpleNamespace(headers={}, user="unknown", auth="unknown")
        result = authenticate_optional(request)
        self.assertIsNone(result)
        self.assertIsNone(request.user)
        self.assertIsNone(request.auth)

    def test_raises_when_token_is_invalid(self):
        request = SimpleNamespace(headers={"X-Session-Token": "bad"})
        with patch(
            "accounts.api.security.authenticate_by_x_session_token",
            return_value=None,
        ):
            with self.assertRaises(HttpError) as exc:
                authenticate_optional(request)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "INVALID_OR_EXPIRED_TOKEN")

    def test_sets_user_and_session_with_bearer_token(self):
        user = SimpleNamespace(is_authenticated=True)
        session = {}
        request = SimpleNamespace(headers={"Authorization": "Bearer token-2"})

        with (
            patch(
                "accounts.api.security.authenticate_by_x_session_token",
                return_value=(user, session),
            ) as auth_mock,
            patch("accounts.api.security.record_authentication") as record_mock,
        ):
            result = authenticate_optional(request)

        self.assertIs(result, user)
        self.assertIs(request.user, user)
        self.assertIs(request.session, session)
        self.assertIs(request.auth, user)
        auth_mock.assert_called_once_with("token-2")
        record_mock.assert_called_once()

    def test_falls_back_to_private_session_assignment_when_public_setter_fails(self):
        class RequestWithReadOnlySession:
            def __init__(self):
                self.headers = {"X-Session-Token": "token-3"}
                self.user = None
                self.auth = None

            @property
            def session(self):
                return None

            @session.setter
            def session(self, _value):
                raise RuntimeError("read-only")

        user = SimpleNamespace(is_authenticated=True)
        session = {}
        request = RequestWithReadOnlySession()

        with (
            patch(
                "accounts.api.security.authenticate_by_x_session_token",
                return_value=(user, session),
            ),
            patch("accounts.api.security.record_authentication"),
        ):
            result = authenticate_optional(request)

        self.assertIs(result, user)
        self.assertIs(request._session, session)
