from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from allauth.core.exceptions import ReauthenticationRequired
from ninja.errors import HttpError

from accounts.services.mfa import MfaService


class _DummyQuery:
    def __init__(self, items: list[Any]):
        self._items = items

    def filter(self, **kwargs):
        filtered = self._items
        for key, value in kwargs.items():
            if key == "type":
                filtered = [
                    item for item in filtered if getattr(item, "type", None) == value
                ]
            elif key == "type__in":
                filtered = [
                    item for item in filtered if getattr(item, "type", None) in value
                ]
        return _DummyQuery(filtered)

    def exists(self) -> bool:
        return bool(self._items)

    def first(self):
        return self._items[0] if self._items else None


class _AuthType:
    TOTP = "totp"
    WEBAUTHN = "webauthn"
    RECOVERY_CODES = "rc"


class _RC:
    def __init__(self, _auth):
        self._codes = ["a", "b", "c"]

    def get_unused_codes(self) -> list[str]:
        return self._codes

    @classmethod
    def activate(cls, _user):
        return SimpleNamespace(instance=SimpleNamespace(type=_AuthType.RECOVERY_CODES))


@contextmanager
def _ctx(_request):
    yield


class MfaServiceUnitTests(TestCase):
    def test_status_reports_totp_and_recovery(self):
        auth_totp = SimpleNamespace(type=_AuthType.TOTP)
        rc_auth = SimpleNamespace(type=_AuthType.RECOVERY_CODES)
        auths = _DummyQuery([auth_totp, rc_auth])

        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports):
            mock_imports.return_value = (
                lambda: None,
                SimpleNamespace(Type=_AuthType, objects=auths),
                _RC,
                None,
                None,
                None,
            )
            out = MfaService.status(SimpleNamespace())
            self.assertTrue(out.has_totp)
            self.assertFalse(out.has_webauthn)
            self.assertTrue(out.has_recovery_codes)
            self.assertEqual(out.recovery_codes_left, 3)

        _run()

    def test_totp_begin_requires_reauth_when_raised(self):
        @patch(
            "accounts.services.mfa.EmailService.status",
            return_value={"email": "u@example.com", "verified": True},
        )
        @patch(
            "accounts.services.mfa.context.request_context",
            side_effect=ReauthenticationRequired(),
        )
        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports, _ctx_patch, _status):
            mock_imports.return_value = (
                lambda: None,
                None,
                None,
                SimpleNamespace,
                None,
                None,
            )
            request = SimpleNamespace(user=SimpleNamespace(), session={})
            with self.assertRaises(HttpError) as exc:
                MfaService.totp_begin(request)
            self.assertEqual(exc.exception.status_code, 401)

        _run()

    def test_totp_begin_requires_verified_email(self):
        @patch(
            "accounts.services.mfa.EmailService.status",
            return_value={"email": "", "verified": False},
        )
        def _run(_status):
            request = SimpleNamespace(user=SimpleNamespace(), session={})
            with self.assertRaises(HttpError) as exc:
                MfaService.totp_begin(request)
            self.assertEqual(exc.exception.status_code, 400)
            self.assertEqual(
                exc.exception.message.get("code"), "EMAIL_VERIFICATION_REQUIRED"
            )

        _run()

    def test_totp_confirm_without_secret(self):
        request = SimpleNamespace(user=SimpleNamespace(), session={})
        with self.assertRaises(HttpError) as exc:
            MfaService.totp_confirm(request, "123456")
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message.get("code"), "TOTP_SETUP_REQUIRED")

    def test_totp_confirm_invalid_code_errors(self):
        class _Form:
            def __init__(self, *_, **__):
                self.errors = {"code": ["invalid"]}

            def is_valid(self):
                return False

        @patch("accounts.services.mfa.context.request_context", _ctx)
        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports):
            mock_imports.return_value = (
                None,
                None,
                None,
                _Form,
                None,
                SimpleNamespace(activate_totp=lambda _r, _f: (SimpleNamespace(), None)),
            )
            request = SimpleNamespace(
                user=SimpleNamespace(), session={"mfa.totp.secret": "s"}
            )
            with self.assertRaises(HttpError) as exc:
                MfaService.totp_confirm(request, "000000")
            self.assertEqual(exc.exception.status_code, 400)
            self.assertEqual(exc.exception.message, {"code": ["invalid"]})

        _run()

    def test_totp_confirm_raises_reauth(self):
        @patch(
            "accounts.services.mfa.context.request_context",
            side_effect=ReauthenticationRequired(),
        )
        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports, _ctx_patch):
            class _Form:
                def __init__(self, *_, **__):
                    self.errors = {}

                def is_valid(self):
                    return True

            mock_imports.return_value = (
                None,
                None,
                None,
                _Form,
                None,
                SimpleNamespace(activate_totp=lambda _r, _f: (SimpleNamespace(), None)),
            )
            request = SimpleNamespace(
                user=SimpleNamespace(), session={"mfa.totp.secret": "s"}
            )
            with self.assertRaises(HttpError) as exc:
                MfaService.totp_confirm(request, "111111")
            self.assertEqual(exc.exception.status_code, 401)

        _run()

    def test_totp_disable_invalid_form(self):
        class _BadForm:
            def __init__(self, *_, **__):
                self.errors = {"code": ["cannot"]}

            def is_valid(self):
                return False

        auth_obj = SimpleNamespace(id="1", user=SimpleNamespace(), type=_AuthType.TOTP)

        @patch("accounts.services.mfa.get_object_or_404", return_value=auth_obj)
        @patch("accounts.services.mfa.context.request_context", _ctx)
        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports, _get):
            mock_imports.return_value = (
                None,
                SimpleNamespace(Type=_AuthType),
                None,
                None,
                _BadForm,
                SimpleNamespace(deactivate_totp=lambda *_: None),
            )
            request = SimpleNamespace(user=SimpleNamespace(), session={})
            with self.assertRaises(HttpError) as exc:
                MfaService.totp_disable(request)
            self.assertEqual(exc.exception.status_code, 400)

        _run()

    def test_regenerate_recovery_codes_blocks_without_mfa(self):
        class _AuthMgr:
            def __init__(self, items: list[Any]):
                self.items = items

            def filter(self, **kwargs):
                return _DummyQuery(self.items).filter(**kwargs)

        @patch("accounts.services.mfa.context.request_context", _ctx)
        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports):
            mock_imports.return_value = (
                None,
                SimpleNamespace(Type=_AuthType, objects=_AuthMgr([])),
                _RC,
                None,
                None,
                None,
            )
            request = SimpleNamespace(user=SimpleNamespace(), session={})
            with self.assertRaises(HttpError) as exc:
                MfaService.regenerate_recovery_codes(request)
            self.assertEqual(exc.exception.status_code, 400)
            self.assertEqual(exc.exception.message.get("code"), "MFA_REQUIRED")

        _run()

    def test_regenerate_recovery_codes_replaces_existing(self):
        existing = SimpleNamespace(type=_AuthType.RECOVERY_CODES, delete=lambda: None)

        class _AuthMgr:
            def filter(self, **kwargs):
                if kwargs.get("type__in"):
                    return _DummyQuery([SimpleNamespace(type=_AuthType.TOTP)])
                if kwargs.get("type") == _AuthType.RECOVERY_CODES:
                    return _DummyQuery([existing])
                return _DummyQuery([])

        @patch("accounts.services.mfa.context.request_context", _ctx)
        @patch("accounts.services.mfa._mfa_imports")
        def _run(mock_imports):
            mock_imports.return_value = (
                None,
                SimpleNamespace(Type=_AuthType, objects=_AuthMgr()),
                _RC,
                None,
                None,
                None,
            )
            request = SimpleNamespace(user=SimpleNamespace(), session={})
            codes = MfaService.regenerate_recovery_codes(request)
            self.assertGreaterEqual(len(codes), 1)

        _run()
