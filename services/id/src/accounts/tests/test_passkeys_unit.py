from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from ninja.errors import HttpError

from accounts.services.passkeys import PasskeyService


@contextmanager
def _ctx(_request):
    yield


class PasskeyServiceUnitTests(TestCase):
    def test_begin_registration_returns_501_when_webauthn_fails(self):
        flows = SimpleNamespace(
            begin_registration=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("webauthn unavailable")
            )
        )
        request = SimpleNamespace(user=SimpleNamespace(id=42))
        user = SimpleNamespace(id=42)

        with (
            patch(
                "accounts.services.passkeys._passkeys_imports",
                return_value=(None, None, flows),
            ),
            patch("accounts.services.passkeys.context.request_context", _ctx),
        ):
            with self.assertRaises(HttpError) as exc:
                PasskeyService.begin_registration(request, user)

        self.assertEqual(exc.exception.status_code, 501)
        self.assertEqual(exc.exception.message, "passkeys_unavailable")
