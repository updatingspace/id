from __future__ import annotations

import hashlib
import hmac
import time
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings
from ninja.errors import HttpError

from core.security import require_internal_signature


def _make_signature(
    *,
    secret: str,
    method: str,
    path: str,
    body: bytes,
    request_id: str,
    timestamp: int,
) -> str:
    body_hash = hashlib.sha256(body or b"").hexdigest()
    message = "\n".join([method.upper(), path, body_hash, request_id, str(timestamp)])
    return hmac.new(
        secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()


class InternalSignatureTests(SimpleTestCase):
    def _request(
        self,
        *,
        headers: dict[str, str],
        body: bytes = b"{}",
        method: str = "POST",
        path: str = "/api/v1/auth/exchange",
    ):
        return SimpleNamespace(headers=headers, body=body, method=method, path=path)

    def test_missing_request_id_rejected(self):
        req = self._request(headers={})
        with self.assertRaises(HttpError) as exc:
            require_internal_signature(req)
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "MISSING_REQUEST_ID")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="sig-secret")
    def test_missing_signature_headers_rejected(self):
        req = self._request(headers={"X-Request-Id": "rid-1"})
        with self.assertRaises(HttpError) as exc:
            require_internal_signature(req)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "UNAUTHORIZED")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="sig-secret")
    def test_timestamp_outside_replay_window_rejected(self):
        ts = int(time.time()) - 301
        req = self._request(
            headers={
                "X-Request-Id": "rid-2",
                "X-Updspace-Timestamp": str(ts),
                "X-Updspace-Signature": "invalid",
            }
        )
        with self.assertRaises(HttpError) as exc:
            require_internal_signature(req)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "UNAUTHORIZED")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="sig-secret")
    def test_invalid_timestamp_format_rejected(self):
        req = self._request(
            headers={
                "X-Request-Id": "rid-invalid-ts",
                "X-Updspace-Timestamp": "not-a-number",
                "X-Updspace-Signature": "invalid",
            }
        )
        with self.assertRaises(HttpError) as exc:
            require_internal_signature(req)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "UNAUTHORIZED")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="")
    def test_missing_secret_fails_closed(self):
        ts = int(time.time())
        req = self._request(
            headers={
                "X-Request-Id": "rid-3",
                "X-Updspace-Timestamp": str(ts),
                "X-Updspace-Signature": "abc",
            }
        )
        with self.assertRaises(HttpError) as exc:
            require_internal_signature(req)
        self.assertEqual(exc.exception.status_code, 500)
        self.assertEqual(exc.exception.message["code"], "SERVER_ERROR")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="sig-secret")
    def test_invalid_signature_rejected(self):
        ts = int(time.time())
        req = self._request(
            headers={
                "X-Request-Id": "rid-4",
                "X-Updspace-Timestamp": str(ts),
                "X-Updspace-Signature": "bad-signature",
            },
            body=b'{"code":"abc"}',
        )
        with self.assertRaises(HttpError) as exc:
            require_internal_signature(req)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertEqual(exc.exception.message["code"], "UNAUTHORIZED")

    @override_settings(BFF_INTERNAL_HMAC_SECRET="sig-secret")
    def test_valid_signature_passes(self):
        body = b'{"code":"exchange"}'
        ts = int(time.time())
        signature = _make_signature(
            secret="sig-secret",
            method="POST",
            path="/api/v1/auth/exchange",
            body=body,
            request_id="rid-5",
            timestamp=ts,
        )
        req = self._request(
            headers={
                "X-Request-Id": "rid-5",
                "X-Updspace-Timestamp": str(ts),
                "X-Updspace-Signature": signature,
            },
            body=body,
        )
        require_internal_signature(req)
