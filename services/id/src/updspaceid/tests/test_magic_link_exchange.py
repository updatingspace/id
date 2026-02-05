from __future__ import annotations

import hashlib
import hmac
import json
import time

from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from accounts.api.router_magic_link import _cache_key


def _signature(
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


@override_settings(BFF_INTERNAL_HMAC_SECRET="exchange-secret")
class MagicLinkExchangeTests(TestCase):
    def setUp(self):
        self.client_http = Client()
        cache.clear()

    def tearDown(self):
        cache.clear()

    def _post_exchange(
        self, body_obj: dict, *, signature: str, request_id: str, timestamp: int
    ):
        body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
        return self.client_http.post(
            "/api/v1/auth/exchange",
            data=body,
            content_type="application/json",
            HTTP_X_REQUEST_ID=request_id,
            HTTP_X_UPDSPACE_TIMESTAMP=str(timestamp),
            HTTP_X_UPDSPACE_SIGNATURE=signature,
        )

    def test_exchange_code_is_single_use(self):
        code = "exchange-code-1"
        cache.set(
            _cache_key(code),
            {
                "user_id": "0d5e5f5a-7fd8-4a8f-a327-778b0e537fcb",
                "master_flags": {"email_verified": True},
                "ttl_seconds": 120,
            },
            timeout=60,
        )
        payload = {"code": code}
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ts = int(time.time())
        sig = _signature(
            secret="exchange-secret",
            method="POST",
            path="/api/v1/auth/exchange",
            body=body,
            request_id="rid-ex-1",
            timestamp=ts,
        )

        first = self._post_exchange(
            payload, signature=sig, request_id="rid-ex-1", timestamp=ts
        )
        self.assertEqual(first.status_code, 200)
        first_payload = first.json()
        self.assertTrue(first_payload["ok"])
        self.assertEqual(
            first_payload["user_id"], "0d5e5f5a-7fd8-4a8f-a327-778b0e537fcb"
        )

        second = self._post_exchange(
            payload, signature=sig, request_id="rid-ex-1", timestamp=ts
        )
        self.assertEqual(second.status_code, 401)
        second_payload = second.json()
        self.assertEqual(second_payload.get("code"), "UNAUTHORIZED")

    def test_exchange_rejects_invalid_signature(self):
        code = "exchange-code-2"
        cache.set(
            _cache_key(code),
            {
                "user_id": "5f96f312-28b4-4f2f-b4fa-b8e47e913efd",
                "master_flags": {},
                "ttl_seconds": 120,
            },
            timeout=60,
        )
        payload = {"code": code}
        ts = int(time.time())
        response = self._post_exchange(
            payload,
            signature="invalid-signature",
            request_id="rid-ex-2",
            timestamp=ts,
        )
        self.assertEqual(response.status_code, 401)
        body = response.json()
        self.assertEqual(body.get("code"), "UNAUTHORIZED")
