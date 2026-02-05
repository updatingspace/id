from __future__ import annotations

from django.test import SimpleTestCase

from core.errors import ErrorEnvelope, error_payload


class ErrorPayloadTests(SimpleTestCase):
    def test_error_payload_without_details(self):
        payload = error_payload("ERR_CODE", "message")
        self.assertEqual(payload, {"code": "ERR_CODE", "message": "message"})

    def test_error_payload_with_details(self):
        payload = error_payload("ERR_CODE", "message", {"field": "value"})
        self.assertEqual(
            payload,
            {"code": "ERR_CODE", "message": "message", "details": {"field": "value"}},
        )

    def test_error_envelope_dataclass(self):
        envelope = ErrorEnvelope(code="ERR", message="failed", details={"x": 1})
        self.assertEqual(envelope.code, "ERR")
        self.assertEqual(envelope.message, "failed")
        self.assertEqual(envelope.details, {"x": 1})
