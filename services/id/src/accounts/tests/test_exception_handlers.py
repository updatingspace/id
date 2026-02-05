from __future__ import annotations

import json

from django.test import RequestFactory, SimpleTestCase
from ninja import NinjaAPI
from ninja.errors import HttpError

from accounts.api.exception_handlers import (
    _error_envelope_response,
    _normalize_form_errors,
    install_http_error_handler,
)


class ExceptionHandlersTests(SimpleTestCase):
    def setUp(self):
        self.api = NinjaAPI()
        install_http_error_handler(self.api)
        self.handler = self.api._exception_handlers[HttpError]
        self.factory = RequestFactory()

    def test_internal_error_hides_raw_detail(self):
        request = self.factory.get("/api/v1/auth/login", HTTP_X_REQUEST_ID="rid-1")
        response = self.handler(
            request,
            HttpError(
                500,
                {
                    "code": "DB_ERROR",
                    "message": "password=secret for user@example.com",
                    "details": {"token": "abc123"},
                },
            ),
        )
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(payload["code"], "SERVER_ERROR")
        self.assertIsNone(payload["details"])
        self.assertIsNone(payload["detail"])

    def test_error_envelope_mode_uses_safe_payload(self):
        request = self.factory.get("/api/v1/auth/login", HTTP_X_REQUEST_ID="rid-2")
        request._error_envelope = True
        response = self.handler(
            request,
            HttpError(
                500,
                {
                    "code": "INTERNAL",
                    "message": "token=abc",
                    "details": {"email": "user@example.com"},
                },
            ),
        )
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(payload["error"]["code"], "SERVER_ERROR")
        self.assertEqual(payload["error"]["message"], "Internal server error")
        self.assertIsNone(payload["error"]["details"])
        self.assertEqual(payload["error"]["request_id"], "rid-2")

    def test_client_error_preserves_code_but_sanitizes_details(self):
        request = self.factory.get("/api/v1/auth/login", HTTP_X_REQUEST_ID="rid-3")
        response = self.handler(
            request,
            HttpError(
                400,
                {
                    "code": "INVALID_INPUT",
                    "message": "invalid email user@example.com",
                    "details": {"email": "user@example.com"},
                },
            ),
        )
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(payload["code"], "INVALID_INPUT")
        self.assertEqual(payload["details"]["email"], "[REDACTED_EMAIL]")

    def test_error_envelope_handles_non_dict_detail(self):
        request = self.factory.get("/oauth/token", HTTP_X_REQUEST_ID="rid-4")
        response = _error_envelope_response(self.api, request, 401, "invalid token")
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(payload["error"]["code"], "HTTP_ERROR")
        self.assertEqual(payload["error"]["message"], "invalid token")
        self.assertEqual(payload["error"]["request_id"], "rid-4")

    def test_normalize_form_errors_returns_none_for_invalid_payloads(self):
        self.assertEqual(_normalize_form_errors("not-json"), (None, None))
        self.assertEqual(_normalize_form_errors("[]"), (None, None))
        self.assertEqual(
            _normalize_form_errors(json.dumps({"email": "bad"})), (None, None)
        )

    def test_validation_errors_are_mapped_to_errors_and_fields(self):
        request = self.factory.post("/api/v1/auth/signup")
        raw = json.dumps(
            {
                "email": [{"message": "invalid email", "code": "invalid"}],
                "password": ["too short"],
            }
        )
        response = self.handler(request, HttpError(400, raw))
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(payload["code"], "VALIDATION_ERROR")
        self.assertIn("errors", payload["details"])
        self.assertEqual(payload["fields"]["email"], "invalid email")

    def test_string_error_maps_to_http_error_code(self):
        request = self.factory.get("/api/v1/auth/login")
        response = self.handler(request, HttpError(403, "forbidden"))
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(payload["code"], "HTTP_ERROR")
        self.assertEqual(payload["message"], "forbidden")
