from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from core.logging_config import get_correlation_id
from core.middleware import (
    CorrelationIdMiddleware,
    RequestIdMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    UserContextMiddleware,
)


class SecurityHeadersMiddlewareTests(SimpleTestCase):
    @override_settings(DEBUG=False)
    def test_sets_security_headers_and_hsts_in_production(self):
        middleware = SecurityHeadersMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/api/v1/auth/me")
        response = middleware(request)

        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response["Content-Security-Policy"])
        self.assertIn("max-age=63072000", response["Strict-Transport-Security"])


class CorrelationIdMiddlewareTests(SimpleTestCase):
    def test_generates_request_id_and_clears_context(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/api/v1/auth/me")
        response = middleware(request)

        uuid.UUID(response["X-Request-Id"])
        self.assertIn("X-Correlation-ID", response)
        self.assertEqual(response["X-Correlation-ID"], response["X-Request-Id"])
        self.assertIsNone(get_correlation_id())

    def test_reuses_incoming_request_id(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get(
            "/api/v1/auth/me",
            HTTP_X_REQUEST_ID="rid-predefined",
            HTTP_X_CORRELATION_ID="cid-predefined",
        )
        response = middleware(request)
        self.assertEqual(response["X-Request-Id"], "rid-predefined")
        self.assertEqual(response["X-Correlation-ID"], "rid-predefined")

    def test_falls_back_to_incoming_correlation_id(self):
        middleware = RequestIdMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get(
            "/api/v1/auth/me",
            HTTP_X_CORRELATION_ID="cid-predefined",
        )
        response = middleware(request)
        self.assertEqual(response["X-Request-Id"], "cid-predefined")
        self.assertEqual(response["X-Correlation-ID"], "cid-predefined")

    def test_old_correlation_middleware_name_is_compatible(self):
        middleware = CorrelationIdMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/api/v1/auth/me")
        response = middleware(request)
        self.assertIn("X-Request-Id", response)


class UserContextMiddlewareTests(SimpleTestCase):
    def test_sets_user_and_tenant_context(self):
        user = SimpleNamespace(is_authenticated=True, pk=777)
        request = SimpleNamespace(user=user, tenant_id="tenant-1")
        middleware = UserContextMiddleware(lambda _request: HttpResponse("ok"))
        with patch("core.middleware.set_user_context") as set_ctx:
            response = middleware(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set_ctx.call_count, 2)

    def test_skips_unauthenticated_user(self):
        user = SimpleNamespace(is_authenticated=False, pk=777)
        request = SimpleNamespace(user=user, tenant_id=None)
        middleware = UserContextMiddleware(lambda _request: HttpResponse("ok"))
        with patch("core.middleware.set_user_context") as set_ctx:
            middleware(request)
        set_ctx.assert_not_called()

    def test_does_not_fail_when_request_user_resolution_raises(self):
        class BrokenRequest:
            tenant_id = "tenant-1"

            @property
            def user(self):
                raise RuntimeError("session backend unavailable")

        middleware = UserContextMiddleware(lambda _request: HttpResponse("ok"))
        with (
            patch("core.middleware.set_user_context") as set_ctx,
            patch("core.middleware.logger.warning") as warn_mock,
        ):
            response = middleware(BrokenRequest())
        self.assertEqual(response.status_code, 200)
        set_ctx.assert_called_once_with(tenant_id="tenant-1")
        warn_mock.assert_called()

    def test_does_not_fail_when_user_auth_check_raises(self):
        class BrokenUser:
            @property
            def is_authenticated(self):
                raise RuntimeError("auth lazy evaluation failed")

        request = SimpleNamespace(user=BrokenUser(), tenant_id="tenant-2")
        middleware = UserContextMiddleware(lambda _request: HttpResponse("ok"))
        with (
            patch("core.middleware.set_user_context") as set_ctx,
            patch("core.middleware.logger.warning") as warn_mock,
        ):
            response = middleware(request)
        self.assertEqual(response.status_code, 200)
        set_ctx.assert_called_once_with(tenant_id="tenant-2")
        warn_mock.assert_called()


class RequestLoggingMiddlewareTests(SimpleTestCase):
    def test_redacts_exception_message_in_log_extra(self):
        middleware = RequestLoggingMiddleware(
            lambda request: (_ for _ in ()).throw(
                RuntimeError("token=abc123 user=user@example.com")
            )
        )
        request = RequestFactory().get("/api/v1/secret")

        with patch("core.middleware.logger.error") as error_mock:
            with self.assertRaises(RuntimeError):
                middleware(request)

        extra = error_mock.call_args.kwargs["extra"]
        self.assertIn("[REDACTED]", extra["exception_message"])
        self.assertIn("[REDACTED_EMAIL]", extra["exception_message"])

    def test_skip_paths_are_not_logged(self):
        middleware = RequestLoggingMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/health")
        with (
            patch("core.middleware.logger.debug") as debug_mock,
            patch("core.middleware.logger.log") as log_mock,
        ):
            response = middleware(request)
        self.assertEqual(response.status_code, 200)
        debug_mock.assert_not_called()
        log_mock.assert_not_called()
