from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from core.logging_config import get_correlation_id
from core.middleware import (
    CorrelationIdMiddleware,
    MetricsMiddleware,
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
    def test_propagates_correlation_id_and_clears_context(self):
        middleware = CorrelationIdMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/api/v1/auth/me")
        response = middleware(request)

        self.assertIn("X-Correlation-ID", response)
        self.assertIsNone(get_correlation_id())

    def test_reuses_incoming_correlation_id(self):
        middleware = CorrelationIdMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get(
            "/api/v1/auth/me",
            HTTP_X_CORRELATION_ID="cid-predefined",
        )
        response = middleware(request)
        self.assertEqual(response["X-Correlation-ID"], "cid-predefined")


class MetricsMiddlewareTests(SimpleTestCase):
    def test_normalizes_high_cardinality_path_segments(self):
        middleware = MetricsMiddleware(lambda request: HttpResponse("ok"))
        normalized = middleware._normalize_path("/api/v1/sessions/ab12cd34")
        self.assertEqual(normalized, "/api/v1/sessions/{id}")

    def test_truncates_very_long_paths(self):
        middleware = MetricsMiddleware(lambda request: HttpResponse("ok"))
        normalized = middleware._normalize_path("/x/" + ("a" * 120))
        self.assertTrue(normalized.endswith("..."))
        self.assertLessEqual(len(normalized), 50)

    def test_skips_excluded_paths(self):
        middleware = MetricsMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/health")
        with patch("core.middleware.metrics.set_gauge") as set_gauge:
            response = middleware(request)
        self.assertEqual(response.status_code, 200)
        set_gauge.assert_not_called()

    def test_records_500_status_when_handler_raises(self):
        middleware = MetricsMiddleware(
            lambda _request: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        request = RequestFactory().get("/api/v1/auth/me")
        with (
            patch("core.middleware.metrics.inc_counter") as inc_counter,
            patch("core.middleware.metrics.observe_histogram"),
            self.assertRaises(RuntimeError),
        ):
            middleware(request)
        labels = inc_counter.call_args.args[1]
        self.assertEqual(labels["status"], "500")


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
