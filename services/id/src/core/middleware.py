"""
Production middleware for UpdSpace ID Service.

Provides:
- Correlation ID propagation
- Request/response metrics instrumentation
- Security headers
- Logging context management
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from core.logging_config import (
    clear_context,
    generate_correlation_id,
    request_path_var,
    sanitize_log_data,
    set_correlation_id,
    set_user_context,
)
from core.monitoring import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_IN_FLIGHT,
    HTTP_REQUESTS_TOTAL,
    metrics,
)

logger = logging.getLogger(__name__)


class CorrelationIdMiddleware:
    """
    Middleware that propagates correlation IDs across requests.

    - Extracts X-Correlation-ID from incoming requests
    - Generates new ID if not present
    - Adds correlation ID to response headers
    - Sets up logging context
    """

    HEADER_NAME = "X-Correlation-ID"

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Extract or generate correlation ID
        correlation_id = (
            request.headers.get(self.HEADER_NAME) or generate_correlation_id()
        )

        # Set in context for logging
        set_correlation_id(correlation_id)
        request_path_var.set(request.path)

        # Attach to request for downstream use
        request.correlation_id = correlation_id  # type: ignore[attr-defined]

        try:
            response = self.get_response(request)

            # Add correlation ID to response
            response[self.HEADER_NAME] = correlation_id

            return response
        finally:
            # Clean up context
            clear_context()


class MetricsMiddleware:
    """
    Middleware that instruments HTTP requests with Prometheus-style metrics.

    Tracks:
    - Request count by method, path, status
    - Request duration histogram
    - In-flight requests gauge
    """

    # Paths to exclude from detailed metrics (high cardinality)
    EXCLUDE_PATHS = {"/health", "/metrics", "/favicon.ico"}

    # Paths to normalize (replace IDs with placeholders)
    PATH_NORMALIZERS = [
        (r"/api/v1/users/[^/]+", "/api/v1/users/{id}"),
        (r"/api/v1/sessions/[^/]+", "/api/v1/sessions/{id}"),
        (r"/oauth/authorize/[^/]+", "/oauth/authorize/{id}"),
    ]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self._in_flight = 0
        import re

        self._normalizers = [
            (re.compile(pattern), replacement)
            for pattern, replacement in self.PATH_NORMALIZERS
        ]

    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path
        method = request.method or "UNKNOWN"

        # Skip metrics for excluded paths
        if path in self.EXCLUDE_PATHS:
            return self.get_response(request)

        # Normalize path for metrics
        normalized_path = self._normalize_path(path)

        # Track in-flight requests
        self._in_flight += 1
        metrics.set_gauge(HTTP_REQUESTS_IN_FLIGHT, self._in_flight)

        start_time = time.perf_counter()

        try:
            response = self.get_response(request)
            status_code = response.status_code
        except Exception:
            status_code = 500
            raise
        finally:
            # Record metrics
            self._in_flight -= 1
            metrics.set_gauge(HTTP_REQUESTS_IN_FLIGHT, self._in_flight)

            duration = time.perf_counter() - start_time
            labels = {
                "method": method,
                "path": normalized_path,
                "status": str(status_code),
            }

            metrics.inc_counter(HTTP_REQUESTS_TOTAL, labels)
            metrics.observe_histogram(HTTP_REQUEST_DURATION_SECONDS, duration, labels)

        return response

    def _normalize_path(self, path: str) -> str:
        """Normalize path to reduce metric cardinality."""
        for pattern, replacement in self._normalizers:
            path = pattern.sub(replacement, path)

        # Truncate very long paths
        if len(path) > 50:
            path = path[:47] + "..."

        return path


class SecurityHeadersMiddleware:
    """
    Middleware that adds security headers to responses.

    Headers:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Referrer-Policy: strict-origin-when-cross-origin
    - Content-Security-Policy (basic)
    - Strict-Transport-Security (HSTS) in production
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self.is_production = not getattr(settings, "DEBUG", True)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Basic security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy (disable dangerous features)
        response["Permissions-Policy"] = (
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), "
            "camera=(), display-capture=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), midi=(), payment=(), usb=()"
        )

        # Content-Security-Policy (basic - customize per deployment)
        if "Content-Security-Policy" not in response:
            csp_directives = [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data: https:",
                "font-src 'self'",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ]
            response["Content-Security-Policy"] = "; ".join(csp_directives)

        # HSTS in production (2 years, include subdomains)
        if self.is_production:
            response["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response


class UserContextMiddleware:
    """
    Middleware that sets user context for logging.

    Extracts user_id and tenant_id from authenticated requests
    and sets them in the logging context.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Set user context if authenticated
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            set_user_context(user_id=str(user.pk))

        # Extract tenant from request if available
        tenant_id = getattr(request, "tenant_id", None)
        if tenant_id:
            set_user_context(tenant_id=str(tenant_id))

        return self.get_response(request)


class RequestLoggingMiddleware:
    """
    Middleware that logs incoming requests and outgoing responses.

    Logs:
    - Request method, path, user agent
    - Response status code, duration
    - Errors with stack traces
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        # Paths to skip logging (health checks, metrics)
        self.skip_paths = {"/health", "/metrics", "/.well-known/jwks.json"}

    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path

        # Skip logging for noisy endpoints
        if path in self.skip_paths:
            return self.get_response(request)

        start_time = time.perf_counter()

        # Log request (debug level)
        request_extra = sanitize_log_data(
            {
                "method": request.method,
                "path": path,
                "user_agent": request.headers.get("User-Agent", "")[:100],
                "content_length": request.headers.get("Content-Length", "0"),
            }
        )
        logger.debug(
            "Request started",
            extra=request_extra,
        )

        try:
            response = self.get_response(request)

            duration_ms = (time.perf_counter() - start_time) * 1000

            # Log response
            log_level = logging.INFO if response.status_code < 400 else logging.WARNING
            response_extra = sanitize_log_data(
                {
                    "method": request.method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                    "content_length": response.get("Content-Length", "0"),
                }
            )
            logger.log(
                log_level,
                "Request completed",
                extra=response_extra,
            )

            return response

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_extra = sanitize_log_data(
                {
                    "method": request.method,
                    "path": path,
                    "duration_ms": round(duration_ms, 2),
                    "exception_type": type(e).__name__,
                    "exception_message": str(e),
                }
            )
            logger.error(
                "Request failed with exception",
                extra=error_extra,
                exc_info=True,
            )
            raise
