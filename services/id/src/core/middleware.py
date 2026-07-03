"""
Production middleware for UpdSpace ID Service.

Provides:
- Request ID propagation
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
    generate_request_id,
    request_path_var,
    sanitize_log_data,
    set_request_id,
    set_user_context,
)
from core.telemetry import annotate_current_span

logger = logging.getLogger(__name__)


class RequestIdMiddleware:
    """
    Middleware that propagates request IDs across requests.

    - Extracts X-Request-Id, then X-Correlation-ID from incoming requests
    - Generates new ID if not present
    - Adds request ID and compatibility correlation ID to response headers
    - Sets up logging context
    """

    REQUEST_HEADER_NAME = "X-Request-Id"
    CORRELATION_HEADER_NAME = "X-Correlation-ID"

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = (
            request.headers.get(self.REQUEST_HEADER_NAME)
            or request.headers.get(self.CORRELATION_HEADER_NAME)
            or generate_request_id()
        )

        # Set in context for logging
        set_request_id(request_id)
        request_path_var.set(request.path)

        # Attach to request for downstream use
        request.request_id = request_id  # type: ignore[attr-defined]
        request.correlation_id = request_id  # type: ignore[attr-defined]

        try:
            response = self.get_response(request)

            # Add canonical request ID and compatibility correlation ID to response
            response[self.REQUEST_HEADER_NAME] = request_id
            response[self.CORRELATION_HEADER_NAME] = request_id

            return response
        finally:
            # Clean up context
            clear_context()


CorrelationIdMiddleware = RequestIdMiddleware


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
        # Resolve user context defensively: request.user may trigger DB access
        # (e.g., SessionMiddleware/AuthMiddleware) and should not break request flow.
        try:
            user = getattr(request, "user", None)
        except Exception:
            logger.warning(
                "Failed to resolve request.user in UserContextMiddleware",
                exc_info=True,
            )
            user = None

        if user is not None:
            try:
                if getattr(user, "is_authenticated", False):
                    set_user_context(user_id=str(getattr(user, "pk", "")))
            except Exception:
                logger.warning(
                    "Failed to evaluate authenticated user in UserContextMiddleware",
                    exc_info=True,
                )

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
                "request_id": getattr(request, "request_id", None),
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
                    "request_id": getattr(request, "request_id", None),
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
            annotate_current_span(
                request,
                route=getattr(request, "resolver_match", None).route
                if getattr(request, "resolver_match", None)
                else path,
                status_code=response.status_code,
            )

            return response

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            error_extra = sanitize_log_data(
                {
                    "method": request.method,
                    "path": path,
                    "request_id": getattr(request, "request_id", None),
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
            annotate_current_span(request, route=path, status_code=500)
            raise
