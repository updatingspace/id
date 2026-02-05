"""
Production monitoring and observability for UpdSpace ID Service.

This module provides:
- Prometheus metrics for auth, OIDC, and system operations
- Request/response instrumentation
- Business metrics tracking (logins, MFA enrollments, token issuance)
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

logger = logging.getLogger(__name__)


class MetricsRegistry:
    """
    Simple in-memory metrics registry for Prometheus-style metrics.
    In production, replace with prometheus_client library.
    """

    _instance: MetricsRegistry | None = None
    
    def __new__(cls) -> MetricsRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._counters: dict[str, dict[tuple, int]] = {}
            cls._instance._histograms: dict[str, dict[tuple, list[float]]] = {}
            cls._instance._gauges: dict[str, dict[tuple, float]] = {}
        return cls._instance

    def inc_counter(self, name: str, labels: dict[str, str] | None = None, value: int = 1) -> None:
        """Increment a counter metric."""
        if name not in self._counters:
            self._counters[name] = {}
        label_key = tuple(sorted((labels or {}).items()))
        self._counters[name][label_key] = self._counters[name].get(label_key, 0) + value

    def observe_histogram(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Record a histogram observation."""
        if name not in self._histograms:
            self._histograms[name] = {}
        label_key = tuple(sorted((labels or {}).items()))
        if label_key not in self._histograms[name]:
            self._histograms[name][label_key] = []
        # Keep last 1000 observations per label set
        observations = self._histograms[name][label_key]
        observations.append(value)
        if len(observations) > 1000:
            self._histograms[name][label_key] = observations[-1000:]

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge metric."""
        if name not in self._gauges:
            self._gauges[name] = {}
        label_key = tuple(sorted((labels or {}).items()))
        self._gauges[name][label_key] = value

    def get_all_metrics(self) -> dict[str, Any]:
        """Export all metrics in a format suitable for Prometheus exposition."""
        return {
            "counters": {
                name: {str(labels): count for labels, count in values.items()}
                for name, values in self._counters.items()
            },
            "histograms": {
                name: {
                    str(labels): {
                        "count": len(obs),
                        "sum": sum(obs),
                        "avg": sum(obs) / len(obs) if obs else 0,
                        "min": min(obs) if obs else 0,
                        "max": max(obs) if obs else 0,
                    }
                    for labels, obs in values.items()
                }
                for name, values in self._histograms.items()
            },
            "gauges": {
                name: {str(labels): value for labels, value in values.items()}
                for name, values in self._gauges.items()
            },
        }

    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        self._counters.clear()
        self._histograms.clear()
        self._gauges.clear()


# Global metrics registry
metrics = MetricsRegistry()


# ============================================================================
# Metric Names (constants for consistency)
# ============================================================================

# HTTP Request metrics
HTTP_REQUESTS_TOTAL = "id_http_requests_total"
HTTP_REQUEST_DURATION_SECONDS = "id_http_request_duration_seconds"
HTTP_REQUESTS_IN_FLIGHT = "id_http_requests_in_flight"

# Authentication metrics
AUTH_LOGIN_ATTEMPTS_TOTAL = "id_auth_login_attempts_total"
AUTH_LOGIN_SUCCESS_TOTAL = "id_auth_login_success_total"
AUTH_LOGIN_FAILURE_TOTAL = "id_auth_login_failure_total"
AUTH_LOGOUT_TOTAL = "id_auth_logout_total"

# MFA metrics
MFA_ENROLLMENT_TOTAL = "id_mfa_enrollment_total"
MFA_VERIFICATION_TOTAL = "id_mfa_verification_total"
MFA_RECOVERY_CODE_USED_TOTAL = "id_mfa_recovery_code_used_total"

# Passkey metrics
PASSKEY_REGISTRATION_TOTAL = "id_passkey_registration_total"
PASSKEY_AUTHENTICATION_TOTAL = "id_passkey_authentication_total"

# OIDC metrics
OIDC_TOKEN_ISSUED_TOTAL = "id_oidc_token_issued_total"
OIDC_TOKEN_REFRESH_TOTAL = "id_oidc_token_refresh_total"
OIDC_TOKEN_REVOKED_TOTAL = "id_oidc_token_revoked_total"
OIDC_AUTHORIZATION_APPROVED_TOTAL = "id_oidc_authorization_approved_total"
OIDC_AUTHORIZATION_DENIED_TOTAL = "id_oidc_authorization_denied_total"
OIDC_USERINFO_REQUESTS_TOTAL = "id_oidc_userinfo_requests_total"

# Rate limiting metrics
RATE_LIMIT_TRIGGERED_TOTAL = "id_rate_limit_triggered_total"

# Session metrics
SESSION_CREATED_TOTAL = "id_session_created_total"
SESSION_REVOKED_TOTAL = "id_session_revoked_total"

# Error metrics
ERRORS_TOTAL = "id_errors_total"


# ============================================================================
# Instrumentation helpers
# ============================================================================

def track_login_attempt(success: bool, method: str = "password", reason: str | None = None) -> None:
    """Track login attempt metrics."""
    labels = {"method": method}
    metrics.inc_counter(AUTH_LOGIN_ATTEMPTS_TOTAL, labels)
    if success:
        metrics.inc_counter(AUTH_LOGIN_SUCCESS_TOTAL, labels)
    else:
        failure_labels = {**labels, "reason": reason or "unknown"}
        metrics.inc_counter(AUTH_LOGIN_FAILURE_TOTAL, failure_labels)


def track_mfa_event(event_type: str, method: str = "totp", success: bool = True) -> None:
    """Track MFA-related events."""
    labels = {"method": method, "success": str(success).lower()}
    if event_type == "enrollment":
        metrics.inc_counter(MFA_ENROLLMENT_TOTAL, labels)
    elif event_type == "verification":
        metrics.inc_counter(MFA_VERIFICATION_TOTAL, labels)
    elif event_type == "recovery":
        metrics.inc_counter(MFA_RECOVERY_CODE_USED_TOTAL, labels)


def track_passkey_event(event_type: str, success: bool = True) -> None:
    """Track passkey/WebAuthn events."""
    labels = {"success": str(success).lower()}
    if event_type == "registration":
        metrics.inc_counter(PASSKEY_REGISTRATION_TOTAL, labels)
    elif event_type == "authentication":
        metrics.inc_counter(PASSKEY_AUTHENTICATION_TOTAL, labels)


def track_oidc_event(
    event_type: str,
    client_id: str | None = None,
    grant_type: str | None = None,
    success: bool = True,
) -> None:
    """Track OIDC-related events."""
    labels: dict[str, str] = {"success": str(success).lower()}
    if client_id:
        labels["client_id"] = client_id[:32]  # Truncate for cardinality control
    if grant_type:
        labels["grant_type"] = grant_type

    if event_type == "token_issued":
        metrics.inc_counter(OIDC_TOKEN_ISSUED_TOTAL, labels)
    elif event_type == "token_refresh":
        metrics.inc_counter(OIDC_TOKEN_REFRESH_TOTAL, labels)
    elif event_type == "token_revoked":
        metrics.inc_counter(OIDC_TOKEN_REVOKED_TOTAL, labels)
    elif event_type == "authorization_approved":
        metrics.inc_counter(OIDC_AUTHORIZATION_APPROVED_TOTAL, labels)
    elif event_type == "authorization_denied":
        metrics.inc_counter(OIDC_AUTHORIZATION_DENIED_TOTAL, labels)
    elif event_type == "userinfo":
        metrics.inc_counter(OIDC_USERINFO_REQUESTS_TOTAL, labels)


def track_rate_limit(scope: str, identifier_type: str) -> None:
    """Track when rate limiting is triggered."""
    labels = {"scope": scope, "identifier_type": identifier_type}
    metrics.inc_counter(RATE_LIMIT_TRIGGERED_TOTAL, labels)


def track_session_event(event_type: str, reason: str | None = None) -> None:
    """Track session lifecycle events."""
    if event_type == "created":
        metrics.inc_counter(SESSION_CREATED_TOTAL)
    elif event_type == "revoked":
        labels = {"reason": reason or "user_requested"}
        metrics.inc_counter(SESSION_REVOKED_TOTAL, labels)


def track_error(error_code: str, endpoint: str | None = None) -> None:
    """Track error occurrences."""
    labels = {"code": error_code}
    if endpoint:
        labels["endpoint"] = endpoint
    metrics.inc_counter(ERRORS_TOTAL, labels)


# ============================================================================
# Decorator for tracking function execution
# ============================================================================

def instrumented(
    metric_name: str,
    labels_fn: Callable[..., dict[str, str]] | None = None,
) -> Callable:
    """
    Decorator to instrument a function with timing metrics.
    
    Usage:
        @instrumented("id_service_operation_duration_seconds", 
                      labels_fn=lambda result: {"operation": "fetch_user"})
        def fetch_user(user_id):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            success = True
            try:
                result = func(*args, **kwargs)
                return result
            except Exception:
                success = False
                raise
            finally:
                duration = time.perf_counter() - start_time
                labels = labels_fn(*args, **kwargs) if labels_fn else {}
                labels["success"] = str(success).lower()
                metrics.observe_histogram(metric_name, duration, labels)
        return wrapper
    return decorator


# ============================================================================
# Prometheus metrics endpoint view
# ============================================================================

def prometheus_metrics_view(request: HttpRequest) -> HttpResponse:
    """
    Expose metrics in Prometheus text exposition format.
    
    Mount at /metrics in urls.py
    """
    all_metrics = metrics.get_all_metrics()
    
    lines = []
    lines.append("# HELP id_service_metrics UpdSpace ID Service metrics")
    lines.append("# TYPE id_service_info gauge")
    lines.append(f'id_service_info{{version="1.0.0"}} 1')
    lines.append("")
    
    # Export counters
    for name, label_values in all_metrics["counters"].items():
        lines.append(f"# HELP {name} Counter metric")
        lines.append(f"# TYPE {name} counter")
        for labels_str, count in label_values.items():
            # Convert string repr of tuple back to prometheus format
            label_part = _format_labels(labels_str)
            lines.append(f"{name}{label_part} {count}")
        lines.append("")
    
    # Export histograms (simplified - just sum and count)
    for name, label_values in all_metrics["histograms"].items():
        lines.append(f"# HELP {name} Histogram metric")
        lines.append(f"# TYPE {name} histogram")
        for labels_str, stats in label_values.items():
            label_part = _format_labels(labels_str)
            lines.append(f'{name}_count{label_part} {stats["count"]}')
            lines.append(f'{name}_sum{label_part} {stats["sum"]:.6f}')
        lines.append("")
    
    # Export gauges
    for name, label_values in all_metrics["gauges"].items():
        lines.append(f"# HELP {name} Gauge metric")
        lines.append(f"# TYPE {name} gauge")
        for labels_str, value in label_values.items():
            label_part = _format_labels(labels_str)
            lines.append(f"{name}{label_part} {value}")
        lines.append("")
    
    content = "\n".join(lines)
    return HttpResponse(content, content_type="text/plain; charset=utf-8")


def _format_labels(labels_str: str) -> str:
    """Convert labels string representation to Prometheus format."""
    if labels_str == "()" or not labels_str:
        return ""
    # Parse the tuple string and format as prometheus labels
    # e.g., "(('method', 'password'), ('success', 'true'))" -> {method="password",success="true"}
    try:
        # Safe eval alternative: parse manually
        import ast
        labels_tuple = ast.literal_eval(labels_str)
        if not labels_tuple:
            return ""
        parts = [f'{k}="{v}"' for k, v in labels_tuple]
        return "{" + ",".join(parts) + "}"
    except (ValueError, SyntaxError):
        return ""
