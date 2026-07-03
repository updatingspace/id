"""
Production monitoring and observability for UpdSpace ID Service.

This module provides:
- Prometheus metrics for auth, OIDC, and system operations
- Business metrics tracking (logins, MFA enrollments, token issuance)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from functools import wraps

from prometheus_client import Counter

logger = logging.getLogger(__name__)


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


AUTH_LOGIN_ATTEMPTS = Counter(
    AUTH_LOGIN_ATTEMPTS_TOTAL,
    "Total login attempts.",
    ("method",),
)
AUTH_LOGIN_SUCCESS = Counter(
    AUTH_LOGIN_SUCCESS_TOTAL,
    "Total successful logins.",
    ("method",),
)
AUTH_LOGIN_FAILURE = Counter(
    AUTH_LOGIN_FAILURE_TOTAL,
    "Total failed logins.",
    ("method", "reason"),
)
MFA_ENROLLMENT = Counter(
    MFA_ENROLLMENT_TOTAL,
    "Total MFA enrollment events.",
    ("method", "success"),
)
MFA_VERIFICATION = Counter(
    MFA_VERIFICATION_TOTAL,
    "Total MFA verification events.",
    ("method", "success"),
)
MFA_RECOVERY_CODE_USED = Counter(
    MFA_RECOVERY_CODE_USED_TOTAL,
    "Total MFA recovery code use events.",
    ("method", "success"),
)
PASSKEY_REGISTRATION = Counter(
    PASSKEY_REGISTRATION_TOTAL,
    "Total passkey registration events.",
    ("success",),
)
PASSKEY_AUTHENTICATION = Counter(
    PASSKEY_AUTHENTICATION_TOTAL,
    "Total passkey authentication events.",
    ("success",),
)
OIDC_TOKEN_ISSUED = Counter(
    OIDC_TOKEN_ISSUED_TOTAL,
    "Total OIDC token issued events.",
    ("success", "client_id", "grant_type"),
)
OIDC_TOKEN_REFRESH = Counter(
    OIDC_TOKEN_REFRESH_TOTAL,
    "Total OIDC token refresh events.",
    ("success", "client_id", "grant_type"),
)
OIDC_TOKEN_REVOKED = Counter(
    OIDC_TOKEN_REVOKED_TOTAL,
    "Total OIDC token revoked events.",
    ("success", "client_id", "grant_type"),
)
OIDC_AUTHORIZATION_APPROVED = Counter(
    OIDC_AUTHORIZATION_APPROVED_TOTAL,
    "Total OIDC authorization approved events.",
    ("success", "client_id", "grant_type"),
)
OIDC_AUTHORIZATION_DENIED = Counter(
    OIDC_AUTHORIZATION_DENIED_TOTAL,
    "Total OIDC authorization denied events.",
    ("success", "client_id", "grant_type"),
)
OIDC_USERINFO_REQUESTS = Counter(
    OIDC_USERINFO_REQUESTS_TOTAL,
    "Total OIDC userinfo request events.",
    ("success", "client_id", "grant_type"),
)
RATE_LIMIT_TRIGGERED = Counter(
    RATE_LIMIT_TRIGGERED_TOTAL,
    "Total rate limit events.",
    ("scope", "identifier_type"),
)
SESSION_CREATED = Counter(
    SESSION_CREATED_TOTAL,
    "Total session creation events.",
)
SESSION_REVOKED = Counter(
    SESSION_REVOKED_TOTAL,
    "Total session revocation events.",
    ("reason",),
)
ERRORS = Counter(
    ERRORS_TOTAL,
    "Total application errors.",
    ("code", "endpoint"),
)

_OIDC_COUNTERS = {
    "token_issued": OIDC_TOKEN_ISSUED,
    "token_refresh": OIDC_TOKEN_REFRESH,
    "token_revoked": OIDC_TOKEN_REVOKED,
    "authorization_approved": OIDC_AUTHORIZATION_APPROVED,
    "authorization_denied": OIDC_AUTHORIZATION_DENIED,
    "userinfo": OIDC_USERINFO_REQUESTS,
}


# ============================================================================
# Instrumentation helpers
# ============================================================================


def track_login_attempt(
    success: bool, method: str = "password", reason: str | None = None
) -> None:
    """Track login attempt metrics."""
    AUTH_LOGIN_ATTEMPTS.labels(method=method).inc()
    if success:
        AUTH_LOGIN_SUCCESS.labels(method=method).inc()
    else:
        AUTH_LOGIN_FAILURE.labels(method=method, reason=reason or "unknown").inc()


def track_mfa_event(
    event_type: str, method: str = "totp", success: bool = True
) -> None:
    """Track MFA-related events."""
    labels = {"method": method, "success": str(success).lower()}
    if event_type == "enrollment":
        MFA_ENROLLMENT.labels(**labels).inc()
    elif event_type == "verification":
        MFA_VERIFICATION.labels(**labels).inc()
    elif event_type == "recovery":
        MFA_RECOVERY_CODE_USED.labels(**labels).inc()


def track_passkey_event(event_type: str, success: bool = True) -> None:
    """Track passkey/WebAuthn events."""
    if event_type == "registration":
        PASSKEY_REGISTRATION.labels(success=str(success).lower()).inc()
    elif event_type == "authentication":
        PASSKEY_AUTHENTICATION.labels(success=str(success).lower()).inc()


def track_oidc_event(
    event_type: str,
    client_id: str | None = None,
    grant_type: str | None = None,
    success: bool = True,
) -> None:
    """Track OIDC-related events."""
    counter = _OIDC_COUNTERS.get(event_type)
    if counter:
        counter.labels(
            success=str(success).lower(),
            client_id=(client_id or "")[:32],
            grant_type=grant_type or "",
        ).inc()


def track_rate_limit(scope: str, identifier_type: str) -> None:
    """Track when rate limiting is triggered."""
    RATE_LIMIT_TRIGGERED.labels(scope=scope, identifier_type=identifier_type).inc()


def track_session_event(event_type: str, reason: str | None = None) -> None:
    """Track session lifecycle events."""
    if event_type == "created":
        SESSION_CREATED.inc()
    elif event_type == "revoked":
        SESSION_REVOKED.labels(reason=reason or "user_requested").inc()


def track_error(error_code: str, endpoint: str | None = None) -> None:
    """Track error occurrences."""
    ERRORS.labels(code=error_code, endpoint=endpoint or "").inc()


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
                logger.debug(
                    "Instrumented function completed",
                    extra={
                        "metric": metric_name,
                        "duration_seconds": duration,
                        **labels,
                    },
                )

        return wrapper

    return decorator
