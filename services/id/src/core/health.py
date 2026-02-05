"""
Health check endpoints for UpdSpace ID Service.

Provides:
- Liveness probe: Is the service running?
- Readiness probe: Is the service ready to accept traffic?
- Detailed health status: Database, cache, external services
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import HttpRequest, JsonResponse

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status of a single component."""
    name: str
    status: HealthStatus
    latency_ms: float | None = None
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Overall health check result."""
    status: HealthStatus
    components: list[ComponentHealth]
    version: str = "1.0.0"
    uptime_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
            "components": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "latency_ms": c.latency_ms,
                    "message": c.message,
                    **({"details": c.details} if c.details else {}),
                }
                for c in self.components
            ],
        }


# Track service start time for uptime calculation
_service_start_time: float | None = None


def set_service_start_time() -> None:
    """Set the service start time (call during startup)."""
    global _service_start_time
    _service_start_time = time.time()


def get_uptime_seconds() -> float | None:
    """Get service uptime in seconds."""
    if _service_start_time is None:
        return None
    return time.time() - _service_start_time


# ============================================================================
# Component health checks
# ============================================================================

def check_database() -> ComponentHealth:
    """Check database connectivity and basic operations."""
    start = time.perf_counter()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        latency_ms = (time.perf_counter() - start) * 1000
        
        # Check if latency is acceptable (< 100ms)
        if latency_ms > 100:
            return ComponentHealth(
                name="database",
                status=HealthStatus.DEGRADED,
                latency_ms=round(latency_ms, 2),
                message="High latency detected",
            )
        
        return ComponentHealth(
            name="database",
            status=HealthStatus.HEALTHY,
            latency_ms=round(latency_ms, 2),
        )
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        logger.error(f"Database health check failed: {e}", exc_info=True)
        return ComponentHealth(
            name="database",
            status=HealthStatus.UNHEALTHY,
            latency_ms=round(latency_ms, 2),
            message=str(e),
        )


def check_cache() -> ComponentHealth:
    """Check cache (Redis) connectivity."""
    start = time.perf_counter()
    test_key = "_health_check_test"
    test_value = str(time.time())
    
    try:
        # Test write
        cache.set(test_key, test_value, timeout=10)
        
        # Test read
        retrieved = cache.get(test_key)
        
        # Test delete
        cache.delete(test_key)
        
        latency_ms = (time.perf_counter() - start) * 1000
        
        if retrieved != test_value:
            return ComponentHealth(
                name="cache",
                status=HealthStatus.DEGRADED,
                latency_ms=round(latency_ms, 2),
                message="Cache read/write inconsistency",
            )
        
        # Check if latency is acceptable (< 50ms for cache)
        if latency_ms > 50:
            return ComponentHealth(
                name="cache",
                status=HealthStatus.DEGRADED,
                latency_ms=round(latency_ms, 2),
                message="High latency detected",
            )
        
        return ComponentHealth(
            name="cache",
            status=HealthStatus.HEALTHY,
            latency_ms=round(latency_ms, 2),
        )
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        logger.warning(f"Cache health check failed: {e}")
        
        # Cache failure is degraded, not unhealthy (service can work without it)
        return ComponentHealth(
            name="cache",
            status=HealthStatus.DEGRADED,
            latency_ms=round(latency_ms, 2),
            message=str(e),
        )


def check_oidc_keys() -> ComponentHealth:
    """Check OIDC signing keys are configured."""
    start = time.perf_counter()
    
    try:
        # Check if OIDC keys are configured
        private_key = getattr(settings, "OIDC_PRIVATE_KEY_PEM", None)
        public_key = getattr(settings, "OIDC_PUBLIC_KEY_PEM", None)
        key_pairs = getattr(settings, "OIDC_KEY_PAIRS", None)
        
        latency_ms = (time.perf_counter() - start) * 1000
        
        if not private_key and not key_pairs:
            return ComponentHealth(
                name="oidc_keys",
                status=HealthStatus.DEGRADED,
                latency_ms=round(latency_ms, 2),
                message="OIDC keys not configured - using development keys",
                details={"configured": False},
            )
        
        # Try to load and validate keys
        from idp.keys import KeyManager
        jwks = KeyManager.jwks()
        
        if not jwks.get("keys"):
            return ComponentHealth(
                name="oidc_keys",
                status=HealthStatus.UNHEALTHY,
                latency_ms=round(latency_ms, 2),
                message="No valid OIDC keys found",
            )
        
        return ComponentHealth(
            name="oidc_keys",
            status=HealthStatus.HEALTHY,
            latency_ms=round(latency_ms, 2),
            details={"key_count": len(jwks["keys"])},
        )
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        logger.error(f"OIDC keys health check failed: {e}", exc_info=True)
        return ComponentHealth(
            name="oidc_keys",
            status=HealthStatus.UNHEALTHY,
            latency_ms=round(latency_ms, 2),
            message=str(e),
        )


def check_email_backend() -> ComponentHealth:
    """Check email backend configuration."""
    start = time.perf_counter()
    
    try:
        from django.core.mail import get_connection
        
        email_backend = getattr(settings, "EMAIL_BACKEND", "")
        latency_ms = (time.perf_counter() - start) * 1000
        
        # Console backend is not production-ready
        if "console" in email_backend.lower() or "filebased" in email_backend.lower():
            return ComponentHealth(
                name="email",
                status=HealthStatus.DEGRADED,
                latency_ms=round(latency_ms, 2),
                message="Non-production email backend",
                details={"backend": email_backend},
            )
        
        # Try to get connection (doesn't actually connect)
        get_connection()
        
        return ComponentHealth(
            name="email",
            status=HealthStatus.HEALTHY,
            latency_ms=round(latency_ms, 2),
            details={"backend": email_backend},
        )
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return ComponentHealth(
            name="email",
            status=HealthStatus.DEGRADED,
            latency_ms=round(latency_ms, 2),
            message=str(e),
        )


# ============================================================================
# Health check endpoints
# ============================================================================

def run_health_check(*, include_details: bool = True) -> HealthCheckResult:
    """
    Run all health checks and return aggregated result.
    
    Args:
        include_details: Whether to include detailed component checks.
    """
    components: list[ComponentHealth] = []
    
    if include_details:
        components = [
            check_database(),
            check_cache(),
            check_oidc_keys(),
            check_email_backend(),
        ]
    
    # Determine overall status
    statuses = [c.status for c in components]
    
    if HealthStatus.UNHEALTHY in statuses:
        overall_status = HealthStatus.UNHEALTHY
    elif HealthStatus.DEGRADED in statuses:
        overall_status = HealthStatus.DEGRADED
    else:
        overall_status = HealthStatus.HEALTHY
    
    return HealthCheckResult(
        status=overall_status,
        components=components,
        uptime_seconds=get_uptime_seconds(),
    )


def liveness_view(request: HttpRequest) -> JsonResponse:
    """
    Liveness probe endpoint.
    
    Returns 200 if the service is running.
    Used by Kubernetes to determine if the pod should be restarted.
    """
    return JsonResponse({"status": "alive"})


def readiness_view(request: HttpRequest) -> JsonResponse:
    """
    Readiness probe endpoint.
    
    Returns 200 if the service is ready to accept traffic.
    Checks database connectivity.
    Used by Kubernetes to determine if traffic should be routed to this pod.
    """
    db_health = check_database()
    
    if db_health.status == HealthStatus.UNHEALTHY:
        return JsonResponse(
            {"status": "not_ready", "reason": db_health.message},
            status=503,
        )
    
    return JsonResponse({"status": "ready"})


def health_view(request: HttpRequest) -> JsonResponse:
    """
    Detailed health check endpoint.
    
    Returns comprehensive health status including all components.
    """
    result = run_health_check(include_details=True)
    
    status_code = 200
    if result.status == HealthStatus.UNHEALTHY:
        status_code = 503
    elif result.status == HealthStatus.DEGRADED:
        status_code = 200  # Still return 200 for degraded (service is operational)
    
    return JsonResponse(result.to_dict(), status=status_code)
