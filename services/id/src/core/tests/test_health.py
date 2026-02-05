"""Tests for health check module."""

from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from core.health import (
    ComponentHealth,
    HealthStatus,
    check_cache,
    check_database,
    check_oidc_keys,
    health_view,
    liveness_view,
    readiness_view,
)


@pytest.fixture
def request_factory():
    """Django request factory."""
    return RequestFactory()


class TestComponentHealth:
    """Tests for ComponentHealth dataclass."""

    def test_healthy_component(self):
        """Healthy component has correct status."""
        health = ComponentHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            latency_ms=1.5,
        )
        assert health.status == HealthStatus.HEALTHY
        assert health.latency_ms == 1.5


class TestDatabaseCheck:
    """Tests for database health check."""

    @patch("django.db.connection.cursor")
    def test_healthy_database(self, mock_cursor):
        """Returns healthy when database responds."""
        mock_ctx = MagicMock()
        mock_ctx.fetchone.return_value = (1,)
        mock_cursor.return_value.__enter__ = lambda s: mock_ctx
        mock_cursor.return_value.__exit__ = MagicMock()

        result = check_database()

        assert result.name == "database"
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
        assert result.latency_ms is not None

    @patch("django.db.connection.cursor")
    def test_unhealthy_database(self, mock_cursor):
        """Returns unhealthy on database error."""
        mock_cursor.side_effect = Exception("Connection failed")

        result = check_database()

        assert result.status == HealthStatus.UNHEALTHY
        assert "Connection failed" in str(result.message)


class TestCacheCheck:
    """Tests for cache health check."""

    @patch("django.core.cache.cache.set")
    @patch("django.core.cache.cache.get")
    @patch("django.core.cache.cache.delete")
    def test_healthy_cache(self, mock_delete, mock_get, mock_set):
        """Returns healthy/degraded when cache works."""
        mock_get.return_value = "health_check_value"

        result = check_cache()

        assert result.name == "cache"
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
        mock_set.assert_called_once()
        mock_delete.assert_called_once()

    @patch("django.core.cache.cache.set")
    def test_cache_failure_is_degraded(self, mock_set):
        """Cache failures should degrade service, not mark unhealthy."""
        mock_set.side_effect = Exception("Redis connection failed")

        result = check_cache()

        assert result.status == HealthStatus.DEGRADED


class TestOidcKeysCheck:
    """Tests for OIDC keys health check."""

    @patch("django.conf.settings")
    def test_development_keys_warning(self, mock_settings):
        """Warns when key material is not configured."""
        mock_settings.OIDC_PRIVATE_KEY_PEM = None
        mock_settings.OIDC_KEY_PAIRS = None

        result = check_oidc_keys()

        assert result.name == "oidc_keys"
        assert result.status == HealthStatus.DEGRADED


@pytest.mark.django_db
class TestHealthViews:
    """Tests for health endpoint views."""

    def test_liveness_returns_alive(self, request_factory):
        """Liveness probe returns alive status."""
        request = request_factory.get("/healthz")

        response = liveness_view(request)

        assert response.status_code == 200
        import json

        data = json.loads(response.content)
        assert data["status"] == "alive"

    def test_readiness_returns_status(self, request_factory):
        """Readiness probe returns ready/not-ready status."""
        request = request_factory.get("/readyz")

        response = readiness_view(request)

        assert response.status_code in [200, 503]

    def test_health_returns_details(self, request_factory):
        """Health endpoint returns detailed status."""
        request = request_factory.get("/health")

        response = health_view(request)

        import json

        data = json.loads(response.content)

        assert "status" in data
        assert "version" in data
        assert "components" in data
        assert "uptime_seconds" in data
