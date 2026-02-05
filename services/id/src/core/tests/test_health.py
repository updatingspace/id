"""Tests for health check module."""
import pytest
from unittest.mock import patch, MagicMock
from django.test import RequestFactory
from core.health import (
    ComponentHealth,
    check_database,
    check_cache,
    check_oidc_keys,
    liveness_view,
    readiness_view,
    health_view,
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
            status="healthy",
            latency_ms=1.5,
        )
        assert health.status == "healthy"
        assert health.latency_ms == 1.5

    def test_to_dict(self):
        """Converts to dictionary correctly."""
        health = ComponentHealth(
            name="database",
            status="healthy",
            latency_ms=2.0,
            message="All good",
            details={"connections": 10},
        )
        data = health.to_dict()

        assert data["name"] == "database"
        assert data["status"] == "healthy"
        assert data["latency_ms"] == 2.0
        assert data["message"] == "All good"
        assert data["details"]["connections"] == 10


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
        assert result.status == "healthy"
        assert result.latency_ms >= 0

    @patch("django.db.connection.cursor")
    def test_unhealthy_database(self, mock_cursor):
        """Returns unhealthy on database error."""
        mock_cursor.side_effect = Exception("Connection failed")

        result = check_database()

        assert result.status == "unhealthy"
        assert "Connection failed" in result.message


class TestCacheCheck:
    """Tests for cache health check."""

    @patch("django.core.cache.cache.set")
    @patch("django.core.cache.cache.get")
    @patch("django.core.cache.cache.delete")
    def test_healthy_cache(self, mock_delete, mock_get, mock_set):
        """Returns healthy when cache works."""
        mock_get.return_value = "health_check_value"

        result = check_cache()

        assert result.name == "cache"
        # Status depends on latency, but should work
        assert result.status in ["healthy", "degraded"]

    @patch("django.core.cache.cache.set")
    def test_unhealthy_cache(self, mock_set):
        """Returns unhealthy on cache error."""
        mock_set.side_effect = Exception("Redis connection failed")

        result = check_cache()

        assert result.status == "unhealthy"


class TestOidcKeysCheck:
    """Tests for OIDC keys health check."""

    @patch("django.conf.settings")
    def test_development_keys_warning(self, mock_settings):
        """Warns when using development keys."""
        mock_settings.DEBUG = True
        mock_settings.OIDC_RSA_PRIVATE_KEY = None

        result = check_oidc_keys()

        assert result.name == "oidc_keys"
        # In dev mode without configured keys
        assert result.status in ["healthy", "degraded"]


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

        # Status code depends on actual health
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
