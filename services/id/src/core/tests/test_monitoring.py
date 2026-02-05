"""Tests for monitoring module."""
import pytest
from core.monitoring import MetricsRegistry, track_login_attempt, track_oidc_event


class TestMetricsRegistry:
    """Tests for MetricsRegistry singleton."""

    def test_singleton_instance(self):
        """Registry returns same instance."""
        reg1 = MetricsRegistry()
        reg2 = MetricsRegistry()
        assert reg1 is reg2

    def test_counter_increment(self):
        """Counter increments correctly."""
        registry = MetricsRegistry()
        registry.counter("test_counter", labels={"type": "test"})
        registry.counter("test_counter", labels={"type": "test"})

        stats = registry._counters.get("test_counter", {})
        assert stats.get(("type", "test"), 0) >= 2

    def test_gauge_set(self):
        """Gauge sets value correctly."""
        registry = MetricsRegistry()
        registry.gauge("test_gauge", 42.5)

        assert registry._gauges.get("test_gauge") == 42.5

    def test_histogram_observe(self):
        """Histogram records observations."""
        registry = MetricsRegistry()
        registry.histogram(
            "test_histogram", 0.5, labels={"method": "GET"}
        )

        key = "test_histogram"
        assert key in registry._histograms


class TestTrackingFunctions:
    """Tests for tracking helper functions."""

    def test_track_login_attempt_success(self):
        """Track successful login."""
        # Should not raise
        track_login_attempt(
            success=True,
            user_id="test-user-123",
            method="password",
        )

    def test_track_login_attempt_failure(self):
        """Track failed login."""
        track_login_attempt(
            success=False,
            method="password",
            failure_reason="invalid_password",
        )

    def test_track_oidc_event(self):
        """Track OIDC events."""
        track_oidc_event(
            event_type="token_issued",
            client_id="test-client",
            grant_type="authorization_code",
        )


class TestPrometheusExport:
    """Tests for Prometheus export format."""

    def test_export_format(self):
        """Export produces valid Prometheus format."""
        registry = MetricsRegistry()
        registry.counter("export_test_total", labels={"status": "200"})

        output = registry.export_prometheus()

        assert "# HELP" in output
        assert "# TYPE" in output
        assert "export_test_total" in output
