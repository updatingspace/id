"""Tests for monitoring module."""

from django.test import RequestFactory

from core.monitoring import (
    AUTH_LOGIN_ATTEMPTS_TOTAL,
    AUTH_LOGIN_FAILURE_TOTAL,
    AUTH_LOGIN_SUCCESS_TOTAL,
    MetricsRegistry,
    track_login_attempt,
    track_oidc_event,
    prometheus_metrics_view,
)


class TestMetricsRegistry:
    """Tests for MetricsRegistry singleton."""

    def setup_method(self):
        MetricsRegistry().reset()

    def test_singleton_instance(self):
        """Registry returns same instance."""
        reg1 = MetricsRegistry()
        reg2 = MetricsRegistry()
        assert reg1 is reg2

    def test_counter_increment(self):
        """Counter increments correctly."""
        registry = MetricsRegistry()
        registry.inc_counter("test_counter", labels={"type": "test"})
        registry.inc_counter("test_counter", labels={"type": "test"})

        labels_key = tuple(sorted({"type": "test"}.items()))
        assert registry._counters["test_counter"][labels_key] == 2

    def test_gauge_set(self):
        """Gauge sets value correctly."""
        registry = MetricsRegistry()
        registry.set_gauge("test_gauge", 42.5)

        labels_key = tuple()
        assert registry._gauges["test_gauge"][labels_key] == 42.5

    def test_histogram_observe(self):
        """Histogram records observations."""
        registry = MetricsRegistry()
        registry.observe_histogram("test_histogram", 0.5, labels={"method": "GET"})

        key = tuple(sorted({"method": "GET"}.items()))
        assert registry._histograms["test_histogram"][key] == [0.5]


class TestTrackingFunctions:
    """Tests for tracking helper functions."""

    def setup_method(self):
        MetricsRegistry().reset()

    def test_track_login_attempt_success(self):
        """Track successful login."""
        track_login_attempt(success=True, method="password")

        counters = MetricsRegistry()._counters
        assert counters[AUTH_LOGIN_ATTEMPTS_TOTAL][(("method", "password"),)] == 1
        assert counters[AUTH_LOGIN_SUCCESS_TOTAL][(("method", "password"),)] == 1

    def test_track_login_attempt_failure(self):
        """Track failed login."""
        track_login_attempt(success=False, method="password", reason="invalid_password")

        counters = MetricsRegistry()._counters
        assert counters[AUTH_LOGIN_ATTEMPTS_TOTAL][(("method", "password"),)] == 1
        assert (
            counters[AUTH_LOGIN_FAILURE_TOTAL][
                (("method", "password"), ("reason", "invalid_password"))
            ]
            == 1
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

    def setup_method(self):
        MetricsRegistry().reset()

    def test_export_format(self):
        """Export produces valid Prometheus format."""
        registry = MetricsRegistry()
        registry.inc_counter("export_test_total", labels={"status": "200"})

        response = prometheus_metrics_view(RequestFactory().get("/metrics"))
        output = response.content.decode("utf-8")

        assert "# HELP" in output
        assert "# TYPE" in output
        assert "export_test_total" in output
