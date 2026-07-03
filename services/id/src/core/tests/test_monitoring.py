"""Tests for monitoring module."""

from django.test import RequestFactory
from django_prometheus.exports import ExportToDjangoView
from prometheus_client import REGISTRY

from core.monitoring import (
    AUTH_LOGIN_ATTEMPTS_TOTAL,
    AUTH_LOGIN_FAILURE_TOTAL,
    AUTH_LOGIN_SUCCESS_TOTAL,
    track_login_attempt,
    track_oidc_event,
)


def _sample_value(name: str, labels: dict[str, str]) -> float:
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if sample.name == name and sample.labels == labels:
                return float(sample.value)
    return 0.0


class TestTrackingFunctions:
    """Tests for tracking helper functions."""

    def test_track_login_attempt_success(self):
        """Track successful login."""
        labels = {"method": "password"}
        before_attempts = _sample_value(AUTH_LOGIN_ATTEMPTS_TOTAL, labels)
        before_success = _sample_value(AUTH_LOGIN_SUCCESS_TOTAL, labels)

        track_login_attempt(success=True, method="password")

        assert _sample_value(AUTH_LOGIN_ATTEMPTS_TOTAL, labels) == before_attempts + 1
        assert _sample_value(AUTH_LOGIN_SUCCESS_TOTAL, labels) == before_success + 1

    def test_track_login_attempt_failure(self):
        """Track failed login."""
        attempts_labels = {"method": "password"}
        failure_labels = {"method": "password", "reason": "invalid_password"}
        before_attempts = _sample_value(AUTH_LOGIN_ATTEMPTS_TOTAL, attempts_labels)
        before_failures = _sample_value(AUTH_LOGIN_FAILURE_TOTAL, failure_labels)

        track_login_attempt(success=False, method="password", reason="invalid_password")

        assert (
            _sample_value(AUTH_LOGIN_ATTEMPTS_TOTAL, attempts_labels)
            == before_attempts + 1
        )
        assert (
            _sample_value(AUTH_LOGIN_FAILURE_TOTAL, failure_labels)
            == before_failures + 1
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

    def test_django_prometheus_export_contains_business_metrics(self):
        """Export produces valid Prometheus format."""
        track_login_attempt(success=True, method="password")

        response = ExportToDjangoView(RequestFactory().get("/metrics"))
        output = response.content.decode("utf-8")

        assert "# HELP" in output
        assert "# TYPE" in output
        assert AUTH_LOGIN_ATTEMPTS_TOTAL in output
