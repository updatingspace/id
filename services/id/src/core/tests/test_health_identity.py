"""Readiness refuses a runtime whose required identity schema is absent."""

from unittest.mock import patch

import pytest
from django.test import RequestFactory

from core.health import (
    ComponentHealth,
    HealthStatus,
    check_auth_schema,
    readiness_view,
)


@pytest.mark.parametrize("missing", ["accounts_accountidentity", "idp_oidctoken"])
def test_readiness_refuses_missing_identity_schema(missing):
    def execute(sql):
        if missing in sql:
            raise RuntimeError("private schema error")

    with patch("core.health.connection.cursor") as cursor:
        cursor.return_value.__enter__.return_value.execute.side_effect = execute
        assert check_auth_schema().status == HealthStatus.UNHEALTHY
        with patch(
            "core.health.check_database",
            return_value=ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY,
            ),
        ):
            response = readiness_view(RequestFactory().get("/readyz"))
    assert response.status_code == 503
    assert b"private" not in response.content


@pytest.mark.django_db
def test_current_identity_schema_is_ready():
    assert check_auth_schema().status == HealthStatus.HEALTHY
