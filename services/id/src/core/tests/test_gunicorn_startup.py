"""Verify that prepared master state is safe to fork with telemetry enabled."""

import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="Gunicorn container runs on Linux")
@pytest.mark.parametrize("driver", ["postgres", "ydb"])
def test_master_prepares_code_without_resources_and_worker_initializes_telemetry(
    driver: str,
):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json
import os
import socket
import sys
import traceback
from pathlib import Path
from unittest.mock import patch

from django.db.backends.base.base import BaseDatabaseWrapper
from app.gunicorn_config import on_starting

with patch.object(BaseDatabaseWrapper, 'ensure_connection', side_effect=AssertionError('master opened database')):
    with patch('ydb.Driver', side_effect=AssertionError('master created a YDB driver')):
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('master opened a network connection')):
            on_starting(None)

from django.db import connections
from core import telemetry
assert 'app.urls' in sys.modules
assert 'app.wsgi' not in sys.modules
assert 'opentelemetry.exporter.otlp.proto.grpc.trace_exporter' in sys.modules
assert not telemetry._configured
assert all(db.connection is None for db in connections.all(initialized_only=True))
assert len(list(Path('/proc/self/task').iterdir())) == 1, 'master started a native SDK thread'

pid = os.fork()
if pid == 0:
    try:
        with patch.object(BaseDatabaseWrapper, 'ensure_connection', side_effect=AssertionError('unexpected database access')):
            from app.wsgi import application
            from django.conf import settings
            from django.test import RequestFactory
            from opentelemetry.instrumentation.django import DjangoInstrumentor

            assert telemetry._configured
            assert DjangoInstrumentor().is_instrumented_by_opentelemetry
            assert any('opentelemetry' in middleware for middleware in settings.MIDDLEWARE)
            # Initialization runs before WSGIHandler loads middleware, rather
            # than mutating settings after the handler has already been built.
            assert any(middleware.__module__.startswith('opentelemetry') for middleware in application._view_middleware)
            factory = RequestFactory()
            for path, expected in [('/healthz', {'status': 'alive'}), ('/api/v1/auth/me', {'user': None})]:
                responses = []
                def start_response(status, headers):
                    responses.append((status, dict(headers)))
                response = application(factory.get(path).environ, start_response)
                try:
                    assert json.loads(b''.join(response)) == expected
                finally:
                    response.close()
                assert responses[0][0].startswith('200 ')
                if path.endswith('/me'):
                    assert responses[0][1]['Cache-Control'] == 'private, no-store'
    except BaseException:
        traceback.print_exc()
        os._exit(1)
    os._exit(0)

_, status = os.waitpid(pid, 0)
assert os.waitstatus_to_exitcode(status) == 0
assert not telemetry._configured, 'worker configuration leaked into the master'
assert len(list(Path('/proc/self/task').iterdir())) == 1
print('master preparation and worker telemetry passed')
""",
        ],
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "app.settings",
            "DJANGO_DEBUG": "true",
            "DJANGO_SECRET_KEY": "local-master-startup-test-secret-32-characters",
            "DJANGO_ALLOWED_HOSTS": "testserver,localhost",
            "DB_DRIVER": driver,
            "DATABASE_URL": "",
            "YDB_ENDPOINT": "grpc://127.0.0.1:2136",
            "YDB_DATABASE": "/local",
            "REDIS_URL": "",
            "OTEL_ENABLED": "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
            "OTEL_EXPORTER_OTLP_HEADERS": "",
            "MONIUM_API_KEY": "",
            "OTEL_TRACES_SAMPLER": "always_off",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "master preparation and worker telemetry passed" in result.stdout
