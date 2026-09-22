"""Exercise a fresh worker, independently of pytest's already imported URL tree."""

import os
import subprocess
import sys


def test_worker_initializes_routes_without_database_and_serves_public_reads():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json
import sys
from unittest.mock import patch
from django.db.backends.base.base import BaseDatabaseWrapper

with patch.object(BaseDatabaseWrapper, 'ensure_connection', side_effect=AssertionError('unexpected database access')):
    from app.wsgi import application
    from django.test import RequestFactory

    assert 'app.urls' in sys.modules, 'routes must be ready before requests arrive'
    factory = RequestFactory()
    for path, expected in [('/healthz', {'status': 'alive'}), ('/api/v1/auth/me', {'user': None})]:
        status_headers = []
        def start_response(status, headers):
            status_headers.append((status, dict(headers)))
        response = application(factory.get(path).environ, start_response)
        try:
            payload = json.loads(b''.join(response))
        finally:
            response.close()
        status, headers = status_headers[0]
        assert status.startswith('200 '), status
        assert payload == expected, payload
        if path.endswith('/me'):
            assert headers['Cache-Control'] == 'private, no-store'
print('worker startup and public requests passed')
""",
        ],
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "app.settings",
            "DJANGO_DEBUG": "true",
            "DJANGO_SECRET_KEY": "local-worker-startup-test-secret-32-characters",
            "DJANGO_ALLOWED_HOSTS": "testserver,localhost",
            "DB_DRIVER": "postgres",
            "DATABASE_URL": "",
            "REDIS_URL": "",
            "OTEL_ENABLED": "false",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "worker startup and public requests passed" in result.stdout
