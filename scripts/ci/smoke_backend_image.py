"""Check the built runtime image offline, including native libraries and fork safety.

Run with the image's non-root user and ``docker run --network none``. No database,
cloud credentials, real accounts, or telemetry collector are needed.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import ssl
import traceback
from pathlib import Path
from unittest.mock import patch


def check_native_libraries() -> None:
    import grpc
    import psycopg
    import ydb
    from argon2 import PasswordHasher
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding
    from fido2.cose import ES256
    from PIL import Image

    assert grpc.__version__ and ydb.__version__ and psycopg.pq.version() > 0
    assert ES256.ALGORITHM == -7
    private_key = Ed25519PrivateKey.generate()
    private_key.public_key().verify(private_key.sign(b"image-smoke"), b"image-smoke")
    hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    assert hasher.verify(hasher.hash("image-smoke-password"), "image-smoke-password")
    for image_format in ("JPEG", "PNG"):
        data = io.BytesIO()
        Image.new("RGB", (8, 8), "white").save(data, format=image_format)
        data.seek(0)
        with Image.open(data) as image:
            image.load()
            assert image.size == (8, 8)
    certificate = x509.load_pem_x509_certificate(
        Path("/usr/local/share/ca-certificates/YandexInternalRootCA.crt").read_bytes()
    )
    assert certificate.public_bytes(
        Encoding.DER
    ) in ssl.create_default_context().get_ca_certs(binary_form=True)


def check_startup() -> None:
    from django.db.backends.base.base import BaseDatabaseWrapper

    from app.gunicorn_config import on_starting

    with (
        patch.object(
            BaseDatabaseWrapper,
            "ensure_connection",
            side_effect=AssertionError("startup opened a database connection"),
        ),
        patch("ydb.Driver", side_effect=AssertionError("startup created a YDB driver")),
        patch.object(
            socket.socket,
            "connect",
            side_effect=AssertionError("startup opened a network connection"),
        ),
    ):
        on_starting(None)

    from core import telemetry

    assert not telemetry._configured
    assert len(list(Path("/proc/self/task").iterdir())) == 1
    child = os.fork()
    if child == 0:
        try:
            with patch.object(
                BaseDatabaseWrapper,
                "ensure_connection",
                side_effect=AssertionError(
                    "public request opened a database connection"
                ),
            ):
                from django.test import RequestFactory

                from app.jobs import application as jobs_application
                from app.wsgi import application

                assert callable(jobs_application)
                assert telemetry._configured
                assert any(
                    middleware.__module__.startswith("opentelemetry")
                    for middleware in application._view_middleware
                )
                factory = RequestFactory()
                for path in (
                    "/healthz",
                    "/api/v1/auth/me",
                    "/api/v1/auth/oauth/providers",
                    "/api/v1/auth/timezones",
                ):
                    responses = []

                    def start_response(
                        status: str, headers: list[tuple[str, str]]
                    ) -> None:
                        responses.append((status, dict(headers)))

                    response = application(factory.get(path).environ, start_response)
                    try:
                        payload = json.loads(b"".join(response))
                    finally:
                        response.close()
                    status, headers = responses[0]
                    assert status.startswith("200 "), (path, status)
                    if path == "/healthz":
                        assert payload == {"status": "alive"}
                    if path.endswith("/me"):
                        assert payload == {"user": None}
                    if path.endswith("/timezones"):
                        assert len(payload["timezones"]) > 300
                    if path.startswith("/api/"):
                        assert headers["Cache-Control"] == "private, no-store"
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert not telemetry._configured
    assert len(list(Path("/proc/self/task").iterdir())) == 1


if __name__ == "__main__":
    os.environ.update(
        {
            "DJANGO_SETTINGS_MODULE": "app.settings",
            "DJANGO_DEBUG": "true",
            "DJANGO_SECRET_KEY": "local-image-smoke-secret-32-characters",
            "DJANGO_ALLOWED_HOSTS": "testserver,localhost",
            "DB_DRIVER": "ydb",
            "DATABASE_URL": "",
            "YDB_ENDPOINT": "grpc://127.0.0.1:2136",
            "YDB_DATABASE": "/local",
            "REDIS_URL": "",
            "OTEL_ENABLED": "true",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
            "OTEL_EXPORTER_OTLP_HEADERS": "",
            "MONIUM_API_KEY": "",
            "OTEL_TRACES_SAMPLER": "always_off",
        }
    )
    assert os.getuid() != 0, "runtime must use the non-root application user"
    assert shutil.which("gcc") is None, "compiler leaked into the runtime image"
    assert shutil.which("uv") is None, "build tool leaked into the runtime image"
    check_native_libraries()
    check_startup()
    print(
        "Image smoke passed: native libraries, CA trust, fork safety, telemetry, jobs, public API"
    )
