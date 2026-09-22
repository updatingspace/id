"""Exercise real YDB auth and cross-connection cache behavior in local CI only."""

from __future__ import annotations

import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
django.setup()

from allauth.account.models import EmailAddress  # noqa: E402
from django.conf import settings  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from django.contrib.sites.models import Site  # noqa: E402
from django.core.cache import cache  # noqa: E402
from django.db import connection, connections, transaction  # noqa: E402
from django.test import Client, override_settings  # noqa: E402
from ninja.errors import HttpError  # noqa: E402

from accounts.services.form_token import FormTokenService  # noqa: E402
from accounts.services.rate_limit import RateLimitService  # noqa: E402


def parallel(function, count=16):
    def run(index):
        try:
            return function(index)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=4) as executor:
        return list(executor.map(run, range(count)))


def main():
    endpoint = urlparse(os.environ.get("YDB_ENDPOINT", ""))
    if (
        settings.DB_DRIVER != "ydb"
        or endpoint.hostname not in {"localhost", "127.0.0.1"}
        or os.environ.get("YDB_DATABASE") != "/local"
    ):
        raise SystemExit("Runtime checks are restricted to a local /local YDB database")

    connection.ensure_connection()
    pool = connection.connection._session_pool
    pool.execute_with_retries(
        'CREATE TABLE IF NOT EXISTS id_shared_cache (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key)) WITH (TTL=Interval("PT0S") ON expires_at AS SECONDS);'
    )
    run_id = uuid.uuid4().hex
    config = {
        "default": {
            "BACKEND": "core.ydb_cache.YDBCache",
            "LOCATION": "id_shared_cache",
            "KEY_PREFIX": run_id,
        }
    }
    with override_settings(
        CACHES=config,
        ALLOWED_HOSTS=["testserver"],
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
        GRAVATAR_AUTOLOAD_ENABLED=False,
    ):
        cache.set("value", {"bytes": b"test"}, 60)
        assert cache.get("value") == {"bytes": b"test"}
        cache.set("expired", "stale", -1)
        assert cache.get("expired") is None
        cache.set("forever", None, None)
        assert cache.get("forever", "absent") is None
        assert sum(parallel(lambda _: cache.add("once", "value", 60))) == 1
        assert parallel(lambda _: cache.take("once")).count("value") == 1
        cache.set("counter", 0, 60)
        assert sorted(parallel(lambda _: cache.incr("counter"))) == list(range(1, 17))
        assert cache.delete("counter") and not cache.delete("counter")
        try:
            cache.incr("counter")
            raise AssertionError("Missing counter must fail")
        except ValueError:
            pass

        issued = FormTokenService.issue(purpose="login")

        def consume(_):
            try:
                FormTokenService.consume(issued.token, purpose="login")
                return True
            except HttpError:
                return False

        assert sum(parallel(consume)) == 1
        decisions = parallel(
            lambda _: RateLimitService._increment("rate", limit=5, window_sec=60)
        )
        assert sum(decision.blocked for decision in decisions) == 11
        print(
            "Shared cache: expiry, add, increment, single-use tokens and rate limits passed"
        )

        User = get_user_model()

        def create_user(index):
            name = f"parallel-{run_id}-{index}"
            user = User.objects.create(username=name)
            assert User.objects.get(pk=user.pk).username == name
            return user.pk

        ids = parallel(create_user, count=8)
        assert len(set(ids)) == 8
        try:
            with transaction.atomic():
                User.objects.create(username="rollback-" + run_id)
                raise RuntimeError("rollback test")
        except RuntimeError:
            pass
        assert not User.objects.filter(username="rollback-" + run_id).exists()
        assert (
            User.objects.filter(username="missing-" + run_id).update(first_name="none")
            == 0
        )
        Site.objects.update_or_create(
            id=1, defaults={"domain": "testserver", "name": "Local ID"}
        )
        client = Client()
        email = "runtime-" + run_id + "@example.com"
        password = "Local-only-Test-Password!123"

        def post(path, payload, purpose="login"):
            token = client.get("/api/v1/auth/form_token", {"purpose": purpose}).json()[
                "form_token"
            ]
            return client.post(
                path,
                data=json.dumps({**payload, "form_token": token}),
                content_type="application/json",
            )

        response = post(
            "/api/v1/auth/signup",
            {
                "email": email,
                "username": "runtime-" + run_id,
                "password": password,
                "birth_date": "1990-01-02",
                "consent_data_processing": True,
            },
            "register",
        )
        assert response.status_code == 201, response.content.decode()[:400]
        assert response.json()["verification_required"] is True
        assert (
            not response.json().get("access_token")
            and not response.json()["meta"]["session_token"]
        )
        response = post("/api/v1/auth/login", {"email": email, "password": password})
        assert response.status_code == 200
        assert response.json()["user"]["email_verified"] is False
        restricted = client.post(
            "/api/v1/auth/mfa/totp/begin",
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=response.json()["meta"]["session_token"],
        )
        assert restricted.json()["code"] == "EMAIL_VERIFICATION_REQUIRED"
        EmailAddress.objects.filter(email=email).update(verified=True)
        response = post("/api/v1/auth/login", {"email": email, "password": password})
        assert response.status_code == 200, response.content.decode()[:400]
        data = response.json()
        assert data["user"] is not None and data["access_token"]
        response = client.get(
            "/api/v1/auth/me", HTTP_X_SESSION_TOKEN=data["meta"]["session_token"]
        )
        assert response.status_code == 200 and response.json()["user"]["email"] == email
        from accounts.models import UserProfile

        profile = UserProfile.objects.get(user=User.objects.get(email=email))
        profile.avatar.name = "avatars/runtime-check.png"
        profile.save(update_fields=["avatar"])
        profile.refresh_from_db()
        assert profile.avatar.name == "avatars/runtime-check.png"
        print(
            "YDB auth: concurrent IDs, rollback, signup, email state, login, profile and avatar update passed"
        )
    connections.close_all()


if __name__ == "__main__":
    main()
