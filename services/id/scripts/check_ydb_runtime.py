"""Exercise real YDB auth and cross-connection cache behavior in local CI only."""

from __future__ import annotations

import json
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
django.setup()

from allauth.account.models import EmailAddress  # noqa: E402
from django.conf import settings  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from django.contrib.sites.models import Site  # noqa: E402
from django.core import mail  # noqa: E402
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
        assert response.status_code == 401
        assert response.json()["code"] == "EMAIL_VERIFICATION_REQUIRED"

        def key_from_mail(route):
            link = re.search(
                r"https?://[^\s]+/" + route + r"#[^\s]+", mail.outbox[-1].body
            )
            assert link is not None, "Recovery email must contain a frontend link"
            return parse_qs(urlparse(link.group()).fragment)["key"][0]

        response = post(
            "/api/v1/auth/email/verification/request",
            {"email": email},
            "email_verification",
        )
        assert response.status_code == 200
        response = client.post(
            "/api/v1/auth/email/verification/confirm",
            data=json.dumps({"key": key_from_mail("verify-email")}),
            content_type="application/json",
        )
        assert response.status_code == 200, response.content.decode()[:400]
        assert EmailAddress.objects.get(email=email).verified
        assert "Email подтверждён" in mail.outbox[-1].subject

        # YDB has no unique constraint on username. Legacy accounts sharing a
        # username must still authenticate only with their own email/password.
        other_password = "Local-only-Other-Password!789"
        other_user = User.objects.create_user(
            username="runtime-" + run_id,
            email="other-" + run_id + "@example.com",
            password=other_password,
        )
        EmailAddress.objects.create(
            user=other_user, email=other_user.email, verified=True, primary=True
        )
        assert User.objects.filter(username=other_user.username).count() == 2
        response = post(
            "/api/v1/auth/login", {"email": email, "password": other_password}
        )
        assert response.status_code == 401, response.content.decode()[:400]
        assert response.json()["code"] == "INVALID_CREDENTIALS"
        response = post("/api/v1/auth/login", {"email": email, "password": password})
        assert response.status_code == 200, response.content.decode()[:400]
        data = response.json()
        assert data["user"] is not None and data["access_token"]
        response = client.get(
            "/api/v1/auth/me", HTTP_X_SESSION_TOKEN=data["meta"]["session_token"]
        )
        assert response.status_code == 200 and response.json()["user"]["email"] == email
        from accounts.models import DataExportRequest, UserConsent

        owner = User.objects.get(email=email)
        UserConsent.objects.create(user=owner, kind="export-check", version="owner")
        UserConsent.objects.create(
            user=other_user, kind="export-check", version="other-user"
        )
        response = client.post(
            "/api/v1/auth/data/export",
            data=json.dumps({"password": password}),
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=data["meta"]["session_token"],
        )
        assert response.status_code == 200, response.content.decode()[:400]
        exported = response.json()["payload"]
        assert exported["user"]["email"] == email
        assert "owner" in [item["version"] for item in exported["consents"]]
        assert "other-user" not in [item["version"] for item in exported["consents"]]
        for collection, field in [
            ("consents", "granted_at"),
            ("login_events", "created_at"),
        ]:
            values = [item[field] for item in exported[collection]]
            assert values == sorted(values, reverse=True)
        assert (
            DataExportRequest.objects.get(user=owner).status
            == DataExportRequest.Status.READY
        )
        from accounts.models import UserProfile

        profile = UserProfile.objects.get(user=User.objects.get(email=email))
        profile.avatar.name = "avatars/runtime-check.png"
        profile.save(update_fields=["avatar"])
        profile.refresh_from_db()
        assert profile.avatar.name == "avatars/runtime-check.png"

        response = post(
            "/api/v1/auth/password/reset/request", {"email": email}, "password_reset"
        )
        assert response.status_code == 200
        key = key_from_mail("reset-password")
        new_password = "Local-only-Recovered-Password!456"
        anonymous = Client()
        payload = json.dumps({"key": key, "password": new_password})
        response = anonymous.post(
            "/api/v1/auth/password/reset/confirm",
            data=payload,
            content_type="application/json",
        )
        assert response.status_code == 200, response.content.decode()[:400]
        assert "Пароль восстановлен" in mail.outbox[-1].subject
        assert User.objects.get(email=email).check_password(new_password)
        assert anonymous.get("/api/v1/auth/me").json() == {"user": None}
        assert (
            Client()
            .get("/api/v1/auth/me", HTTP_X_SESSION_TOKEN=data["meta"]["session_token"])
            .status_code
            == 401
        )
        replay = anonymous.post(
            "/api/v1/auth/password/reset/confirm",
            data=payload,
            content_type="application/json",
        )
        assert replay.status_code == 400
        assert replay.json()["code"] == "INVALID_RECOVERY_LINK"
        response = post(
            "/api/v1/auth/login", {"email": email, "password": new_password}
        )
        assert response.status_code == 200
        client = Client()
        response = post(
            "/api/v1/auth/login",
            {"email": other_user.email.upper(), "password": other_password},
        )
        assert response.status_code == 200, response.content.decode()[:400]
        assert response.json()["user"]["email"] == other_user.email
        from accounts.tests.webauthn_helpers import VirtualPasskey

        other_token = response.json()["meta"]["session_token"]
        response = client.post(
            "/api/v1/auth/passkeys/begin",
            data=json.dumps({"passwordless": True}),
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=other_token,
        )
        assert response.status_code == 200, response.content.decode()[:400]
        key = VirtualPasskey()
        credential = key.register(response.json()["creation_options"]["publicKey"])
        response = client.post(
            "/api/v1/auth/passkeys/complete",
            data=json.dumps({"name": "Runtime passkey", "credential": credential}),
            content_type="application/json",
            HTTP_X_SESSION_TOKEN=other_token,
        )
        assert response.status_code == 200, response.content.decode()[:400]
        assert response.json()["authenticator"]["is_passwordless"]
        passkey_client = Client()
        response = passkey_client.post("/api/v1/auth/passkeys/login/begin")
        assertion = key.authenticate(response.json()["request_options"]["publicKey"])
        response = passkey_client.post(
            "/api/v1/auth/passkeys/login/complete",
            data=json.dumps({"credential": assertion}),
            content_type="application/json",
        )
        assert response.status_code == 200, response.content.decode()[:400]
        assert response.json()["user"]["email"] == other_user.email
        print(
            "YDB auth: concurrent IDs, rollback, signup, email verification, duplicate usernames, password recovery, session revocation, profile, export and passkeys passed"
        )
    connections.close_all()


if __name__ == "__main__":
    main()
