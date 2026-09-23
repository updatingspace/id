"""Exercise the two-phase identity contract on disposable localhost YDB only."""

import json
import os
import uuid
from types import SimpleNamespace
from urllib.parse import urlparse

import django

django.setup()

from allauth.account.models import EmailAddress  # noqa: E402
from django.conf import settings  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from django.db import connections  # noqa: E402
from django.test import Client, override_settings  # noqa: E402

from accounts.services.identity import resolve_identity  # noqa: E402
from idp.models import OidcClient, OidcToken  # noqa: E402
from idp.services import OidcService, _decode_jwt_token  # noqa: E402
from updspaceid.models import TenantMembership  # noqa: E402


def main():
    if (
        settings.DB_DRIVER != "ydb"
        or urlparse(os.environ.get("YDB_ENDPOINT", "")).hostname
        not in {"localhost", "127.0.0.1"}
        or os.environ.get("YDB_DATABASE") != "/local"
    ):
        raise SystemExit("This check requires disposable local /local YDB")
    suffix = uuid.uuid4().hex
    user = get_user_model().objects.create_user(
        username=f"identity-{suffix}",
        email=f"{suffix}@example.invalid",
        password="Local-runtime-only-295!",
    )
    EmailAddress.objects.create(
        user=user, email=user.email, primary=True, verified=True
    )
    with override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False):
        frozen = resolve_identity(user)
        assert frozen.identity_id is None
        assert frozen.public_subject == str(user.pk)
    client = OidcClient.objects.create(
        client_id=f"identity-{suffix}",
        name="Identity runtime RP",
        is_public=True,
        grant_types=["authorization_code", "refresh_token"],
    )
    with override_settings(
        ALLOWED_HOSTS=["testserver"],
        ID_GLOBAL_IDENTITY_PROVISIONING=True,
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
    ):
        browser = Client()
        form = browser.get("/api/v1/auth/form_token", {"purpose": "login"}).json()
        login = browser.post(
            "/api/v1/auth/login",
            json.dumps(
                {
                    "email": user.email,
                    "password": "Local-runtime-only-295!",
                    "form_token": form["form_token"],
                }
            ),
            content_type="application/json",
        )
        assert login.status_code == 200, login.status_code
        binding = resolve_identity(user)
        assert isinstance(binding.identity_id, uuid.UUID)
        assert binding.public_subject == frozen.public_subject
        assert not TenantMembership.objects.filter(user_id=binding.identity_id).exists()
        tokens = OidcService._issue_tokens(
            user=user,
            client=client,
            scope="openid offline_access",
            nonce="",
        )
        with override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=False):
            claims = OidcService.userinfo(tokens["access_token"])
            assert claims["sub"] == frozen.public_subject
            assert claims["user_id"] == str(binding.identity_id)
            refreshed = OidcService.refresh_tokens(
                {
                    "client_id": client.client_id,
                    "refresh_token": tokens["refresh_token"],
                },
                request=SimpleNamespace(headers={}),
            )
            assert (
                _decode_jwt_token(refreshed["id_token"])["sub"] == frozen.public_subject
            )
            assert OidcService.userinfo(refreshed["access_token"])["user_id"] == str(
                binding.identity_id
            )
        assert (
            OidcToken.objects.filter(client=client, revoked_at__isnull=True).count()
            == 1
        )
    connections.close_all()
    print(
        "PASS: phase one freeze, password provisioning, stable opaque sub, canonical UUID, no membership, refresh and compatible rollback runtime"
    )


if __name__ == "__main__":
    main()
