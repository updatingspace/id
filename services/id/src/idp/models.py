from __future__ import annotations

import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.utils import timezone


def generate_client_id() -> str:
    return secrets.token_urlsafe(18)


def generate_client_secret() -> str:
    return secrets.token_urlsafe(32)


class OidcClient(models.Model):
    client_id = models.CharField(
        max_length=64,
        unique=True,
        default=generate_client_id,
        editable=False,
    )
    client_secret_hash = models.CharField(max_length=256, blank=True)
    name = models.CharField(max_length=128)
    description = models.CharField(max_length=256, blank=True)
    logo_url = models.URLField(blank=True)
    redirect_uris = models.JSONField(default=list)
    allowed_scopes = models.JSONField(default=list)
    grant_types = models.JSONField(default=list)
    response_types = models.JSONField(default=list)
    is_public = models.BooleanField(default=True)
    is_first_party = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "OIDC клиент"
        verbose_name_plural = "OIDC клиенты"
        indexes = [
            models.Index(fields=["client_id"], name="oidc_client_id_idx"),
        ]

    def set_secret(self, raw: str | None = None) -> str:
        secret = raw or generate_client_secret()
        self.client_secret_hash = make_password(secret)
        return secret

    def check_secret(self, raw: str | None) -> bool:
        if self.is_public:
            return True
        if not raw:
            return False
        return check_password(raw, self.client_secret_hash or "")


class OidcAuthorizationRequest(models.Model):
    request_id = models.CharField(max_length=64, primary_key=True, editable=False)
    client = models.ForeignKey(OidcClient, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    redirect_uri = models.TextField()
    scope = models.TextField()
    state = models.CharField(max_length=256, blank=True)
    nonce = models.CharField(max_length=256, blank=True)
    code_challenge = models.CharField(max_length=256, blank=True)
    code_challenge_method = models.CharField(max_length=16, blank=True)
    prompt = models.CharField(max_length=32, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = "OIDC запрос авторизации"
        verbose_name_plural = "OIDC запросы авторизации"
        indexes = [
            models.Index(fields=["client", "expires_at"], name="oidc_req_client_idx"),
            models.Index(fields=["user", "expires_at"], name="oidc_req_user_idx"),
        ]


class OidcAuthorizationCode(models.Model):
    code = models.CharField(max_length=128, primary_key=True)
    client = models.ForeignKey(OidcClient, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    redirect_uri = models.TextField()
    scope = models.TextField()
    nonce = models.CharField(max_length=256, blank=True)
    code_challenge = models.CharField(max_length=256, blank=True)
    code_challenge_method = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "OIDC код авторизации"
        verbose_name_plural = "OIDC коды авторизации"
        indexes = [
            models.Index(fields=["client", "expires_at"], name="oidc_code_client_idx"),
            models.Index(fields=["user", "expires_at"], name="oidc_code_user_idx"),
        ]


class OidcConsent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client = models.ForeignKey(OidcClient, on_delete=models.CASCADE)
    scopes = models.JSONField(default=list)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "OIDC согласие"
        verbose_name_plural = "OIDC согласия"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "client"], name="oidc_consent_user_client_uniq"
            ),
        ]
        indexes = [
            models.Index(fields=["user", "updated_at"], name="oidc_consent_user_idx"),
        ]


class OidcToken(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client = models.ForeignKey(OidcClient, on_delete=models.CASCADE)
    access_jti = models.CharField(max_length=128, db_index=True)
    id_jti = models.CharField(max_length=128, blank=True)
    refresh_token_hash = models.CharField(max_length=256, blank=True)
    scope = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    access_expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "OIDC токен"
        verbose_name_plural = "OIDC токены"
        indexes = [
            models.Index(fields=["access_jti"], name="oidc_token_access_idx"),
            models.Index(fields=["refresh_expires_at"], name="oidc_token_refresh_idx"),
            models.Index(fields=["user", "client"], name="oidc_token_user_client_idx"),
        ]
