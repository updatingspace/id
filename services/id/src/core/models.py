from __future__ import annotations

from django.conf import settings
from django.db import models


class UserSessionMeta(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="session_meta",
    )
    session_key = models.CharField(max_length=128, db_index=True)
    session_token = models.CharField(
        max_length=255, null=True, blank=True, db_index=True
    )
    user_agent = models.CharField(max_length=512, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_reason = models.CharField(max_length=64, blank=True)

    class Meta:
        verbose_name = "Метаданные сессии пользователя"
        verbose_name_plural = "Метаданные сессий пользователя"
        unique_together = ("user", "session_key")

    def __str__(self) -> str:  # pragma: no cover - для удобства в админке
        return f"{self.user} @ {self.session_key}"


class UserSessionToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="session_tokens",
    )
    session_key = models.CharField(max_length=128, db_index=True)
    refresh_jti = models.CharField(max_length=255, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Связка сессионного ключа и refresh JTI"
        verbose_name_plural = "Связки сессионного ключа и refresh JTI"
        unique_together = ("user", "refresh_jti")

    def __str__(self) -> str:  # pragma: no cover - для удобства в админке
        return f"{self.user} · {self.session_key} · {self.refresh_jti}"


__all__ = ["UserSessionMeta", "UserSessionToken"]
