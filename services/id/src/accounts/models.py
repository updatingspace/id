from __future__ import annotations

import uuid
from pathlib import Path

from django.conf import settings
from django.db import models
from django.utils import timezone as dj_timezone


def user_avatar_upload_to(instance: UserProfile, filename: str) -> str:
    """
    Store avatars inside per-user folders to avoid name collisions.
    """
    ext = Path(filename).suffix or ".jpg"
    return f"avatars/user_{instance.user_id}/{uuid.uuid4().hex}{ext}"


class UserProfile(models.Model):
    class AvatarSource(models.TextChoices):
        NONE = "none", "Нет"
        GRAVATAR = "gravatar", "Gravatar"
        UPLOAD = "upload", "Загрузка"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    avatar = models.ImageField(upload_to=user_avatar_upload_to, null=True, blank=True)
    avatar_source = models.CharField(
        max_length=16,
        choices=AvatarSource.choices,
        default=AvatarSource.NONE,
    )
    gravatar_enabled = models.BooleanField(
        default=True,
        help_text=(
            "Разрешать авто-подгрузку аватара из Gravatar, пока пользователь сам "
            "не загружает/не удаляет фото."
        ),
    )
    gravatar_checked_at = models.DateTimeField(null=True, blank=True)
    phone_number = models.CharField(max_length=32, blank=True)
    phone_verified = models.BooleanField(default=False)
    birth_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Профиль пользователя"
        verbose_name_plural = "Профили пользователей"

    def __str__(self) -> str:  # pragma: no cover - административное удобство
        return f"Profile({self.user_id})"


class UserPreferences(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="preferences",
    )
    language = models.CharField(max_length=8, default="en")
    timezone = models.CharField(max_length=64, blank=True)
    marketing_opt_in = models.BooleanField(default=False)
    marketing_opt_in_at = models.DateTimeField(null=True, blank=True)
    marketing_opt_out_at = models.DateTimeField(null=True, blank=True)
    privacy_scope_defaults = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=dj_timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Предпочтения пользователя"
        verbose_name_plural = "Предпочтения пользователей"


class UserConsent(models.Model):
    class Kind(models.TextChoices):
        DATA_PROCESSING = "data_processing", "Согласие на обработку данных"
        MARKETING = "marketing", "Согласие на маркетинг"
        PARENTAL = "parental", "Согласие родителя/опекуна"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="consents",
    )
    kind = models.CharField(max_length=32, choices=Kind.choices)
    version = models.CharField(max_length=32, blank=True)
    granted_at = models.DateTimeField(default=dj_timezone.now)
    revoked_at = models.DateTimeField(null=True, blank=True)
    source = models.CharField(max_length=64, blank=True)
    meta = models.JSONField(default=dict)

    class Meta:
        verbose_name = "Согласие пользователя"
        verbose_name_plural = "Согласия пользователей"
        indexes = [
            models.Index(fields=["user", "kind"], name="acct_consent_user_kind_idx"),
            models.Index(fields=["kind", "granted_at"], name="acct_consent_kind_idx"),
        ]


class UserDevice(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="devices",
    )
    device_id = models.CharField(max_length=64)
    user_agent = models.CharField(max_length=512, blank=True)
    first_seen = models.DateTimeField(default=dj_timezone.now)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name = "Устройство пользователя"
        verbose_name_plural = "Устройства пользователей"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "device_id"],
                name="acct_device_user_device_uniq",
            ),
        ]
        indexes = [
            models.Index(
                fields=["user", "last_seen"], name="acct_device_user_last_idx"
            ),
        ]


class LoginEvent(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "success", "Успешный вход"
        FAILURE = "failure", "Ошибка входа"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_events",
    )
    status = models.CharField(max_length=16, choices=Status.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    ip_hash = models.CharField(max_length=64, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    device_id = models.CharField(max_length=64, blank=True)
    location = models.CharField(max_length=128, blank=True)
    is_new_device = models.BooleanField(default=False)
    reason = models.CharField(max_length=64, blank=True)
    meta = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=dj_timezone.now)

    class Meta:
        verbose_name = "Событие входа"
        verbose_name_plural = "События входа"
        indexes = [
            models.Index(fields=["user", "created_at"], name="acct_login_user_idx"),
            models.Index(fields=["status", "created_at"], name="acct_login_status_idx"),
        ]


class AccountEvent(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="account_events",
    )
    action = models.CharField(max_length=64)
    meta = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=dj_timezone.now)

    class Meta:
        verbose_name = "Событие аккаунта"
        verbose_name_plural = "События аккаунта"
        indexes = [
            models.Index(fields=["action", "created_at"], name="acct_event_action_idx"),
            models.Index(fields=["user", "created_at"], name="acct_event_user_idx"),
        ]


class DataExportRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Ожидание"
        READY = "ready", "Готово"
        FAILED = "failed", "Ошибка"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="data_exports",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    requested_at = models.DateTimeField(default=dj_timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    format = models.CharField(max_length=16, default="json")
    error = models.CharField(max_length=256, blank=True)

    class Meta:
        verbose_name = "Запрос на экспорт данных"
        verbose_name_plural = "Запросы на экспорт данных"
        indexes = [
            models.Index(fields=["user", "requested_at"], name="acct_export_user_idx"),
            models.Index(
                fields=["status", "requested_at"], name="acct_export_status_idx"
            ),
        ]


class AccountDeletionRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Ожидание"
        EXECUTED = "executed", "Выполнено"
        CANCELED = "canceled", "Отменено"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="deletion_requests",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    requested_at = models.DateTimeField(default=dj_timezone.now)
    executed_at = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=256, blank=True)

    class Meta:
        verbose_name = "Запрос на удаление аккаунта"
        verbose_name_plural = "Запросы на удаление аккаунта"
        indexes = [
            models.Index(
                fields=["status", "requested_at"], name="acct_delete_status_idx"
            ),
        ]


__all__ = [
    "UserProfile",
    "UserPreferences",
    "UserConsent",
    "UserDevice",
    "LoginEvent",
    "AccountEvent",
    "DataExportRequest",
    "AccountDeletionRequest",
    "user_avatar_upload_to",
]
