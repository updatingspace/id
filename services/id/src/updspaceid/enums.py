from __future__ import annotations

from django.db import models


class UserStatus(models.TextChoices):
    ACTIVE = "active", "active"
    SUSPENDED = "suspended", "suspended"
    BANNED = "banned", "banned"
    MIGRATED_UNCLAIMED = "migrated_unclaimed", "migrated_unclaimed"


class ApplicationStatus(models.TextChoices):
    PENDING = "pending", "pending"
    APPROVED = "approved", "approved"
    REJECTED = "rejected", "rejected"


class MembershipStatus(models.TextChoices):
    ACTIVE = "active", "active"
    DISABLED = "disabled", "disabled"


class ExternalProvider(models.TextChoices):
    GITHUB = "github", "github"
    DISCORD = "discord", "discord"
    STEAM = "steam", "steam"


class OAuthPurpose(models.TextChoices):
    LINK = "link", "link"
    LOGIN = "login", "login"
