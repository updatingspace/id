from __future__ import annotations

# ruff: noqa: E501

import secrets
import uuid

from django.db import models
from django.utils import timezone

from updspaceid.enums import (
    ApplicationStatus,
    ExternalProvider,
    MembershipStatus,
    OAuthPurpose,
    UserStatus,
)


def generate_token_urlsafe(length_bytes: int = 32) -> str:
    # urlsafe returns base64-like; keep it reasonably short for URLs.
    return secrets.token_urlsafe(length_bytes)


class Tenant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=64, unique=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_tenant"


class User(models.Model):
    user_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    username = models.CharField(max_length=64, blank=True)
    display_name = models.CharField(max_length=128, blank=True)
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    status = models.CharField(
        max_length=32,
        choices=UserStatus.choices,
        default=UserStatus.MIGRATED_UNCLAIMED,
    )
    system_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_user"
        indexes = [
            models.Index(fields=["email"], name="usid_user_email_idx"),
            models.Index(fields=["status"], name="usid_user_status_idx"),
        ]


class Application(models.Model):
    id = models.BigAutoField(primary_key=True)
    tenant_slug = models.SlugField(max_length=64)
    payload_json = models.JSONField(default=dict)
    status = models.CharField(
        max_length=16,
        choices=ApplicationStatus.choices,
        default=ApplicationStatus.PENDING,
    )
    created_at = models.DateTimeField(default=timezone.now)
    reviewed_by_user_id = models.UUIDField(null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "usid_application"
        indexes = [
            models.Index(
                fields=["tenant_slug", "status"],
                name="usid_app_tenant_status_idx",
            ),
            models.Index(
                fields=["status", "created_at"],
                name="usid_app_status_created_idx",
            ),
        ]


class TenantMembership(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    status = models.CharField(
        max_length=16,
        choices=MembershipStatus.choices,
        default=MembershipStatus.ACTIVE,
    )
    base_role = models.CharField(max_length=64, default="member")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_tenant_membership"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "tenant"],
                name="usid_memb_user_tenant_uniq",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant", "status"],
                name="usid_memb_tenant_status_idx",
            ),
        ]


class ActivationToken(models.Model):
    token = models.CharField(
        max_length=128,
        primary_key=True,
        default=generate_token_urlsafe,
        editable=False,
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_activation_token"
        indexes = [
            models.Index(
                fields=["tenant", "expires_at"],
                name="usid_activation_tenant_exp_idx",
            ),
            models.Index(
                fields=["expires_at"],
                name="usid_activation_exp_idx",
            ),
        ]


class MagicLinkToken(models.Model):
    token = models.CharField(
        max_length=128,
        primary_key=True,
        default=generate_token_urlsafe,
        editable=False,
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    ip_hash = models.CharField(max_length=64, blank=True)
    ua_hash = models.CharField(max_length=64, blank=True)
    skip_context_validation = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_magic_link_token"
        indexes = [
            models.Index(fields=["expires_at"], name="usid_magic_exp_idx"),
        ]


class ExternalIdentity(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="external_identities",
    )
    provider = models.CharField(
        max_length=16,
        choices=ExternalProvider.choices,
    )
    subject = models.CharField(max_length=128)
    tokens_json = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "usid_external_identity"
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "subject"],
                name="usid_ext_provider_subject_uniq",
            ),
            models.UniqueConstraint(
                fields=["user", "provider"],
                name="usid_ext_user_provider_uniq",
            ),
        ]
        indexes = [
            models.Index(fields=["provider"], name="usid_ext_provider_idx"),
        ]


class AuditLog(models.Model):
    id = models.BigAutoField(primary_key=True)
    actor_user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=64)
    target_type = models.CharField(max_length=64)
    target_id = models.CharField(max_length=128)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    meta_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_audit_log"
        indexes = [
            models.Index(
                fields=["action", "created_at"],
                name="usid_audit_action_created_idx",
            ),
            models.Index(
                fields=["tenant", "created_at"],
                name="usid_audit_tenant_created_idx",
            ),
        ]


class OutboxEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name="outbox_events",
    )
    event_type = models.CharField(max_length=64)
    payload_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)
    processed_at = models.DateTimeField(null=True, blank=True)
    attempts = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)

    class Meta:
        db_table = "usid_outbox"
        indexes = [
            models.Index(
                fields=["event_type", "created_at"], name="usid_outbox_type_created_idx"
            ),
            models.Index(
                fields=["tenant", "created_at"], name="usid_outbox_tenant_created_idx"
            ),
            models.Index(fields=["processed_at"], name="usid_outbox_processed_idx"),
        ]


class MigrationMap(models.Model):
    id = models.BigAutoField(primary_key=True)
    old_system = models.CharField(max_length=64)
    old_user_id = models.CharField(max_length=128)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_migration_map"
        constraints = [
            models.UniqueConstraint(
                fields=["old_system", "old_user_id"],
                name="usid_migration_old_uniq",
            ),
        ]


class OAuthState(models.Model):
    state = models.CharField(
        max_length=128,
        primary_key=True,
        default=generate_token_urlsafe,
        editable=False,
    )
    nonce = models.CharField(max_length=128, default=generate_token_urlsafe)
    provider = models.CharField(
        max_length=16,
        choices=ExternalProvider.choices,
    )
    purpose = models.CharField(max_length=16, choices=OAuthPurpose.choices)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    redirect_uri = models.TextField(blank=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "usid_oauth_state"
        indexes = [
            models.Index(
                fields=["provider", "purpose", "expires_at"],
                name="usid_oauth_idx",
            ),
        ]


class IdSession(models.Model):
    token = models.CharField(
        max_length=128,
        primary_key=True,
        default=generate_token_urlsafe,
        editable=False,
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    ip_hash = models.CharField(max_length=64, blank=True)
    ua_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "usid_session"
        indexes = [
            models.Index(fields=["expires_at"], name="usid_session_exp_idx"),
            models.Index(
                fields=["user", "expires_at"],
                name="usid_session_user_exp_idx",
            ),
        ]
