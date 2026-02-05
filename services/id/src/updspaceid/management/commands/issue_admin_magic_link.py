from __future__ import annotations

import os
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from updspaceid.enums import MembershipStatus, UserStatus
from updspaceid.models import Tenant, TenantMembership, User
from updspaceid.emailing import build_magic_link_url
from updspaceid.services import ensure_tenant, request_magic_link


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Command(BaseCommand):
    help = "Create/update a system admin user for a tenant and print a magic link."

    def add_arguments(self, parser):
        parser.add_argument(
            "--email",
            type=str,
            default="dev@aef.local",
            help="Email for the system admin user.",
        )
        parser.add_argument(
            "--username",
            type=str,
            default="dev",
            help="Username to set if the user does not have one.",
        )
        parser.add_argument(
            "--display-name",
            type=str,
            default="Dev Admin",
            help="Display name to set if the user does not have one.",
        )
        parser.add_argument(
            "--tenant-id",
            type=str,
            default=os.getenv(
                "DEFAULT_TENANT_ID",
                "00000000-0000-0000-0000-000000000001",
            ),
            help="Tenant UUID (defaults to DEFAULT_TENANT_ID).",
        )
        parser.add_argument(
            "--tenant-slug",
            type=str,
            default=os.getenv("DEFAULT_TENANT_SLUG", "aef"),
            help="Tenant slug (defaults to DEFAULT_TENANT_SLUG).",
        )
        parser.add_argument(
            "--redirect-to",
            type=str,
            default=None,
            help="BFF callback URL for magic link redirect.",
        )

    def handle(self, *args: Any, **options: Any):
        if not _env_flag("DEV_AUTH_MODE", False):
            raise CommandError("DEV_AUTH_MODE=true is required to issue a magic link.")

        email = str(options["email"] or "").strip().lower()
        if not email:
            raise CommandError("--email is required.")

        default_tenant_id = os.getenv(
            "DEFAULT_TENANT_ID",
            "00000000-0000-0000-0000-000000000001",
        )
        tenant_id = str(options["tenant_id"] or default_tenant_id).strip()
        tenant_slug = str(options["tenant_slug"] or "").strip()
        if not tenant_id or not tenant_slug:
            raise CommandError("--tenant-id and --tenant-slug are required.")

        tenant = Tenant.objects.filter(slug=tenant_slug).first()
        if tenant:
            if str(tenant.id) != tenant_id and tenant_id != default_tenant_id:
                raise CommandError(
                    "Tenant slug already exists with a different ID. "
                    "Pass the existing tenant ID or use the correct --tenant-slug."
                )
            if str(tenant.id) != tenant_id:
                self.stdout.write(
                    self.style.WARNING(
                        f"Tenant slug '{tenant_slug}' already exists "
                        f"with id {tenant.id}; using existing tenant."
                    )
                )
        else:
            existing_by_id = Tenant.objects.filter(id=tenant_id).first()
            if existing_by_id and existing_by_id.slug != tenant_slug:
                raise CommandError(
                    f"Tenant id {tenant_id} belongs to slug "
                    f"'{existing_by_id.slug}'."
                )
            tenant = ensure_tenant(tenant_id, tenant_slug)

        username = str(options["username"] or "").strip()
        display_name = str(options["display_name"] or "").strip()

        user, _ = User.objects.get_or_create(
            email=email,
            defaults={
                "username": username,
                "display_name": display_name,
                "status": UserStatus.ACTIVE,
                "email_verified": True,
                "system_admin": True,
            },
        )

        update_fields: list[str] = []
        if user.status != UserStatus.ACTIVE:
            user.status = UserStatus.ACTIVE
            update_fields.append("status")
        if not user.email_verified:
            user.email_verified = True
            update_fields.append("email_verified")
        if not user.system_admin:
            user.system_admin = True
            update_fields.append("system_admin")
        if username and not user.username:
            user.username = username
            update_fields.append("username")
        if display_name and not user.display_name:
            user.display_name = display_name
            update_fields.append("display_name")
        if update_fields:
            user.save(update_fields=update_fields)

        membership, created = TenantMembership.objects.get_or_create(
            user=user,
            tenant=tenant,
            defaults={
                "status": MembershipStatus.ACTIVE,
                "base_role": "admin",
            },
        )
        if not created:
            membership_updates: list[str] = []
            if membership.status != MembershipStatus.ACTIVE:
                membership.status = MembershipStatus.ACTIVE
                membership_updates.append("status")
            if membership.base_role != "admin":
                membership.base_role = "admin"
                membership_updates.append("base_role")
            if membership_updates:
                membership.save(update_fields=membership_updates)

        token = request_magic_link(
            email=email,
            ip="127.0.0.1",
            ua="issue_admin_magic_link",
            skip_context_validation=True,
        )
        if not token:
            raise CommandError("Magic link token was not issued for this user.")

        redirect_to = str(options["redirect_to"] or "").strip()
        if not redirect_to:
            redirect_to = (
                f"http://{tenant_slug}.localhost/api/v1/session/callback"
            )

        magic_link = build_magic_link_url(
            token=token.raw_token,
            redirect_to=redirect_to,
        )

        self.stdout.write("System admin ready:")
        self.stdout.write(f"  Email: {user.email}")
        self.stdout.write(f"  Tenant: {tenant.slug} ({tenant.id})")
        self.stdout.write(f"  Magic link: {magic_link}")
        if token.expires_at:
            self.stdout.write(f"  Expires at: {token.expires_at.isoformat()}")
