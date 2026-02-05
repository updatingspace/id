from __future__ import annotations

import os
import uuid
from io import StringIO
from urllib.parse import quote

from django.core.management import call_command
from django.test import TestCase

from updspaceid.enums import MembershipStatus, UserStatus
from updspaceid.models import Tenant, TenantMembership, User


class IssueAdminMagicLinkCommandTests(TestCase):
    def setUp(self):
        self._dev_auth_mode = os.environ.get("DEV_AUTH_MODE")
        os.environ["DEV_AUTH_MODE"] = "true"

    def tearDown(self):
        if self._dev_auth_mode is None:
            os.environ.pop("DEV_AUTH_MODE", None)
        else:
            os.environ["DEV_AUTH_MODE"] = self._dev_auth_mode

    def test_creates_admin_user_and_magic_link(self):
        tenant_id = str(uuid.uuid4())
        tenant_slug = "aef"
        redirect_to = "http://aef.localhost/api/v1/session/callback"

        out = StringIO()
        call_command(
            "issue_admin_magic_link",
            "--email",
            "dev@aef.local",
            "--tenant-id",
            tenant_id,
            "--tenant-slug",
            tenant_slug,
            "--redirect-to",
            redirect_to,
            stdout=out,
        )

        user = User.objects.get(email="dev@aef.local")
        self.assertEqual(user.status, UserStatus.ACTIVE)
        self.assertTrue(user.email_verified)
        self.assertTrue(user.system_admin)

        membership = TenantMembership.objects.get(user=user, tenant__id=tenant_id)
        self.assertEqual(membership.status, MembershipStatus.ACTIVE)
        self.assertEqual(membership.base_role, "admin")

        output = out.getvalue()
        self.assertIn("Magic link:", output)
        self.assertIn(quote(redirect_to, safe=""), output)

    def test_existing_tenant_slug_uses_existing_id(self):
        existing_tenant_id = uuid.uuid4()
        existing_tenant = Tenant.objects.create(
            id=existing_tenant_id,
            slug="aef",
        )
        default_tenant_id = "00000000-0000-0000-0000-000000000001"

        out = StringIO()
        call_command(
            "issue_admin_magic_link",
            "--email",
            "dev2@aef.local",
            "--tenant-id",
            default_tenant_id,
            "--tenant-slug",
            "aef",
            "--redirect-to",
            "http://aef.localhost/api/v1/session/callback",
            stdout=out,
        )

        user = User.objects.get(email="dev2@aef.local")
        membership = TenantMembership.objects.get(user=user, tenant=existing_tenant)
        self.assertEqual(membership.tenant.id, existing_tenant_id)
