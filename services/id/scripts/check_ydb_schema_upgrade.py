"""Rehearse N-1 -> current YDB schema, only on an empty disposable local DB."""

from __future__ import annotations

import os
from urllib.parse import urlparse

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
django.setup()

from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.core.management.base import CommandError  # noqa: E402
from django.db import connection  # noqa: E402
from django.db.migrations.loader import MigrationLoader  # noqa: E402
from django.test import override_settings  # noqa: E402
from django.utils import timezone  # noqa: E402

from core.management.commands.migrate_ydb import _ordered_models  # noqa: E402
from core.ydb_migrations import LEDGER_TABLE, read_ledger  # noqa: E402


def main() -> None:
    endpoint = urlparse(os.environ.get("YDB_ENDPOINT", ""))
    if (
        settings.DB_DRIVER != "ydb"
        or endpoint.hostname not in {"localhost", "127.0.0.1"}
        or os.environ.get("YDB_DATABASE") != "/local"
    ):
        raise RuntimeError(
            "Schema rehearsal requires a disposable localhost YDB /local"
        )
    connection.ensure_connection()
    with override_settings(MIGRATION_MODULES={}):
        loader = MigrationLoader(None)
        baseline = {
            "accounts": "0003_remove_country_code",
            "idp": "0002_alter_oidctoken_id",
            "updspaceid": "0004_magiclink_skip_context",
        }
        targets = [
            node for node in loader.graph.leaf_nodes() if node[0] not in baseline
        ]
        targets.extend(baseline.items())
        legacy_apps = loader.project_state(targets).apps
    legacy_models = list(_ordered_models(legacy_apps))
    existing = set(connection.introspection.table_names())
    managed = {model._meta.db_table for model in legacy_models}
    if existing.intersection(managed | {LEDGER_TABLE, "accounts_accountidentity"}):
        raise RuntimeError(
            "Schema rehearsal refuses a database with existing ID tables"
        )
    with connection.schema_editor() as editor:
        for model in legacy_models:
            # The old bootstrap omitted implicit many-to-many join tables.
            if not model._meta.auto_created:
                editor.create_model(model)

    User = legacy_apps.get_model(settings.AUTH_USER_MODEL)
    Email = legacy_apps.get_model("account", "EmailAddress")
    Master = legacy_apps.get_model("updspaceid", "User")
    Tenant = legacy_apps.get_model("updspaceid", "Tenant")
    Membership = legacy_apps.get_model("updspaceid", "TenantMembership")
    user = User.objects.create(
        username="schema-rehearsal", email="schema@example.test", password="!"
    )
    Email.objects.create(user_id=user.pk, email=user.email, verified=True, primary=True)
    standalone = User.objects.create(
        username="legacy-standalone", email="standalone@example.test", password="!"
    )
    Email.objects.create(
        user_id=standalone.pk, email=standalone.email, verified=True, primary=True
    )
    master = Master.objects.create(
        email=user.email, email_verified=True, status="active"
    )
    tenant = Tenant.objects.create(slug="schema-rehearsal")
    member = Membership.objects.create(
        user_id=master.pk, tenant_id=tenant.pk, status="active", base_role="member"
    )
    now = timezone.now().replace(microsecond=0)
    assert "subject" not in {
        column.name for column in connection.get_describe("idp_oidctoken").columns
    }
    call_command("migrate_ydb", dry_run=True)
    assert LEDGER_TABLE not in set(connection.introspection.table_names())
    assert "source" not in {
        column.name
        for column in connection.get_describe("usid_tenant_membership").columns
    }

    # Crash between independent DDL steps. The next run must resume safely.
    with connection.schema_editor() as editor:
        editor.execute("ALTER TABLE `idp_oidctoken` ADD COLUMN `subject` Utf8;")
    # Migration must not change the email-based subject observed by the still
    # serving old binary, even when a later phase enables provisioning.
    with override_settings(ID_GLOBAL_IDENTITY_PROVISIONING=True):
        call_command("migrate_ydb")
    call_command("migrate_ydb", check=True)
    ledger = read_ledger(connection, set(connection.introspection.table_names()))
    call_command("migrate_ydb")
    assert (
        read_ledger(connection, set(connection.introspection.table_names())) == ledger
    )
    # Simulate a crash after CREATE TABLE, before its implicit deferred index.
    # Existing ledger entries must not hide independently missing schema work.
    session_index = next(
        index.name
        for index in connection.get_describe("django_session").indexes
        if tuple(index.index_columns) == ("expire_date",)
    )
    with connection.schema_editor() as editor:
        editor.execute(
            f"ALTER TABLE `django_session` DROP INDEX {connection.ops.quote_name(session_index)};"
        )
    try:
        call_command("migrate_ydb", check=True)
    except CommandError as exc:
        assert "pending" in str(exc)
    else:
        raise AssertionError("Schema check accepted a missing implicit index")
    assert session_index not in {
        index.name for index in connection.get_describe("django_session").indexes
    }
    call_command("migrate_ydb")
    call_command("migrate_ydb", check=True)
    assert session_index in {
        index.name for index in connection.get_describe("django_session").indexes
    }
    assert (
        read_ledger(connection, set(connection.introspection.table_names())) == ledger
    )
    assert User.objects.filter(pk=user.pk, email=user.email).exists()
    assert Membership.objects.filter(pk=member.pk, base_role="member").exists()
    from accounts.models import AccountIdentity

    binding = AccountIdentity.objects.get(user_id=user.pk)
    assert binding.identity_id == master.pk
    assert binding.public_subject == str(master.pk)
    standalone_binding = AccountIdentity.objects.get(user_id=standalone.pk)
    assert standalone_binding.public_subject == str(standalone.pk)
    assert standalone_binding.identity_id is None
    assert not Master.objects.filter(email=standalone.email).exists()

    # An old binary can keep inserting rows without the nullable new column.
    other = Master.objects.create(email="legacy-writer@example.test", status="active")
    old_write = Membership.objects.create(
        user_id=other.pk, tenant_id=tenant.pk, status="active", base_role="member"
    )
    assert Membership.objects.filter(pk=old_write.pk).exists()
    assert binding.created_at >= now
    print(
        "PASS: N-1 data retained; dry-run is read-only; partial DDL and implicit indexes resume; bindings frozen without provisioning; rerun stable; old writer compatible"
    )
    connection.close()


if __name__ == "__main__":
    main()
