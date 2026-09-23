"""Guard the upgrade policy; real YDB N-1/resume checks live in runtime CI."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from core.management.commands.migrate_ydb import _ordered_models
from core.ydb_migrations import (
    AddColumn,
    MIGRATIONS,
    normalized_type,
    pending_columns,
    validate_ledger,
    validate_models,
)


class SchemaFixture:
    def __init__(self, columns, primary_key=("id",)):
        self.description = SimpleNamespace(
            columns=[
                SimpleNamespace(name=name, type=kind) for name, kind in columns.items()
            ],
            primary_key=primary_key,
        )

    def get_describe(self, table):
        return self.description


def model_fixture(fields):
    return SimpleNamespace(
        _meta=SimpleNamespace(
            db_table="accounts",
            pk=SimpleNamespace(column="id"),
            local_concrete_fields=[
                SimpleNamespace(
                    column=name,
                    null=nullable,
                    db_type=lambda connection, kind=kind: kind,
                )
                for name, kind, nullable in fields
            ],
        )
    )


def test_changed_or_unknown_recorded_migration_is_rejected():
    migration = MIGRATIONS[0]
    validate_ledger({migration.name: migration.checksum})
    with pytest.raises(CommandError, match="was modified"):
        validate_ledger({migration.name: "previous checksum"})
    with pytest.raises(CommandError, match="Unknown applied"):
        validate_ledger({"9999_future_release": "checksum"})
    changed = replace(migration, operations=())
    assert changed.checksum != migration.checksum


def test_existing_schema_upgrade_is_explicit_and_resumable():
    op = AddColumn("accounts", "subject", "Utf8")
    migration = replace(MIGRATIONS[0], operations=(op,))
    old = SchemaFixture({"id": "Int64"})
    assert pending_columns(old, {"accounts"}, (migration,)) == [op]
    # A process stopped after DDL but before its ledger write: no second ALTER.
    expanded = SchemaFixture({"id": "Int64", "subject": "Utf8?"})
    assert pending_columns(expanded, {"accounts"}, (migration,)) == []


def test_existing_wrong_type_is_not_silently_accepted_or_replaced():
    migration = replace(
        MIGRATIONS[0], operations=(AddColumn("accounts", "subject", "Utf8"),)
    )
    with pytest.raises(CommandError, match="type drift"):
        pending_columns(SchemaFixture({"subject": "Int64"}), {"accounts"}, (migration,))


def test_unknown_column_change_blocks_schema_plan():
    old = SchemaFixture({"id": "Int64"})
    model = model_fixture((("id", "BigSerial", False), ("secret", "Utf8", True)))
    with pytest.raises(CommandError, match="Unregistered"):
        validate_models(old, [model], {"accounts"}, [])
    validate_models(
        old, [model], {"accounts"}, [AddColumn("accounts", "secret", "Utf8")]
    )


def test_primary_key_and_type_changes_require_explicit_migration():
    model = model_fixture((("id", "BigSerial", False),))
    with pytest.raises(CommandError, match="primary key drift"):
        validate_models(
            SchemaFixture({"id": "Int64"}, ("other",)), [model], {"accounts"}, []
        )
    with pytest.raises(CommandError, match="type drift"):
        validate_models(SchemaFixture({"id": "Utf8"}), [model], {"accounts"}, [])


@pytest.mark.parametrize(
    "physical,nullable",
    [("Utf8?", False), ("Optional<Utf8>", False), ("Utf8", True)],
)
def test_nullability_drift_is_rejected_in_both_directions(physical, nullable):
    old = SchemaFixture({"id": "Int64", "subject": physical})
    required = model_fixture(
        (("id", "BigSerial", False), ("subject", "Utf8", nullable))
    )
    with pytest.raises(CommandError, match="nullability drift"):
        validate_models(old, [required], {"accounts"}, [])


def test_extra_columns_are_preserved_for_rollback_compatibility():
    validate_models(
        SchemaFixture({"id": "Int64", "future_column": "Utf8?"}),
        [model_fixture((("id", "BigSerial", False),))],
        {"accounts"},
        [],
    )


def test_bootstrap_includes_django_implicit_join_tables():
    names = {model._meta.db_table for model in _ordered_models()}
    assert {
        "auth_user_groups",
        "auth_user_user_permissions",
        "auth_group_permissions",
    } <= names


def test_ydb_runner_refuses_non_ydb_database():
    with pytest.raises(CommandError, match="only run when DB_DRIVER=ydb"):
        call_command("migrate_ydb", dry_run=True)


@pytest.mark.parametrize(
    "raw,expected",
    [("BigSerial", "Int64"), ("Datetime?", "Datetime"), ("Optional<Utf8>", "Utf8")],
)
def test_ydb_introspection_type_spellings(raw, expected):
    assert normalized_type(raw) == expected


def test_migration_identifiers_cannot_inject_ddl():
    with pytest.raises(CommandError, match="Invalid identifier"):
        _ = AddColumn("table`; DROP TABLE users;", "subject", "Utf8").sql
