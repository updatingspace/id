"""Reviewed, additive YDB schema changes with a resumable migration ledger.

DDL is not transactional. Each step must inspect its postcondition before doing
work, and the ledger is written only after the whole migration is verified.
Dropping columns, changing types and data backfills require explicit future
migrations; the runner never infers destructive changes from Django models.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from django.core.management.base import CommandError

LEDGER_TABLE = "id_schema_migrations"


@dataclass(frozen=True)
class AddColumn:
    table: str
    column: str
    data_type: str

    @property
    def sql(self) -> str:
        # Only reviewed identifiers and primitive types belong in migrations.
        for name in (self.table, self.column, self.data_type):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise CommandError("Invalid identifier in YDB migration")
        # An omitted nullability modifier creates a nullable expansion column.
        # Old binaries may keep inserting rows without the new column.
        return (
            f"ALTER TABLE `{self.table}` ADD COLUMN `{self.column}` {self.data_type};"
        )


@dataclass(frozen=True)
class SchemaMigration:
    name: str
    operations: tuple[AddColumn, ...]
    data_migration: str = ""

    @property
    def checksum(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


MIGRATIONS = (
    SchemaMigration(
        "0001_immutable_identity",
        (AddColumn("idp_oidctoken", "subject", "Utf8"),),
        data_migration="freeze_account_identities_v1",
    ),
)


def normalized_type(raw: str) -> str:
    raw = raw.removesuffix("?")
    if raw.startswith("Optional<") and raw.endswith(">"):
        raw = raw[9:-1]
    return {"Serial": "Int32", "BigSerial": "Int64", "SmallSerial": "Int16"}.get(
        raw, raw
    )


def read_ledger(connection, tables: set[str]) -> dict[str, str]:
    if LEDGER_TABLE not in tables:
        return {}
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT name, checksum FROM `{LEDGER_TABLE}`")
        return dict(cursor.fetchall())


def validate_ledger(applied: dict[str, str], migrations=MIGRATIONS) -> None:
    expected = {migration.name: migration.checksum for migration in migrations}
    for name, checksum in applied.items():
        if name not in expected:
            raise CommandError(
                f"Unknown applied YDB migration: {name}; use the matching release"
            )
        if checksum != expected[name]:
            raise CommandError(f"Applied YDB migration was modified: {name}")


def pending_columns(
    connection, tables: set[str], migrations=MIGRATIONS
) -> list[AddColumn]:
    pending = []
    for migration in migrations:
        for operation in migration.operations:
            if operation.table not in tables:
                continue  # Current model bootstrap includes these columns.
            columns = {
                c.name: str(c.type)
                for c in connection.get_describe(operation.table).columns
            }
            if operation.column not in columns:
                pending.append(operation)
            elif normalized_type(columns[operation.column]) != operation.data_type:
                raise CommandError(
                    f"YDB type drift: {operation.table}.{operation.column}"
                )
    return pending


def validate_models(
    connection, models, tables: set[str], planned: list[AddColumn]
) -> None:
    additions = {(op.table, op.column): op for op in planned}
    for model in models:
        table = model._meta.db_table
        if table not in tables:
            continue
        description = connection.get_describe(table)
        columns = {c.name: str(c.type) for c in description.columns}
        if list(description.primary_key) != [model._meta.pk.column]:
            raise CommandError(f"YDB primary key drift: {table}")
        for field in model._meta.local_concrete_fields:
            expected = field.db_type(connection)
            if expected is None:
                continue
            actual = columns.get(field.column)
            if actual is None:
                addition = additions.get((table, field.column))
                if addition and normalized_type(expected) == addition.data_type:
                    if not field.null:
                        raise CommandError(
                            f"YDB additive expansion must be nullable: {table}.{field.column}"
                        )
                    continue
                raise CommandError(
                    f"Unregistered YDB column change: {table}.{field.column}"
                )
            if normalized_type(actual) != normalized_type(expected):
                raise CommandError(f"YDB type drift: {table}.{field.column}")
            nullable = actual.endswith("?") or (
                actual.startswith("Optional<") and actual.endswith(">")
            )
            if nullable != field.null:
                raise CommandError(f"YDB nullability drift: {table}.{field.column}")


def write_ledger(connection, migrations=MIGRATIONS) -> None:
    with connection.schema_editor() as editor:
        editor.execute(
            f"CREATE TABLE IF NOT EXISTS `{LEDGER_TABLE}` ("
            "name Utf8 NOT NULL, checksum Utf8 NOT NULL, applied_at Datetime NOT NULL, "
            "PRIMARY KEY (name));"
        )
    for migration in migrations:
        if not re.fullmatch(r"[A-Za-z0-9_]+", migration.name):
            raise CommandError("Invalid YDB migration name")
        # Values are immutable source-controlled names and computed hex digests.
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPSERT INTO `{LEDGER_TABLE}` (name, checksum, applied_at) "
                f"VALUES ('{migration.name}', '{migration.checksum}', CurrentUtcDatetime());"
            )


def apply_data_migration(connection, migration: SchemaMigration) -> dict:
    if not migration.data_migration:
        return {}
    if migration.data_migration != "freeze_account_identities_v1":
        raise CommandError(f"Unknown YDB data migration: {migration.data_migration}")
    from accounts.services.identity import backfill_identity_bindings

    return backfill_identity_bindings(using=connection.alias)
