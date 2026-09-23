from __future__ import annotations

from collections.abc import Iterable

from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from core.ydb_migrations import (
    MIGRATIONS,
    apply_data_migration,
    pending_columns,
    read_ledger,
    validate_ledger,
    validate_models,
    write_ledger,
)


class Command(BaseCommand):
    help = "Bootstrap and apply reviewed additive YDB migrations; reject schema drift."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print pending tables, columns, indexes and migration versions without writing.",
        )
        parser.add_argument(
            "--check",
            action="store_true",
            help="Fail if schema work is pending; never write.",
        )

    def handle(self, *args, **options):
        engine = connection.settings_dict.get("ENGINE", "")
        if "ydb_backend" not in engine:
            raise CommandError(
                "migrate_ydb can only run when DB_DRIVER=ydb / "
                "ENGINE=ydb_backend.backend"
            )

        connection.ensure_connection()
        models = list(_ordered_models())
        existing_tables = set(connection.introspection.table_names())
        applied = read_ledger(connection, existing_tables)
        validate_ledger(applied)
        columns = pending_columns(connection, existing_tables)
        validate_models(connection, models, existing_tables, columns)
        pending_versions = [m for m in MIGRATIONS if m.name not in applied]
        index_changes = _pending_indexes(connection, models, existing_tables)
        read_only = options["dry_run"] or options["check"]
        created = 0
        skipped = 0

        with connection.schema_editor() as schema_editor:
            for model in models:
                table_name = model._meta.db_table
                if table_name in existing_tables:
                    skipped += 1
                    self.stdout.write(
                        self.style.NOTICE(f"skip {model._meta.label} ({table_name})")
                    )
                    continue

                if read_only:
                    self.stdout.write(f"create {model._meta.label} ({table_name})")
                    continue

                schema_editor.create_model(model)
                existing_tables.add(table_name)
                created += 1
                self.stdout.write(
                    self.style.SUCCESS(f"created {model._meta.label} ({table_name})")
                )

            for operation in columns:
                self.stdout.write(operation.sql)
                if not read_only:
                    schema_editor.execute(operation.sql)
            for table, statement in index_changes:
                self.stdout.write(f"add index {table}.{statement.parts['name']}")
                if not read_only:
                    schema_editor.execute(statement)
        for migration in pending_versions:
            if migration.data_migration:
                self.stdout.write(f"backfill {migration.data_migration} (resumable)")
            self.stdout.write(
                f"record migration {migration.name} ({migration.checksum})"
            )

        if read_only:
            pending = bool(
                pending_versions
                or columns
                or index_changes
                or any(model._meta.db_table not in existing_tables for model in models)
            )
            if options["check"] and pending:
                raise CommandError("YDB schema migrations are pending")
            self.stdout.write(self.style.SUCCESS("YDB schema plan complete"))
            return

        # DDL may partially succeed. A rerun rechecks each operation, and records
        # success only once all required columns and indexes are present.
        validate_models(connection, models, existing_tables, [])
        if pending_columns(connection, existing_tables):
            raise CommandError("YDB schema expansion did not complete")
        if _pending_indexes(connection, models, existing_tables):
            raise CommandError("YDB index creation did not complete")
        for migration in pending_versions:
            result = apply_data_migration(connection, migration)
            if result:
                self.stdout.write(f"backfill {migration.name}: {result}")
            write_ledger(connection, (migration,))

        self.stdout.write(
            self.style.SUCCESS(
                f"migrate_ydb completed: created={created}, skipped={skipped}"
            )
        )


def _pending_indexes(connection, models, tables: set[str]) -> list[tuple]:
    """Use exactly bootstrap's inventory, including implicit field/FK indexes.

    YDB creates these indexes after CREATE TABLE. A crash before deferred SQL
    completes leaves the table present, so reruns must inspect them separately.
    """
    editor = connection.schema_editor(collect_sql=True)
    pending = []
    for model in models:
        table = model._meta.db_table
        if table not in tables:
            continue
        actual = {
            editor.quote_name(index.name): tuple(index.index_columns)
            for index in connection.get_describe(table).indexes
        }
        for statement in editor._model_indexes_sql(model):
            name = str(statement.parts["name"])
            expected = tuple(statement.parts["columns"].columns)
            if name in actual and actual[name] != expected:
                raise CommandError(f"YDB index drift: {table}.{name}")
            if name not in actual:
                pending.append((table, statement))
    return pending


def _ordered_models(registry=apps) -> Iterable[type]:
    managed_models = [
        model
        for model in registry.get_models(include_auto_created=True)
        if model._meta.managed and not model._meta.proxy
    ]
    managed_set = set(managed_models)
    remaining = set(managed_models)
    ordered: list[type] = []

    while remaining:
        ordered_set = set(ordered)
        ready = sorted(
            [
                model
                for model in remaining
                if _dependencies(model, managed_set) <= ordered_set
            ],
            key=lambda model: model._meta.label_lower,
        )
        if not ready:
            ready = sorted(remaining, key=lambda model: model._meta.label_lower)
        for model in ready:
            ordered.append(model)
            remaining.remove(model)

    return ordered


def _dependencies(model: type, managed_set: set[type]) -> set[type]:
    deps: set[type] = set()
    for field in model._meta.local_fields:
        remote_field = getattr(field, "remote_field", None)
        remote_model = getattr(remote_field, "model", None)
        if isinstance(remote_model, type) and remote_model in managed_set:
            deps.add(remote_model)
    return deps
