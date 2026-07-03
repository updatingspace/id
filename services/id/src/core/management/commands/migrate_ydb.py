from __future__ import annotations

from collections.abc import Iterable

from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import connection


class Command(BaseCommand):
    help = (
        "Bootstrap current Django models into YDB using the configured schema editor."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print the tables/models that would be created.",
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

                if options["dry_run"]:
                    self.stdout.write(f"create {model._meta.label} ({table_name})")
                    continue

                schema_editor.create_model(model)
                existing_tables.add(table_name)
                created += 1
                self.stdout.write(
                    self.style.SUCCESS(f"created {model._meta.label} ({table_name})")
                )

        if options["dry_run"]:
            self.stdout.write(self.style.SUCCESS(f"planned {len(models)} models"))
            return

        self.stdout.write(
            self.style.SUCCESS(
                f"migrate_ydb completed: created={created}, skipped={skipped}"
            )
        )


def _ordered_models() -> Iterable[type]:
    managed_models = [
        model
        for model in apps.get_models(include_auto_created=False)
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
