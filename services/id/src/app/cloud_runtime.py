from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import dj_database_url
import ydb
from django.core.exceptions import ImproperlyConfigured
from django.db.utils import NotSupportedError


def _require(name: str, read_env: Callable[[str, str | None], str | None]) -> str:
    value = read_env(name)
    if value is None:
        raise ImproperlyConfigured(f"{name} must be set when DB_DRIVER=ydb")
    return value


def _parse_endpoint(endpoint: str) -> tuple[str, int, str]:
    parsed = urlparse(endpoint if "://" in endpoint else f"grpc://{endpoint}")
    host = parsed.hostname
    port = parsed.port or 2136
    if not host:
        raise ImproperlyConfigured(
            "YDB_ENDPOINT must be host:port or grpc[s]://host:port"
        )
    protocol = parsed.scheme or "grpc"
    return host, port, protocol


def _normalize_database_version(version):
    if version in (None, ("main",), "main"):
        return ("main",) if version == "main" else version

    if isinstance(version, str):
        numeric_parts = re.findall(r"\d+", version)
        return (
            tuple(int(part) for part in numeric_parts) if numeric_parts else (version,)
        )

    normalized: list[int | str] = []
    for part in version:
        if isinstance(part, int):
            normalized.append(part)
            continue
        if isinstance(part, str):
            if part == "main":
                return ("main",)
            numeric_parts = re.findall(r"\d+", part)
            if numeric_parts:
                normalized.extend(int(item) for item in numeric_parts)
            continue
        normalized.append(part)

    return tuple(normalized) if normalized else version


def _can_compare_database_versions(version, minimum_version) -> bool:
    if version in (None, ("main",)) or minimum_version is None:
        return False
    return all(isinstance(part, int) for part in version) and all(
        isinstance(part, int) for part in minimum_version
    )


def _patch_ydb_version_check() -> None:
    try:
        from ydb_backend.backend import base as ydb_base
    except Exception:
        return

    if getattr(ydb_base.DatabaseWrapper, "_updspace_id_version_patch", False):
        return

    original_get_database_version = ydb_base.DatabaseWrapper.get_database_version

    def _normalized_get_database_version(self):
        return _normalize_database_version(original_get_database_version(self))

    def _normalized_check_database_version_supported(self):
        version = _normalize_database_version(original_get_database_version(self))
        minimum_version = _normalize_database_version(
            self.features.minimum_database_version
        )
        if (
            _can_compare_database_versions(version, minimum_version)
            and version < minimum_version
        ):
            db_version = ".".join(map(str, version))
            min_db_version = ".".join(map(str, minimum_version))
            raise NotSupportedError(
                f"{self.display_name} {min_db_version} or later is required "
                f"(found {db_version})."
            )
        return None

    ydb_base.DatabaseWrapper.get_database_version = _normalized_get_database_version
    ydb_base.DatabaseWrapper.check_database_version_supported = (
        _normalized_check_database_version_supported
    )
    ydb_base.DatabaseWrapper._updspace_id_version_patch = True


def _patch_ydb_jsonfield_adapter() -> None:
    try:
        from ydb_backend.backend import operations as ydb_operations
    except Exception:
        return

    if getattr(ydb_operations.DatabaseOperations, "_updspace_id_json_patch", False):
        return

    def _adapt_json_value(self, value, encoder):
        if value is None:
            return None
        return json.dumps(value, cls=encoder, separators=(",", ":"))

    ydb_operations.DatabaseOperations.adapt_json_value = _adapt_json_value
    ydb_operations.DatabaseOperations._updspace_id_json_patch = True


def _patch_ydb_query_parameters() -> None:
    # django-ydb-backend 0.0.1b1 drops parameters without a model column.
    # Django's exists() starts with SELECT %s (the literal 1), so subsequent
    # parameters shift and the compiler raises IndexError before querying YDB.
    from ydb_backend.models.sql import compiler

    if getattr(compiler, "_updspace_id_parameters_patch", False):
        return

    def _parameters(placeholders, columns, field_types, params):
        result = {}
        for index, (placeholder, value) in enumerate(zip(placeholders, params)):
            column = columns[index] if index < len(columns) else None
            field_type = field_types.get(column)
            if field_type is None:
                # The SDK infers literal/annotation parameter types. Keep their
                # position rather than treating them as a neighbouring column.
                result[placeholder] = value
                continue
            parameter_type = compiler._ydb_types[field_type]
            if value is None:
                parameter_type = ydb.OptionalType(parameter_type)
            elif field_type == "DateTimeField":
                value = int(value.timestamp())
            elif field_type in {"FileField", "FilePathField"} and isinstance(
                value, str
            ):
                value = value.encode()
            result[placeholder] = (value, parameter_type)
        return result

    compiler._generate_params_for_update = _parameters

    def _field_type(field):
        while getattr(field, "target_field", None) is not None:
            field = field.target_field
        return field.get_internal_type()

    def _insert_data(fields, rows):
        def prepare(field, value):
            if value is None:
                return None
            kind = _field_type(field)
            if kind == "DateTimeField":
                return int(value.timestamp())
            if kind in {"FileField", "FilePathField"} and isinstance(value, str):
                return value.encode()
            return value

        return [
            {field.column: prepare(field, value) for field, value in zip(fields, row)}
            for row in rows
        ]

    def _insert_type(fields):
        struct = ydb.StructType()
        for field in fields:
            field_type = compiler._ydb_types[_field_type(field)]
            if field.null:
                field_type = ydb.OptionalType(field_type)
            struct.add_member(field.column, field_type)
        return ydb.ListType(struct)

    def _insert_sql(self):
        opts = self.query.get_meta()
        fields = self.query.fields or [opts.pk]
        qn = self.connection.ops.quote_name
        # Parameter types are supplied to the SDK with $in_; duplicating a
        # non-nullable DECLARE breaks nullable model fields such as last_login.
        names = ", ".join(qn(field.column) for field in fields)
        return [
            f"{self._get_statement()} {qn(opts.db_table)} ({names})",
            f"SELECT {names} FROM AS_TABLE($in_);",
        ]

    compiler._get_data = _insert_data
    compiler._get_data_type = _insert_type
    compiler.BaseSQLWriteCompiler._prepare_sql_statement = _insert_sql

    def _execute_insert(self, returning_fields=None):
        rows = []
        with self.connection.cursor() as cursor:
            for sql, params in self.as_sql():
                if returning_fields:
                    names = ", ".join(
                        self.connection.ops.quote_name(field.column)
                        for field in returning_fields
                    )
                    sql = sql.rstrip(";") + f" RETURNING {names};"
                # Use the active data transaction, including for get_or_create.
                cursor.execute(sql, params)
                if returning_fields:
                    rows.extend(cursor.fetchall())
        if returning_fields:
            cols = [
                field.get_col(self.query.get_meta().db_table)
                for field in returning_fields
            ]
            converters = self.get_converters(cols)
            if converters:
                rows = list(self.apply_converters(rows, converters))
        return rows

    # ORDER BY id DESC in the upstream driver can return another request's ID.
    compiler.BaseSQLWriteCompiler.execute_sql = _execute_insert

    def _update_sql(self):
        from django.db.models.sql.compiler import SQLUpdateCompiler

        sql, params = SQLUpdateCompiler.as_sql(self)
        if not sql:
            return sql, params
        # The upstream mapping uses field.name, so user_id is untyped and the
        # SDK infers Int64 even when the referenced user PK is an Int32.
        columns = compiler._extract_column_names(sql)
        sql, placeholders = compiler._replace_placeholders(sql)
        field_types = {
            field.column: _field_type(field)
            for field in self.query.model._meta.concrete_fields
        }
        return sql, _parameters(placeholders, columns, field_types, params)

    compiler.SQLUpdateCompiler.as_sql = _update_sql

    def _execute_update(self, result_type=None):
        sql, params = self.as_sql()
        if not sql:
            return 0
        pk = self.connection.ops.quote_name(self.query.get_meta().pk.column)
        with self.connection.cursor() as cursor:
            cursor.execute(sql.rstrip(";") + f" RETURNING {pk};", params)
            return len(cursor.fetchall())

    compiler.SQLUpdateCompiler.execute_sql = _execute_update

    from ydb_backend.backend.base import DatabaseWrapper
    from ydb_backend.backend.operations import DatabaseOperations
    from ydb_dbapi import IsolationLevel
    from django.conf import settings
    from django.utils import timezone
    from datetime import timezone as datetime_timezone

    original_converters = DatabaseOperations.get_db_converters

    def _datetime_value(value, expression, connection):
        if value is not None and settings.USE_TZ and timezone.is_naive(value):
            return timezone.make_aware(value, datetime_timezone.utc)
        return value

    def _file_value(value, expression, connection):
        return value.decode() if isinstance(value, bytes) else value

    def _converters(self, expression):
        result = original_converters(self, expression)
        kind = _field_type(expression.output_field)
        if kind == "DateTimeField":
            result.append(_datetime_value)
        elif kind in {"FileField", "FilePathField"}:
            result.append(_file_value)
        return result

    DatabaseOperations.get_db_converters = _converters

    def _set_autocommit(self, autocommit):
        self.connection.set_isolation_level(
            IsolationLevel.AUTOCOMMIT if autocommit else IsolationLevel.SERIALIZABLE
        )
        if not autocommit:
            self.connection.begin()

    DatabaseWrapper._set_autocommit = _set_autocommit
    compiler._updspace_id_parameters_patch = True


def build_database_settings(
    *,
    base_dir: Path,
    read_env: Callable[[str, str | None], str | None],
    conn_max_age: int = 600,
) -> tuple[str, dict[str, dict]]:
    db_driver = (read_env("DB_DRIVER", "postgres") or "postgres").strip().lower()

    if db_driver == "postgres":
        database_url = read_env("DATABASE_URL")
        if database_url:
            return (
                db_driver,
                {
                    "default": dj_database_url.config(
                        default=database_url,
                        conn_max_age=conn_max_age,
                    )
                },
            )
        return (
            db_driver,
            {
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": base_dir / "db.sqlite3",
                }
            },
        )

    if db_driver != "ydb":
        raise ImproperlyConfigured("DB_DRIVER must be one of: postgres, ydb")

    _patch_ydb_version_check()
    _patch_ydb_jsonfield_adapter()
    _patch_ydb_query_parameters()

    ydb_endpoint = _require("YDB_ENDPOINT", read_env)
    ydb_database = _require("YDB_DATABASE", read_env)
    ydb_name = read_env("YDB_NAME", "default") or "default"
    host, port, protocol = _parse_endpoint(ydb_endpoint)

    database_settings: dict[str, object] = {
        "ENGINE": "ydb_backend.backend",
        "NAME": ydb_name,
        "HOST": host,
        "PORT": str(port),
        "DATABASE": ydb_database,
        "OPTIONS": {"protocol": protocol},
        "CONN_MAX_AGE": conn_max_age,
    }

    credentials_mode = (
        (read_env("YDB_CREDENTIALS_MODE", "metadata") or "metadata").strip().lower()
    )
    if credentials_mode == "token":
        database_settings["CREDENTIALS"] = {"token": _require("YDB_TOKEN", read_env)}
    elif credentials_mode == "sa_json":
        raw = _require("YDB_SERVICE_ACCOUNT_JSON", read_env)
        try:
            database_settings["CREDENTIALS"] = {"service_account_json": json.loads(raw)}
        except json.JSONDecodeError as exc:
            raise ImproperlyConfigured(
                "YDB_SERVICE_ACCOUNT_JSON must contain valid JSON"
            ) from exc
    elif credentials_mode == "metadata":
        database_settings["CREDENTIALS"] = ydb.iam.MetadataUrlCredentials()
    elif credentials_mode != "metadata":
        raise ImproperlyConfigured(
            "YDB_CREDENTIALS_MODE must be one of: metadata, token, sa_json"
        )

    return db_driver, {"default": database_settings}


def build_ydb_migration_modules(*app_labels: str) -> dict[str, str]:
    return {app_label: f"{app_label}.migrations_ydb" for app_label in app_labels}
