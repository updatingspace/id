from __future__ import annotations

import json
import re
import uuid
from datetime import date, datetime
from decimal import Decimal
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


def _patch_ydb_write_compiler_relation_types() -> None:
    try:
        from ydb_backend.models.sql import compiler as ydb_compiler
    except Exception:
        return

    if getattr(ydb_compiler.BaseSQLWriteCompiler, "_updspace_id_relation_patch", False):
        return

    def _field_internal_type(field) -> str:
        target_field = getattr(field, "target_field", None)
        if target_field is not None:
            return target_field.get_internal_type()
        internal_type = field.get_internal_type()
        if internal_type in {"FileField", "ImageField"}:
            return "TextField"
        return internal_type

    def _ydb_field_type(field):
        field_type = ydb_compiler._ydb_types[_field_internal_type(field)]
        if getattr(field, "null", False):
            return ydb.OptionalType(field_type)
        return field_type

    def _patched_prepare_sql_statement(self):
        qn = self.connection.ops.quote_name
        opts = self.query.get_meta()
        fields = self.query.fields or [opts.pk]

        field_types = [
            qn(f.column)
            + ": "
            + self.connection.introspection.get_field_type(_field_internal_type(f), {})
            for f in fields
        ]
        in_ = f"{', '.join(field_types)}"

        return [
            f"DECLARE $in_ as List<Struct<{in_}>>;",
            f"{self._get_statement()} {qn(opts.db_table)}",
            f"({', '.join(qn(f.column) for f in fields)})",
            f"SELECT {', '.join(qn(f.column) for f in fields)} FROM AS_TABLE($in_);",
        ]

    def _patched_get_data_type(fields):
        struct_type = ydb.StructType()
        for field in fields:
            struct_type.add_member(
                field.column,
                _ydb_field_type(field),
            )
        return ydb.ListType(struct_type)

    def _patched_get_data(fields, param_rows):
        result = []
        for row in param_rows:
            struct = {}
            for index, field in enumerate(fields):
                value = row[index]
                if _field_internal_type(field) == "DateTimeField" and value is not None:
                    value = int(value.timestamp())
                struct[field.column] = value
            result.append(struct)
        return result

    def _infer_ydb_param_type(value):
        if isinstance(value, bool):
            return ydb_compiler._ydb_types["BooleanField"], value
        if isinstance(value, datetime):
            return ydb_compiler._ydb_types["DateTimeField"], int(value.timestamp())
        if isinstance(value, date):
            return ydb_compiler._ydb_types["DateField"], value
        if isinstance(value, uuid.UUID):
            return ydb_compiler._ydb_types["UUIDField"], value
        if isinstance(value, int):
            return ydb.PrimitiveType.Int64, value
        if isinstance(value, float):
            return ydb_compiler._ydb_types["DoubleField"], value
        if isinstance(value, Decimal):
            return ydb_compiler._ydb_types["DecimalField"], value
        if isinstance(value, bytes):
            return ydb_compiler._ydb_types["BinaryField"], value
        return ydb_compiler._ydb_types["TextField"], value

    def _patched_generate_params_for_update(
        placeholder_rows, columns, field_types, params
    ):
        modified_params = {}
        for placeholder, value in zip(placeholder_rows, params, strict=False):
            ydb_type, prepared = _infer_ydb_param_type(value)
            modified_params[placeholder] = (prepared, ydb_type)
        return modified_params

    ydb_compiler.BaseSQLWriteCompiler._prepare_sql_statement = (
        _patched_prepare_sql_statement
    )
    ydb_compiler._get_data = _patched_get_data
    ydb_compiler._get_data_type = _patched_get_data_type
    ydb_compiler._generate_params_for_update = _patched_generate_params_for_update
    ydb_compiler.BaseSQLWriteCompiler._updspace_id_relation_patch = True


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
    _patch_ydb_write_compiler_relation_types()

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
