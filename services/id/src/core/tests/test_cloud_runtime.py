import json
import uuid
from datetime import datetime, timezone

import pytest
from django.core.exceptions import ImproperlyConfigured

from app.cloud_runtime import build_database_settings, build_ydb_migration_modules


def _reader(values):
    def read_env(name, default=None):
        return values.get(name, default)

    return read_env


def test_build_database_settings_defaults_to_sqlite_when_postgres_url_missing(tmp_path):
    db_driver, databases = build_database_settings(
        base_dir=tmp_path,
        read_env=_reader({}),
    )

    assert db_driver == "postgres"
    assert databases["default"]["ENGINE"] == "django.db.backends.sqlite3"


def test_build_database_settings_accepts_service_account_json(tmp_path):
    db_driver, databases = build_database_settings(
        base_dir=tmp_path,
        read_env=_reader(
            {
                "DB_DRIVER": "ydb",
                "YDB_ENDPOINT": "grpcs://ydb.serverless.yandexcloud.net:2135",
                "YDB_DATABASE": "/ru-central1/example/database",
                "YDB_CREDENTIALS_MODE": "sa_json",
                "YDB_SERVICE_ACCOUNT_JSON": json.dumps({"id": "service-account"}),
            }
        ),
    )

    default = databases["default"]
    assert db_driver == "ydb"
    assert default["ENGINE"] == "ydb_backend.backend"
    assert default["HOST"] == "ydb.serverless.yandexcloud.net"
    assert default["PORT"] == "2135"
    assert default["DATABASE"] == "/ru-central1/example/database"
    assert default["OPTIONS"] == {"protocol": "grpcs"}
    assert default["CREDENTIALS"] == {"service_account_json": {"id": "service-account"}}


def test_build_database_settings_uses_metadata_credentials_by_default_for_ydb(tmp_path):
    db_driver, databases = build_database_settings(
        base_dir=tmp_path,
        read_env=_reader(
            {
                "DB_DRIVER": "ydb",
                "YDB_ENDPOINT": "grpcs://ydb.serverless.yandexcloud.net:2135",
                "YDB_DATABASE": "/ru-central1/example/database",
            }
        ),
    )

    default = databases["default"]
    assert db_driver == "ydb"
    assert default["CREDENTIALS"].__class__.__name__ == "MetadataUrlCredentials"


def test_ydb_write_compiler_uses_target_field_type_for_foreign_keys(tmp_path):
    build_database_settings(
        base_dir=tmp_path,
        read_env=_reader(
            {
                "DB_DRIVER": "ydb",
                "YDB_ENDPOINT": "grpcs://ydb.serverless.yandexcloud.net:2135",
                "YDB_DATABASE": "/ru-central1/example/database",
            }
        ),
    )

    from ydb_backend.models.sql import compiler as ydb_compiler

    class FakeOps:
        @staticmethod
        def quote_name(name):
            return f"`{name}`"

    class FakeIntrospection:
        @staticmethod
        def get_field_type(data_type, description):
            return {
                "BigAutoField": "Int64",
                "UUIDField": "UUID",
            }[data_type]

    class FakeConnection:
        ops = FakeOps()
        introspection = FakeIntrospection()

    class FakeMeta:
        db_table = "smoke_table"
        pk = None

    class FakeQuery:
        fields = []

        @staticmethod
        def get_meta():
            return FakeMeta()

    class FakeCompiler(ydb_compiler.BaseSQLWriteCompiler):
        connection = FakeConnection()
        query = FakeQuery()

        def _get_statement(self):
            return "UPSERT INTO"

    class FakeTargetField:
        def __init__(self, internal_type):
            self.internal_type = internal_type

        def get_internal_type(self):
            return self.internal_type

    class FakeForeignKeyField:
        def __init__(self, column, target_internal_type):
            self.column = column
            self.target_field = FakeTargetField(target_internal_type)

        @staticmethod
        def get_internal_type():
            return "ForeignKey"

    big_auto_fk = FakeForeignKeyField("user_id", "BigAutoField")
    uuid_fk = FakeForeignKeyField("tenant_id", "UUIDField")
    FakeQuery.fields = [big_auto_fk, uuid_fk]

    compiler = FakeCompiler.__new__(FakeCompiler)
    compiler.connection = FakeConnection()
    compiler.query = FakeQuery()
    sql = " ".join(compiler._prepare_sql_statement())

    assert "`user_id`: Int64" in sql
    assert "`tenant_id`: UUID" in sql


def test_ydb_select_param_binding_infers_types_when_columns_do_not_match(tmp_path):
    build_database_settings(
        base_dir=tmp_path,
        read_env=_reader(
            {
                "DB_DRIVER": "ydb",
                "YDB_ENDPOINT": "grpcs://ydb.serverless.yandexcloud.net:2135",
                "YDB_DATABASE": "/ru-central1/example/database",
            }
        ),
    )

    from ydb_backend.models.sql import compiler as ydb_compiler

    uid = uuid.uuid4()
    now = datetime(2026, 7, 4, 19, 16, tzinfo=timezone.utc)
    params = ydb_compiler._generate_params_for_update(
        ["$element_1", "$element_2", "$element_3", "$element_4"],
        ["id"],
        {"id": "BigAutoField"},
        [42, uid, True, now],
    )

    assert params["$element_1"][0] == 42
    assert str(params["$element_1"][1]) == "Int64"
    assert params["$element_2"][0] == uid
    assert str(params["$element_2"][1]) == "UUID"
    assert params["$element_3"][0] is True
    assert str(params["$element_3"][1]) == "Bool"
    assert params["$element_4"][0] == int(now.timestamp())
    assert str(params["$element_4"][1]) == "Datetime"


def test_ydb_insert_data_keeps_nullable_datetime_none(tmp_path):
    build_database_settings(
        base_dir=tmp_path,
        read_env=_reader(
            {
                "DB_DRIVER": "ydb",
                "YDB_ENDPOINT": "grpcs://ydb.serverless.yandexcloud.net:2135",
                "YDB_DATABASE": "/ru-central1/example/database",
            }
        ),
    )

    from ydb_backend.models.sql import compiler as ydb_compiler

    class FakeDateTimeField:
        column = "checked_at"

        @staticmethod
        def get_internal_type():
            return "DateTimeField"

    now = datetime(2026, 7, 4, 19, 24, tzinfo=timezone.utc)

    rows = ydb_compiler._get_data(
        [FakeDateTimeField()],
        [[None], [now]],
    )

    assert rows[0]["checked_at"] is None
    assert rows[1]["checked_at"] == int(now.timestamp())


def test_build_database_settings_rejects_unknown_driver(tmp_path):
    with pytest.raises(ImproperlyConfigured):
        build_database_settings(
            base_dir=tmp_path,
            read_env=_reader({"DB_DRIVER": "mysql"}),
        )


def test_build_ydb_migration_modules():
    assert build_ydb_migration_modules("accounts", "idp") == {
        "accounts": "accounts.migrations_ydb",
        "idp": "idp.migrations_ydb",
    }
