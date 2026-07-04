import json

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


def test_build_database_settings_patches_ydb_jsonfield_adapter(tmp_path):
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

    from ydb_backend.backend.operations import DatabaseOperations

    operations = DatabaseOperations(connection=None)
    assert operations.adapt_json_value(["openid", "profile"], encoder=None) == (
        '["openid","profile"]'
    )
    assert operations.adapt_json_value({"scope": "openid"}, encoder=None) == (
        '{"scope":"openid"}'
    )
    assert operations.adapt_json_value(None, encoder=None) is None


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
