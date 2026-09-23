"""Resume the same model indexes that the installed YDB backend creates."""

from io import StringIO
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.sessions.models import Session
from django.core.management.base import CommandError
from ydb_backend.backend.base import DatabaseWrapper

from core.management.commands.migrate_ydb import Command, _pending_indexes
from idp.models import OidcToken


@pytest.fixture
def schema_connection():
    # SQL generation only: no socket or database is opened.
    connection = DatabaseWrapper(
        {
            "NAME": "default",
            "ENGINE": "ydb_backend.backend",
            "OPTIONS": {"endpoint": "grpc://localhost:2136", "database": "/local"},
        }
    )
    connection.get_describe = MagicMock(return_value=SimpleNamespace(indexes=[]))
    return connection


def test_implicit_session_index_is_detected_and_uses_bootstrap_sql(schema_connection):
    assert Session._meta.indexes == []
    [(table, statement)] = _pending_indexes(
        schema_connection, [Session], {"django_session"}
    )
    assert table == "django_session"
    assert str(statement) == (
        "ALTER TABLE `django_session` ADD INDEX "
        "`django_session_expire_date_a5c62663` GLOBAL ON (`expire_date`);"
    )
    schema_connection.get_describe.return_value.indexes = [
        SimpleNamespace(
            name="django_session_expire_date_a5c62663", index_columns=["expire_date"]
        )
    ]
    assert _pending_indexes(schema_connection, [Session], {"django_session"}) == []


def test_present_meta_indexes_do_not_hide_missing_implicit_fk(schema_connection):
    inventory = _pending_indexes(schema_connection, [OidcToken], {"idp_oidctoken"})
    schema_connection.get_describe.return_value.indexes = [
        SimpleNamespace(
            name=str(statement.parts["name"]).strip("`"),
            index_columns=statement.parts["columns"].columns,
        )
        for _, statement in inventory
        if tuple(statement.parts["columns"].columns) != ("client_id",)
    ]
    [(table, statement)] = _pending_indexes(
        schema_connection, [OidcToken], {"idp_oidctoken"}
    )
    assert table == "idp_oidctoken"
    assert tuple(statement.parts["columns"].columns) == ("client_id",)


def test_implicit_index_with_wrong_columns_is_not_overwritten(schema_connection):
    schema_connection.get_describe.return_value.indexes = [
        SimpleNamespace(
            name="django_session_expire_date_a5c62663", index_columns=["session_key"]
        )
    ]
    with pytest.raises(CommandError, match="index drift"):
        _pending_indexes(schema_connection, [Session], {"django_session"})


def test_missing_table_is_left_to_model_bootstrap(schema_connection):
    assert _pending_indexes(schema_connection, [Session], set()) == []
    schema_connection.get_describe.assert_not_called()


def test_command_does_not_record_success_when_index_postcondition_fails():
    connection = MagicMock()
    connection.settings_dict = {"ENGINE": "ydb_backend.backend"}
    connection.introspection.table_names.return_value = ["django_session"]
    statement = SimpleNamespace(parts={"name": "missing_index"})
    module = "core.management.commands.migrate_ydb"
    with (
        patch(f"{module}.connection", connection),
        patch(f"{module}._ordered_models", return_value=[Session]),
        patch(f"{module}.read_ledger", return_value={}),
        patch(f"{module}.validate_ledger"),
        patch(f"{module}.pending_columns", return_value=[]),
        patch(f"{module}.validate_models"),
        patch(
            f"{module}._pending_indexes",
            return_value=[("django_session", statement)],
        ),
        patch(f"{module}.apply_data_migration") as backfill,
        patch(f"{module}.write_ledger") as ledger,
    ):
        with pytest.raises(CommandError, match="index creation did not complete"):
            Command(stdout=StringIO()).handle(dry_run=False, check=False)
    backfill.assert_not_called()
    ledger.assert_not_called()
