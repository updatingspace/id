from datetime import datetime, timezone

import ydb
from django.contrib.auth import get_user_model
from django.db.models import Value

from app.cloud_runtime import _patch_ydb_query_parameters


def _compiler(query):
    from ydb_backend.backend.base import DatabaseWrapper

    _patch_ydb_query_parameters()
    connection = DatabaseWrapper({"NAME": "default", "OPTIONS": {}})
    return query.get_compiler(connection=connection)


def test_exists_keeps_literal_before_email_parameter():
    query = (
        get_user_model()
        .objects.filter(email__iexact="User@example.invalid")
        .query.exists()
    )
    sql, params = _compiler(query).as_sql()
    assert "SELECT $element_1" in sql
    assert params["$element_1"] == 1
    assert params["$element_2"] == ("User@example.invalid", ydb.PrimitiveType.Utf8)


def test_annotation_does_not_shift_filter_parameter():
    query = (
        get_user_model()
        .objects.annotate(label=Value("marker"))
        .filter(username="example")
        .query
    )
    _, params = _compiler(query).as_sql()
    assert params["$element_1"] == "marker"
    assert params["$element_2"] == ("example", ydb.PrimitiveType.Utf8)


def test_datetime_and_null_parameters_keep_types():
    from ydb_backend.models.sql import compiler

    _patch_ydb_query_parameters()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    params = compiler._generate_params_for_update(
        ["$a", "$b"], ["created", "created"], {"created": "DateTimeField"}, [now, None]
    )
    assert params["$a"] == (int(now.timestamp()), ydb.PrimitiveType.Datetime)
    assert params["$b"][0] is None
    assert str(params["$b"][1]) == "Datetime?"
