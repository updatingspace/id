"""Shared Django cache backed by the existing YDB database.

Terraform owns the table and its TTL policy. Mutations use serializable YDB
transactions so independent container instances cannot consume one token twice.
"""

from __future__ import annotations

import hashlib
import pickle
import re
import time

import ydb
from django.core.cache.backends.base import DEFAULT_TIMEOUT, BaseCache
from django.db import connection

_DELETE = object()
_UNCHANGED = object()


class YDBCache(BaseCache):
    def __init__(self, location, params):
        super().__init__(params)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", location):
            raise ValueError("YDB cache location must be a table name")
        self.table = f"`{location}`"

    def _key(self, key, version):
        return hashlib.sha256(
            self.make_and_validate_key(key, version).encode()
        ).hexdigest()

    @staticmethod
    def _pool():
        connection.ensure_connection()
        return connection.connection._session_pool

    def _expiry(self, timeout):
        expiry = self.get_backend_timeout(timeout)
        return None if expiry is None else int(expiry)

    @staticmethod
    def _decode(rows):
        if not rows or (
            rows[0].expires_at is not None and rows[0].expires_at <= time.time()
        ):
            return None, False
        return pickle.loads(rows[0].value), True

    def _read(self, tx, key):
        result = list(
            tx.execute(
                f"SELECT value, expires_at FROM {self.table} WHERE cache_key = $key;",
                {"$key": key},
            )
        )
        return self._decode(result[0].rows)

    def _write(self, tx, key, value, expiry):
        if value is _DELETE:
            list(
                tx.execute(
                    f"DELETE FROM {self.table} WHERE cache_key = $key;", {"$key": key}
                )
            )
        else:
            list(
                tx.execute(
                    f"UPSERT INTO {self.table} (cache_key, value, expires_at) VALUES ($key, $value, $expiry);",
                    {
                        "$key": key,
                        "$value": pickle.dumps(value, pickle.HIGHEST_PROTOCOL),
                        "$expiry": (expiry, ydb.OptionalType(ydb.PrimitiveType.Uint64)),
                    },
                )
            )

    def _mutate(self, key, update, version=None):
        key = self._key(key, version)

        def operation(session):
            with session.transaction(ydb.QuerySerializableReadWrite()) as tx:
                current, found = self._read(tx, key)
                value, expiry, result = update(current, found)
                if value is not _UNCHANGED:
                    self._write(tx, key, value, expiry)
                tx.commit()
                return result

        return self._pool().retry_operation_sync(operation)

    def get(self, key, default=None, version=None):
        key = self._key(key, version)

        def operation(session):
            with session.transaction(ydb.QuerySnapshotReadOnly()) as tx:
                value, found = self._read(tx, key)
                tx.commit()
                return value if found else default

        return self._pool().retry_operation_sync(operation)

    def set(self, key, value, timeout=DEFAULT_TIMEOUT, version=None):
        key = self._key(key, version)
        expiry = self._expiry(timeout)

        def operation(session):
            with session.transaction(ydb.QuerySerializableReadWrite()) as tx:
                self._write(tx, key, value, expiry)
                tx.commit()

        self._pool().retry_operation_sync(operation)

    def add(self, key, value, timeout=DEFAULT_TIMEOUT, version=None):
        return self._mutate(
            key,
            lambda current, found: (
                (_UNCHANGED, None, False)
                if found
                else (value, self._expiry(timeout), True)
            ),
            version,
        )

    def delete(self, key, version=None):
        return self._mutate(key, lambda current, found: (_DELETE, None, found), version)

    def take(self, key, default=None, version=None):
        """Atomically read and remove a one-time value."""
        return self._mutate(
            key,
            lambda current, found: (_DELETE, None, current if found else default),
            version,
        )

    def update_atomic(self, key, update, version=None):
        """update(value) -> (new value, TTL); retried on write conflicts."""

        def apply(current, found):
            value, timeout = update(current if found else None)
            return value, self._expiry(timeout), value

        return self._mutate(key, apply, version)

    def incr(self, key, delta=1, version=None):
        # Read the expiry in the same transaction so incrementing preserves TTL.
        key = self._key(key, version)

        def operation(session):
            with session.transaction(ydb.QuerySerializableReadWrite()) as tx:
                results = list(
                    tx.execute(
                        f"SELECT value, expires_at FROM {self.table} WHERE cache_key = $key;",
                        {"$key": key},
                    )
                )
                rows = results[0].rows
                value, found = self._decode(rows)
                if not found:
                    raise ValueError("Key not found")
                value += delta
                self._write(tx, key, value, rows[0].expires_at)
                tx.commit()
                return value

        return self._pool().retry_operation_sync(operation)

    def clear(self):
        self._pool().execute_with_retries(f"DELETE FROM {self.table};")
        return True
