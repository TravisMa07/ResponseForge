"""Small file-backed SQLite store with atomic document/key transactions.

Domain contracts are revalidated by the core on every trust-boundary read. This
module provides serialization, transaction isolation and persistence only.
"""

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

COLLECTIONS = frozenset(
    {
        "alerts",
        "incidents",
        "case_meta",
        "proposals",
        "approvals",
        "executions",
        "evidence",
        "workflows",
        "callbacks",
        "audit",
        "metrics",
    }
)
APPLICATION_ID = 0x52464745  # RFGE: distinguish this file from another application's DB.
SCHEMA_VERSION = 1


class StorageError(RuntimeError):
    """The file is incompatible or a storage operation could not complete."""


class ConflictError(ValueError):
    """An immutable document identity is already present."""


def _encode(value: dict[str, Any]) -> str:
    if not isinstance(value, dict):
        raise ValueError("document must be a JSON object")
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _collection(value: str) -> None:
    if value not in COLLECTIONS:
        raise StorageError("unknown document collection")


class Transaction:
    """A connection owned by one Store.transaction context, never shared."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._active = True

    def _check(self) -> None:
        if not self._active:
            raise StorageError("transaction has ended")

    def get(self, collection: str, key: str) -> dict[str, Any] | None:
        self._check()
        _collection(collection)
        row = self._connection.execute(
            "SELECT payload FROM documents WHERE collection = ? AND key = ?",
            (collection, key),
        ).fetchone()
        if row is None:
            return None
        value: object = json.loads(row[0])
        if not isinstance(value, dict):
            raise StorageError("stored document is not a JSON object")
        return value

    def insert(self, collection: str, key: str, value: dict[str, Any]) -> None:
        self._check()
        _collection(collection)
        payload = _encode(value)
        try:
            self._connection.execute(
                "INSERT INTO documents(collection, key, payload) VALUES (?, ?, ?)",
                (collection, key, payload),
            )
        except sqlite3.IntegrityError as error:
            raise ConflictError("document identity already exists") from error

    def replace(self, collection: str, key: str, value: dict[str, Any]) -> None:
        self._check()
        _collection(collection)
        if collection in {"audit", "metrics"}:
            raise StorageError("audit and metric documents are append-only")
        payload = _encode(value)
        result = self._connection.execute(
            "UPDATE documents SET payload = ? WHERE collection = ? AND key = ?",
            (payload, collection, key),
        )
        if not result.rowcount:
            raise KeyError(key)

    def list(self, collection: str) -> tuple[dict[str, Any], ...]:
        self._check()
        _collection(collection)
        rows = self._connection.execute(
            "SELECT payload FROM documents WHERE collection = ? ORDER BY sequence",
            (collection,),
        )
        values = []
        for row in rows:
            value: object = json.loads(row[0])
            if not isinstance(value, dict):
                raise StorageError("stored document is not a JSON object")
            values.append(value)
        return tuple(values)

    def get_key(self, namespace: str, key: str) -> str | None:
        self._check()
        row = self._connection.execute(
            "SELECT value FROM unique_keys WHERE namespace = ? AND key = ?", (namespace, key)
        ).fetchone()
        return None if row is None else str(row[0])

    def claim_key(self, namespace: str, key: str, value: str) -> bool:
        self._check()
        result = self._connection.execute(
            "INSERT INTO unique_keys(namespace, key, value) VALUES (?, ?, ?) "
            "ON CONFLICT(namespace, key) DO NOTHING",
            (namespace, key, value),
        )
        return result.rowcount == 1

    def consume_rate(self, actor_id: str, now: datetime, limit: int = 60) -> bool:
        self._check()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("rate window requires aware current time")
        if limit < 1:
            raise ValueError("rate limit must be positive")
        minute = int(now.timestamp() // 60)
        row = self._connection.execute(
            "INSERT INTO rate_limits(actor_id, minute, count) VALUES (?, ?, 1) "
            "ON CONFLICT(actor_id, minute) DO UPDATE SET count = count + 1 "
            "WHERE count < ? RETURNING count",
            (actor_id, minute, limit),
        ).fetchone()
        return row is not None


class Store:
    """Initialize a known file format and create short serialized transactions."""

    def __init__(self, path: str | Path) -> None:
        if str(path) == ":memory:":
            raise StorageError("file-backed database is required")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.version = SCHEMA_VERSION

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _identity(connection: sqlite3.Connection) -> tuple[int, int, bool]:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        populated = (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
            is not None
        )
        return application_id, version, populated

    @staticmethod
    def _validate_identity(identity: tuple[int, int, bool]) -> None:
        application_id, version, populated = identity
        if version > SCHEMA_VERSION:
            raise StorageError("database schema version is newer than supported")
        if application_id == APPLICATION_ID and version == SCHEMA_VERSION and populated:
            return
        if application_id == 0 and version == 0 and not populated:
            return
        raise StorageError("database is foreign or has an unsupported schema")

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            # All identity reads belong to one locked snapshot: separate pre-lock
            # PRAGMAs can straddle another constructor's migration commit.
            connection.execute("BEGIN IMMEDIATE")
            identity = self._identity(connection)
            self._validate_identity(identity)
            if identity[1] == 0:
                connection.execute(
                    "CREATE TABLE documents ("
                    "sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "collection TEXT NOT NULL CHECK(collection IN ("
                    + ",".join("'" + value + "'" for value in sorted(COLLECTIONS))
                    + ")), key TEXT NOT NULL, payload TEXT NOT NULL "
                    "CHECK(json_valid(payload) AND json_type(payload) = 'object'), "
                    "UNIQUE(collection, key))"
                )
                connection.execute(
                    "CREATE TABLE unique_keys (namespace TEXT NOT NULL, key TEXT NOT NULL, "
                    "value TEXT NOT NULL, PRIMARY KEY(namespace, key))"
                )
                connection.execute(
                    "CREATE TABLE rate_limits (actor_id TEXT NOT NULL, minute INTEGER NOT NULL, "
                    "count INTEGER NOT NULL CHECK(count > 0), PRIMARY KEY(actor_id, minute))"
                )
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS immutable_audit_update "
                "BEFORE UPDATE ON documents WHEN OLD.collection IN ('audit', 'metrics') "
                "BEGIN SELECT RAISE(ABORT, 'append-only document'); END"
            )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS immutable_audit_delete "
                "BEFORE DELETE ON documents WHEN OLD.collection IN ('audit', 'metrics') "
                "BEGIN SELECT RAISE(ABORT, 'append-only document'); END"
            )
            # INSERT OR REPLACE has implicit deletes which do not fire delete
            # triggers on default external connections. Guard both unique IDs.
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS immutable_audit_replace "
                "BEFORE INSERT ON documents WHEN EXISTS (SELECT 1 FROM documents "
                "WHERE collection IN ('audit', 'metrics') AND "
                "((collection = NEW.collection AND key = NEW.key) OR sequence = NEW.sequence)) "
                "BEGIN SELECT RAISE(ABORT, 'append-only document'); END"
            )
            connection.commit()
            self._enable_wal(connection)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _enable_wal(connection: sqlite3.Connection) -> None:
        # A concurrent initializer may hold the rollback-journal lock just as
        # the first initializer changes journal mode. Retry only that bounded
        # initialization race; ordinary transactions use SQLite's busy timeout.
        deadline = time.monotonic() + 5
        while True:
            try:
                mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                if mode != "wal":
                    raise StorageError("WAL journal mode could not be enabled")
                return
            except sqlite3.OperationalError as error:
                if "locked" not in str(error).lower() or time.monotonic() >= deadline:
                    raise StorageError("WAL journal mode could not be enabled") from error
                time.sleep(0.01)

    @contextmanager
    def transaction(self) -> Iterator[Transaction]:
        connection = self._connect()
        tx = Transaction(connection)
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield tx
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            tx._active = False
            connection.close()
