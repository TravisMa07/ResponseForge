"""D01/D02/D18/D22: durable storage expectations independent of core logic."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from responseforge.storage import ConflictError, StorageError, Store

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_fresh_file_reopens_with_documents_and_unique_keys(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite"
    first = Store(path)
    assert first.version == 1
    with first.transaction() as tx:
        tx.insert("incidents", "case-1", {"value": ["original"]})
        assert tx.claim_key("dedup", "source:1", "case-1")
        assert not tx.claim_key("dedup", "source:1", "other-case")
    with Store(path).transaction() as tx:
        assert tx.get("incidents", "case-1") == {"value": ["original"]}
        assert tx.get_key("dedup", "source:1") == "case-1"
        detached = tx.get("incidents", "case-1")
        assert detached is not None
        detached["value"].append("not stored")
        assert tx.get("incidents", "case-1") == {"value": ["original"]}


@pytest.mark.parametrize("exception", [RuntimeError("fault"), KeyboardInterrupt()])
def test_partial_transaction_rolls_back_documents_and_keys(
    tmp_path: Path, exception: BaseException
) -> None:
    store = Store(tmp_path / "rollback.sqlite")
    with pytest.raises(type(exception)):
        with store.transaction() as tx:
            tx.insert("incidents", "case-1", {"value": 1})
            assert tx.claim_key("reservation", "key", "case-1")
            raise exception
    with store.transaction() as tx:
        assert tx.get("incidents", "case-1") is None
        assert tx.get_key("reservation", "key") is None


def test_insert_conflicts_and_missing_replace_do_not_upsert(tmp_path: Path) -> None:
    store = Store(tmp_path / "duplicates.sqlite")
    with store.transaction() as tx:
        tx.insert("incidents", "case-1", {"value": 1})
    with pytest.raises(ConflictError):
        with store.transaction() as tx:
            tx.insert("incidents", "case-1", {"value": 2})
    with pytest.raises(KeyError):
        with store.transaction() as tx:
            tx.replace("incidents", "not-present", {"value": 3})
    with store.transaction() as tx:
        assert tx.list("incidents") == ({"value": 1},)


def test_future_version_refused_without_rewriting_database(tmp_path: Path) -> None:
    path = tmp_path / "future.sqlite"
    Store(path)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version=999")
    before = path.read_bytes()
    with pytest.raises(StorageError):
        Store(path)
    assert path.read_bytes() == before
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 999


def test_populated_foreign_database_refused_without_changes(tmp_path: Path) -> None:
    path = tmp_path / "foreign.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE foreign_content (value TEXT)")
        conn.execute("INSERT INTO foreign_content VALUES ('retain me')")
    before = path.read_bytes()
    with pytest.raises(StorageError):
        Store(path)
    assert path.read_bytes() == before


def test_in_memory_store_is_not_accepted_as_durable() -> None:
    with pytest.raises((ValueError, StorageError)):
        Store(":memory:")


def test_sql_shaped_identifiers_remain_inert_and_collections_are_allowlisted(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "inert.sqlite")
    key = "x'; DROP TABLE incidents; --"
    with store.transaction() as tx:
        tx.insert("incidents", key, {"text": "untrusted"})
        assert tx.get("incidents", key) == {"text": "untrusted"}
    with pytest.raises((ValueError, StorageError)):
        with store.transaction() as tx:
            tx.insert("incidents; DROP TABLE incidents", key, {})
    with store.transaction() as tx:
        assert tx.get("incidents", key) == {"text": "untrusted"}


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_non_json_numeric_values_rejected(tmp_path: Path, number: float) -> None:
    store = Store(tmp_path / "numeric.sqlite")
    with pytest.raises((ValueError, StorageError)):
        with store.transaction() as tx:
            tx.insert("incidents", "invalid-json", {"value": number})
    with store.transaction() as tx:
        assert tx.get("incidents", "invalid-json") is None


@pytest.mark.parametrize("collection", ["audit", "metrics"])
def test_append_only_collections_reject_repository_replacement(
    tmp_path: Path, collection: str
) -> None:
    store = Store(tmp_path / "append.sqlite")
    with store.transaction() as tx:
        tx.insert(collection, "event-1", {"event_id": "event-1", "value": "original"})
    with pytest.raises((ValueError, StorageError)):
        with store.transaction() as tx:
            tx.replace(collection, "event-1", {"event_id": "event-1", "value": "tampered"})
    with store.transaction() as tx:
        assert tx.get(collection, "event-1") == {"event_id": "event-1", "value": "original"}


def test_concurrent_store_creation_and_claim_have_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.sqlite"

    def claim(index: int) -> bool:
        with Store(path).transaction() as tx:
            return tx.claim_key("dispatch", "same-action", str(index))

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(claim, range(16)))
    assert sum(results) == 1


def test_rate_limit_is_durable_actor_scoped_and_resets_next_minute(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite"
    with Store(path).transaction() as tx:
        assert all(tx.consume_rate("actor-1", NOW) for _ in range(60))
        assert tx.consume_rate("actor-2", NOW)
    with Store(path).transaction() as tx:
        assert not tx.consume_rate("actor-1", NOW)
        assert tx.consume_rate("actor-1", NOW + timedelta(minutes=1))


@pytest.mark.parametrize("collection", ["audit", "metrics"])
@pytest.mark.parametrize("mutation", ["UPDATE", "DELETE"])
def test_append_only_collections_reject_raw_sql_mutation(
    tmp_path: Path, collection: str, mutation: str
) -> None:
    """Exercise the DB boundary, deliberately bypassing repository protections."""
    path = tmp_path / "raw-append.sqlite"
    store = Store(path)
    with store.transaction() as tx:
        tx.insert(collection, "event-1", {"event_id": "event-1", "value": "original"})
    # The documents table is the storage layout, not an alternate behavior oracle.
    statement = (
        "UPDATE documents SET payload='{}' WHERE collection=? AND key=?"
        if mutation == "UPDATE"
        else "DELETE FROM documents WHERE collection=? AND key=?"
    )
    with sqlite3.connect(path) as conn:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement, (collection, "event-1"))
    with store.transaction() as tx:
        assert tx.get(collection, "event-1") == {"event_id": "event-1", "value": "original"}
