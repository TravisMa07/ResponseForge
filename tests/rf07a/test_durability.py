"""Atomic source/case identity survives honest retry, failure and concurrency."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from responseforge.api import create_app
from responseforge.core import CaseService
from responseforge.integrations.wazuh.service import WazuhService
from responseforge.storage import StorageError, Store, Transaction
from tests.rf07a.helpers import OTHER, Clock, auth, config, encoded, payload, principals, settings

PATH = "/v1/integrations/wazuh/alerts"


def accepted(tmp_path, name="case"):
    clock = Clock()
    configured = settings(tmp_path / (name + ".sqlite3"))
    app = create_app(configured, clock=clock)
    client = TestClient(app)
    first = client.post(PATH, content=encoded(), headers=auth())
    assert first.status_code == 201
    return configured, app, client, first.json()["incident_id"], clock


@pytest.mark.parametrize("change", ["whitespace", "hidden-field", "rule", "timestamp"])
def test_original_identity_with_any_changed_received_byte_conflicts(tmp_path, change):
    _, app, client, case, _ = accepted(tmp_path)
    value = payload()
    if change == "hidden-field":
        value["unused"] = "different-private-source-field"
    elif change == "rule":
        value["rule"]["level"] = 10
    elif change == "timestamp":
        value["timestamp"] = "2026-02-03T14:15:17.123+0200"
    raw = encoded(value) + (b"\n" if change == "whitespace" else b"")
    with app.state.store.transaction() as tx:
        before = {
            name: tx.list(name)
            for name in ("alerts", "incidents", "case_meta", "evidence", "metrics", "callbacks")
        }
    conflict = client.post(PATH, content=raw, headers=auth())
    assert conflict.status_code == 409 and "different-private-source-field" not in conflict.text
    with app.state.store.transaction() as tx:
        assert {name: tx.list(name) for name in before} == before
        assert len(tx.list("incidents")) == 1 and not tx.list("executions")
    assert client.post(PATH, content=encoded(), headers=auth()).json()["incident_id"] == case


def test_original_native_id_remains_distinct_for_another_configured_agent(tmp_path):
    _, app, client, case, _ = accepted(tmp_path)
    changed = payload(agent={"id": "010", "name": OTHER.hostname})
    second = client.post(PATH, content=encoded(changed), headers=auth())
    assert second.status_code == 201 and second.json()["incident_id"] != case
    with app.state.store.transaction() as tx:
        alerts = tx.list("alerts")
        assert len(alerts) == 2 and len({a["alert_id"] for a in alerts}) == 2
        assert len(tx.list("evidence")) == 4
        assert {a["provenance"]["original_event_ids"][0] for a in alerts} == {payload()["id"]}


def test_trusted_manager_namespace_does_not_use_payload_manager_label(tmp_path):
    configured, app, _, case, clock = accepted(tmp_path)
    changed = replace(configured, wazuh=config(manager_id="second-trusted-manager"))
    other_app = create_app(changed, clock=clock)
    client = TestClient(other_app)
    second = client.post(PATH, content=encoded(), headers=auth())
    assert second.status_code == 201 and second.json()["incident_id"] != case
    with app.state.store.transaction() as tx:
        alerts = tx.list("alerts")
        assert len({a["scenario_id"] for a in alerts}) == 2
        assert len({a["alert_id"] for a in alerts}) == 2
    labels = client.get(f"/v1/incidents/{case}/report", headers=auth("analyst")).json()
    assert labels["source_selection"] == labels["source_transformation"] == "unavailable"


@pytest.mark.parametrize(
    "point",
    [
        "alerts",
        "incidents",
        "case_meta",
        "metrics",
        "evidence-first",
        "evidence-second",
        "callbacks",
        "source-audit",
    ],
)
def test_every_partial_native_insert_failure_rolls_back_and_retry_is_complete(
    tmp_path, monkeypatch, point
):
    configured = settings(tmp_path / (point + ".sqlite3"))
    app = create_app(configured, clock=Clock())
    client = TestClient(app)
    original = Transaction.insert
    counts = {}

    def fail_after_insert(tx, collection, key, value):
        original(tx, collection, key, value)
        counts[collection] = counts.get(collection, 0) + 1
        hit = (
            collection == point
            or point == "evidence-first"
            and collection == "evidence"
            and counts[collection] == 1
            or point == "evidence-second"
            and collection == "evidence"
            and counts[collection] == 2
            or point == "source-audit"
            and collection == "audit"
            and value.get("operation") == "wazuh_source_received"
        )
        if hit:
            raise StorageError("ORIGINAL-SYNTHETIC-TRANSACTION-FAILURE")

    with monkeypatch.context() as patch:
        patch.setattr(Transaction, "insert", fail_after_insert)
        failed = client.post(PATH, content=encoded(), headers=auth())
    assert failed.status_code == 503 and "ORIGINAL-SYNTHETIC" not in failed.text
    with app.state.store.transaction() as tx:
        assert all(
            not tx.list(name)
            for name in (
                "alerts",
                "incidents",
                "case_meta",
                "metrics",
                "evidence",
                "callbacks",
                "audit",
                "proposals",
                "executions",
            )
        )
    recovered = client.post(PATH, content=encoded(), headers=auth())
    assert recovered.status_code == 201 and not recovered.json()["duplicate"]
    with app.state.store.transaction() as tx:
        assert len(tx.list("alerts")) == len(tx.list("incidents")) == len(tx.list("metrics")) == 1
        assert len(tx.list("evidence")) == 2 and len(tx.list("callbacks")) == 1


def test_concurrent_exact_delivery_is_one_common_core_case(tmp_path):
    configured = settings(tmp_path / "concurrent.sqlite3")
    clock = Clock()
    actor = principals()["source"]
    Store(configured.database_path)

    def deliver(_):
        core = CaseService(Store(configured.database_path), configured, clock=clock)
        return WazuhService(core).intake(encoded(), actor)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = tuple(pool.map(deliver, range(12)))
    assert len({r.incident_id for r in results}) == len({r.correlation_id for r in results}) == 1
    assert sum(not r.duplicate for r in results) == 1
    with Store(configured.database_path).transaction() as tx:
        assert (
            len(tx.list("alerts"))
            == len(tx.list("incidents"))
            == len(tx.list("metrics"))
            == len(tx.list("callbacks"))
            == 1
        )
        assert len(tx.list("evidence")) == 2 and not tx.list("executions")


@pytest.mark.parametrize(
    "corruption",
    [
        "missing-receipt",
        "raw",
        "receipt-manager",
        "receipt-case",
        "receipt-alert",
        "receipt-evidence",
        "stored-alert",
        "stored-evidence",
        "stored-incident",
        "stored-meta",
    ],
)
def test_changed_or_missing_original_native_proof_is_not_repaired(tmp_path, corruption):
    configured, app, _, case, clock = accepted(tmp_path)
    receipt_key = "wazuh-source:" + case
    if corruption == "missing-receipt":
        import sqlite3

        with sqlite3.connect(configured.database_path) as connection:
            connection.execute(
                "DELETE FROM documents WHERE collection=? AND key=?", ("callbacks", receipt_key)
            )
    else:
        with app.state.store.transaction() as tx:
            receipt = tx.get("callbacks", receipt_key)
            if corruption == "raw":
                receipt["raw_json"] += " "
            elif corruption == "receipt-manager":
                receipt["manager_id"] = "wrong-manager"
            elif corruption == "receipt-case":
                receipt["incident_id"] = "wrong-case"
            elif corruption == "receipt-alert":
                receipt["alert"]["severity"] = "critical"
            elif corruption == "receipt-evidence":
                receipt["evidence"][0]["classification"] = "public"
            elif corruption == "stored-alert":
                value = tx.get("alerts", case)
                value["provenance"]["sha256"] = "f" * 64
                tx.replace("alerts", case, value)
            elif corruption == "stored-evidence":
                key = receipt["evidence"][0]["evidence_id"]
                value = tx.get("evidence", key)
                value["classification"] = "public"
                tx.replace("evidence", key, value)
            elif corruption == "stored-incident":
                value = tx.get("incidents", case)
                value["scenario_id"] = "wrong-source"
                tx.replace("incidents", case, value)
            elif corruption == "stored-meta":
                value = tx.get("case_meta", case)
                value["mode"] = "replay"
                tx.replace("case_meta", case, value)
            tx.replace("callbacks", receipt_key, receipt)
    restarted = TestClient(create_app(configured, clock=clock))
    result = restarted.post(PATH, content=encoded(), headers=auth())
    assert result.status_code == 409
    with app.state.store.transaction() as tx:
        assert len(tx.list("incidents")) == 1 and not tx.list("executions")
    # Report may refuse an inconsistent case or disclose unavailable source proof.
    report = restarted.get(f"/v1/incidents/{case}/report", headers=auth("analyst"))
    assert (
        report.status_code == 409
        or report.status_code == 200
        and report.json()["source_selection"] == "unavailable"
    )
