"""Native receipt reports remain source-bound, redacted and response-capability-free."""

from datetime import timedelta

from fastapi.testclient import TestClient

from responseforge.api import create_app
from tests.rf07a.helpers import ENDPOINT, TOKENS, Clock, auth, encoded, payload, settings


def test_reports_label_live_intake_without_verified_effect_and_hide_raw_payload(tmp_path):
    clock = Clock()
    app = create_app(settings(tmp_path / "reports.sqlite3"), clock=clock)
    client = TestClient(app)
    raw = encoded(
        payload(
            full_log="SYNTHETIC-PRIVATE-COMMAND <script>alert('untrusted')</script> "
            + TOKENS["source"],
            data={"secret": "SYNTHETIC-PRIVATE-TOKEN", "command": "never-run"},
            rule={"id": "550", "level": 7, "description": "SYNTHETIC-PRIVATE-DESCRIPTION"},
            syscheck={"path": "SYNTHETIC-PRIVATE-PATH"},
        )
    )
    result = client.post("/v1/integrations/wazuh/alerts", content=raw, headers=auth())
    assert result.status_code == 201
    case = result.json()["incident_id"]
    report = client.get(f"/v1/incidents/{case}/report", headers=auth("analyst"))
    assert report.status_code == 200
    value = report.json()
    assert (
        value["mode"] == "live" and value["simulated"] is False and value["verified_live"] is False
    )
    assert value["source_selection"] == "complete_received_alert"
    assert value["source_transformation"] == "wazuh-alert-json-v1"
    assert value["known_gap_count"] == 1
    assert len(value["evidence"]) == 2 and not value["actions"]
    assert any(e["availability"] == "unavailable" for e in value["evidence"])
    assert value["alert"]["endpoint"]["hostname"] == "[redacted]"
    html = client.get(f"/v1/incidents/{case}/report?format=html", headers=auth("analyst"))
    assert html.status_code == 200 and "text/html" in html.headers["content-type"]
    for text in (report.text, html.text):
        assert all(token not in text for token in TOKENS.values())
        assert "SYNTHETIC-PRIVATE" not in text and "<script>" not in text
        assert "raw_json" not in text and "untrusted-manager-label" not in text
    with app.state.store.transaction() as tx:
        assert tx.get("callbacks", "wazuh-source:" + case)["raw_json"].encode() == raw
    assert client.get(f"/v1/incidents/{case}/report", headers=auth()).status_code == 403


def test_approved_manual_action_still_cannot_dispatch_through_live_dry_run(tmp_path):
    clock = Clock()
    app = create_app(settings(tmp_path / "dryrun.sqlite3"), clock=clock)
    client = TestClient(app)
    result = client.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=auth())
    assert result.status_code == 201
    case = result.json()["incident_id"]
    for state in ("TRIAGING", "INVESTIGATING"):
        assert (
            client.post(
                f"/v1/incidents/{case}/transition", json={"status": state}, headers=auth("analyst")
            ).status_code
            == 200
        )
    proposal = {
        "proposal_id": "rf07-manual-proposal",
        "incident_id": case,
        "mode": "live",
        "target": {"endpoint": ENDPOINT.model_dump(mode="json"), "resource": "marker:rf07"},
        "action": "test_marker",
        "rationale": "Original synthetic dry-run authority test",
        "risk": "non_disruptive",
        "created_at": clock().isoformat(),
        "expires_at": (clock() + timedelta(minutes=30)).isoformat(),
        "idempotency_key": "rf07-original-dryrun",
    }
    offered = client.post(
        f"/v1/incidents/{case}/actions/propose", json=proposal, headers=auth("analyst")
    )
    assert offered.status_code == 200
    approval = {"expires_at": (clock() + timedelta(minutes=20)).isoformat()}
    assert (
        client.post(
            "/v1/actions/rf07-manual-proposal/approve", json=approval, headers=auth("workflow")
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/actions/rf07-manual-proposal/approve", json=approval, headers=auth("approver")
        ).status_code
        == 200
    )
    refused = client.post(
        "/v1/actions/rf07-manual-proposal/execute",
        json={"provider": "mock-edr"},
        headers=auth("executor"),
    )
    assert refused.status_code == 403
    with app.state.store.transaction() as tx:
        assert not tx.list("executions")
        assert not any(v["operation"] == "dispatch_reserved" for v in tx.list("audit"))
    report = client.get(f"/v1/incidents/{case}/report", headers=auth("analyst")).json()
    assert report["verified_live"] is False and report["simulated"] is False
