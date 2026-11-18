"""I01-I07: authenticated offline cases, redacted reports and actual CLI reruns."""

import asyncio
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from responseforge.core import ServiceError
from responseforge.integrations.mock_edr import MockResponseProvider
from responseforge.replay import load_replay
from responseforge.replay_driver import run_replay
from responseforge.reports import build_report, render_html, write_report
from responseforge.storage import Store
from tests.rf02.helpers import approved as prepare_approved
from tests.rf02.helpers import world
from tests.rf03.helpers import ENDPOINT, NOW, event, fixture


def run_case(tmp_path: Path, *, decision="none", record=None, clock=lambda: NOW):
    source = tmp_path / "source.jsonl"
    fixture(source, [event() if record is None else record])
    batch = load_replay(source, source_id="original-test")
    result = asyncio.run(
        run_replay(
            batch,
            database_path=tmp_path / "cases.sqlite",
            mock_path=tmp_path / "mock.sqlite",
            output_dir=tmp_path / "reports",
            decision=decision,
            clock=clock,
        )
    )
    return batch, result


def documents(tmp_path: Path, collection: str):
    with Store(tmp_path / "cases.sqlite").transaction() as tx:
        return tx.list(collection)


def test_default_replay_stops_before_approval_with_ready_source_linked_case(tmp_path: Path) -> None:
    batch, summary = run_case(tmp_path)
    assert len(summary.incident_ids) == 1 and summary.simulated and not summary.verified_live
    assert documents(tmp_path, "incidents")[0]["status"] == "AWAITING_APPROVAL"
    assert len(documents(tmp_path, "proposals")) == 1
    assert not documents(tmp_path, "approvals") and not documents(tmp_path, "executions")
    evidence = documents(tmp_path, "evidence")
    assert any(x["availability"] == "unavailable" and x["unavailable_reason"] for x in evidence)
    assert any(
        x["availability"] == "available" and x["provenance"]["sha256"] == batch.sha256
        for x in evidence
    )
    metrics = documents(tmp_path, "metrics")
    assert [x["kind"] for x in metrics] == ["alert_accepted", "case_ready"]
    assert metrics[0]["correlation_id"] == metrics[1]["correlation_id"]
    assert metrics[1]["readiness"]["known_gaps"]
    assert MockResponseProvider(tmp_path / "mock.sqlite").snapshot(ENDPOINT)["effect_count"] == 0
    assert len(summary.report_paths) == 2


@pytest.mark.parametrize("decision,effects", [("approve", 1), ("reject", 0)])
def test_operator_decision_controls_actual_simulated_effect(
    tmp_path: Path, decision: str, effects: int
) -> None:
    _, summary = run_case(tmp_path, decision=decision)
    assert documents(tmp_path, "incidents")[0]["status"] == "RESOLVED"
    assert documents(tmp_path, "approvals")[0]["decision"] == (
        "approved" if decision == "approve" else "rejected"
    )
    state = MockResponseProvider(tmp_path / "mock.sqlite").snapshot(ENDPOINT)
    assert state["effect_count"] == effects
    assert ("42" in state["running_processes"]) == (effects == 0)
    if effects:
        execution = documents(tmp_path, "executions")[0]
        assert execution["verification"]["status"] == "verified"
        assert (
            execution["verification"]["simulated"]
            and not execution["verification"]["verified_live"]
        )
    else:
        assert not documents(tmp_path, "executions")
    assert summary.simulated and not summary.verified_live


@pytest.mark.parametrize(
    "record",
    [
        event(
            fields={
                "image": "powershell.exe",
                "command_line": "powershell Get-Date",
                "process_id": "42",
                "process_guid": "benign-guid",
            }
        ),
        event(
            fields={
                "image": "powershell.exe",
                "command_line": "powershell -WindowStyle Hidden -EncodedCommand INERT",
                "process_guid": "missing-id-guid",
            }
        ),
    ],
)
def test_benign_and_missing_target_cannot_invent_action(tmp_path: Path, record: dict) -> None:
    run_case(tmp_path, decision="approve", record=record)
    assert documents(tmp_path, "incidents")[0]["status"] == "RESOLVED"
    assert not documents(tmp_path, "proposals") and not documents(tmp_path, "executions")
    ready = next(x for x in documents(tmp_path, "metrics") if x["kind"] == "case_ready")
    assert ready["readiness"]["no_action_reason"]
    assert not ready["readiness"]["proposal_ids"]
    assert MockResponseProvider(tmp_path / "mock.sqlite").snapshot(ENDPOINT)["effect_count"] == 0


def test_rerun_after_expiry_reuses_case_evidence_proposal_and_effect(tmp_path: Path) -> None:
    batch, first = run_case(tmp_path, decision="approve")
    original = {
        name: documents(tmp_path, name)
        for name in (
            "alerts",
            "incidents",
            "evidence",
            "proposals",
            "approvals",
            "executions",
            "metrics",
        )
    }
    second = asyncio.run(
        run_replay(
            batch,
            database_path=tmp_path / "cases.sqlite",
            mock_path=tmp_path / "mock.sqlite",
            output_dir=tmp_path / "reports",
            decision="approve",
            clock=lambda: NOW + timedelta(days=1),
        )
    )
    assert first.incident_ids == second.incident_ids
    for name, value in original.items():
        assert documents(tmp_path, name) == value, name
    assert MockResponseProvider(tmp_path / "mock.sqlite").snapshot(ENDPOINT)["effect_count"] == 1


def test_json_html_reports_preserve_redacted_semantics_without_raw_commands(tmp_path: Path) -> None:
    batch, summary = run_case(tmp_path, decision="approve")
    json_path = next(Path(x) for x in summary.report_paths if str(x).endswith(".json"))
    html_path = next(Path(x) for x in summary.report_paths if str(x).endswith(".html"))
    report = json.loads(json_path.read_text())
    raw = json_path.read_text() + html_path.read_text()
    assert "INERT-EXAMPLE" not in raw and "missing-parent-guid" not in raw
    assert "-EncodedCommand" not in raw and "synthetic.example" not in raw
    assert batch.sha256 in raw and "event-1" in raw
    assert "RESOLVED" in raw and "verified" in raw
    assert report["simulated"] is True and report["verified_live"] is False
    assert "<script" not in html_path.read_text().lower()
    assert "<iframe" not in html_path.read_text().lower()


def test_report_redacts_unknown_free_text_and_known_secrets_and_escapes_html(
    tmp_path: Path,
) -> None:
    w = world(tmp_path / "report.sqlite")
    proposal = prepare_approved(w)
    secret = "UNIQUE_PRIVATE_BEARER_SECRET_123456789"
    # Persist valid-model free text, not a raw invalid schema, to test default redaction.
    with w.service.store.transaction() as tx:
        row = tx.get("incidents", proposal.incident_id)
        row["assessment"] = "private command and " + secret
        tx.replace("incidents", proposal.incident_id, row)
    report = build_report(w.service, proposal.incident_id, w.actors["analyst"], secrets=(secret,))
    text = json.dumps(report) + render_html(report)
    assert secret not in text and "private command" not in text
    assert "process:42" not in text
    hostile = dict(report, extra="<script>alert('x')</script><img src=x onerror=alert(1)>")
    html = render_html(hostile)
    assert "<script" not in html and "<img" not in html
    paths = write_report(report, tmp_path / "safe")
    assert all(p.resolve().is_relative_to((tmp_path / "safe").resolve()) for p in paths)
    with pytest.raises(ServiceError):
        build_report(w.service, proposal.incident_id, w.actors["source"])


def test_actual_cli_replay_and_duplicate_invocation_are_offline_and_sanitized(
    tmp_path: Path,
) -> None:
    source = fixture(tmp_path / "cli.jsonl", [event()])
    args = [
        sys.executable,
        "-m",
        "responseforge",
        "--replay",
        str(source),
        "--source-id",
        "original-cli",
        "--database",
        str(tmp_path / "cases.sqlite"),
        "--mock-database",
        str(tmp_path / "mock.sqlite"),
        "--output-dir",
        str(tmp_path / "reports"),
        "--decision",
        "approve",
    ]
    first = subprocess.run(args, capture_output=True, text=True, check=False, timeout=20)
    assert first.returncode == 0, first.stderr
    second = subprocess.run(args, capture_output=True, text=True, check=False, timeout=20)
    assert second.returncode == 0, second.stderr
    assert "INERT-EXAMPLE" not in first.stdout + second.stdout
    assert "simulated" in first.stdout and "verified_live" in first.stdout
    assert len(documents(tmp_path, "incidents")) == 1
    assert len(list((tmp_path / "reports").glob("*.json"))) == 1
    assert len(list((tmp_path / "reports").glob("*.html"))) == 1
    assert MockResponseProvider(tmp_path / "mock.sqlite").snapshot(ENDPOINT)["effect_count"] == 1


def test_report_output_hashes_untrusted_case_identity_and_redacts_new_sensitive_fields(
    tmp_path: Path,
) -> None:
    w = world(tmp_path / "safe-path.sqlite")
    proposal = prepare_approved(w)
    report = build_report(w.service, proposal.incident_id, w.actors["analyst"])
    report.update(
        incident_id="../../outside<script>alert(1)</script>",
        command_line="UNIQUE-COMMAND-SECRET",
        arbitrary={"api_token": "UNIQUE-TOKEN-SECRET", "raw_payload": "UNIQUE-RAW-SECRET"},
    )
    paths = write_report(report, tmp_path / "export")
    assert all(path.parent.resolve() == (tmp_path / "export").resolve() for path in paths)
    output = "".join(path.read_text() for path in paths)
    assert "UNIQUE-COMMAND-SECRET" not in output
    assert "UNIQUE-TOKEN-SECRET" not in output
    assert "UNIQUE-RAW-SECRET" not in output
    assert "<script" not in next(path for path in paths if path.suffix == ".html").read_text()


def test_empty_or_only_quarantined_source_cannot_claim_success(tmp_path: Path) -> None:
    source = tmp_path / "empty.jsonl"
    source.write_text("SECRET-invalid-record\n")
    batch = load_replay(source, source_id="original-empty")
    assert not batch.events and len(batch.quarantine) == 1
    with pytest.raises(ValueError):
        asyncio.run(
            run_replay(
                batch,
                database_path=tmp_path / "cases.sqlite",
                mock_path=tmp_path / "mock.sqlite",
                output_dir=tmp_path / "reports",
                clock=lambda: NOW,
            )
        )
    assert not list((tmp_path / "reports").glob("*.json"))


def test_future_report_fields_and_short_auth_env_names_cannot_leak(tmp_path: Path) -> None:
    w = world(tmp_path / "future-redaction.sqlite")
    proposal = prepare_approved(w)
    report = build_report(w.service, proposal.incident_id, w.actors["analyst"])
    report.update(
        env={"HOME": "UNIQUE-PRIVATE-ENV"},
        auth={"value": "UNIQUE-PRIVATE-AUTH"},
        investigation_note="UNIQUE-FUTURE-FREE-TEXT",
        extra={"nested": {"env": "UNIQUE-NESTED-ENV", "auth": "UNIQUE-NESTED-AUTH"}},
    )
    html = render_html(report)
    paths = write_report(report, tmp_path / "redacted-future")
    text = html + "".join(path.read_text() for path in paths)
    for value in (
        "UNIQUE-PRIVATE-ENV",
        "UNIQUE-PRIVATE-AUTH",
        "UNIQUE-FUTURE-FREE-TEXT",
        "UNIQUE-NESTED-ENV",
        "UNIQUE-NESTED-AUTH",
    ):
        assert value not in text
