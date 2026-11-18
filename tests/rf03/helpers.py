"""Original synthetic records and approval grants, never real endpoint data."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from responseforge.contracts import ActionProposal, Approval, ApprovedAction, EndpointRef

NOW = datetime(2026, 1, 2, 12, tzinfo=UTC)
ENDPOINT = EndpointRef(endpoint_id="original-host", hostname="synthetic.example")


def event(event_id: str = "event-1", **changes: Any) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "scenario_id": "original-scenario",
        "endpoint": ENDPOINT.model_dump(mode="json"),
        "observed_at": "2026-01-01T12:00:00Z",
        "artifact": "process",
        "fields": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -WindowStyle Hidden -EncodedCommand INERT-EXAMPLE",
            "process_id": "42",
            "process_guid": "synthetic-process-guid",
            "parent_process_guid": "missing-parent-guid",
        },
    } | changes


def fixture(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("\n".join(json.dumps(row) for row in records) + "\n")
    return path


def approved(
    *,
    proposal_id: str = "proposal-1",
    action: str = "terminate_process",
    resource: str = "process:42",
    endpoint: EndpointRef = ENDPOINT,
    **changes: Any,
) -> ApprovedAction:
    proposal = ActionProposal.model_validate(
        {
            "proposal_id": proposal_id,
            "incident_id": "case-1",
            "mode": "replay",
            "target": {"endpoint": endpoint, "resource": resource},
            "action": action,
            "rationale": "Original synthetic approval fixture",
            "risk": "disruptive",
            "created_at": NOW - timedelta(minutes=5),
            "expires_at": NOW + timedelta(minutes=25),
            "idempotency_key": "key-" + proposal_id,
        }
        | changes
    )
    approval = Approval.model_validate(
        {
            "approval_id": "approval-" + proposal_id,
            "proposal": proposal,
            "approver_id": "human-synthetic",
            "decision": "approved",
            "decided_at": NOW - timedelta(minutes=1),
            "expires_at": NOW + timedelta(minutes=20),
        }
    )
    return ApprovedAction(proposal=proposal, approval=approval)
