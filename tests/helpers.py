"""Independent synthetic examples; identifiers never imply recorded/live evidence."""

from datetime import UTC, datetime
from typing import Any

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def endpoint(**changes: Any) -> dict[str, Any]:
    return {"endpoint_id": "synthetic-host", "hostname": "lab-host", "agent_id": None} | changes


def provenance(**changes: Any) -> dict[str, Any]:
    return {
        "source": "synthetic",
        "source_ref": "fixture://original/1",
        "sha256": "a" * 64,
        "original_event_ids": ["event-1"],
    } | changes


def alert(**changes: Any) -> dict[str, Any]:
    return {
        "alert_id": "alert-1",
        "mode": "replay",
        "source": "synthetic",
        "scenario_id": "scenario-1",
        "endpoint": endpoint(),
        "event_time": "2026-01-01T07:00:00-05:00",
        "ingested_at": "2026-01-02T12:00:00Z",
        "rule_id": "rule-1",
        "severity": "high",
        "provenance": provenance(),
        "evidence_refs": ["evidence-1"],
    } | changes


def proposal(**changes: Any) -> dict[str, Any]:
    return {
        "proposal_id": "proposal-1",
        "incident_id": "incident-1",
        "mode": "replay",
        "target": {"endpoint": endpoint(), "resource": "process:42"},
        "action": "terminate_process",
        "rationale": "Synthetic suspicious process requires review",
        "risk": "disruptive",
        "created_at": "2026-01-01T11:50:00Z",
        "expires_at": "2026-01-01T12:30:00Z",
        "idempotency_key": "action-key-1",
    } | changes


def approval(**changes: Any) -> dict[str, Any]:
    return {
        "approval_id": "approval-1",
        "proposal": proposal(),
        "approver_id": "analyst-1",
        "decision": "approved",
        "decided_at": "2026-01-01T11:55:00Z",
        "expires_at": "2026-01-01T12:20:00Z",
    } | changes


def evidence(**changes: Any) -> dict[str, Any]:
    return {
        "evidence_id": "evidence-1",
        "incident_id": "incident-1",
        "mode": "replay",
        "endpoint": endpoint(),
        "observed_at": "2026-01-01T12:00:00Z",
        "collected_at": "2026-01-02T12:00:00Z",
        "availability": "available",
        "provenance": provenance(),
        "unavailable_reason": None,
    } | changes


def verification(**changes: Any) -> dict[str, Any]:
    return {
        "status": "pending",
        "simulated": True,
        "verified_live": False,
        "detail": "Simulated effect not yet checked",
    } | changes


def execution(**changes: Any) -> dict[str, Any]:
    return {
        "execution_id": "execution-1",
        "proposal_id": "proposal-1",
        "incident_id": "incident-1",
        "provider": "mock",
        "mode": "replay",
        "dispatch_state": "pending",
        "requested_at": "2026-01-01T12:00:00Z",
        "updated_at": "2026-01-01T12:00:00Z",
        "verification": verification(),
    } | changes


def readiness(**changes: Any) -> dict[str, Any]:
    return {
        "evidence_refs": ["evidence-1"],
        "known_gaps": [],
        "proposal_ids": ["proposal-1"],
        "audit_event_id": "audit-1",
    } | changes


def metric(**changes: Any) -> dict[str, Any]:
    return {
        "event_id": "metric-1",
        "kind": "alert_accepted",
        "incident_id": "incident-1",
        "alert_id": "alert-1",
        "correlation_id": "correlation-1",
        "scenario_id": "scenario-1",
        "mode": "replay",
        "revision": "synthetic-revision",
        "environment": "offline-test",
        "occurred_at": "2026-01-01T12:00:00Z",
    } | changes
