"""Requirement oracles frozen in docs/expectations/rf-01.md (C01-C11)."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from responseforge.contracts import (
    ActionExecution,
    ActionProposal,
    Alert,
    Approval,
    CaseReadiness,
    CollectionRequest,
    Enrichment,
    Evidence,
    MetricEvent,
    PlaybookRun,
    Provenance,
    VerificationResult,
)
from tests.helpers import (
    NOW,
    alert,
    approval,
    endpoint,
    evidence,
    execution,
    metric,
    proposal,
    provenance,
    readiness,
    verification,
)


def test_alert_utc_normalization_preserves_original_and_receipt_time() -> None:
    value = Alert.model_validate(alert())
    assert value.event_time == NOW
    assert value.event_time.utcoffset() == timedelta(0)
    assert value.ingested_at == NOW + timedelta(days=1)
    future = Alert.model_validate(alert(event_time="2026-01-03T12:00:00Z"))
    assert future.event_time > future.ingested_at


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": "2.0"},
        {"command": "anything"},
        {"approved": True},
        {"alert_id": ""},
        {"alert_id": " alert"},
        {"alert_id": "alert "},
        {"alert_id": 42},
        {"event_time": "2026-01-01T12:00:00"},
        {"event_time": 1767268800},
        {"event_time": "1767268800"},
        {"mode": "automatic"},
    ],
)
def test_alert_rejects_untrusted_or_ambiguous_input(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Alert.model_validate(alert(**changes))


def test_alert_missing_identity_rejected() -> None:
    data = alert()
    del data["alert_id"]
    with pytest.raises(ValidationError):
        Alert.model_validate(data)


@pytest.mark.parametrize(
    "model,data",
    [
        (Alert, alert()),
        (ActionProposal, proposal()),
        (Approval, approval()),
        (Evidence, evidence()),
        (ActionExecution, execution()),
        (CaseReadiness, readiness()),
        (MetricEvent, metric()),
    ],
)
def test_v1_json_roundtrip_and_closed_schema(model: type, data: dict[str, object]) -> None:
    value = model.model_validate(data)
    assert model.model_validate_json(value.model_dump_json()) == value
    schema = model.model_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_proposal_and_nested_scope_are_immutable() -> None:
    value = ActionProposal.model_validate(proposal())
    with pytest.raises(ValidationError):
        value.rationale = "Changed after approval"
    with pytest.raises(ValidationError):
        value.target.resource = "process:999"
    with pytest.raises(ValidationError):
        value.target.endpoint.agent_id = "other-agent"
    proof = Provenance.model_validate(provenance())
    assert isinstance(proof.original_event_ids, tuple)


@pytest.mark.parametrize(
    "changes",
    [
        {"provenance": None},
        {"observed_at": None},
        {"unavailable_reason": "missing"},
        {"availability": "unavailable", "unavailable_reason": None, "provenance": None},
        {"availability": "unavailable", "unavailable_reason": "not recorded"},
    ],
)
def test_evidence_does_not_invent_provenance(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Evidence.model_validate(evidence(**changes))


def test_unavailable_evidence_has_explicit_reason() -> None:
    value = Evidence.model_validate(
        evidence(
            availability="unavailable",
            provenance=None,
            observed_at=None,
            unavailable_reason="Parent not recorded",
        )
    )
    assert value.unavailable_reason == "Parent not recorded"
    assert value.provenance is None


@pytest.mark.parametrize(
    "changes",
    [
        {"sha256": "g" * 64},
        {"sha256": "A" * 64},
        {"sha256": "a" * 63},
        {"original_event_ids": []},
        {"original_event_ids": [""]},
    ],
)
def test_provenance_requires_integrity_and_original_ids(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Provenance.model_validate(provenance(**changes))


@pytest.mark.parametrize("end", ["2026-01-01T11:59:59Z", "2026-01-02T12:00:01Z"])
def test_collection_window_is_ordered_and_bounded(end: str) -> None:
    with pytest.raises(ValidationError):
        CollectionRequest(
            incident_id="incident-1",
            mode="replay",
            scenario_id="scenario-1",
            endpoint=endpoint(),
            start=NOW,
            end=end,
            artifact="process",
        )


def test_collection_exact_24_hour_boundary() -> None:
    value = CollectionRequest(
        incident_id="incident-1",
        mode="replay",
        scenario_id="scenario-1",
        endpoint=endpoint(),
        start=NOW,
        end=NOW + timedelta(hours=24),
        artifact="process",
    )
    assert value.end - value.start == timedelta(hours=24)


@pytest.mark.parametrize(
    "expires_at",
    [
        "2026-01-01T11:49:59Z",
        "2026-01-01T11:50:00Z",
        "2026-01-01T12:50:01Z",
    ],
)
def test_proposal_ttl_bounds(expires_at: str) -> None:
    with pytest.raises(ValidationError):
        ActionProposal.model_validate(proposal(expires_at=expires_at))


def test_exact_one_hour_proposal_ttl_is_valid() -> None:
    ActionProposal.model_validate(proposal(expires_at="2026-01-01T12:50:00Z"))


@pytest.mark.parametrize(
    "action",
    [
        "terminate_process",
        "quarantine_file",
        "block_indicator",
        "isolate_host",
        "unisolate_host",
        "disable_persistence",
    ],
)
def test_disruptive_actions_cannot_downgrade_risk(action: str) -> None:
    with pytest.raises(ValidationError):
        ActionProposal.model_validate(proposal(action=action, risk="non_disruptive"))


def test_no_arbitrary_command_action() -> None:
    with pytest.raises(ValidationError):
        ActionProposal.model_validate(proposal(action="run_shell"))
    with pytest.raises(ValidationError):
        ActionProposal.model_validate(proposal(arguments="untrusted"))


@pytest.mark.parametrize(
    "changes",
    [
        {"decided_at": "2026-01-01T11:49:00Z"},
        {"expires_at": "2026-01-01T11:55:00Z"},
        {"expires_at": "2026-01-01T12:30:01Z"},
    ],
)
def test_approval_timestamp_relationships(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Approval.model_validate(approval(**changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"simulated": True, "verified_live": True, "status": "verified", "checked_at": NOW},
        {"simulated": False, "verified_live": True},
        {"status": "verified"},
        {"simulated": "true"},
        {"verified_live": 0},
    ],
)
def test_verification_flags_require_real_proof(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        VerificationResult.model_validate(verification(**changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "live"},
        {"verification": verification(simulated=False)},
        {"verification": verification(status="verified", checked_at=NOW)},
        {"dispatch_state": "uncertain"},
        {"dispatch_state": "failed"},
        {"updated_at": "2026-01-01T11:59:59Z"},
    ],
)
def test_dispatch_does_not_claim_effect_or_hide_uncertainty(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ActionExecution.model_validate(execution(**changes))


def test_simulated_and_live_verified_results_are_distinct() -> None:
    simulated = ActionExecution.model_validate(
        execution(
            dispatch_state="acknowledged",
            verification=verification(status="verified", checked_at=NOW),
        )
    )
    live = ActionExecution.model_validate(
        execution(
            mode="live",
            dispatch_state="acknowledged",
            verification=verification(
                status="verified", simulated=False, verified_live=True, checked_at=NOW
            ),
        )
    )
    assert simulated.verification.simulated and not simulated.verification.verified_live
    assert live.verification.verified_live and not live.verification.simulated
    uncertain = ActionExecution.model_validate(
        execution(dispatch_state="uncertain", error="ack lost")
    )
    assert uncertain.dispatch_state == "uncertain"
    assert uncertain.verification.status == "pending"


@pytest.mark.parametrize(
    "changes",
    [
        {"evidence_refs": []},
        {"audit_event_id": ""},
        {"proposal_ids": []},
        {"no_action_reason": "No supported action"},
        {"proposal_ids": [], "no_action_reason": ""},
    ],
)
def test_case_readiness_requires_evidence_gaps_decision_and_audit(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        CaseReadiness.model_validate(readiness(**changes))


def test_case_readiness_requires_explicit_gaps() -> None:
    data = readiness()
    del data["known_gaps"]
    with pytest.raises(ValidationError):
        CaseReadiness.model_validate(data)


@pytest.mark.parametrize(
    "decision", [{}, {"proposal_ids": [], "no_action_reason": "No supported action"}]
)
def test_ready_metric_has_correlated_review_packet(decision: dict[str, object]) -> None:
    ready = MetricEvent.model_validate(metric(kind="case_ready", readiness=readiness(**decision)))
    accepted = MetricEvent.model_validate(metric())
    assert ready.readiness is not None
    assert ready.readiness.known_gaps == ()
    for name in ("incident_id", "alert_id", "correlation_id", "scenario_id", "mode"):
        assert getattr(ready, name) == getattr(accepted, name)


@pytest.mark.parametrize("changes", [{"kind": "case_ready"}, {"readiness": readiness()}])
def test_metric_event_kind_controls_readiness(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        MetricEvent.model_validate(metric(**changes))


@pytest.mark.parametrize(
    "status,ended_at",
    [
        ("running", NOW),
        ("succeeded", None),
        ("failed", NOW - timedelta(seconds=1)),
    ],
)
def test_playbook_run_timestamp_state_consistency(status: str, ended_at: object) -> None:
    with pytest.raises(ValidationError):
        PlaybookRun(
            run_id="run-1",
            incident_id="incident-1",
            workflow_id="workflow-1",
            workflow_version="1",
            correlation_id="correlation-1",
            started_at=NOW,
            ended_at=ended_at,
            status=status,
        )


@pytest.mark.parametrize(
    "status,result,error",
    [
        ("success", None, None),
        ("timeout", "invented success", "timeout"),
        ("failed", None, None),
    ],
)
def test_enrichment_does_not_invent_results(status: str, result: object, error: object) -> None:
    with pytest.raises(ValidationError):
        Enrichment(
            enrichment_id="enrichment-1",
            incident_id="incident-1",
            indicator="synthetic.test",
            provider="offline",
            queried_at=NOW,
            status=status,
            result=result,
            error=error,
        )


def test_input_scope_mutation_does_not_change_validated_proposal() -> None:
    data = proposal()
    value = ActionProposal.model_validate(data)
    data["target"]["resource"] = "process:999"
    assert value.target.resource == "process:42"


def test_non_disruptive_marker_still_has_explicit_scoped_proposal() -> None:
    value = ActionProposal.model_validate(proposal(action="test_marker", risk="non_disruptive"))
    assert value.action == "test_marker"
    assert value.target.endpoint.endpoint_id == "synthetic-host"


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "running", "ended_at": None},
        {"status": "succeeded", "ended_at": NOW},
        {"status": "timeout", "ended_at": NOW + timedelta(seconds=1)},
    ],
)
def test_playbook_run_valid_terminal_and_running_shapes(changes: dict[str, object]) -> None:
    value = PlaybookRun.model_validate(
        {
            "run_id": "run-1",
            "incident_id": "incident-1",
            "workflow_id": "workflow-1",
            "workflow_version": "1",
            "correlation_id": "correlation-1",
            "started_at": NOW,
        }
        | changes
    )
    assert PlaybookRun.model_validate_json(value.model_dump_json()) == value


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "success", "result": "No offline match"},
        {"status": "timeout", "error": "Provider timed out"},
        {"status": "unavailable", "error": "No provider configured"},
    ],
)
def test_enrichment_preserves_explicit_success_or_gap(changes: dict[str, object]) -> None:
    value = Enrichment.model_validate(
        {
            "enrichment_id": "enrichment-1",
            "incident_id": "incident-1",
            "indicator": "synthetic.test",
            "provider": "offline",
            "queried_at": NOW,
        }
        | changes
    )
    assert Enrichment.model_validate_json(value.model_dump_json()) == value
