"""Independent transition matrix and approval trust expectations (P01-P09)."""

from dataclasses import replace
from datetime import timedelta
from itertools import product
from typing import Any

import pytest

from responseforge.contracts import (
    ActionCapability,
    ActionProposal,
    ActionType,
    Approval,
    IncidentStatus,
    Mode,
)
from responseforge.policy import (
    AuthorizationContext,
    PolicyError,
    validate_approval,
    validate_transition,
)
from tests.helpers import NOW, approval, endpoint, proposal

# Deliberately independent of production transition maps.
ALLOWED = {
    ("RECEIVED", "TRIAGING"),
    ("TRIAGING", "INVESTIGATING"),
    ("INVESTIGATING", "AWAITING_APPROVAL"),
    ("INVESTIGATING", "RESOLVED"),
    ("AWAITING_APPROVAL", "RESPONDING"),
    ("AWAITING_APPROVAL", "RESOLVED"),
    ("RESPONDING", "CONTAINED"),
    ("RESPONDING", "RESOLVED"),
    ("RESPONDING", "FAILED"),
    ("CONTAINED", "CLOSED"),
    ("RESOLVED", "CLOSED"),
    ("FAILED", "CLOSED"),
}
STATES = (
    "RECEIVED",
    "TRIAGING",
    "INVESTIGATING",
    "AWAITING_APPROVAL",
    "RESPONDING",
    "CONTAINED",
    "RESOLVED",
    "FAILED",
    "CLOSED",
)


@pytest.mark.parametrize(
    "current,requested,reviewed",
    [(*pair, reviewed) for pair in product(STATES, repeat=2) for reviewed in (False, True)],
)
def test_all_incident_transition_pairs(current: str, requested: str, reviewed: bool) -> None:
    allowed = (current, requested) in ALLOWED and (requested != "CLOSED" or reviewed)
    if allowed:
        assert (
            validate_transition(
                IncidentStatus(current), IncidentStatus(requested), reviewed=reviewed
            )
            is None
        )
    else:
        with pytest.raises(PolicyError):
            validate_transition(
                IncidentStatus(current), IncidentStatus(requested), reviewed=reviewed
            )


def authorized() -> AuthorizationContext:
    return AuthorizationContext(
        actor_id="analyst-1",
        authenticated=True,
        roles=frozenset({"approver"}),
        allowed_endpoint_ids=frozenset({"synthetic-host"}),
        allowed_actions=frozenset({ActionType("terminate_process")}),
    )


def capability(**changes: Any) -> ActionCapability:
    return ActionCapability.model_validate(
        {
            "provider": "mock",
            "provider_version": "1",
            "mode": "replay",
            "action": "terminate_process",
        }
        | changes
    )


def request(**changes: Any) -> dict[str, Any]:
    accepted = Approval.model_validate(approval())
    return {
        "proposal": ActionProposal.model_validate(proposal()),
        "approval": accepted,
        "context": authorized(),
        "stored_approval": accepted,
        "capabilities": (capability(),),
        "runtime_mode": Mode("replay"),
        "now": NOW,
    } | changes


def test_valid_approval_returns_exact_original_scope() -> None:
    args = request()
    result = validate_approval(**args)
    assert result.proposal == args["proposal"]
    assert result.approval == args["approval"]


@pytest.mark.parametrize(
    "context",
    [
        replace(authorized(), authenticated=False),
        replace(authorized(), roles=frozenset({"analyst"})),
        replace(authorized(), actor_id="forged-person"),
        replace(authorized(), allowed_endpoint_ids=frozenset()),
        replace(authorized(), allowed_actions=frozenset()),
    ],
)
def test_server_authentication_identity_role_and_allowlists(context: AuthorizationContext) -> None:
    with pytest.raises(PolicyError):
        validate_approval(**request(context=context))


@pytest.mark.parametrize(
    "stored", [None, Approval.model_validate(approval(approval_id="different-server-record"))]
)
def test_client_approval_requires_exact_server_record(stored: Approval | None) -> None:
    with pytest.raises(PolicyError):
        validate_approval(**request(stored_approval=stored))


@pytest.mark.parametrize(
    "changes",
    [
        {"target": {"endpoint": endpoint(endpoint_id="other-host"), "resource": "process:42"}},
        {"target": {"endpoint": endpoint(agent_id="different-agent"), "resource": "process:42"}},
        {"target": {"endpoint": endpoint(), "resource": "process:999"}},
        {"action": "isolate_host"},
        {"mode": "live"},
        {"rationale": "Changed rationale"},
        {"idempotency_key": "new-key"},
        {"expires_at": "2026-01-01T12:29:00Z"},
        {"proposal_id": "other-proposal"},
        {"incident_id": "other-case"},
    ],
)
def test_approval_binds_entire_proposal_snapshot(changes: dict[str, object]) -> None:
    changed = ActionProposal.model_validate(proposal(**changes))
    with pytest.raises(PolicyError):
        validate_approval(**request(proposal=changed))


@pytest.mark.parametrize("decision", ["rejected", "cancelled"])
def test_nonapproved_decision_never_dispatches(decision: str) -> None:
    denied = Approval.model_validate(approval(decision=decision))
    with pytest.raises(PolicyError):
        validate_approval(**request(approval=denied, stored_approval=denied))


@pytest.mark.parametrize(
    "now",
    [
        NOW + timedelta(minutes=20),
        NOW + timedelta(minutes=21),
        NOW - timedelta(minutes=6),
        NOW.replace(tzinfo=None),
    ],
)
def test_expiry_boundary_future_decision_and_naive_clock_deny(now: object) -> None:
    with pytest.raises(PolicyError):
        validate_approval(**request(now=now))


def test_approval_valid_immediately_before_expiry() -> None:
    validate_approval(**request(now=NOW + timedelta(minutes=20) - timedelta(microseconds=1)))


@pytest.mark.parametrize(
    "changes",
    [
        {"capabilities": ()},
        {"capabilities": (capability(action="isolate_host"),)},
        {"capabilities": (capability(mode="live"),)},
        {"runtime_mode": Mode("live")},
    ],
)
def test_capability_and_runtime_mode_must_match(changes: dict[str, object]) -> None:
    with pytest.raises(PolicyError):
        validate_approval(**request(**changes))


def test_live_requires_enrolled_agent_and_never_falls_back_to_replay() -> None:
    live_proposal = ActionProposal.model_validate(proposal(mode="live"))
    live_approval = Approval.model_validate(approval(proposal=live_proposal))
    args = request(
        proposal=live_proposal,
        approval=live_approval,
        stored_approval=live_approval,
        runtime_mode=Mode("live"),
        capabilities=(capability(mode="live"),),
    )
    with pytest.raises(PolicyError):
        validate_approval(**args)
    enrolled = ActionProposal.model_validate(
        proposal(
            mode="live", target={"endpoint": endpoint(agent_id="agent-1"), "resource": "process:42"}
        )
    )
    accepted = Approval.model_validate(approval(proposal=enrolled))
    result = validate_approval(
        **(args | {"proposal": enrolled, "approval": accepted, "stored_approval": accepted})
    )
    assert result.proposal.mode == "live"


def test_failed_validation_does_not_poison_later_valid_request() -> None:
    valid = request()
    with pytest.raises(PolicyError):
        validate_approval(**(valid | {"stored_approval": None}))
    assert validate_approval(**valid).proposal == valid["proposal"]
