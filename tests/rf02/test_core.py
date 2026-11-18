"""D03-D23: independent durable case and controlled adapter expectations."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from responseforge.contracts import (
    ActionProposal,
    CaseReadiness,
    Evidence,
    IncidentStatus,
    Mode,
)
from responseforge.core import ServiceError
from responseforge.runtime import WorkflowCallback
from responseforge.storage import Store
from tests.rf02.helpers import (
    ENDPOINT,
    TOKENS,
    SimulatedCrash,
    alert,
    approved,
    prepared,
    principal,
    world,
)


def test_concurrent_identical_intake_is_one_atomic_case_with_stable_correlation(
    tmp_path: Path,
) -> None:
    w = world(tmp_path / "intake.sqlite")

    def deliver(_: int):
        return w.reopened().service.intake(alert(), w.actors["source"])

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = tuple(pool.map(deliver, range(12)))
    assert len({r.incident_id for r in results}) == 1
    assert len({r.correlation_id for r in results}) == 1
    assert sum(not r.duplicate for r in results) == 1
    case_id = results[0].incident_id
    assert len(w.service.list_incidents(w.actors["analyst"])) == 1
    metrics = w.service.metrics(case_id, w.actors["analyst"])
    assert len(metrics) == 1
    assert metrics[0].kind == "alert_accepted"
    assert metrics[0].occurred_at == w.clock()
    assert metrics[0].occurred_at != alert().ingested_at
    assert metrics[0].revision == "synthetic-rf02-test"
    audit = w.service.audit(case_id, w.actors["analyst"])
    assert len(audit) == 1
    with Store(w.settings.database_path).transaction() as tx:
        assert len(tx.list("alerts")) == len(tx.list("incidents")) == len(tx.list("metrics")) == 1


def test_duplicate_payload_change_conflicts_but_source_scenario_are_scoped(tmp_path: Path) -> None:
    w = world(tmp_path / "identity.sqlite")
    first = w.service.intake(alert(), w.actors["source"])
    with pytest.raises(ServiceError) as error:
        w.service.intake(alert(severity="critical"), w.actors["source"])
    assert error.value.status_code == 409
    for changed in (alert(source="other-synthetic"), alert(scenario_id="other-scenario")):
        other = w.service.intake(changed, w.actors["source"])
        assert other.incident_id != first.incident_id
    with pytest.raises(ServiceError):
        w.service.intake(alert(mode="live"), w.actors["source"])


@pytest.mark.parametrize(
    "changes",
    [
        {"source": "forged-source"},
        {"endpoint": ENDPOINT.model_copy(update={"hostname": "spoofed-host"})},
        {"endpoint": ENDPOINT.model_copy(update={"agent_id": "forged-agent"})},
    ],
)
def test_intake_rejects_spoofed_source_and_canonical_identity(
    tmp_path: Path, changes: dict
) -> None:
    w = world(tmp_path / "spoof.sqlite")
    with pytest.raises(ServiceError):
        w.service.intake(alert(**changes), w.actors["source"])
    assert w.service.list_incidents(w.actors["analyst"]) == ()


def test_intake_revalidates_model_copy_bypass(tmp_path: Path) -> None:
    w = world(tmp_path / "copy.sqlite")
    malformed = alert().model_copy(update={"event_time": "not-a-time"})
    with pytest.raises((ValidationError, ServiceError, ValueError)):
        w.service.intake(malformed, w.actors["source"])
    assert w.service.list_incidents(w.actors["analyst"]) == ()


@pytest.mark.parametrize(
    "target",
    [
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESPONDING,
        IncidentStatus.CONTAINED,
        IncidentStatus.RECEIVED,
    ],
)
def test_no_skip_self_or_manual_dispatch_transition(tmp_path: Path, target: IncidentStatus) -> None:
    w = world(tmp_path / "transition.sqlite")
    case = w.service.intake(alert(), w.actors["source"])
    with pytest.raises(ServiceError):
        w.service.transition(case.incident_id, target, w.actors["analyst"])
    assert w.service.get_incident(case.incident_id, w.actors["analyst"]).status == "RECEIVED"


def test_scope_filtered_list_and_read_denial(tmp_path: Path) -> None:
    w = world(tmp_path / "read.sqlite")
    case = w.service.intake(alert(), w.actors["source"])
    outsider = principal("analyst", actor_id="outsider", endpoint_ids=frozenset())
    scoped = w.reopened(
        credentials=w.settings.credentials | {"outsider-credential".ljust(48, "x"): outsider}
    )
    assert scoped.service.list_incidents(outsider) == ()
    with pytest.raises(ServiceError):
        scoped.service.get_incident(case.incident_id, outsider)


def test_proposal_and_decision_retry_are_immutable(tmp_path: Path) -> None:
    w = world(tmp_path / "proposal.sqlite")
    proposal = prepared(w)
    assert w.service.propose(proposal.incident_id, proposal, w.actors["analyst"]) == proposal
    for changes in (
        {"rationale": "changed"},
        {"idempotency_key": "different-key"},
        {"expires_at": w.clock() + timedelta(minutes=29)},
        {"action": "isolate_host"},
        {"target": {"endpoint": ENDPOINT, "resource": "marker:rf-test"}},
    ):
        changed = ActionProposal.model_validate(proposal.model_dump(mode="json") | changes)
        with pytest.raises(ServiceError):
            w.service.propose(proposal.incident_id, changed, w.actors["analyst"])
    expiry = w.clock() + timedelta(minutes=20)
    decision = w.service.decide(proposal.proposal_id, "approved", expiry, w.actors["approver"])
    assert decision.approver_id == w.actors["approver"].actor_id
    assert decision.proposal == proposal
    assert (
        w.service.decide(proposal.proposal_id, "approved", expiry, w.actors["approver"]) == decision
    )
    with pytest.raises(ServiceError):
        w.service.decide(proposal.proposal_id, "rejected", expiry, w.actors["approver"])


def test_global_action_idempotency_key_cannot_authorize_second_case(tmp_path: Path) -> None:
    w = world(tmp_path / "action-key.sqlite")
    first = prepared(w)
    second = prepared(w, suffix="2")
    changed = ActionProposal.model_validate(
        second.model_dump(mode="json")
        | {
            "proposal_id": "another-id",
            "idempotency_key": first.idempotency_key,
        }
    )
    with pytest.raises(ServiceError):
        w.service.propose(second.incident_id, changed, w.actors["analyst"])


@pytest.mark.parametrize(
    "actor_changes",
    [
        {"human": False},
        {"roles": frozenset({"analyst"})},
        {"endpoint_ids": frozenset()},
        {"actions": frozenset()},
        {"resources": frozenset()},
    ],
)
def test_only_authorized_human_can_approve(tmp_path: Path, actor_changes: dict) -> None:
    w = world(tmp_path / "approval-auth.sqlite")
    proposal = prepared(w)
    with pytest.raises(ServiceError):
        w.service.decide(
            proposal.proposal_id,
            "approved",
            w.clock() + timedelta(minutes=20),
            replace(w.actors["approver"], **actor_changes),
        )
    assert w.service.action(proposal.proposal_id, w.actors["analyst"]).approval is None


@pytest.mark.parametrize("minutes", [-1, 0, 31])
def test_invalid_approval_expiry_never_stored(tmp_path: Path, minutes: int) -> None:
    w = world(tmp_path / "expiry.sqlite")
    proposal = prepared(w)
    with pytest.raises((ServiceError, ValidationError)):
        w.service.decide(
            proposal.proposal_id,
            "approved",
            w.clock() + timedelta(minutes=minutes),
            w.actors["approver"],
        )
    assert w.service.action(proposal.proposal_id, w.actors["analyst"]).approval is None


@pytest.mark.parametrize("decision", ["rejected", "cancelled"])
def test_rejected_or_cancelled_approval_prevents_dispatch(tmp_path: Path, decision: str) -> None:
    w = world(tmp_path / "rejected.sqlite")
    proposal = prepared(w)
    w.service.decide(
        proposal.proposal_id, decision, w.clock() + timedelta(minutes=20), w.actors["approver"]
    )
    with pytest.raises(ServiceError):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    assert w.provider.execute_calls == w.provider.effect_count == 0


def test_expired_approval_and_revoked_subject_cannot_dispatch(tmp_path: Path) -> None:
    w = world(tmp_path / "revoked.sqlite")
    proposal = approved(w)
    revoked = w.reopened(
        credentials={
            token: actor
            for token, actor in w.settings.credentials.items()
            if actor.actor_id != w.actors["approver"].actor_id
        }
    )
    with pytest.raises(ServiceError):
        asyncio.run(
            revoked.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
        )
    w.clock.advance(minutes=20)
    with pytest.raises(ServiceError):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    assert w.provider.execute_calls == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"provider": "unconfigured"},
        {"provider_version": "unqualified-v2"},
        {"mode": "live"},
        {"action": "test_marker"},
    ],
)
def test_capability_matches_configured_provider_version_mode_action(
    tmp_path: Path, changes: dict
) -> None:
    w = world(tmp_path / "capability.sqlite")
    proposal = approved(w)
    w.provider.capability_changes = changes
    with pytest.raises(ServiceError):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    assert w.provider.execute_calls == 0


def test_live_default_dry_run_makes_no_adapter_call(tmp_path: Path) -> None:
    w = world(tmp_path / "live.sqlite", mode=Mode.LIVE)
    proposal = approved(w)
    with pytest.raises(ServiceError):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    assert w.provider.capability_calls == w.provider.execute_calls == w.provider.verify_calls == 0


def test_success_is_verified_and_duplicates_remain_one_effect_after_restart_expiry(
    tmp_path: Path,
) -> None:
    w = world(tmp_path / "success.sqlite")
    proposal = approved(w)
    w.provider.store_path = Path(w.settings.database_path)
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert result.execution_id == "exec-" + proposal.proposal_id
    assert result.verification.status == "verified"
    assert result.verification.simulated and not result.verification.verified_live
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "RESOLVED"
    w.clock.advance(hours=2)
    retry = asyncio.run(
        w.reopened().service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert retry == result
    assert w.provider.execute_calls == w.provider.effect_count == w.provider.verify_calls == 1
    assert w.provider.capability_calls == 1
    audit = w.service.audit(proposal.incident_id, w.actors["analyst"])
    assert any(
        item.operation == "dispatch_reserved" and item.actor == "executor-actor" for item in audit
    )


def test_concurrent_execute_commits_reservation_before_external_io(tmp_path: Path) -> None:
    w = world(tmp_path / "concurrent-execute.sqlite")
    proposal = approved(w)

    async def deliver():
        w.provider.started, w.provider.release = asyncio.Event(), asyncio.Event()
        task = asyncio.create_task(
            w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
        )
        await w.provider.started.wait()
        duplicate = await w.reopened().service.execute(
            proposal.proposal_id, "controlled", w.actors["executor"]
        )
        assert duplicate.dispatch_state == "pending"
        assert w.provider.execute_calls == 1
        w.provider.release.set()
        return await task

    result = asyncio.run(deliver())
    assert result.verification.status == "verified"
    assert w.provider.effect_count == 1


@pytest.mark.parametrize("behavior,effects", [("crash_before_effect", 0), ("effect_then_crash", 1)])
def test_crash_reservation_survives_and_reconcile_never_redispatches(
    tmp_path: Path, behavior: str, effects: int
) -> None:
    w = world(tmp_path / "crash.sqlite")
    proposal = approved(w)
    w.provider.execute_behavior = behavior
    with pytest.raises(SimulatedCrash):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    restarted = w.reopened()
    retry = asyncio.run(
        restarted.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert retry.dispatch_state == "pending"
    assert w.provider.execute_calls == 1
    assert w.provider.effect_count == effects
    recovered = asyncio.run(
        restarted.service.reconcile(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert w.provider.execute_calls == 1
    assert w.provider.verify_calls == 1
    assert recovered.verification.status == ("verified" if effects else "pending")
    if effects:
        assert (
            restarted.service.get_incident(proposal.incident_id, w.actors["analyst"]).status
            == "RESOLVED"
        )


@pytest.mark.parametrize("behavior", ["effect_then_error", "effect_then_timeout"])
def test_lost_acknowledgement_is_uncertain_then_verified_without_duplicate_effect(
    tmp_path: Path, behavior: str
) -> None:
    w = world(tmp_path / "lost-ack.sqlite", timeout=0.01)
    proposal = approved(w)
    w.provider.execute_behavior = behavior
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert result.dispatch_state == "uncertain"
    assert result.verification.status != "verified"
    assert "SECRET" not in result.model_dump_json()
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "RESPONDING"
    with pytest.raises(ServiceError):
        w.service.transition(proposal.incident_id, IncidentStatus.RESOLVED, w.actors["analyst"])
    recovered = asyncio.run(
        w.reopened().service.reconcile(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert recovered.verification.status == "verified"
    assert w.provider.execute_calls == w.provider.effect_count == w.provider.verify_calls == 1
    assert "SECRET" not in str(w.service.audit(proposal.incident_id, w.actors["analyst"]))


@pytest.mark.parametrize(
    "changes",
    [
        {"execution_id": "forged-execution"},
        {"proposal_id": "another-action"},
        {"incident_id": "another-case"},
        {"provider": "another-provider"},
        {"requested_at": "2025-12-31T00:00:00Z"},
        {"updated_at": "2026-01-02T00:00:00Z"},
    ],
)
def test_forged_or_misordered_provider_result_is_not_success(tmp_path: Path, changes: dict) -> None:
    w = world(tmp_path / "forged-result.sqlite")
    proposal = approved(w)
    w.provider.result_changes = changes
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert result.dispatch_state == "uncertain"
    assert result.verification.status != "verified"
    assert w.provider.verify_calls == 0
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "RESPONDING"


@pytest.mark.parametrize("verification", ["pending", "error", "timeout", "old_time"])
def test_execute_claim_does_not_replace_separate_verification(
    tmp_path: Path, verification: str
) -> None:
    w = world(tmp_path / "verify.sqlite", timeout=0.01)
    proposal = approved(w, action="isolate_host")
    w.provider.execute_behavior = "claimed_verified"
    w.provider.verify_behavior = verification
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert w.provider.verify_calls == 1
    assert result.verification.status != "verified"
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "RESPONDING"


def test_verified_isolation_and_reviewed_close_are_distinct(tmp_path: Path) -> None:
    w = world(tmp_path / "isolate.sqlite")
    proposal = approved(w, action="isolate_host")
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert result.verification.status == "verified"
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "CONTAINED"
    with pytest.raises(ServiceError):
        w.service.transition(proposal.incident_id, IncidentStatus.CLOSED, w.actors["analyst"])
    closed = w.service.transition(
        proposal.incident_id, IncidentStatus.CLOSED, w.actors["analyst"], reviewed=True
    )
    assert closed.status == "CLOSED"


def test_persisted_corrupt_proposal_is_revalidated_before_execute(tmp_path: Path) -> None:
    w = world(tmp_path / "corrupt.sqlite")
    proposal = approved(w)
    with Store(w.settings.database_path).transaction() as tx:
        value = tx.get("proposals", proposal.proposal_id)
        assert value is not None
        value["expires_at"] = "not-a-timestamp"
        tx.replace("proposals", proposal.proposal_id, value)
    with pytest.raises((ServiceError, ValidationError, ValueError)):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    assert w.provider.execute_calls == 0


def test_ready_packet_resolves_case_scoped_references_and_emits_once(tmp_path: Path) -> None:
    w = world(tmp_path / "ready.sqlite")
    proposal = prepared(w)
    item = Evidence.model_validate(
        {
            "evidence_id": "evidence-ready",
            "incident_id": proposal.incident_id,
            "mode": "replay",
            "endpoint": ENDPOINT,
            "observed_at": w.clock() - timedelta(days=1),
            "collected_at": w.clock(),
            "availability": "available",
            "provenance": alert().provenance,
            "unavailable_reason": None,
        }
    )
    assert w.service.add_evidence(proposal.incident_id, item, w.actors["analyst"]) == item
    audit_id = w.service.audit(proposal.incident_id, w.actors["analyst"])[0].event_id
    packet = CaseReadiness(
        evidence_refs=(item.evidence_id,),
        known_gaps=("Parent not recorded",),
        proposal_ids=(proposal.proposal_id,),
        audit_event_id=audit_id,
    )
    for change in (
        {"evidence_refs": ("missing",)},
        {"audit_event_id": "missing"},
        {"proposal_ids": ("missing",)},
    ):
        invalid = CaseReadiness.model_validate(packet.model_dump(mode="json") | change)
        with pytest.raises(ServiceError):
            w.service.mark_ready(proposal.incident_id, invalid, w.actors["analyst"])
    ready = w.service.mark_ready(proposal.incident_id, packet, w.actors["analyst"])
    assert w.service.mark_ready(proposal.incident_id, packet, w.actors["analyst"]) == ready
    accepted = w.service.metrics(proposal.incident_id, w.actors["analyst"])[0]
    assert ready.kind == "case_ready" and ready.correlation_id == accepted.correlation_id
    assert ready.readiness.known_gaps == ("Parent not recorded",)
    assert len(w.service.metrics(proposal.incident_id, w.actors["analyst"])) == 2


def test_evidence_and_readiness_cannot_cross_case_boundary(tmp_path: Path) -> None:
    w = world(tmp_path / "cross-case.sqlite")
    first, second = prepared(w), prepared(w, suffix="2")
    item = Evidence.model_validate(
        {
            "evidence_id": "foreign-evidence",
            "incident_id": second.incident_id,
            "mode": "replay",
            "endpoint": ENDPOINT,
            "observed_at": w.clock(),
            "collected_at": w.clock(),
            "availability": "available",
            "provenance": alert().provenance,
            "unavailable_reason": None,
        }
    )
    with pytest.raises(ServiceError):
        w.service.add_evidence(first.incident_id, item, w.actors["analyst"])
    w.service.add_evidence(second.incident_id, item, w.actors["analyst"])
    second_audit = w.service.audit(second.incident_id, w.actors["analyst"])[0].event_id
    packet = CaseReadiness(
        evidence_refs=(item.evidence_id,),
        known_gaps=(),
        proposal_ids=(second.proposal_id,),
        audit_event_id=second_audit,
    )
    with pytest.raises(ServiceError):
        w.service.mark_ready(first.incident_id, packet, w.actors["analyst"])


def test_callback_exact_registered_correlation_and_nonce_survive_restart(tmp_path: Path) -> None:
    w = world(tmp_path / "callback.sqlite")
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(
        intake.incident_id, "run-1", "workflow-1", "v1", w.actors["analyst"]
    )
    item = WorkflowCallback(
        run_id="run-1",
        incident_id=intake.incident_id,
        workflow_id="workflow-1",
        correlation_id=intake.correlation_id,
        status="succeeded",
    )
    result = w.service.callback(
        item, w.actors["workflow"], nonce="unique-nonce-1", sent_at=w.clock()
    )
    assert result.status == "succeeded" and result.ended_at == w.clock()
    restarted = w.reopened()
    with pytest.raises(ServiceError):
        restarted.service.callback(
            item, w.actors["workflow"], nonce="unique-nonce-1", sent_at=w.clock()
        )
    assert (
        restarted.service.callback(
            item, w.actors["workflow"], nonce="unique-nonce-2", sent_at=w.clock()
        )
        == result
    )
    changed = WorkflowCallback.model_validate(item.model_dump(mode="json") | {"status": "failed"})
    with pytest.raises(ServiceError):
        restarted.service.callback(
            changed, w.actors["workflow"], nonce="unique-nonce-3", sent_at=w.clock()
        )
    assert (
        restarted.service.get_incident(intake.incident_id, w.actors["analyst"]).status == "RECEIVED"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "forged-run"},
        {"incident_id": "forged-case"},
        {"workflow_id": "forged-workflow"},
        {"correlation_id": "forged-correlation"},
    ],
)
def test_callback_mismatch_cannot_mutate_registered_run(tmp_path: Path, change: dict) -> None:
    w = world(tmp_path / "callback-scope.sqlite")
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(
        intake.incident_id, "run-1", "workflow-1", "v1", w.actors["analyst"]
    )
    item = WorkflowCallback.model_validate(
        {
            "run_id": "run-1",
            "incident_id": intake.incident_id,
            "workflow_id": "workflow-1",
            "correlation_id": intake.correlation_id,
            "status": "succeeded",
        }
        | change
    )
    with pytest.raises(ServiceError):
        w.service.callback(item, w.actors["workflow"], nonce="new-nonce", sent_at=w.clock())
    with Store(w.settings.database_path).transaction() as tx:
        assert tx.get("workflows", "run-1")["status"] == "running"


@pytest.mark.parametrize("offset", [-301, 301])
def test_callback_stale_or_future_timestamp_denied(tmp_path: Path, offset: int) -> None:
    w = world(tmp_path / "callback-time.sqlite")
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(
        intake.incident_id, "run-1", "workflow-1", "v1", w.actors["analyst"]
    )
    item = WorkflowCallback(
        run_id="run-1",
        incident_id=intake.incident_id,
        workflow_id="workflow-1",
        correlation_id=intake.correlation_id,
        status="failed",
    )
    with pytest.raises(ServiceError):
        w.service.callback(
            item,
            w.actors["workflow"],
            nonce="fresh-nonce",
            sent_at=w.clock() + timedelta(seconds=offset),
        )


def test_stale_concurrent_reconciliation_cannot_overwrite_verified_effect(tmp_path: Path) -> None:
    w = world(tmp_path / "stale-reconcile.sqlite", timeout=1)
    proposal = approved(w)
    w.provider.verify_behavior = "pending"
    initial = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert initial.verification.status == "pending"

    async def race():
        entered, release = asyncio.Event(), asyncio.Event()
        calls = 0

        async def verify(execution):
            nonlocal calls
            calls += 1
            if calls == 1:
                entered.set()
                await release.wait()
                return w.provider._verification("failed")
            return w.provider._verification("verified")

        w.provider.verify = verify
        stale = asyncio.create_task(
            w.service.reconcile(proposal.proposal_id, "controlled", w.actors["executor"])
        )
        await entered.wait()
        settled = await w.reopened().service.reconcile(
            proposal.proposal_id, "controlled", w.actors["executor"]
        )
        assert settled.verification.status == "verified"
        release.set()
        late = await stale
        return late, settled

    late, settled = asyncio.run(race())
    saved = w.service.action(proposal.proposal_id, w.actors["analyst"]).execution
    assert saved == settled == late
    assert saved.verification.status == "verified"
    assert w.provider.execute_calls == w.provider.effect_count == 1
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "RESOLVED"


def test_definitive_verification_failure_is_durable_not_containment(tmp_path: Path) -> None:
    w = world(tmp_path / "verification-failed.sqlite")
    proposal = approved(w, action="isolate_host")
    w.provider.verify_behavior = "failed"
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert result.verification.status == "failed"
    assert w.service.get_incident(proposal.incident_id, w.actors["analyst"]).status == "FAILED"
    assert (
        asyncio.run(
            w.reopened().service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
        )
        == result
    )
    assert w.provider.execute_calls == w.provider.effect_count == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("endpoint_ids", frozenset()),
        ("actions", frozenset()),
        ("resources", frozenset()),
    ],
)
def test_executor_scope_revocation_applies_even_to_duplicate_delivery(
    tmp_path: Path, field: str, value: frozenset
) -> None:
    w = world(tmp_path / "executor-revoked.sqlite")
    proposal = approved(w)
    asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    revoked_actor = replace(w.actors["executor"], **{field: value})
    restarted = w.reopened(credentials=w.settings.credentials | {TOKENS["executor"]: revoked_actor})
    with pytest.raises(ServiceError):
        asyncio.run(restarted.service.execute(proposal.proposal_id, "controlled", revoked_actor))
    assert w.provider.execute_calls == 1


def test_unauthorized_resource_proposal_has_no_side_effect_and_later_valid_succeeds(
    tmp_path: Path,
) -> None:
    w = world(tmp_path / "resource.sqlite")
    proposal = prepared(w)
    altered = ActionProposal.model_validate(
        proposal.model_dump(mode="json")
        | {
            "proposal_id": "unknown-resource-proposal",
            "idempotency_key": "unknown-resource-key",
            "target": {"endpoint": ENDPOINT, "resource": "process:arbitrary"},
        }
    )
    with pytest.raises(ServiceError):
        w.service.propose(proposal.incident_id, altered, w.actors["analyst"])
    with Store(w.settings.database_path).transaction() as tx:
        assert tx.get("proposals", altered.proposal_id) is None
    assert w.service.propose(proposal.incident_id, proposal, w.actors["analyst"]) == proposal
    assert any(
        event.operation == "denied"
        for event in w.service.audit(proposal.incident_id, w.actors["analyst"])
    )


@pytest.mark.parametrize("operation", ["execute", "reconcile", "action"])
def test_valid_but_swapped_execution_record_cannot_supply_another_cases_proof(
    tmp_path: Path, operation: str
) -> None:
    """Schema-valid storage is still untrusted when its row correlation differs."""
    w = world(tmp_path / "swapped-execution.sqlite")
    first, second = approved(w), approved(w, suffix="2")
    asyncio.run(w.service.execute(second.proposal_id, "controlled", w.actors["executor"]))
    with Store(w.settings.database_path).transaction() as tx:
        foreign = tx.get("executions", second.proposal_id)
        assert foreign is not None
        tx.insert("executions", first.proposal_id, foreign)
    with pytest.raises(ServiceError):
        if operation == "action":
            w.service.action(first.proposal_id, w.actors["analyst"])
        else:
            asyncio.run(
                getattr(w.service, operation)(first.proposal_id, "controlled", w.actors["executor"])
            )
    assert w.provider.execute_calls == w.provider.effect_count == 1
    assert (
        w.service.get_incident(first.incident_id, w.actors["analyst"]).status == "AWAITING_APPROVAL"
    )


def test_reconfigured_endpoint_canonical_identity_filters_old_agent_case(tmp_path: Path) -> None:
    w = world(tmp_path / "canonical-agent.sqlite")
    case = w.service.intake(alert(), w.actors["source"])
    restarted = w.reopened(endpoints=(ENDPOINT.model_copy(update={"agent_id": "new-agent"}),))
    assert restarted.service.list_incidents(w.actors["analyst"]) == ()
    with pytest.raises(ServiceError):
        restarted.service.get_incident(case.incident_id, w.actors["analyst"])


def test_reconciliation_requires_original_reserved_provider_version(tmp_path: Path) -> None:
    w = world(tmp_path / "reserved-provider-version.sqlite")
    proposal = approved(w)
    w.provider.execute_behavior = "crash_before_effect"
    with pytest.raises(SimulatedCrash):
        asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"]))
    w.provider.version = "test-v2"
    restarted = w.reopened(provider_versions={"controlled": "test-v2"})
    with pytest.raises(ServiceError):
        asyncio.run(
            restarted.service.reconcile(proposal.proposal_id, "controlled", w.actors["executor"])
        )
    assert w.provider.verify_calls == 0
    assert w.provider.execute_calls == 1


@pytest.mark.parametrize("operation", ["action", "decide", "execute"])
def test_wrong_role_known_action_denial_is_audited_on_case(tmp_path: Path, operation: str) -> None:
    w = world(tmp_path / "denial-audit.sqlite")
    proposal = prepared(w)
    previous = len(
        [
            event
            for event in w.service.audit(proposal.incident_id, w.actors["analyst"])
            if event.operation == "denied"
        ]
    )
    with pytest.raises(ServiceError):
        if operation == "decide":
            w.service.decide(
                proposal.proposal_id,
                "approved",
                w.clock() + timedelta(minutes=10),
                w.actors["source"],
            )
        elif operation == "execute":
            asyncio.run(w.service.execute(proposal.proposal_id, "controlled", w.actors["source"]))
        else:
            w.service.action(proposal.proposal_id, w.actors["source"])
    denials = [
        event
        for event in w.service.audit(proposal.incident_id, w.actors["analyst"])
        if event.operation == "denied"
    ]
    assert len(denials) == previous + 1
    assert denials[-1].actor == w.actors["source"].actor_id


@pytest.mark.parametrize("offset", [-86400, 86400])
def test_invalid_pending_verification_time_is_rejected_without_bricking_recovery(
    tmp_path: Path, offset: int
) -> None:
    w = world(tmp_path / "pending-proof-time.sqlite")
    proposal = approved(w)
    healthy_verify = w.provider.verify

    async def malformed_pending(execution):
        return w.provider._verification("pending").model_copy(
            update={"checked_at": w.clock() + timedelta(seconds=offset)}
        )

    w.provider.verify = malformed_pending
    result = asyncio.run(
        w.service.execute(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert result.verification.status != "verified"
    assert result.verification.checked_at is None or (
        result.requested_at <= result.verification.checked_at <= w.clock()
    )
    w.provider.verify = healthy_verify
    recovered = asyncio.run(
        w.reopened().service.reconcile(proposal.proposal_id, "controlled", w.actors["executor"])
    )
    assert recovered.verification.status == "verified"
    assert w.provider.execute_calls == w.provider.effect_count == 1
