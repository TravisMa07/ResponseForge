"""Durable steps call real core policy and a persistent simulated provider."""

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from responseforge.contracts import IncidentStatus
from responseforge.core import ServiceError
from responseforge.integrations.shuffle.models import WorkflowBinding
from tests.rf04.helpers import OTHER_RUN, WF
from tests.rf05.helpers import ENDPOINT, effects, event, reopened, world
from tests.rf05.test_assessment import network, persistence


def test_prepare_is_bound_source_linked_and_awaits_human(tmp_path):
    w = world(tmp_path)
    plan = asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert plan.request == w.request and plan.source_sha256 == w.batch.sha256
    assert plan.proposal_id and plan.evidence_refs and plan.readiness_event_id
    state = w.service.gate(w.incident_id, w.request, w.actors["workflow"])
    assert state.status == "awaiting_approval" and state.execution is None


def prepare(w):
    return asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))


def approve(w, plan, *, seconds=120):
    return w.core.decide(
        plan.proposal_id, "approved", w.clock() + timedelta(seconds=seconds), w.actors["approver"]
    )


def test_duplicate_and_restart_preserve_original_plan_proposal_and_metric(tmp_path):
    w = world(tmp_path)
    first = prepare(w)
    original = w.core.action(first.proposal_id, w.actors["analyst"]).proposal
    w.clock.advance(seconds=10)
    second = asyncio.run(reopened(w).prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert second == first
    assert w.core.action(first.proposal_id, w.actors["analyst"]).proposal == original
    metrics = w.core.metrics(w.incident_id, w.actors["analyst"])
    assert len([item for item in metrics if item.kind == "case_ready"]) == 1
    assert effects(w) == 0


def test_supported_approved_dispatch_is_verified_simulated_once(tmp_path):
    w = world(tmp_path)
    plan = prepare(w)
    approve(w, plan)
    assert w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "ready"
    result = asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert result.status == "completed"
    assert result.execution.verification.status == "verified"
    assert (
        result.execution.verification.simulated and not result.execution.verification.verified_live
    )
    assert effects(w) == 1
    duplicate = asyncio.run(reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert duplicate.execution == result.execution and effects(w) == 1


def test_existing_verified_effect_is_not_erased_by_later_approval_expiry(tmp_path):
    w = world(tmp_path)
    plan = prepare(w)
    approve(w, plan, seconds=2)
    result = asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    w.clock.advance(seconds=3)
    duplicate = asyncio.run(reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert duplicate.status == "completed" and duplicate.execution == result.execution
    assert effects(w) == 1


@pytest.mark.parametrize("decision", ["rejected", "cancelled"])
def test_denied_decision_is_not_ready_and_never_changes_mock_state(tmp_path, decision):
    w = world(tmp_path)
    plan = prepare(w)
    w.core.decide(
        plan.proposal_id, decision, w.clock() + timedelta(seconds=120), w.actors["approver"]
    )
    state = w.service.gate(w.incident_id, w.request, w.actors["workflow"])
    assert state.status == "denied" and state.execution is None
    assert effects(w) == 0


def test_expired_approval_gate_never_claims_ready(tmp_path):
    w = world(tmp_path)
    plan = prepare(w)
    approve(w, plan, seconds=1)
    w.clock.advance(seconds=2)
    state = w.service.gate(w.incident_id, w.request, w.actors["workflow"])
    assert state.status == "expired" and effects(w) == 0


def test_expired_proposal_with_no_decision_is_expired(tmp_path):
    w = world(tmp_path)
    plan = prepare(w)
    proposal = w.core.action(plan.proposal_id, w.actors["analyst"]).proposal
    w.clock.now = proposal.expires_at
    assert w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "expired"
    assert effects(w) == 0


def test_persistence_unsupported_escalates_without_proposal_or_effect(tmp_path):
    w = world(tmp_path, kind="persistence", records=[event(), persistence()])
    plan = prepare(w)
    assert plan.assessment.disposition == "escalate" and plan.proposal_id is None
    assert any("support" in gap.casefold() for gap in plan.known_gaps)
    assert w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "no_action"
    with w.core.store.transaction() as tx:
        assert not tx.list("proposals") and not tx.list("executions")
    assert effects(w) == 0


def test_benign_prepare_marks_readiness_without_fabricating_resolution(tmp_path):
    w = world(
        tmp_path,
        records=[
            event(fields={"image": "notepad.exe", "process_id": "42", "process_guid": "benign"})
        ],
    )
    plan = prepare(w)
    assert plan.assessment.disposition == "no_action" and plan.proposal_id is None
    assert plan.evidence_refs
    assert (
        w.core.get_incident(w.incident_id, w.actors["analyst"]).status
        == IncidentStatus.INVESTIGATING
    )
    assert effects(w) == 0


def test_containment_reuses_real_mock_isolation_contract(tmp_path):
    w = world(tmp_path, kind="containment", records=[event(), network()])
    plan = prepare(w)
    proposal = w.core.action(plan.proposal_id, w.actors["analyst"]).proposal
    assert proposal.target.resource == "host:" + ENDPOINT.endpoint_id
    approve(w, plan)
    result = asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert result.status == "completed" and w.provider.snapshot(ENDPOINT)["isolated"] is True
    assert effects(w) == 1


@pytest.mark.parametrize("fault", ["error_after_effect", "timeout_after_effect"])
def test_uncertain_dispatch_recovers_by_verification_without_second_execute(
    tmp_path, fault, monkeypatch
):
    w = world(tmp_path, fault=fault)
    plan = prepare(w)
    approve(w, plan)
    calls = 0
    original = w.provider.execute

    async def execute(action):
        nonlocal calls
        calls += 1
        return await original(action)

    monkeypatch.setattr(w.provider, "execute", execute)
    first = asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert first.status == "uncertain" and effects(w) == 1 and calls == 1
    second = asyncio.run(reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert second.status == "completed" and effects(w) == 1 and calls == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", "foreign-case"),
        ("run_id", OTHER_RUN),
        ("correlation_id", "foreign"),
        ("workflow_id", "22222222-2222-4222-8222-222222222222"),
        ("mode", "live"),
    ],
)
def test_forged_step_scope_rejects_before_provider_or_case_mutation(
    tmp_path, field, value, monkeypatch
):
    w = world(tmp_path)
    calls = 0

    async def capabilities(endpoint):
        nonlocal calls
        calls += 1
        raise AssertionError("Out-of-scope request reached provider")

    monkeypatch.setattr(w.provider, "capabilities", capabilities)
    request = type(w.request).model_validate(w.request.model_dump(mode="json") | {field: value})
    with pytest.raises(ServiceError):
        asyncio.run(w.service.prepare(w.incident_id, request, w.actors["workflow"]))
    with w.core.store.transaction() as tx:
        assert not tx.list("proposals") and not tx.list("evidence")
    assert calls == 0 and effects(w) == 0


@pytest.mark.parametrize("role", ["source", "analyst", "executor", "approver"])
def test_other_valid_roles_cannot_use_workflow_facade(tmp_path, role):
    w = world(tmp_path)
    with pytest.raises(ServiceError) as error:
        asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors[role]))
    assert error.value.status_code == 403 and effects(w) == 0


@pytest.mark.parametrize(
    "change", ["self_declared_approver", "self_declared_human", "unknown_actor"]
)
def test_forged_workflow_principal_never_inherits_technical_authority(tmp_path, change):
    w = world(tmp_path)
    actor = w.actors["workflow"]
    if change == "self_declared_approver":
        actor = replace(actor, roles=frozenset({"workflow", "approver"}))
    elif change == "self_declared_human":
        actor = replace(actor, human=True)
    else:
        actor = replace(actor, actor_id="unknown-workflow")
    with pytest.raises(ServiceError):
        asyncio.run(w.service.prepare(w.incident_id, w.request, actor))
    assert effects(w) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "https://foreign.invalid"),
        ("workflow_version", "unreviewed"),
        ("workflow_sha256", "f" * 64),
    ],
)
def test_changed_original_delivery_rejects_before_collection(tmp_path, field, value, monkeypatch):
    w = world(tmp_path)
    with w.core.store.transaction() as tx:
        record = tx.get("callbacks", "shuffle:" + w.request.run_id)
        record[field] = value
        tx.replace("callbacks", "shuffle:" + w.request.run_id, record)
    calls = 0

    async def collect(request):
        nonlocal calls
        calls += 1
        raise AssertionError("Mismatched binding reached collection")

    monkeypatch.setattr(w.settings.evidence_provider, "collect", collect)
    with pytest.raises(ServiceError):
        prepare(w)
    assert calls == 0 and effects(w) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", "foreign"),
        ("provider_version", "unreviewed"),
        ("source_sha256", "f" * 64),
        ("proposal_id", "foreign-proposal"),
    ],
)
def test_corrupt_cached_plan_cannot_authorize_dispatch(tmp_path, field, value):
    w = world(tmp_path)
    prepare(w)
    with w.core.store.transaction() as tx:
        record = tx.get("callbacks", "playbook-plan:" + w.request.run_id)
        record[field] = value
        tx.replace("callbacks", "playbook-plan:" + w.request.run_id, record)
    with pytest.raises(ServiceError):
        w.service.gate(w.incident_id, w.request, w.actors["workflow"])
    assert effects(w) == 0


def test_current_provider_pin_cannot_replace_original_plan_pin(tmp_path):
    w = world(tmp_path)
    prepare(w)
    changed = reopened(w, provider_versions={w.provider.name: "unreviewed-v2"})
    with pytest.raises(ServiceError):
        changed.gate(w.incident_id, w.request, w.actors["workflow"])
    assert effects(w) == 0


def test_rebound_workflow_graph_cannot_reuse_prepared_plan(tmp_path):
    w = world(tmp_path)
    prepare(w)
    changed = reopened(
        w, shuffle_bindings={WF: WorkflowBinding(version="rf05-test-v1", sha256="f" * 64)}
    )
    with pytest.raises(ServiceError):
        changed.gate(w.incident_id, w.request, w.actors["workflow"])
    assert effects(w) == 0


def test_capability_failure_is_unavailable_not_unsupported(tmp_path, monkeypatch):
    w = world(tmp_path)

    async def capabilities(endpoint):
        raise RuntimeError("PRIVATE_CAPABILITY_FAILURE")

    monkeypatch.setattr(w.provider, "capabilities", capabilities)
    with pytest.raises(ServiceError) as error:
        prepare(w)
    assert error.value.status_code == 503
    assert "PRIVATE_CAPABILITY_FAILURE" not in error.value.detail
    with w.core.store.transaction() as tx:
        assert not tx.list("proposals")
    assert effects(w) == 0


def test_capability_timeout_is_a_bounded_unavailable_failure(tmp_path, monkeypatch):
    w = world(tmp_path, timeout=0.01)

    async def capabilities(endpoint):
        await asyncio.Event().wait()

    monkeypatch.setattr(w.provider, "capabilities", capabilities)
    with pytest.raises(ServiceError) as error:
        prepare(w)
    assert error.value.status_code == 503 and effects(w) == 0


@pytest.mark.parametrize("decision", ["none", "rejected", "cancelled", "expired"])
def test_dispatch_rejects_unapproved_decision_and_audits_denial(tmp_path, decision):
    w = world(tmp_path)
    plan = prepare(w)
    if decision in {"rejected", "cancelled"}:
        w.core.decide(
            plan.proposal_id, decision, w.clock() + timedelta(seconds=120), w.actors["approver"]
        )
    elif decision == "expired":
        approve(w, plan, seconds=1)
        w.clock.advance(seconds=2)
    before = len(w.core.audit(w.incident_id, w.actors["analyst"]))
    with pytest.raises(ServiceError) as error:
        asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert error.value.status_code == 409 and effects(w) == 0
    audit = w.core.audit(w.incident_id, w.actors["analyst"])
    assert len(audit) > before and any(item.operation == "denied" for item in audit[before:])


def test_approval_expiry_during_provider_capability_check_cannot_dispatch(tmp_path, monkeypatch):
    w = world(tmp_path)
    plan = prepare(w)
    approve(w, plan, seconds=1)
    assert w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "ready"
    original = w.provider.capabilities

    async def capabilities(endpoint):
        w.clock.advance(seconds=2)
        return await original(endpoint)

    monkeypatch.setattr(w.provider, "capabilities", capabilities)
    with pytest.raises(ServiceError) as error:
        asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert error.value.status_code == 409 and effects(w) == 0


def test_workflow_finishing_during_capability_read_cannot_authorize_new_effect(
    tmp_path, monkeypatch
):
    w = world(tmp_path)
    plan = prepare(w)
    approve(w, plan)
    original = w.provider.capabilities

    async def capabilities(endpoint):
        with w.core.store.transaction() as tx:
            run = tx.get("workflows", w.request.run_id)
            run.update(status="succeeded", ended_at=w.clock().isoformat())
            tx.replace("workflows", w.request.run_id, run)
        return await original(endpoint)

    monkeypatch.setattr(w.provider, "capabilities", capabilities)
    with pytest.raises(ServiceError) as error:
        asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert error.value.status_code == 409 and effects(w) == 0


@pytest.mark.parametrize("role", ["analyst", "executor"])
@pytest.mark.parametrize("restriction", ["action", "resource"])
def test_technical_scope_restriction_rejects_before_evidence_mutation(tmp_path, role, restriction):
    w = world(tmp_path)
    principal = w.actors[role]
    changed = replace(
        principal,
        **({"actions": frozenset()} if restriction == "action" else {"resources": frozenset()}),
    )
    credentials = {
        token: changed if actor.actor_id == principal.actor_id else actor
        for token, actor in w.settings.credentials.items()
    }
    service = reopened(w, credentials=credentials)
    with pytest.raises(ServiceError) as error:
        asyncio.run(service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert error.value.status_code == 403 and effects(w) == 0
    with w.core.store.transaction() as tx:
        assert not tx.list("evidence") and not tx.list("proposals")


def test_interrupted_prepare_reuses_original_proposal_without_renewing_ttl(tmp_path, monkeypatch):
    from tests.rf02.helpers import SimulatedCrash

    w = world(tmp_path)
    original = w.core.mark_ready

    def crash(*args, **kwargs):
        raise SimulatedCrash("Stopped after durable proposal before readiness")

    monkeypatch.setattr(w.core, "mark_ready", crash)
    with pytest.raises(SimulatedCrash):
        prepare(w)
    with w.core.store.transaction() as tx:
        rows = tx.list("proposals")
        assert len(rows) == 1
        proposal = rows[0]
        assert tx.get("callbacks", "playbook-plan:" + w.request.run_id) is None
    w.clock.advance(seconds=10)
    monkeypatch.setattr(w.core, "mark_ready", original)
    result = asyncio.run(reopened(w).prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert result.proposal_id == proposal["proposal_id"]
    with w.core.store.transaction() as tx:
        assert tx.get("proposals", result.proposal_id) == proposal
    assert effects(w) == 0


def test_readiness_metric_retains_real_evidence_gaps_audit_and_provenance(tmp_path):
    w = world(tmp_path)
    plan = prepare(w)
    metrics = w.core.metrics(w.incident_id, w.actors["analyst"])
    assert [item.kind for item in metrics] == ["alert_accepted", "case_ready"]
    ready = metrics[-1]
    assert (
        ready.event_id == plan.readiness_event_id
        and ready.correlation_id == w.request.correlation_id
    )
    assert ready.revision == w.settings.revision and ready.environment == w.settings.environment
    assert ready.readiness.evidence_refs == plan.evidence_refs
    assert ready.readiness.proposal_ids == (plan.proposal_id,)
    assert ready.readiness.known_gaps == plan.known_gaps
    with w.core.store.transaction() as tx:
        for reference in plan.evidence_refs:
            evidence = tx.get("evidence", reference)
            assert evidence["availability"] == "available"
            assert evidence["provenance"]["sha256"] == w.batch.sha256
        audit = tx.get("audit", ready.readiness.audit_event_id)
        assert audit["incident_id"] == w.incident_id and audit["operation"] == "alert_accepted"


@pytest.mark.parametrize("field,value", [("resource", "process:999"), ("action", "isolate_host")])
def test_corrupt_plan_cannot_replace_recorded_target_or_action(tmp_path, field, value):
    w = world(tmp_path)
    prepare(w)
    with w.core.store.transaction() as tx:
        plan = tx.get("callbacks", "playbook-plan:" + w.request.run_id)
        plan["assessment"][field] = value
        tx.replace("callbacks", "playbook-plan:" + w.request.run_id, plan)
    with pytest.raises(ServiceError):
        w.service.gate(w.incident_id, w.request, w.actors["workflow"])
    assert effects(w) == 0


def test_corrupt_original_proposal_cannot_move_creation_after_prepared_plan(tmp_path):
    w = world(tmp_path)
    plan = prepare(w)
    original = w.core.action(plan.proposal_id, w.actors["analyst"]).proposal
    w.clock.advance(seconds=10)
    with w.core.store.transaction() as tx:
        value = tx.get("proposals", plan.proposal_id)
        value["created_at"] = (original.created_at + timedelta(seconds=5)).isoformat()
        value["expires_at"] = (original.expires_at + timedelta(seconds=5)).isoformat()
        tx.replace("proposals", plan.proposal_id, value)
    with pytest.raises(ServiceError):
        w.service.gate(w.incident_id, w.request, w.actors["workflow"])
    assert effects(w) == 0


def test_uncertain_effect_reconciles_after_approval_expiry_without_redispatch(
    tmp_path, monkeypatch
):
    w = world(tmp_path, fault="error_after_effect")
    plan = prepare(w)
    approve(w, plan, seconds=1)
    first = asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert first.status == "uncertain" and effects(w) == 1
    w.clock.advance(seconds=2)

    async def forbidden(action):
        raise AssertionError("Expired uncertain effect was redispatched")

    monkeypatch.setattr(w.provider, "execute", forbidden)
    second = asyncio.run(reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert second.status == "completed" and effects(w) == 1


def test_known_provider_failure_is_recorded_and_not_retried(tmp_path, monkeypatch):
    w = world(tmp_path, fault="fail_before_effect")
    plan = prepare(w)
    approve(w, plan)
    first = asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert first.status == "failed" and effects(w) == 0

    async def forbidden(action):
        raise AssertionError("Known failure was blindly retried")

    monkeypatch.setattr(w.provider, "execute", forbidden)
    second = asyncio.run(reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert second.status == "failed" and second.execution == first.execution and effects(w) == 0


def test_changed_registered_source_rejects_before_collection_or_capabilities(tmp_path, monkeypatch):
    w = world(tmp_path)
    changed = type(w.batch).model_validate(w.batch.model_dump(mode="json") | {"sha256": "f" * 64})
    service = reopened(w, replay_batch=changed)
    calls = 0

    async def forbidden(request):
        nonlocal calls
        calls += 1
        raise AssertionError("Changed source reached provider")

    monkeypatch.setattr(w.provider, "capabilities", forbidden)
    monkeypatch.setattr(w.settings.evidence_provider, "collect", forbidden)
    with pytest.raises(ServiceError):
        asyncio.run(service.prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert calls == 0 and effects(w) == 0


def test_registered_run_without_original_delivery_is_insufficient(tmp_path):
    w = world(tmp_path)
    w.core.register_workflow(w.incident_id, OTHER_RUN, WF, "rf05-test-v1", w.actors["analyst"])
    request = type(w.request).model_validate(
        w.request.model_dump(mode="json") | {"run_id": OTHER_RUN}
    )
    with pytest.raises(ServiceError):
        asyncio.run(w.service.prepare(w.incident_id, request, w.actors["workflow"]))
    with w.core.store.transaction() as tx:
        assert not tx.list("evidence") and not tx.list("proposals")


@pytest.mark.parametrize("before_prepare", [True, False])
def test_terminal_workflow_cannot_authorize_a_new_plan_or_effect(tmp_path, before_prepare):
    w = world(tmp_path)
    if not before_prepare:
        plan = prepare(w)
        approve(w, plan)
    with w.core.store.transaction() as tx:
        row = tx.get("workflows", w.request.run_id)
        row.update(status="succeeded", ended_at=w.clock().isoformat())
        tx.replace("workflows", w.request.run_id, row)
    with pytest.raises(ServiceError):
        if before_prepare:
            prepare(w)
        else:
            asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert effects(w) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("original_event_ids", ["unrecorded-event"]),
        ("source_ref", "fixture:unregistered-source"),
        ("source", "unqualified-live-provider"),
        ("observed_at", "2025-01-01T12:00:01Z"),
    ],
)
def test_cached_evidence_must_retain_exact_recorded_provenance(tmp_path, field, value):
    w = world(tmp_path)
    plan = prepare(w)
    with w.core.store.transaction() as tx:
        item = tx.get("evidence", plan.evidence_refs[0])
        if field == "observed_at":
            item[field] = value
        else:
            item["provenance"][field] = value
        tx.replace("evidence", plan.evidence_refs[0], item)
    with pytest.raises(ServiceError):
        reopened(w).gate(w.incident_id, w.request, w.actors["workflow"])
    assert effects(w) == 0


def test_explicit_later_workflow_invocation_reuses_approved_proposal_and_one_effect(tmp_path):
    from responseforge.integrations.shuffle.models import DeliveryRecord, ShuffleArgument
    from responseforge.playbooks.models import PlaybookStepRequest

    w = world(tmp_path)
    original = prepare(w)
    assert (
        w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "awaiting_approval"
    )
    approve(w, original)
    w.clock.advance(seconds=1)
    w.core.register_workflow(w.incident_id, OTHER_RUN, WF, "rf05-test-v1", w.actors["analyst"])
    argument = ShuffleArgument(
        incident_id=w.incident_id,
        run_id=OTHER_RUN,
        correlation_id=w.request.correlation_id,
        mode="replay",
    )
    outbox = DeliveryRecord(
        argument=argument,
        workflow_id=WF,
        workflow_version="rf05-test-v1",
        workflow_sha256="b" * 64,
        origin=w.settings.shuffle_config.base_url,
        state="accepted",
        created_at=w.clock(),
        updated_at=w.clock(),
    )
    with w.core.store.transaction() as tx:
        tx.insert("callbacks", "shuffle:" + OTHER_RUN, outbox.model_dump(mode="json"))
    request = PlaybookStepRequest(**argument.model_dump(mode="json"), workflow_id=WF)
    resumed = asyncio.run(w.service.prepare(w.incident_id, request, w.actors["workflow"]))
    assert resumed.proposal_id == original.proposal_id
    assert resumed.readiness_event_id == original.readiness_event_id
    first = asyncio.run(w.service.dispatch(w.incident_id, request, w.actors["workflow"]))
    repeated = asyncio.run(reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert first.status == repeated.status == "completed"
    assert first.execution == repeated.execution and effects(w) == 1
