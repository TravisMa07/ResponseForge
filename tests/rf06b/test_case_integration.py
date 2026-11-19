"""Offline real core/SQLite policy integration, never genuine Shuffle proof."""

import asyncio
import json
from datetime import timedelta

import pytest

from responseforge.core import ServiceError
from responseforge.replay import make_alerts
from responseforge.reports import build_report
from tests.rf05 import helpers as old
from tests.rf06b.helpers import NOW, batch, recorded

CASES = [
    ("process_create", "process", "propose"),
    ("process_access", "process", "escalate"),
    ("task_create", "persistence", "escalate"),
    ("file_create", "containment", "propose"),
    ("dns_query", "containment", "propose"),
]
ACTIONABLE = [
    ("process_create", "process"),
    ("file_create", "containment"),
    ("dns_query", "containment"),
]


def world(tmp_path, monkeypatch, event, kind, *, fault="none"):
    source = batch([event])
    original_principal = old.Principal

    def source_fixture(path, records=None):
        return source, make_alerts(source, ingested_at=NOW)[0]

    def principal(**values):
        if "source" in values["roles"]:
            values["sources"] = frozenset({"splunk-attack-data"})
        return original_principal(**values)

    monkeypatch.setattr(old, "source", source_fixture)
    monkeypatch.setattr(old, "Principal", principal)
    return old.world(tmp_path, kind=kind, fault=fault)


def prepare(w):
    return asyncio.run(w.service.prepare(w.incident_id, w.request, w.actors["workflow"]))


def dispatch(w):
    return asyncio.run(w.service.dispatch(w.incident_id, w.request, w.actors["workflow"]))


@pytest.mark.parametrize("event_kind,playbook,disposition", CASES)
def test_five_source_like_cases_retain_proof_readiness_safe_report_and_duplicate_plan(
    tmp_path, monkeypatch, event_kind, playbook, disposition
):
    w = world(tmp_path, monkeypatch, recorded(event_kind), playbook)
    first = prepare(w)
    assert first.assessment.disposition == disposition and first.evidence_refs and first.known_gaps
    assert bool(first.proposal_id) == (disposition == "propose")
    duplicate = w.core.intake(w.alert, w.actors["source"])
    assert duplicate.incident_id == w.incident_id
    again = asyncio.run(old.reopened(w).prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert again == first
    metrics = w.core.metrics(w.incident_id, w.actors["analyst"])
    assert len([m for m in metrics if m.kind == "case_ready"]) == 1
    available = [
        e
        for e in w.core.evidence(w.incident_id, w.actors["analyst"])
        if e.availability == "available"
    ]
    assert len(available) == 1
    assert available[0].provenance.original_event_ids == ("31",)
    assert available[0].provenance.source == "splunk-attack-data"
    assert available[0].provenance.sha256 == w.batch.sha256
    report = build_report(w.core, w.incident_id, w.actors["analyst"])
    assert report["simulated"] is True and report["verified_live"] is False
    assert report["alert"]["provenance"]["sha256"] == w.batch.sha256
    assert "INERT" not in json.dumps(report)
    assert old.effects(w) == 0
    assert w.core.audit(w.incident_id, w.actors["analyst"])


@pytest.mark.parametrize("event_kind,playbook", ACTIONABLE)
def test_genuine_core_human_approval_records_one_verified_simulated_effect_across_restart(
    tmp_path, monkeypatch, event_kind, playbook
):
    w = world(tmp_path, monkeypatch, recorded(event_kind), playbook)
    plan = prepare(w)
    assert (
        w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "awaiting_approval"
    )
    w.core.decide(
        plan.proposal_id, "approved", w.clock() + timedelta(seconds=120), w.actors["approver"]
    )
    result = dispatch(w)
    assert result.status == "completed" and result.execution.verification.status == "verified"
    assert (
        result.execution.verification.simulated and not result.execution.verification.verified_live
    )
    assert old.effects(w) == 1
    repeated = asyncio.run(old.reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert repeated.execution == result.execution and old.effects(w) == 1
    report = build_report(w.core, w.incident_id, w.actors["analyst"])
    assert (
        report["decision_summary"] == "verified_simulated_effect"
        and report["verified_live"] is False
    )


@pytest.mark.parametrize("decision", ["rejected", "expired", "forged"])
@pytest.mark.parametrize("event_kind,playbook", ACTIONABLE)
def test_denied_expired_or_workflow_forged_human_decision_has_zero_effect(
    tmp_path, monkeypatch, event_kind, playbook, decision
):
    w = world(tmp_path, monkeypatch, recorded(event_kind), playbook)
    plan = prepare(w)
    if decision == "forged":
        with pytest.raises(ServiceError):
            w.core.decide(
                plan.proposal_id,
                "approved",
                w.clock() + timedelta(seconds=120),
                w.actors["workflow"],
            )
    else:
        w.core.decide(
            plan.proposal_id,
            "rejected" if decision == "rejected" else "approved",
            w.clock() + timedelta(seconds=1),
            w.actors["approver"],
        )
        if decision == "expired":
            w.clock.advance(seconds=2)
    with pytest.raises(ServiceError):
        dispatch(w)
    assert old.effects(w) == 0


@pytest.mark.parametrize("fault", ["error_after_effect", "timeout_after_effect"])
@pytest.mark.parametrize("event_kind,playbook", ACTIONABLE)
def test_uncertain_original_recorded_effect_reconciles_without_repeat_delivery(
    tmp_path, monkeypatch, event_kind, playbook, fault
):
    w = world(tmp_path, monkeypatch, recorded(event_kind), playbook, fault=fault)
    plan = prepare(w)
    w.core.decide(
        plan.proposal_id, "approved", w.clock() + timedelta(seconds=120), w.actors["approver"]
    )
    first = dispatch(w)
    assert first.status == "uncertain" and old.effects(w) == 1

    async def forbidden_repeat(action):
        raise AssertionError("Uncertain effect was sent again")

    monkeypatch.setattr(w.provider, "execute", forbidden_repeat)
    second = asyncio.run(old.reopened(w).dispatch(w.incident_id, w.request, w.actors["workflow"]))
    assert (
        second.status == "completed"
        and second.execution.execution_id == first.execution.execution_id
    )
    assert old.effects(w) == 1


@pytest.mark.parametrize("event_kind,playbook", ACTIONABLE)
def test_source_like_synthetic_incomplete_identity_escalates_without_proposal(
    tmp_path, monkeypatch, event_kind, playbook
):
    event = recorded(event_kind)
    fields = dict(event.fields)
    del fields["process_guid"]
    w = world(tmp_path, monkeypatch, event.model_copy(update={"fields": fields}), playbook)
    plan = prepare(w)
    assert plan.assessment.disposition == "escalate" and plan.proposal_id is None
    assert w.service.gate(w.incident_id, w.request, w.actors["workflow"]).status == "no_action"
    assert old.effects(w) == 0


@pytest.mark.parametrize(
    "field,value",
    [("original_event_ids", ["999"]), ("source_ref", "fixture:forged"), ("sha256", "f" * 64)],
)
def test_cached_recorded_plan_rejects_corrupted_source_proof(tmp_path, monkeypatch, field, value):
    w = world(tmp_path, monkeypatch, recorded(), "process")
    plan = prepare(w)
    with w.core.store.transaction() as tx:
        proof = tx.get("evidence", plan.evidence_refs[0])
        proof["provenance"][field] = value
        tx.replace("evidence", plan.evidence_refs[0], proof)
    with pytest.raises(ServiceError) as captured:
        asyncio.run(old.reopened(w).prepare(w.incident_id, w.request, w.actors["workflow"]))
    assert captured.value.status_code == 409 and old.effects(w) == 0
