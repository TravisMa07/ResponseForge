"""Cached runtime evidence is re-observed, never converted into another launch."""

import asyncio
from copy import deepcopy
from types import SimpleNamespace

import pytest

from responseforge.integrations.shuffle import playbook_qualification as qualification
from responseforge.integrations.shuffle.models import ShuffleArgument, VendorExecution
from tests.rf05b.helpers import NOW, OTHER, RUN, WF

_CASE = "original-case"
_CORRELATION = "original-correlation"
_HASH = "a" * 64
_VERSION = "original-reviewed-v1"


def lab_world(monkeypatch, *, label="process-awaiting"):
    # Independent frozen scenario facts, not copied from implementation _EXPECTED.
    cases = {
        "process-awaiting": ("process", "process", "awaiting_approval", "SKIPPED", "finished"),
        "callback-loss": ("callback-loss", "process", "awaiting_approval", "SKIPPED", "uncertain"),
        "task-failure": ("task-failure", "process", "unavailable", "unavailable", "uncertain"),
        "restart": ("restart", "process", "awaiting_approval", "SKIPPED", "finished"),
    }
    profile, kind, gate, dispatch, state = cases[label]
    record = {
        "run_id": RUN,
        "incident_id": _CASE,
        "workflow_id": WF,
        "kind": kind,
        "vendor_status": "FINISHED",
        "delivery_state": state,
        "gate_status": gate,
        "dispatch_native": dispatch,
        "effect_count": 0,
        "graph_verified": True,
        "audit_verified": True,
        "duplicate_start": True,
        "callback_fault_proven": label == "callback-loss",
        "task_failure_proven": label == "task-failure",
        "core_restart_proven": label == "restart",
        "proposal_id": "original-proposal",
    }
    original = {
        "run_id": RUN,
        "incident_id": _CASE,
        "correlation_id": _CORRELATION,
        "workflow_id": WF,
        "reserved": True,
        "core_restart_proven": label == "restart",
    }
    argument = ShuffleArgument(
        incident_id=_CASE, run_id=RUN, correlation_id=_CORRELATION, mode="replay"
    )
    callback = (
        None if label == "task-failure" else "FAILURE" if label == "callback-loss" else "SUCCESS"
    )
    observation = VendorExecution(
        workflow_id=WF,
        execution_id=RUN,
        argument=argument,
        workflow_sha256=_HASH,
        vendor_status="FINISHED",
        callback_status=callback,
    )
    delivery = {
        "schema_version": "1.0",
        "record_type": "shuffle_delivery",
        "argument": argument.model_dump(mode="json"),
        "workflow_id": WF,
        "workflow_version": _VERSION,
        "workflow_sha256": _HASH,
        "origin": "https://shuffle.invalid",
        "callback_status": callback,
        "state": state,
        "created_at": NOW,
        "updated_at": NOW,
        "vendor_status": "FINISHED",
    }
    audit = [{"operation": "playbook_prepared", "detail": "Original prepared run " + RUN}]
    if label != "task-failure":
        audit.append({"operation": "workflow_callback", "detail": "Authenticated original node"})
    if label == "callback-loss":
        audit.append(
            {"operation": "qualification_callback_ack_delay", "detail": "Post-commit fault"}
        )
    if label == "task-failure":
        audit.append({"operation": "qualification_prepare_failure", "detail": "Post-commit fault"})
    calls = []
    lab = qualification._Lab.__new__(qualification._Lab)
    lab.journal = {
        "results": {label: record},
        "runs": {label: original},
        "cases": {profile: {"incident_id": _CASE, "correlation_id": _CORRELATION}},
        "workflows": {kind: {"workflow_id": WF, "sha256": _HASH}},
    }
    lab.workflows = {kind: {"id": WF}}
    lab.core = object()
    lab.roles = {"analyst": "SYNTHETIC_PRIVATE_ANALYST_CREDENTIAL_NOT_FOR_NETWORK"}
    lab.env = {"SHUFFLE_DEFAULT_APIKEY": "SYNTHETIC_PRIVATE_VENDOR_KEY_NOT_FOR_NETWORK"}
    lab.transport = SimpleNamespace()
    lab.transport.config = SimpleNamespace(base_url="https://shuffle.invalid")

    async def get_execution(workflow_id, execution_id, observed_argument):
        calls.append(("observe", workflow_id, execution_id, observed_argument))
        return world.observation

    async def request(client, method, path, *, token=None, body=None, **kwargs):
        calls.append((method, path, body))
        assert client is lab.core
        # A resumed verification may reconcile the original core record; it may
        # never intake another case or send the original launch again.
        assert method == "POST" and path == "/v1/incidents/" + _CASE + "/shuffle/reconcile"
        assert body == {"run_id": RUN}
        return deepcopy(world.delivery)

    async def get_audit(incident):
        calls.append(("audit", incident))
        assert incident == _CASE
        return deepcopy(world.audit)

    def forbidden_snapshot(profile):
        # The historical no-effect run is followed by an approved run on the
        # same case, so today's durable effect count would correctly be one.
        raise AssertionError("Historical cache must not compare today's effect count")

    lab.transport.get_execution = get_execution
    lab.audit = get_audit
    lab.snapshot = forbidden_snapshot
    lab.save = lambda: (_ for _ in ()).throw(
        AssertionError("Cached read must not rewrite reservations")
    )
    monkeypatch.setattr(qualification, "_request", request)
    world = SimpleNamespace(
        lab=lab,
        label=label,
        profile=profile,
        kind=kind,
        record=record,
        original=original,
        observation=observation,
        delivery=delivery,
        audit=audit,
        calls=calls,
        argument=argument,
    )
    return world


@pytest.mark.parametrize("label", ["process-awaiting", "callback-loss", "task-failure", "restart"])
def test_coherent_cached_original_is_reobserved_without_comparing_current_effects(
    monkeypatch, label
):
    w = lab_world(monkeypatch, label=label)
    answer = asyncio.run(w.lab.cached(w.label, w.profile, w.kind))
    assert answer == w.record and answer["effect_count"] == 0
    assert answer is not w.record
    assert w.calls[0] == ("observe", WF, RUN, w.argument)
    assert len(w.calls) == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("gate_status", "ready"),
        ("kind", "containment"),
        ("effect_count", 1),
        ("effect_count", False),
        ("dispatch_native", "SUCCESS"),
        ("run_id", OTHER),
        ("incident_id", "other-case"),
        ("workflow_id", OTHER),
        ("audit_verified", False),
        ("graph_verified", "true"),
        ("duplicate_start", False),
    ],
)
def test_tampered_saved_phase_kind_count_or_identity_rejects_before_observation(
    monkeypatch, field, value
):
    w = lab_world(monkeypatch)
    w.record[field] = value
    with pytest.raises(ValueError):
        asyncio.run(w.lab.cached(w.label, w.profile, w.kind))
    assert not w.calls


@pytest.mark.parametrize(
    "field,value", [("workflow_id", OTHER), ("incident_id", "other-case"), ("run_id", OTHER)]
)
def test_original_reservation_identity_cannot_be_rebound(monkeypatch, field, value):
    w = lab_world(monkeypatch)
    w.original[field] = value
    with pytest.raises(ValueError):
        asyncio.run(w.lab.cached(w.label, w.profile, w.kind))
    assert not w.calls


@pytest.mark.parametrize("change", ["callback", "hash", "vendor"])
def test_original_vendor_completion_must_still_match(monkeypatch, change):
    w = lab_world(monkeypatch)
    values = {
        "callback": {"callback_status": None},
        "hash": {"workflow_sha256": "b" * 64},
        "vendor": {"vendor_status": "EXECUTING"},
    }[change]
    w.observation = w.observation.model_copy(update=values)
    with pytest.raises(ValueError):
        asyncio.run(w.lab.cached(w.label, w.profile, w.kind))
    assert w.calls == [("observe", WF, RUN, w.argument)]


@pytest.mark.parametrize("change", ["delivery", "missing_prepared", "wrong_prepared_run"])
def test_original_core_delivery_and_prepared_audit_remain_required(monkeypatch, change):
    w = lab_world(monkeypatch)
    if change == "delivery":
        w.delivery["state"] = "uncertain"
    elif change == "missing_prepared":
        w.audit[:] = [entry for entry in w.audit if entry["operation"] != "playbook_prepared"]
    else:
        w.audit[0]["detail"] = "Prepared another run " + OTHER
    with pytest.raises(ValueError):
        asyncio.run(w.lab.cached(w.label, w.profile, w.kind))


@pytest.mark.parametrize("change", ["run", "case", "correlation", "workflow", "graph"])
def test_core_delivery_success_cannot_echo_another_original_scope(monkeypatch, change):
    w = lab_world(monkeypatch)
    if change in {"run", "case", "correlation"}:
        key = {"run": "run_id", "case": "incident_id", "correlation": "correlation_id"}[change]
        w.delivery["argument"][key] = OTHER
    elif change == "workflow":
        w.delivery["workflow_id"] = OTHER
    else:
        w.delivery["workflow_sha256"] = "b" * 64
    with pytest.raises(ValueError):
        asyncio.run(w.lab.cached(w.label, w.profile, w.kind))


@pytest.mark.parametrize(
    "label,missing",
    [
        ("process-awaiting", "workflow_callback"),
        ("callback-loss", "qualification_callback_ack_delay"),
        ("task-failure", "qualification_prepare_failure"),
    ],
)
def test_cached_authenticated_callback_and_injected_fault_proofs_cannot_disappear(
    monkeypatch, label, missing
):
    w = lab_world(monkeypatch, label=label)
    w.audit[:] = [entry for entry in w.audit if entry["operation"] != missing]
    with pytest.raises(ValueError):
        asyncio.run(w.lab.cached(w.label, w.profile, w.kind))


def test_run_cache_hit_reobserves_original_without_intake_or_start(monkeypatch):
    w = lab_world(monkeypatch)
    answer = asyncio.run(w.lab.run(w.label, w.profile, w.kind, "awaiting_approval", 0))
    assert answer == w.record and len(w.calls) == 3
    assert not [
        call for call in w.calls if call[0] == "POST" and call[1].endswith("/shuffle/start")
    ]


@pytest.mark.parametrize("change", ["phase", "kind", "effects", "saved"])
def test_run_cache_hit_does_not_skip_frozen_invocation_validation(monkeypatch, change):
    w = lab_world(monkeypatch)
    kind, gate, effects = w.kind, "awaiting_approval", 0
    if change == "phase":
        gate = "ready"
    elif change == "kind":
        kind = "containment"
    elif change == "effects":
        effects = 1
    else:
        w.record["gate_status"] = "ready"
        w.record["dispatch_native"] = "SUCCESS"
    with pytest.raises(ValueError):
        asyncio.run(w.lab.run(w.label, w.profile, kind, gate, effects))
    assert not w.calls
