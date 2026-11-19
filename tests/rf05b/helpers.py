"""Original native wire fixtures, independently specified from frozen vendor facts."""

import json
from copy import deepcopy
from pathlib import Path

from responseforge.integrations.shuffle.models import workflow_artifact

WF = "11111111-1111-4111-8111-111111111111"
TASK_APP = "22222222-2222-4222-8222-222222222222"
RUN = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
PREPARE = "55555555-5555-4555-8555-555555555555"
GATE = "66666666-6666-4666-8666-666666666666"
DISPATCH = "77777777-7777-4777-8777-777777777777"
CALLBACK = "88888888-8888-4888-8888-888888888888"
CALLBACK_APP = "99999999-9999-4999-8999-999999999999"
KEY = "SYNTHETIC_RF05B_PRIVATE_WORKFLOW_CREDENTIAL_NOT_FOR_NETWORK"
AUTH = "SYNTHETIC_RF05B_VENDOR_EXECUTION_AUTHORIZATION"
BACKEND = "http://shuffle-backend:5001"
NOW = "2026-01-01T12:00:00Z"


def argument(**changes):
    return {
        "schema_version": "1.0",
        "incident_id": "case-1",
        "run_id": RUN,
        "correlation_id": "correlation-1",
        "mode": "replay",
    } | changes


def request(**changes):
    return argument() | {"workflow_id": WF} | changes


def node(step="prepare", **changes):
    ids = {"prepare": PREPARE, "gate": GATE, "dispatch": DISPATCH, "callback": CALLBACK}
    return {
        "id": ids[step],
        "app_id": CALLBACK_APP if step == "callback" else TASK_APP,
        "app_name": "responseforge_callback" if step == "callback" else "responseforge_tasks",
        "app_version": "1.0.0",
        "name": step,
        "label": step.title(),
        "environment": "ResponseForge",
        "parameters": [],
    } | changes


def graph():
    def edge(source, target, conditions=None):
        return {"source_id": source, "destination_id": target, "conditions": conditions or []}

    condition = {
        "source": {"variant": "STATIC_VALUE", "value": "$Gate.status"},
        "condition": {"value": "matches regex"},
        "destination": {"variant": "STATIC_VALUE", "value": "^(ready|uncertain)$"},
    }
    return {
        "id": WF,
        "name": "Original RF05B independent graph",
        "start": PREPARE,
        "actions": [node("prepare"), node("gate"), node("dispatch"), node("callback")],
        "branches": [
            edge(PREPARE, GATE),
            edge(GATE, DISPATCH, [condition]),
            edge(GATE, CALLBACK),
            edge(DISPATCH, CALLBACK),
        ],
        "triggers": [],
        "workflow_variables": [],
        "execution_variables": [],
        "configuration": {"exit_on_error": True},
    }


def result(step, status="ready", *, delivery="accepted", native_status="SUCCESS", kind="process"):
    body = {
        "schema_version": "1.0",
        "delivery": delivery,
        "run_id": RUN,
        "step": step,
        "status": status,
        "kind": kind,
        "mode": "replay",
    }
    return {
        "action": node(step),
        "execution_id": RUN,
        "authorization": AUTH,
        "status": native_status,
        "result": json.dumps(body),
    }


def execution(*, gate_status="ready", selected=True, **changes):
    results = [
        result("prepare", "prepared"),
        result("gate", gate_status),
        result("dispatch", "completed")
        if selected
        else result("dispatch", "skipped", delivery="skipped", native_status="SKIPPED"),
    ]
    results.append(
        {
            "action": node("callback"),
            "execution_id": RUN,
            "status": "SUCCESS",
            "result": '{"delivery":"accepted","outcome":"succeeded"}',
        }
    )
    return {
        "execution_id": RUN,
        "workflow_id": WF,
        "execution_argument": json.dumps(argument()),
        "workflow": graph(),
        "status": "FINISHED",
        "results": results,
    } | changes


def environment(step="prepare", **changes):
    return {
        "ACTION": json.dumps(node(step)),
        "EXECUTIONID": RUN,
        "AUTHORIZATION": AUTH,
        "BASE_URL": BACKEND,
    } | changes


def private_config(tmp_path: Path, **changes):
    path = tmp_path / "callback.json"
    value = {
        "base_url": "https://responseforge-core:8000",
        "api_key": KEY,
        "workflow_ids": [WF],
        "shuffle_backend": BACKEND,
        "workflow_graphs": {WF: workflow_artifact(graph()).sha256},
    } | changes
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def plan(**changes):
    return {
        "schema_version": "1.0",
        "record_type": "playbook_plan",
        "request": request(),
        "kind": "process",
        "source_sha256": "a" * 64,
        "assessment": {
            "kind": "process",
            "disposition": "propose",
            "action": "terminate_process",
            "resource": "process:42",
            "rationale": "Original recorded condition",
            "event_ids": ["event-1"],
            "known_gaps": ["Recorded parent missing"],
        },
        "evidence_refs": ["evidence-1"],
        "known_gaps": ["Recorded parent missing"],
        "proposal_id": "proposal-1",
        "provider": "mock-edr",
        "provider_version": "1.0",
        "created_at": NOW,
        "readiness_event_id": "metric-1",
    } | changes


def progress(status="ready", **changes):
    value = {
        "schema_version": "1.0",
        "request": request(),
        "kind": "process",
        "status": status,
        "proposal_id": "proposal-1",
        "execution": None,
    }
    if status == "completed":
        value["execution"] = {
            "schema_version": "1.0",
            "execution_id": "exec-proposal-1",
            "proposal_id": "proposal-1",
            "incident_id": "case-1",
            "provider": "mock-edr",
            "mode": "replay",
            "dispatch_state": "acknowledged",
            "requested_at": NOW,
            "updated_at": NOW,
            "verification": {
                "status": "verified",
                "simulated": True,
                "verified_live": False,
                "checked_at": NOW,
                "detail": "Simulated proof",
            },
            "error": None,
        }
    return value | changes


def clone(value):
    return deepcopy(value)
