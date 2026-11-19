"""Original four-node topology and predicate expectations from the frozen source contract."""

import json
from copy import deepcopy
from uuid import UUID

import pytest

from responseforge.integrations.shuffle.graphs import (
    build_workflow,
    dispatch_selected,
    validate_workflow,
)
from tests.rf05b.helpers import AUTH, CALLBACK_APP, KEY, OTHER, TASK_APP, clone, execution


def test_process_builder_has_four_reviewed_nodes_and_one_callback():
    value = build_workflow("process", TASK_APP, CALLBACK_APP)
    assert "id" not in value
    assert len(value["actions"]) == 4
    assert sorted(item["name"] for item in value["actions"]) == [
        "callback",
        "dispatch",
        "gate",
        "prepare",
    ]
    assert (
        len([item for item in value["actions"] if item["app_name"] == "responseforge_callback"])
        == 1
    )
    validate_workflow(value, "process", TASK_APP, CALLBACK_APP)


def test_ready_gate_selects_dispatch_from_bound_native_proof():
    assert dispatch_selected(execution()) is True


@pytest.mark.parametrize("kind", ["process", "persistence", "containment"])
def test_each_graph_is_deterministic_and_has_exact_native_topology(kind):
    a = build_workflow(kind, TASK_APP, CALLBACK_APP)
    b = build_workflow(kind, TASK_APP, CALLBACK_APP)
    assert a == b and "id" not in a
    names = {item["name"]: item for item in a["actions"]}
    assert set(names) == {"prepare", "gate", "dispatch", "callback"}
    assert a["start"] == names["prepare"]["id"]
    assert all(UUID(item["id"]).version == 5 for item in a["actions"])
    assert all(item["environment"] == "ResponseForge" for item in a["actions"])
    assert not a["triggers"] and not a["workflow_variables"] and not a["execution_variables"]
    assert a["configuration"]["exit_on_error"] is True
    assert {tuple((branch["source_id"], branch["destination_id"])) for branch in a["branches"]} == {
        (names["prepare"]["id"], names["gate"]["id"]),
        (names["gate"]["id"], names["dispatch"]["id"]),
        (names["gate"]["id"], names["callback"]["id"]),
        (names["dispatch"]["id"], names["callback"]["id"]),
    }
    for step in ("prepare", "gate", "dispatch"):
        assert names[step]["app_name"] == "responseforge_tasks"
        assert names[step]["app_id"] == TASK_APP and names[step]["app_version"] == "1.0.0"
        assert not names[step].get("parameters")
    assert names["callback"]["app_name"] == "responseforge_callback"
    assert names["callback"]["app_id"] == CALLBACK_APP
    conditional = [
        branch for branch in a["branches"] if branch["destination_id"] == names["dispatch"]["id"]
    ]
    assert len(conditional) == 1 and len(conditional[0]["conditions"]) == 1
    condition = conditional[0]["conditions"][0]
    assert condition["source"]["value"] == "$Gate.status"
    assert condition["condition"]["value"] == "matches regex"
    assert condition["destination"]["value"] == "^(ready|uncertain)$"
    assert all(not item.get("authentication_id") for item in a["actions"])
    assert not any(token in json.dumps(a) for token in [KEY, AUTH, "https://"])
    validate_workflow(a, kind, TASK_APP, CALLBACK_APP)


@pytest.mark.parametrize(
    "change",
    [
        "extra_node",
        "start",
        "dispatch_app",
        "version",
        "parameters",
        "environment",
        "predicate",
        "extra_edge",
        "missing_edge",
        "trigger",
        "variables",
        "exit",
        "callback",
    ],
)
def test_modified_executable_graph_is_rejected(change):
    value = build_workflow("process", TASK_APP, CALLBACK_APP)
    nodes = {item["name"]: item for item in value["actions"]}
    if change == "extra_node":
        value["actions"].append(deepcopy(nodes["dispatch"]))
    elif change == "start":
        value["start"] = nodes["dispatch"]["id"]
    elif change == "dispatch_app":
        nodes["dispatch"]["app_name"] = "http"
    elif change == "version":
        nodes["gate"]["app_version"] = "9.9.9"
    elif change == "parameters":
        nodes["prepare"]["parameters"] = [{"name": "url", "value": "https://attacker.invalid"}]
    elif change == "environment":
        nodes["dispatch"]["environment"] = "cloud"
    elif change == "predicate":
        edge = next(
            item for item in value["branches"] if item["destination_id"] == nodes["dispatch"]["id"]
        )
        edge["conditions"][0]["destination"]["value"] = ".*"
    elif change == "extra_edge":
        value["branches"].append(
            {
                "source_id": nodes["prepare"]["id"],
                "destination_id": nodes["dispatch"]["id"],
                "conditions": [],
            }
        )
    elif change == "missing_edge":
        value["branches"].pop()
    elif change == "trigger":
        value["triggers"] = [{"type": "WEBHOOK"}]
    elif change == "variables":
        value["workflow_variables"] = [{"name": "url", "value": "https://attacker.invalid"}]
    elif change == "exit":
        value["configuration"]["exit_on_error"] = False
    else:
        nodes["callback"]["parameters"][0]["value"] = "failed"
    with pytest.raises(ValueError):
        validate_workflow(value, "process", TASK_APP, CALLBACK_APP)


@pytest.mark.parametrize(
    "value", ["invalid", "00000000-0000-0000-0000-000000000000", "https://attacker.invalid"]
)
def test_graph_builder_rejects_noncanonical_registered_app_ids(value):
    with pytest.raises(ValueError):
        build_workflow("process", value, CALLBACK_APP)


@pytest.mark.parametrize(
    "status,selected",
    [
        ("ready", True),
        ("uncertain", True),
        ("awaiting_approval", False),
        ("denied", False),
        ("expired", False),
        ("no_action", False),
        ("completed", False),
        ("failed", False),
    ],
)
def test_only_the_two_frozen_gate_statuses_select_dispatch(status, selected):
    assert dispatch_selected(execution(gate_status=status, selected=selected)) is selected


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "native_failure",
        "wrong_run",
        "wrong_node",
        "wrong_kind",
        "unknown_status",
        "malformed",
    ],
)
def test_bad_gate_proof_never_defaults_to_ready(change):
    value = execution()
    gate = value["results"][1]
    if change == "missing":
        value["results"].pop(1)
    elif change == "duplicate":
        value["results"].append(clone(gate))
    elif change == "native_failure":
        gate["status"] = "FAILURE"
    elif change == "wrong_run":
        body = json.loads(gate["result"])
        body["run_id"] = OTHER
        gate["result"] = json.dumps(body)
    elif change == "wrong_node":
        gate["action"]["id"] = OTHER
    elif change == "wrong_kind":
        body = json.loads(gate["result"])
        body["kind"] = "unknown"
        gate["result"] = json.dumps(body)
    elif change == "unknown_status":
        body = json.loads(gate["result"])
        body["status"] = "approved"
        gate["result"] = json.dumps(body)
    else:
        gate["result"] = "invalid-json"
    with pytest.raises(ValueError):
        dispatch_selected(value)
