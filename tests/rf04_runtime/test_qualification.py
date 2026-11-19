"""Proof gates are offline-testable; none of these are real vendor evidence."""

from copy import deepcopy

import pytest

from responseforge.integrations.shuffle.qualification import (
    _qualified_results,
    _reviewed_workflow,
    _workflow,
)
from tests.rf04.helpers import RUN, WF


def reviewed():
    template = _workflow(WF, "Original transport-only workflow", "succeeded")
    value = deepcopy(template) | {"id": RUN}
    return template, value


def test_only_intended_native_action_graph_can_be_reviewed():
    template, value = reviewed()
    _reviewed_workflow(value, template, exit_on_error=False)


@pytest.mark.parametrize(
    "change", ["command", "app", "branch", "trigger", "parameter", "auth", "mode", "start"]
)
def test_imported_workflow_cannot_silently_expand_scope(change):
    template, value = reviewed()
    if change == "command":
        value["actions"][0]["name"] = "curl"
    elif change == "app":
        value["actions"][0]["app_id"] = RUN
    elif change == "branch":
        value["branches"] = [{"destination_id": RUN}]
    elif change == "trigger":
        value["triggers"] = [{"type": "WEBHOOK"}]
    elif change == "parameter":
        value["actions"][0]["parameters"][0]["value"] = "unreviewed"
    elif change == "auth":
        value["actions"][0]["authentication_id"] = RUN
    elif change == "mode":
        value["actions"][0]["environment"] = "Live"
    else:
        value["start"] = WF
    with pytest.raises(ValueError):
        _reviewed_workflow(value, template, exit_on_error=False)


def complete_proof():
    states = {
        "success": "finished",
        "failure": "failed",
        "timeout": "uncertain",
        "restart": "finished",
        "lost_start_ack": "finished",
    }
    workflows = {name: {"workflow_id": WF, "sha256": "a" * 64} for name in states}
    results = {
        name: {
            "workflow_id": WF,
            "workflow_sha256": "a" * 64,
            "delivery_state": state,
            "vendor_status": "FAILURE" if name in {"failure", "timeout"} else "FINISHED",
            "callback_audit": True,
            "duplicate_intake": True,
            "duplicate_start": True,
            "graph_verified": True,
            "native_app_results": 1,
            "native_app_containers": 1,
            "native_status": "FAILURE" if name in {"failure", "timeout"} else "SUCCESS",
            "actual_start_ack_timeout": name == "lost_start_ack",
            "post_commit_start_delay_proven": name == "lost_start_ack",
            "post_commit_callback_delay_proven": name == "timeout",
        }
        for name, state in states.items()
    }
    return results, workflows


def test_complete_case_names_alone_do_not_qualify_runtime():
    results, workflows = complete_proof()
    assert _qualified_results(results, workflows)
    assert not _qualified_results({name: {} for name in results}, workflows)


@pytest.mark.parametrize(
    "case,key,value",
    [
        ("success", "callback_audit", False),
        ("success", "graph_verified", False),
        ("success", "native_app_containers", 2),
        ("failure", "delivery_state", "finished"),
        ("restart", "native_status", "FAILURE"),
        ("timeout", "post_commit_callback_delay_proven", False),
        ("lost_start_ack", "actual_start_ack_timeout", False),
        ("lost_start_ack", "post_commit_start_delay_proven", False),
        ("success", "workflow_sha256", "b" * 64),
    ],
)
def test_missing_conflicting_or_rebound_evidence_cannot_pass(case, key, value):
    results, workflows = complete_proof()
    results[case][key] = value
    assert not _qualified_results(results, workflows)
