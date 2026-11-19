"""Three native domain task proofs are required in addition to a final callback."""

import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from responseforge.integrations.shuffle.client import ShuffleTransport
from responseforge.integrations.shuffle.models import ShuffleArgument, ShuffleConfig, TaskResult
from tests.rf05b.helpers import KEY, OTHER, RUN, WF, argument, clone, execution, result


def observed(value):
    transport = httpx.MockTransport(lambda item: httpx.Response(200, json=value))
    client = ShuffleTransport(
        ShuffleConfig(
            base_url="https://shuffle.invalid", api_key=KEY, workflow_ids=frozenset({WF})
        ),
        transport=transport,
    )
    return asyncio.run(client.get_execution(WF, RUN, ShuffleArgument.model_validate(argument())))


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
def test_complete_matching_domain_proof_can_project_final_callback(status, selected):
    assert observed(execution(gate_status=status, selected=selected)).callback_status == "SUCCESS"


@pytest.mark.parametrize(
    "change",
    [
        "prepare_missing",
        "gate_missing",
        "dispatch_missing",
        "duplicate_prepare",
        "duplicate_gate",
        "duplicate_dispatch",
        "prepare_failed",
        "gate_failed",
        "dispatch_failed",
        "wrong_run",
        "kind_conflict",
        "unexpected_dispatch",
        "unexpected_skip",
        "missing_body",
        "extra_secret",
        "unknown_task",
    ],
)
def test_successful_final_callback_cannot_hide_invalid_domain_task_proof(change):
    value = execution()
    if change.endswith("_missing"):
        name = change.removesuffix("_missing")
        value["results"] = [item for item in value["results"] if item["action"]["name"] != name]
    elif change.startswith("duplicate_"):
        name = change.removeprefix("duplicate_")
        value["results"].append(
            clone(next(item for item in value["results"] if item["action"]["name"] == name))
        )
    elif change.endswith("_failed"):
        name = change.removesuffix("_failed")
        next(item for item in value["results"] if item["action"]["name"] == name)["status"] = (
            "FAILURE"
        )
    elif change == "wrong_run":
        value["results"][0]["execution_id"] = OTHER
    elif change == "kind_conflict":
        payload = json.loads(value["results"][1]["result"])
        payload["kind"] = "containment"
        value["results"][1]["result"] = json.dumps(payload)
    elif change == "unexpected_dispatch":
        value["results"][1] = result("gate", "denied")
    elif change == "unexpected_skip":
        value["results"][2] = result(
            "dispatch", "skipped", delivery="skipped", native_status="SKIPPED"
        )
    elif change == "missing_body":
        value["results"][0]["result"] = "{}"
    elif change == "extra_secret":
        payload = json.loads(value["results"][0]["result"])
        payload["credential"] = KEY
        value["results"][0]["result"] = json.dumps(payload)
    else:
        extra = clone(value["results"][0])
        extra["action"]["id"] = OTHER
        extra["action"]["name"] = "approve"
        value["results"].append(extra)
    assert observed(value).callback_status is None


def test_failed_dispatch_with_vendor_finished_and_callback_success_is_unverified():
    value = execution()
    value["results"][2] = result(
        "dispatch", "unavailable", delivery="rejected", native_status="FAILURE", kind=None
    )
    assert value["status"] == "FINISHED" and value["results"][-1]["status"] == "SUCCESS"
    assert observed(value).callback_status is None


def test_legacy_callback_only_proof_remains_compatible():
    value = execution()
    value["workflow"]["actions"] = [value["workflow"]["actions"][-1]]
    value["workflow"]["start"] = value["workflow"]["actions"][0]["id"]
    value["workflow"]["branches"] = []
    value["results"] = [value["results"][-1]]
    assert observed(value).callback_status == "SUCCESS"


@pytest.mark.parametrize(
    "change",
    [
        {"delivery": "accepted", "step": "gate", "status": "prepared"},
        {"delivery": "accepted", "kind": None},
        {"delivery": "skipped", "step": "prepare", "status": "skipped"},
        {"delivery": "uncertain", "status": "completed"},
        {"mode": "live"},
        {"approved": True},
        {"run_id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
    ],
)
def test_task_result_rejects_forged_or_inconsistent_claims(change):
    value = {
        "delivery": "accepted",
        "step": "prepare",
        "status": "prepared",
        "kind": "process",
        "run_id": RUN,
        "mode": "replay",
    } | change
    with pytest.raises(ValidationError):
        TaskResult.model_validate(value)


@pytest.mark.parametrize(
    "change", ["body_run", "body_step", "body_mode", "native_execution", "app_id", "version"]
)
def test_domain_native_receipt_is_bound_to_its_exact_node_and_run(change):
    value = execution()
    receipt = value["results"][1]
    if change.startswith("body_"):
        body = json.loads(receipt["result"])
        body[{"body_run": "run_id", "body_step": "step", "body_mode": "mode"}[change]] = {
            "body_run": OTHER,
            "body_step": "prepare",
            "body_mode": "live",
        }[change]
        receipt["result"] = json.dumps(body)
    elif change == "native_execution":
        receipt["execution_id"] = OTHER
    elif change == "app_id":
        receipt["action"]["app_id"] = OTHER
    else:
        receipt["action"]["app_version"] = "9.9.9"
    assert observed(value).callback_status is None


def test_vendor_sanitized_empty_task_app_id_can_still_match_unique_bound_node():
    value = execution()
    for item in value["results"]:
        item["action"]["app_id"] = ""
    assert observed(value).callback_status == "SUCCESS"
