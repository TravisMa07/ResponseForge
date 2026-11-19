"""Independent native action outcomes; FINISHED alone is not action success."""

import asyncio
import json
from copy import deepcopy

import httpx
import pytest

from responseforge.integrations.shuffle.client import ShuffleTransport
from tests.rf04.helpers import (
    EXECUTION_SECRET,
    OTHER_RUN,
    RUN,
    WF,
    argument,
    config,
    native_result,
    workflow,
)
from tests.rf04.test_client import wire_response
from tests.rf04.test_coordinator import reopened
from tests.rf04_runtime.test_reconciliation import deliver, scenario, stored_run


def test_finished_vendor_with_native_failure_and_failed_node_records_failure(tmp_path):
    s = scenario(tmp_path, vendor_status="FINISHED")
    s.wire["native_status"] = "FAILURE"
    deliver(s, item=s.callback.model_copy(update={"status": "failed"}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "failed"
    assert observed.vendor_status == "FINISHED"
    assert observed.callback_status == "FAILURE"
    assert stored_run(s)["status"] == "failed" and s.wire["starts"] == 1


def test_lost_postcommit_callback_ack_never_turns_native_failure_into_success(tmp_path):
    s = scenario(tmp_path, vendor_status="FINISHED")
    s.wire["native_status"] = "FAILURE"
    deliver(s)
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain"
    assert observed.vendor_status == "FINISHED" and observed.callback_status == "FAILURE"
    assert stored_run(s)["status"] == "running"
    assert stored_run(s)["ended_at"] is None and s.wire["starts"] == 1


def client_execution(*, results=None, graph=None, status="FINISHED"):
    payload = {
        "execution_id": RUN,
        "workflow_id": WF,
        "workflow": graph or workflow(),
        "execution_argument": argument().model_dump_json(),
        "status": status,
        "results": native_result() if results is None else results,
    }
    sender = ShuffleTransport(
        config(), transport=httpx.MockTransport(lambda request: wire_response(200, json=payload))
    )
    return asyncio.run(sender.get_execution(WF, RUN, argument()))


@pytest.mark.parametrize("status", ["SUCCESS", "FAILURE"])
def test_client_projects_exact_native_action_outcome_without_result_secrets(status):
    results = native_result(status)
    results[0]["authorization"] = EXECUTION_SECRET
    results[0]["result"] = json.dumps({"private": EXECUTION_SECRET})
    observed = client_execution(results=results)
    assert observed.callback_status == status
    assert observed.vendor_status == "FINISHED"
    assert EXECUTION_SECRET not in observed.model_dump_json() + repr(observed)


@pytest.mark.parametrize("results", [[], None, {}, "not-results"])
def test_missing_or_invalid_native_results_cannot_claim_action_success(results):
    # Explicit null needs a raw document because the helper default is positive.
    if results is None:
        payload = {
            "execution_id": RUN,
            "workflow_id": WF,
            "workflow": workflow(),
            "execution_argument": argument().model_dump_json(),
            "status": "FINISHED",
        }
        sender = ShuffleTransport(
            config(),
            transport=httpx.MockTransport(lambda request: wire_response(200, json=payload)),
        )
        observed = asyncio.run(sender.get_execution(WF, RUN, argument()))
    else:
        observed = client_execution(results=results)
    assert observed.callback_status is None


@pytest.mark.parametrize(
    "changes",
    [
        {"execution_id": OTHER_RUN},
        {"execution_id": None},
        {"status": "FINISHED"},
        {"status": "UNKNOWN"},
        {"status": True},
    ],
)
def test_wrong_execution_or_unknown_native_status_has_no_outcome(changes):
    results = native_result()
    results[0].update(changes)
    assert client_execution(results=results).callback_status is None


@pytest.mark.parametrize(
    "changes",
    [
        {"id": OTHER_RUN},
        {"app_name": "http"},
        {"app_version": "9.9.9"},
        {"name": "curl"},
        {"app_id": "forged-unreviewed-app"},
    ],
)
def test_native_action_metadata_must_exactly_match_reviewed_graph_node(changes):
    results = native_result()
    results[0]["action"].update(changes)
    assert client_execution(results=results).callback_status is None


@pytest.mark.parametrize("second_status", ["SUCCESS", "FAILURE"])
def test_duplicate_native_result_is_ambiguous_even_when_outcomes_match(second_status):
    results = native_result() + native_result(second_status)
    assert client_execution(results=results).callback_status is None


def test_duplicate_same_node_with_conflicting_metadata_is_not_silently_ignored():
    valid = native_result()[0]
    forged = deepcopy(valid)
    forged["action"]["app_version"] = "0.0.0"
    assert client_execution(results=[valid, forged]).callback_status is None


def test_reviewed_app_id_is_bound_as_well_as_action_name_and_version():
    graph = workflow()
    graph["actions"][0]["app_id"] = "approved-callback-app"
    results = native_result()
    results[0]["action"]["app_id"] = "approved-callback-app"
    assert client_execution(results=results, graph=graph).callback_status == "SUCCESS"
    results[0]["action"]["app_id"] = "another-app-with-same-name"
    assert client_execution(results=results, graph=graph).callback_status is None


def test_other_graph_node_result_does_not_replace_or_duplicate_callback_node():
    other = {
        "id": OTHER_RUN,
        "app_name": "other-reviewed-app",
        "app_version": "1.0.0",
        "name": "noop",
    }
    graph = workflow(actions=workflow()["actions"] + [other])
    results = native_result() + [{"execution_id": RUN, "action": other, "status": "SUCCESS"}]
    assert client_execution(results=results, graph=graph).callback_status == "SUCCESS"


@pytest.mark.parametrize("vendor", ["FINISHED", "SUCCESS", "FAILURE", "ABORTED"])
@pytest.mark.parametrize("node", ["failed", "timeout"])
def test_bound_native_failure_and_failed_or_timeout_node_finalize_failure(tmp_path, vendor, node):
    s = scenario(tmp_path, vendor_status=vendor)
    s.wire["native_status"] = "FAILURE"
    deliver(s, item=s.callback.model_copy(update={"status": node}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "failed" and observed.vendor_status == vendor
    assert observed.callback_status == "FAILURE" and stored_run(s)["status"] == node
    assert s.wire["starts"] == 1


@pytest.mark.parametrize("vendor", ["FAILURE", "ABORTED"])
@pytest.mark.parametrize("node", ["succeeded", "failed", "timeout"])
def test_vendor_failure_with_native_success_is_conflicting_for_every_node(tmp_path, vendor, node):
    s = scenario(tmp_path, vendor_status=vendor)
    s.wire["native_status"] = "SUCCESS"
    deliver(s, item=s.callback.model_copy(update={"status": node}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain" and stored_run(s)["status"] == "running"
    assert stored_run(s)["ended_at"] is None and s.wire["starts"] == 1


@pytest.mark.parametrize("vendor", ["FINISHED", "SUCCESS"])
def test_agreed_native_success_requires_node_and_preserves_vendor_status(tmp_path, vendor):
    s = scenario(tmp_path, vendor_status=vendor)
    s.wire["native_status"] = "SUCCESS"
    deliver(s)
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "finished" and observed.vendor_status == vendor
    assert observed.callback_status == "SUCCESS" and stored_run(s)["status"] == "succeeded"
    assert s.v.w.provider.effect_count == 0


def test_multiple_reviewed_callback_nodes_require_explicit_disambiguation():
    other = deepcopy(workflow()["actions"][0])
    other["id"] = OTHER_RUN
    graph = workflow(actions=workflow()["actions"] + [other])
    assert client_execution(results=native_result(), graph=graph).callback_status is None


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "wrong-node", "wrong-execution", "unknown-status"]
)
def test_invalid_native_proof_cannot_finalize_even_with_valid_graph_and_core_node(tmp_path, fault):
    s = scenario(tmp_path)
    deliver(s)
    results = native_result()
    if fault == "missing":
        results = []
    elif fault == "duplicate":
        results += native_result()
    elif fault == "wrong-node":
        results[0]["action"]["id"] = OTHER_RUN
    elif fault == "wrong-execution":
        results[0]["execution_id"] = OTHER_RUN
    else:
        results[0]["status"] = "FINISHED"

    def response(request):
        return wire_response(
            200,
            json={
                "execution_id": RUN,
                "workflow_id": WF,
                "workflow": workflow(),
                "execution_argument": s.wire["argument"],
                "status": "FINISHED",
                "results": results,
            },
        )

    observed = asyncio.run(
        reopened(s.v, handler=response).reconcile(s.v.incident_id, RUN, s.v.actor)
    )
    assert observed.state == "uncertain" and observed.callback_status is None
    assert observed.vendor_status == "FINISHED" and stored_run(s)["status"] == "running"
    assert s.wire["starts"] == 1 and s.v.w.provider.effect_count == 0


@pytest.mark.parametrize("vendor", ["EXECUTING", "WAITING"])
@pytest.mark.parametrize("native,node", [("SUCCESS", "succeeded"), ("FAILURE", "failed")])
def test_native_and_core_agreement_still_wait_for_whole_vendor_completion(
    tmp_path, vendor, native, node
):
    s = scenario(tmp_path, vendor_status=vendor)
    s.wire["native_status"] = native
    deliver(s, item=s.callback.model_copy(update={"status": node}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state not in {"finished", "failed", "rejected"}
    assert observed.vendor_status == vendor and observed.callback_status == native
    assert stored_run(s)["status"] == "running" and stored_run(s)["ended_at"] is None


def test_foreign_callback_receipt_cannot_be_ignored():
    payload = native_result()
    foreign = deepcopy(payload[0])
    foreign["action"]["id"] = OTHER_RUN
    foreign["status"] = "FAILURE"
    from responseforge.integrations.shuffle.client import _callback_status

    assert (
        _callback_status(
            {
                "workflow": workflow(),
                "execution_id": argument().run_id,
                "results": payload + [foreign],
            }
        )
        is None
    )


@pytest.mark.parametrize(
    "state,native",
    [("finished", None), ("finished", "FAILURE"), ("failed", None), ("failed", "SUCCESS")],
)
def test_invalid_or_legacy_terminal_record_cannot_bypass_native_proof(tmp_path, state, native):
    from responseforge.core import ServiceError

    s = scenario(tmp_path)
    with s.v.service.store.transaction() as tx:
        row = tx.get("callbacks", "shuffle:" + argument().run_id)
        row.update(state=state, vendor_status="FINISHED", callback_status=native)
        tx.replace("callbacks", "shuffle:" + argument().run_id, row)
    with pytest.raises(ServiceError, match="Stored workflow delivery is invalid"):
        asyncio.run(s.v.coordinator.reconcile(s.v.incident_id, argument().run_id, s.v.actor))
    assert stored_run(s)["status"] == "running" and s.wire["starts"] == 1


def test_vendor_sanitized_empty_app_id_retains_bound_node_identity():
    from responseforge.integrations.shuffle.client import _callback_status

    graph = workflow()
    graph["actions"][0]["app_id"] = WF
    receipt = native_result()
    receipt[0]["action"]["app_id"] = ""
    assert (
        _callback_status({"workflow": graph, "execution_id": argument().run_id, "results": receipt})
        == "SUCCESS"
    )
