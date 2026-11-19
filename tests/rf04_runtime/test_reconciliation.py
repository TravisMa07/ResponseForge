"""Independent two-observation completion rules; vendor transport is simulated."""

import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest

from responseforge.api import create_app
from responseforge.core import ServiceError
from responseforge.integrations.shuffle.callback import CallbackConfig, CallbackTransport
from responseforge.runtime import WorkflowCallback
from tests.rf02.helpers import TOKENS
from tests.rf04.helpers import RUN, WF, native_result, workflow
from tests.rf04.test_client import wire_response
from tests.rf04.test_coordinator import case_world, reopened


def scenario(tmp_path, *, vendor_status="FINISHED"):
    wire = {
        "vendor_status": vendor_status,
        "argument": None,
        "starts": 0,
        "lookups": 0,
        "native_status": "FAILURE" if vendor_status in {"FAILURE", "ABORTED"} else "SUCCESS",
    }

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        if request.url.path.endswith("/execute"):
            wire["starts"] += 1
            wire["argument"] = json.loads(request.content)["execution_argument"]
            return wire_response(200, json={"success": True, "execution_id": RUN})
        wire["lookups"] += 1
        return wire_response(
            200,
            json={
                "execution_id": RUN,
                "workflow_id": WF,
                "workflow": workflow(),
                "execution_argument": wire["argument"],
                "status": wire["vendor_status"],
                "results": native_result(wire["native_status"]),
            },
        )

    v = case_world(tmp_path, handler)
    receipt = asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    callback = WorkflowCallback(
        run_id=RUN,
        incident_id=v.incident_id,
        workflow_id=WF,
        correlation_id=receipt.argument.correlation_id,
        status="succeeded",
    )
    return SimpleNamespace(v=v, wire=wire, callback=callback)


def stored_run(s):
    with s.v.service.store.transaction() as tx:
        return tx.get("workflows", RUN)


def deliver(s, *, item=None, nonce="node-observation-1", service=None):
    service = service or s.v.service
    return service.callback(
        item or s.callback, s.v.w.actors["workflow"], nonce=nonce, sent_at=s.v.w.clock()
    )


def test_authenticated_node_alone_cannot_finalize_vendor_run(tmp_path):
    s = scenario(tmp_path)
    acknowledgement = deliver(s)
    assert stored_run(s)["status"] == "running"
    assert stored_run(s)["ended_at"] is None
    assert acknowledgement.accepted is True and acknowledgement.vendor_verified is False
    assert s.wire["lookups"] == 0 and s.wire["starts"] == 1


def test_vendor_terminal_alone_cannot_finalize_without_authenticated_node(tmp_path):
    s = scenario(tmp_path)
    observed = asyncio.run(s.v.coordinator.reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain"
    assert stored_run(s)["status"] == "running"
    assert s.wire["lookups"] == 1 and s.wire["starts"] == 1


@pytest.mark.parametrize("vendor_status", ["FINISHED", "SUCCESS"])
def test_matching_node_and_vendor_graph_finalize_once_across_restart(tmp_path, vendor_status):
    s = scenario(tmp_path, vendor_status=vendor_status)
    deliver(s)
    restart = reopened(s.v)
    duplicate = asyncio.run(restart.start(s.v.incident_id, WF, RUN, s.v.actor))
    assert duplicate.state == "accepted" and s.wire["starts"] == 1
    completed = asyncio.run(restart.reconcile(s.v.incident_id, RUN, s.v.actor))
    assert completed.state == "finished"
    assert stored_run(s)["status"] == "succeeded"
    assert stored_run(s)["ended_at"] is not None
    before = s.wire["lookups"]
    assert asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor)) == completed
    assert s.wire["lookups"] == before and s.wire["starts"] == 1
    assert s.v.service.get_incident(s.v.incident_id, s.v.actor).status == "RECEIVED"
    assert s.v.w.provider.effect_count == 0


@pytest.mark.parametrize("vendor_status", ["FAILURE", "ABORTED"])
def test_agreed_failure_is_recorded_without_success_or_endpoint_effect(tmp_path, vendor_status):
    s = scenario(tmp_path, vendor_status=vendor_status)
    deliver(s, item=s.callback.model_copy(update={"status": "failed"}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "failed"
    assert stored_run(s)["status"] == "failed" and s.wire["starts"] == 1
    assert s.v.w.provider.effect_count == 0


@pytest.mark.parametrize(
    "node,vendor", [("succeeded", "FAILURE"), ("failed", "FINISHED"), ("timeout", "FINISHED")]
)
def test_disagreeing_observations_remain_uncertain_and_running(tmp_path, node, vendor):
    s = scenario(tmp_path, vendor_status=vendor)
    deliver(s, item=s.callback.model_copy(update={"status": node}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain" and stored_run(s)["status"] == "running"
    assert stored_run(s)["ended_at"] is None and s.wire["starts"] == 1


def test_vendor_only_then_node_can_reconcile_original_run_without_redispatch(tmp_path):
    s = scenario(tmp_path)
    first = asyncio.run(s.v.coordinator.reconcile(s.v.incident_id, RUN, s.v.actor))
    assert first.state == "uncertain"
    deliver(s)
    final = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert final.state == "finished" and s.wire["starts"] == 1 and s.wire["lookups"] == 2


def test_forged_node_does_not_consume_nonce_or_satisfy_completion(tmp_path):
    s = scenario(tmp_path)
    forged = s.callback.model_copy(update={"correlation_id": "forged-correlation"})
    with pytest.raises(ServiceError):
        deliver(s, item=forged)
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain" and stored_run(s)["status"] == "running"
    deliver(s)
    assert asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor)).state == "finished"
    assert s.wire["starts"] == 1


def test_replayed_or_conflicting_node_cannot_replace_original_observation(tmp_path):
    s = scenario(tmp_path, vendor_status="FAILURE")
    failed = s.callback.model_copy(update={"status": "failed"})
    deliver(s, item=failed)
    with pytest.raises(ServiceError):
        deliver(s, item=failed)
    with pytest.raises(ServiceError):
        deliver(s, item=s.callback, nonce="fresh-but-conflicting-node")
    assert stored_run(s)["status"] == "running"
    assert asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor)).state == "failed"


def test_expired_or_wrong_role_callback_cannot_satisfy_completion(tmp_path):
    s = scenario(tmp_path)
    with pytest.raises(ServiceError):
        s.v.service.callback(s.callback, s.v.actor, nonce="wrong-role", sent_at=s.v.w.clock())
    with pytest.raises(ServiceError):
        s.v.service.callback(
            s.callback,
            s.v.w.actors["workflow"],
            nonce="expired",
            sent_at=s.v.w.clock() - timedelta(seconds=301),
        )
    assert (
        asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor)).state == "uncertain"
    )
    assert stored_run(s)["status"] == "running"


def test_acknowledgement_transport_stores_node_without_claiming_vendor_completion(tmp_path):
    s = scenario(tmp_path)
    sender = CallbackTransport(
        CallbackConfig(
            base_url="https://core.invalid",
            api_key=TOKENS["workflow"],
            workflow_ids=frozenset({WF}),
        ),
        transport=httpx.ASGITransport(app=create_app(s.v.service.settings, clock=s.v.w.clock)),
        clock=s.v.w.clock,
        nonce_factory=lambda: "strict-node-acknowledgement",
    )
    receipt = asyncio.run(sender.send(s.callback))
    assert receipt.delivery == "accepted" and receipt.callback == s.callback
    assert stored_run(s)["status"] == "running" and s.wire["lookups"] == 0
    assert asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor)).state == "finished"


@pytest.mark.parametrize("vendor_status", ["FAILURE", "ABORTED"])
def test_agreed_timeout_preserves_timeout_status_instead_of_generic_failure(
    tmp_path, vendor_status
):
    s = scenario(tmp_path, vendor_status=vendor_status)
    deliver(s, item=s.callback.model_copy(update={"status": "timeout"}))
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "failed" and stored_run(s)["status"] == "timeout"
    assert s.wire["starts"] == 1 and s.v.w.provider.effect_count == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "44444444-4444-4444-8444-444444444444"),
        ("workflow_id", "22222222-2222-4222-8222-222222222222"),
        ("incident_id", "another-case"),
        ("correlation_id", "another-correlation"),
        ("status", "approved"),
    ],
)
def test_corrupted_node_identity_or_status_cannot_satisfy_completion(tmp_path, field, value):
    s = scenario(tmp_path)
    deliver(s)
    with s.v.service.store.transaction() as tx:
        node = tx.get("callbacks", "shuffle-node:" + RUN)
        node["callback"][field] = value
        tx.replace("callbacks", "shuffle-node:" + RUN, node)
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain" and stored_run(s)["status"] == "running"


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "live"},
        {"record_type": "arbitrary-record"},
        {"actor_id": ""},
    ],
)
def test_mismatched_or_malformed_node_provenance_cannot_finalize(tmp_path, changes):
    s = scenario(tmp_path)
    deliver(s)
    with s.v.service.store.transaction() as tx:
        node = tx.get("callbacks", "shuffle-node:" + RUN)
        node.update(changes)
        tx.replace("callbacks", "shuffle-node:" + RUN, node)
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain" and stored_run(s)["status"] == "running"


def test_future_received_node_timestamp_cannot_finalize(tmp_path):
    s = scenario(tmp_path)
    deliver(s)
    with s.v.service.store.transaction() as tx:
        node = tx.get("callbacks", "shuffle-node:" + RUN)
        node["received_at"] = (s.v.w.clock() + timedelta(seconds=1)).isoformat()
        tx.replace("callbacks", "shuffle-node:" + RUN, node)
    observed = asyncio.run(reopened(s.v).reconcile(s.v.incident_id, RUN, s.v.actor))
    assert observed.state == "uncertain" and stored_run(s)["status"] == "running"


@pytest.mark.parametrize(
    "changes",
    [
        {"vendor_verified": True},
        {"accepted": False},
        {"received_at": "invalid"},
        {"correlation_id": "forged-correlation"},
        {"status": "failed"},
    ],
)
def test_sender_requires_strict_exact_node_acknowledgement(changes):
    from tests.rf04_runtime.test_pilot_app import KEY

    callback = WorkflowCallback(
        run_id=RUN,
        incident_id="case-1",
        workflow_id=WF,
        correlation_id="correlation-1",
        status="succeeded",
    )
    ack = (
        callback.model_dump(mode="json")
        | {"accepted": True, "vendor_verified": False, "received_at": "2026-01-01T12:00:00Z"}
        | changes
    )
    sender = CallbackTransport(
        CallbackConfig(base_url="https://core.invalid", api_key=KEY, workflow_ids=frozenset({WF})),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=ack)),
    )
    assert asyncio.run(sender.send(callback)).delivery == "uncertain"
