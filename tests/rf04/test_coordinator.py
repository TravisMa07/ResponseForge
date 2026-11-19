"""D01-D04: durable launch suppression and lookup-only recovery through real core."""

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from responseforge.core import CaseService, ServiceError
from responseforge.integrations.shuffle.client import ShuffleTransport
from responseforge.integrations.shuffle.coordinator import ShuffleCoordinator
from responseforge.integrations.shuffle.models import WorkflowBinding
from responseforge.runtime import WorkflowCallback
from responseforge.storage import Store
from tests.rf02.helpers import ENDPOINT, SimulatedCrash, alert, world
from tests.rf04.helpers import (
    EXECUTION_SECRET,
    OTHER_RUN,
    RUN,
    WF,
    config,
    fingerprint,
    workflow,
)
from tests.rf04.test_client import wire_response


def case_world(tmp_path: Path, handler):
    w = world(tmp_path / "cases.sqlite")
    accepted = w.service.intake(alert(), w.actors["source"])
    cfg = config()
    bindings = {WF: WorkflowBinding(version="reviewed-test-v1", sha256=fingerprint(workflow()))}
    settings = replace(w.settings, shuffle_config=cfg, shuffle_bindings=bindings)
    service = CaseService(Store(settings.database_path), settings, clock=w.clock)
    transport = httpx.MockTransport(handler)
    client = ShuffleTransport(cfg, transport=transport)
    return SimpleNamespace(
        w=w,
        service=service,
        cfg=cfg,
        bindings=bindings,
        client=client,
        transport=transport,
        coordinator=ShuffleCoordinator(service, client, bindings),
        incident_id=accepted.incident_id,
        actor=w.actors["analyst"],
    )


def reopened(v, *, settings=None, cfg=None, bindings=None, handler=None):
    settings = settings or v.service.settings
    cfg = cfg or v.cfg
    bindings = bindings or v.bindings
    if handler is None:
        handler = v.transport
    else:
        handler = httpx.MockTransport(handler)
    service = CaseService(Store(settings.database_path), settings, clock=v.w.clock)
    return ShuffleCoordinator(service, ShuffleTransport(cfg, transport=handler), bindings)


def authenticated_node(v, *, status="succeeded", nonce="explicit-recovery-node"):
    """RF-04 runtime refinement: a positive poll also needs real core receipt."""
    with v.service.store.transaction() as tx:
        run = tx.get("workflows", RUN)
    acknowledgement = v.service.callback(
        WorkflowCallback(
            run_id=RUN,
            incident_id=v.incident_id,
            workflow_id=WF,
            correlation_id=run["correlation_id"],
            status=status,
        ),
        v.w.actors["workflow"],
        nonce=nonce,
        sent_at=v.w.clock(),
    )
    assert acknowledgement.accepted is True and acknowledgement.vendor_verified is False
    return acknowledgement


def test_start_is_durable_and_duplicate_reopen_never_posts_again(tmp_path: Path) -> None:
    calls, arguments = [], []

    def handler(request):
        calls.append(request)
        if request.method == "GET":
            return wire_response(200, json=workflow())
        body = json.loads(request.content)
        arguments.append(json.loads(body["execution_argument"]))
        return wire_response(
            200, json={"success": True, "execution_id": RUN, "authorization": EXECUTION_SECRET}
        )

    v = case_world(tmp_path, handler)
    first = asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    assert first.state == "accepted" and first.argument.incident_id == v.incident_id
    assert first.argument.run_id == RUN
    assert len(arguments) == 1
    with v.service.store.transaction() as tx:
        record = tx.get("callbacks", "shuffle:" + RUN)
        run = tx.get("workflows", RUN)
    assert record["state"] == "accepted" and run["status"] == "running"
    assert EXECUTION_SECRET not in json.dumps(record)
    second = asyncio.run(reopened(v).start(v.incident_id, WF, RUN, v.actor))
    assert second == first
    assert len([r for r in calls if r.url.path.endswith("/execute")]) == 1
    audit = v.service.audit(v.incident_id, v.actor)
    assert any(e.operation == "shuffle_reserved" for e in audit)
    assert v.service.get_incident(v.incident_id, v.actor).status == "RECEIVED"


def test_concurrent_duplicate_observes_committed_reservation_before_external_io(
    tmp_path: Path,
) -> None:
    posted = []
    started, release = None, None

    async def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        posted.append(request)
        started.set()
        await release.wait()
        return wire_response(200, json={"success": True, "execution_id": RUN})

    v = case_world(tmp_path, handler)

    async def deliver():
        nonlocal started, release
        started, release = asyncio.Event(), asyncio.Event()
        first = asyncio.create_task(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
        await started.wait()
        duplicate = await reopened(v).start(v.incident_id, WF, RUN, v.actor)
        assert duplicate.state == "reserved"
        assert len(posted) == 1
        release.set()
        return await first

    result = asyncio.run(deliver())
    assert result.state == "accepted" and len(posted) == 1


@pytest.mark.parametrize("fault", ["timeout", "crash"])
def test_ambiguous_launch_reconciles_original_uuid_without_second_start(
    tmp_path: Path,
    fault: str,
) -> None:
    starts, lookup, encoded = [], [], []

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        if request.url.path.endswith("/execute"):
            starts.append(request)
            encoded.append(json.loads(request.content)["execution_argument"])
            if fault == "timeout":
                raise httpx.ReadTimeout("SENSITIVE-REMOTE-DETAIL", request=request)
            raise SimulatedCrash("after durable launch reservation")
        lookup.append(request)
        assert json.loads(request.content) == {"execution_id": RUN}
        return wire_response(
            200,
            json={
                "execution_id": RUN,
                "workflow_id": WF,
                "workflow": workflow(),
                "execution_argument": encoded[0],
                "status": "FINISHED",
                "authorization": EXECUTION_SECRET,
            },
        )

    v = case_world(tmp_path, handler)
    if fault == "crash":
        with pytest.raises(SimulatedCrash):
            asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    else:
        first = asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
        assert first.state == "uncertain"
    duplicate = asyncio.run(reopened(v).start(v.incident_id, WF, RUN, v.actor))
    assert duplicate.state in {"reserved", "uncertain"}
    authenticated_node(v)
    recovered = asyncio.run(reopened(v).reconcile(v.incident_id, RUN, v.actor))
    assert recovered.state == "finished" and recovered.vendor_status == "FINISHED"
    assert len(starts) == 1 and len(lookup) == 1
    with v.service.store.transaction() as tx:
        run = tx.get("workflows", RUN)
    assert run["status"] == "succeeded"
    assert v.service.get_incident(v.incident_id, v.actor).status == "RECEIVED"
    assert "SENSITIVE-REMOTE-DETAIL" not in str(v.service.audit(v.incident_id, v.actor))


def test_preflight_workflow_hash_mismatch_never_reserves_or_launches(tmp_path: Path) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(200, json=workflow(start=OTHER_RUN))

    v = case_world(tmp_path, handler)
    with pytest.raises((ServiceError, ValueError)):
        asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    assert all(r.method == "GET" for r in calls)
    with v.service.store.transaction() as tx:
        assert tx.get("callbacks", "shuffle:" + RUN) is None
        assert tx.get("workflows", RUN) is None


def test_run_identity_cannot_be_reused_for_another_case_or_binding(tmp_path: Path) -> None:
    posts = []

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        posts.append(request)
        return wire_response(200, json={"success": True, "execution_id": RUN})

    v = case_world(tmp_path, handler)
    asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    other = v.service.intake(alert(alert_id="other-case"), v.w.actors["source"]).incident_id
    with pytest.raises((ServiceError, ValueError)):
        asyncio.run(reopened(v).start(other, WF, RUN, v.actor))
    changed = {WF: WorkflowBinding(version="different-version", sha256=fingerprint(workflow()))}
    with pytest.raises((ServiceError, ValueError)):
        asyncio.run(reopened(v, bindings=changed).start(v.incident_id, WF, RUN, v.actor))
    new_origin = config(base_url="https://another-shuffle.invalid")
    with pytest.raises((ServiceError, ValueError)):
        asyncio.run(reopened(v, cfg=new_origin).start(v.incident_id, WF, RUN, v.actor))
    assert len(posts) == 1


def test_revoked_actor_and_changed_full_endpoint_cannot_launch_or_reuse(tmp_path: Path) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(200, json=workflow())

    v = case_world(tmp_path, handler)
    denied = replace(v.service.settings, credentials={})
    with pytest.raises(ServiceError):
        asyncio.run(reopened(v, settings=denied).start(v.incident_id, WF, RUN, v.actor))
    changed = replace(
        v.service.settings, endpoints=(ENDPOINT.model_copy(update={"agent_id": "new-agent"}),)
    )
    with pytest.raises(ServiceError):
        asyncio.run(reopened(v, settings=changed).start(v.incident_id, WF, RUN, v.actor))
    assert not calls


def test_callback_gate_does_not_accept_forged_actor_or_replayed_nonce_after_launch(
    tmp_path: Path,
) -> None:
    from responseforge.runtime import WorkflowCallback

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        return wire_response(200, json={"success": True, "execution_id": RUN})

    v = case_world(tmp_path, handler)
    receipt = asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    item = WorkflowCallback(
        run_id=RUN,
        incident_id=v.incident_id,
        workflow_id=WF,
        correlation_id=receipt.argument.correlation_id,
        status="succeeded",
    )
    with pytest.raises(ServiceError):
        v.service.callback(item, v.actor, nonce="unique-test-nonce", sent_at=v.w.clock())
    success = v.service.callback(
        item, v.w.actors["workflow"], nonce="unique-test-nonce", sent_at=v.w.clock()
    )
    assert success.status == "succeeded"
    with pytest.raises(ServiceError):
        v.service.callback(
            item, v.w.actors["workflow"], nonce="unique-test-nonce", sent_at=v.w.clock()
        )


def test_stale_concurrent_failed_lookup_cannot_overwrite_finished_run(tmp_path: Path) -> None:
    encoded = []
    waiting, release = None, None
    lookups = 0

    async def handler(request):
        nonlocal lookups
        if request.method == "GET":
            return wire_response(200, json=workflow())
        if request.url.path.endswith("/execute"):
            encoded.append(json.loads(request.content)["execution_argument"])
            return wire_response(200, json={"success": True, "execution_id": RUN})
        lookups += 1
        if lookups == 1:
            waiting.set()
            await release.wait()
            status = "FAILURE"
        else:
            status = "FINISHED"
        return wire_response(
            200,
            json={
                "execution_id": RUN,
                "workflow_id": WF,
                "workflow": workflow(),
                "execution_argument": encoded[0],
                "status": status,
            },
        )

    v = case_world(tmp_path, handler)

    async def race():
        nonlocal waiting, release
        waiting, release = asyncio.Event(), asyncio.Event()
        await v.coordinator.start(v.incident_id, WF, RUN, v.actor)
        authenticated_node(v)
        slow = asyncio.create_task(v.coordinator.reconcile(v.incident_id, RUN, v.actor))
        await waiting.wait()
        final = await reopened(v).reconcile(v.incident_id, RUN, v.actor)
        assert final.state == "finished"
        release.set()
        try:
            stale = await slow
            assert stale.state == "finished"
        except ServiceError as error:
            assert error.status_code == 409
        return final

    result = asyncio.run(race())
    with v.service.store.transaction() as tx:
        assert tx.get("callbacks", "shuffle:" + RUN)["state"] == "finished"
        assert tx.get("workflows", RUN)["status"] == "succeeded"
    assert result.state == "finished" and lookups == 2


def test_process_exit_after_reserved_start_stays_lookup_only_on_restart(tmp_path: Path) -> None:
    import subprocess
    import sys

    def initial(request):
        raise AssertionError("parent must not dispatch before child")

    v = case_world(tmp_path, initial)
    marker = tmp_path / "synthetic-start.json"
    child = r"""
import asyncio, json, os, sys
from pathlib import Path
from tests.rf04.test_coordinator import case_world
from tests.rf04.test_client import wire_response
from tests.rf04.helpers import WF,RUN,workflow
marker=Path(sys.argv[2])
def handler(request):
    if request.method=="GET": return wire_response(200,json=workflow())
    marker.write_text(json.loads(request.content)["execution_argument"])
    os._exit(73)
v=case_world(Path(sys.argv[1]),handler)
asyncio.run(v.coordinator.start(v.incident_id,WF,RUN,v.actor))
"""
    died = subprocess.run(
        [sys.executable, "-c", child, str(tmp_path), str(marker)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert died.returncode == 73, died.stderr
    assert marker.exists()
    calls = []

    def lookup(request):
        calls.append(request)
        assert request.url.path == "/api/v1/streams/results"
        return wire_response(
            200,
            json={
                "execution_id": RUN,
                "workflow_id": WF,
                "workflow": workflow(),
                "execution_argument": marker.read_text(),
                "status": "FINISHED",
            },
        )

    restart = reopened(v, handler=lookup)
    duplicate = asyncio.run(restart.start(v.incident_id, WF, RUN, v.actor))
    assert duplicate.state == "reserved" and not calls
    authenticated_node(v)
    observed = asyncio.run(restart.reconcile(v.incident_id, RUN, v.actor))
    assert observed.state == "finished" and len(calls) == 1


def test_schema_valid_workflow_row_under_wrong_run_key_rejects_before_start(tmp_path: Path) -> None:
    posts = []

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        posts.append(request)
        return wire_response(200, json={"success": True, "execution_id": RUN})

    v = case_world(tmp_path, handler)
    v.service.register_workflow(v.incident_id, RUN, WF, "reviewed-test-v1", v.actor)
    with v.service.store.transaction() as tx:
        row = tx.get("workflows", RUN)
        row["run_id"] = OTHER_RUN
        tx.replace("workflows", RUN, row)
    with pytest.raises(ServiceError):
        asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    assert not posts


@pytest.mark.parametrize("snapshot", ["missing", "changed-graph"])
@pytest.mark.parametrize("terminal", ["FINISHED", "FAILURE"])
def test_terminal_execution_must_carry_original_reviewed_workflow_graph(
    tmp_path: Path,
    snapshot: str,
    terminal: str,
) -> None:
    starts, encoded = [], []

    def handler(request):
        if request.method == "GET":
            return wire_response(200, json=workflow())
        if request.url.path.endswith("/execute"):
            starts.append(request)
            encoded.append(json.loads(request.content)["execution_argument"])
            return wire_response(200, json={"success": True, "execution_id": RUN})
        payload = {
            "execution_id": RUN,
            "workflow_id": WF,
            "execution_argument": encoded[0],
            "status": terminal,
        }
        if snapshot == "changed-graph":
            payload["workflow"] = workflow(
                actions=[{"id": RUN, "name": "DIFFERENT_EXECUTED_GRAPH"}]
            )
        return wire_response(200, json=payload)

    v = case_world(tmp_path, handler)
    asyncio.run(v.coordinator.start(v.incident_id, WF, RUN, v.actor))
    result = asyncio.run(reopened(v).reconcile(v.incident_id, RUN, v.actor))
    assert result.state == "uncertain"
    with v.service.store.transaction() as tx:
        assert tx.get("workflows", RUN)["status"] == "running"
    assert len(starts) == 1
    repeated = asyncio.run(reopened(v).start(v.incident_id, WF, RUN, v.actor))
    assert repeated.state == "uncertain" and len(starts) == 1
