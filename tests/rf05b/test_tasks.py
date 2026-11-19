"""Native task wire behavior, with injected HTTP and no actual Shuffle claim."""

import asyncio
import json

import httpx
import pytest

from responseforge.integrations.shuffle.tasks import execute_task
from tests.rf05b.helpers import (
    AUTH,
    BACKEND,
    KEY,
    OTHER,
    RUN,
    WF,
    argument,
    clone,
    environment,
    execution,
    node,
    plan,
    private_config,
    progress,
    request,
    result,
)


def test_prepare_uses_original_argument_and_workflow_only_private_auth(tmp_path):
    calls = []

    def handler(item):
        calls.append(item)
        if item.url.path == "/api/v1/streams/results":
            return httpx.Response(200, json=execution(results=[]))
        if item.url.host == "responseforge-core":
            assert item.url.path == "/v1/incidents/case-1/playbooks/prepare"
            assert item.headers["Authorization"] == "Bearer " + KEY
            assert json.loads(item.content) == request()
            return httpx.Response(200, json=plan())
        assert item.url.path == "/api/v1/streams"
        return httpx.Response(200, json={"success": True})

    answer = asyncio.run(
        execute_task(
            environment(), private_config(tmp_path), transport=httpx.MockTransport(handler)
        )
    )
    assert answer["delivery"] == "accepted" and answer["status"] == "prepared"
    assert answer["run_id"] == RUN and answer["step"] == "prepare"
    assert len(calls) == 3
    assert json.loads(calls[0].content) == {"execution_id": RUN, "authorization": AUTH}
    submitted = json.loads(calls[-1].content)
    assert submitted["status"] == "SUCCESS" and submitted["execution_id"] == RUN
    body = json.loads(submitted["result"])
    assert set(body) <= {"schema_version", "delivery", "run_id", "step", "status", "kind", "mode"}
    assert body["kind"] == "process" and WF not in json.dumps(body)
    assert (
        KEY not in str(answer) + submitted["result"]
        and AUTH not in str(answer) + submitted["result"]
    )


def run_task(
    tmp_path,
    *,
    step="prepare",
    original=None,
    response=None,
    core_status=200,
    fault=None,
    params=None,
):
    calls = []
    original = (
        execution(results=[] if step != "dispatch" else [result("gate", "ready")])
        if original is None
        else original
    )
    response = (
        (plan() if step == "prepare" else progress("completed" if step == "dispatch" else "ready"))
        if response is None
        else response
    )

    def handler(item):
        calls.append(item)
        if item.url.path == "/api/v1/streams/results":
            return httpx.Response(200, json=original)
        if item.url.host == "responseforge-core":
            if fault is not None:
                raise fault(KEY + AUTH, request=item)
            return httpx.Response(core_status, json=response)
        assert item.url.path == "/api/v1/streams"
        return httpx.Response(200, json={"success": True})

    env = environment(step)
    if params is not None:
        env["ACTION"] = json.dumps(node(step, parameters=params))
    answer = asyncio.run(
        execute_task(env, private_config(tmp_path), transport=httpx.MockTransport(handler))
    )
    return answer, calls


@pytest.mark.parametrize("step", ["gate", "dispatch"])
def test_gate_and_selected_dispatch_use_only_their_fixed_core_route(tmp_path, step):
    answer, calls = run_task(tmp_path, step=step)
    core = [item for item in calls if item.url.host == "responseforge-core"]
    assert len(core) == 1 and core[0].url.path == "/v1/incidents/case-1/playbooks/" + step
    assert json.loads(core[0].content) == request()
    assert answer["delivery"] == "accepted" and answer["step"] == step
    assert answer["status"] == ("ready" if step == "gate" else "completed")


@pytest.mark.parametrize(
    "status", ["awaiting_approval", "denied", "expired", "no_action", "completed", "failed"]
)
def test_unselected_dispatch_emits_native_skipped_without_core_io(tmp_path, status):
    original = execution(gate_status=status, selected=False)
    original["results"] = [result("gate", status)]
    answer, calls = run_task(tmp_path, step="dispatch", original=original)
    assert answer["delivery"] == "skipped" and answer["status"] == "skipped"
    assert not [item for item in calls if item.url.host == "responseforge-core"]
    submissions = [item for item in calls if item.url.path == "/api/v1/streams"]
    assert len(submissions) == 1
    payload = json.loads(submissions[0].content)
    assert payload["status"] == "SKIPPED" and json.loads(payload["result"])["step"] == "dispatch"


@pytest.mark.parametrize("parameters", [None, []])
def test_empty_parameters_remain_compatible_with_vendor_serialization(tmp_path, parameters):
    env = environment(ACTION=json.dumps(node(parameters=parameters)))
    calls = []

    def handler(item):
        calls.append(item)
        if item.url.path == "/api/v1/streams/results":
            return httpx.Response(200, json=execution(results=[]))
        return httpx.Response(
            200, json=plan() if item.url.host == "responseforge-core" else {"success": True}
        )

    answer = asyncio.run(
        execute_task(env, private_config(tmp_path), transport=httpx.MockTransport(handler))
    )
    assert answer["delivery"] == "accepted"


@pytest.mark.parametrize(
    "changes",
    [
        {"app_name": "http"},
        {"app_version": "9.9.9"},
        {"name": "approve"},
        {"id": "invalid"},
        {"app_id": "invalid"},
        {"parameters": [{"name": "url", "value": "https://attacker.invalid"}]},
        {"parameters": [{"name": "approved", "value": True}]},
        {"parameters": [{"name": "provider", "value": "attacker"}]},
        {"parameters": [{"name": "target", "value": "another-host"}]},
        {"parameters": [{"name": "command", "value": "UNTRUSTED_COMMAND"}]},
        {"parameters": [{"name": "outcome", "value": "succeeded"}]},
    ],
)
def test_unreviewed_task_input_never_reaches_any_network(tmp_path, changes):
    calls = []
    with pytest.raises(ValueError) as error:
        asyncio.run(
            execute_task(
                environment(ACTION=json.dumps(node(**changes))),
                private_config(tmp_path),
                transport=httpx.MockTransport(lambda item: calls.append(item)),
            )
        )
    assert not calls and KEY not in str(error.value) and AUTH not in str(error.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"BASE_URL": "https://attacker.invalid"},
        {"BASE_URL": BACKEND + "/unexpected"},
        {"AUTHORIZATION": ""},
        {"EXECUTIONID": "invalid"},
        {"ACTION": "invalid-json"},
    ],
)
def test_invalid_worker_environment_is_rejected_before_io(tmp_path, changes):
    calls = []
    with pytest.raises(ValueError):
        asyncio.run(
            execute_task(
                environment(**changes),
                private_config(tmp_path),
                transport=httpx.MockTransport(lambda item: calls.append(item)),
            )
        )
    assert not calls


@pytest.mark.parametrize(
    "change", ["workflow", "run", "mode", "node", "duplicate_node", "node_app", "graph"]
)
def test_original_scope_or_node_mismatch_cannot_reach_core(tmp_path, change):
    original = execution(results=[])
    if change == "workflow":
        original["workflow_id"] = OTHER
    elif change == "run":
        original["execution_id"] = OTHER
    elif change == "mode":
        original["execution_argument"] = json.dumps(argument(mode="live"))
    elif change == "node":
        original["workflow"]["actions"][0]["id"] = OTHER
    elif change == "duplicate_node":
        original["workflow"]["actions"].append(clone(original["workflow"]["actions"][0]))
    elif change == "node_app":
        original["workflow"]["actions"][0]["app_id"] = OTHER
    else:
        original["workflow"]["configuration"]["exit_on_error"] = False
    calls = []

    def handler(item):
        calls.append(item)
        return httpx.Response(
            200, json=original if item.url.path.endswith("/results") else {"success": True}
        )

    try:
        answer = asyncio.run(
            execute_task(
                environment(), private_config(tmp_path), transport=httpx.MockTransport(handler)
            )
        )
    except ValueError:
        pass
    else:
        assert answer["delivery"] != "accepted"
    assert not [item for item in calls if item.url.host == "responseforge-core"]


@pytest.mark.parametrize("core_status", [401, 403, 409, 422, 500, 503])
def test_core_rejection_is_a_failed_sanitized_native_result(tmp_path, core_status):
    answer, calls = run_task(tmp_path, core_status=core_status, response={"detail": KEY + AUTH})
    assert answer["delivery"] != "accepted" and answer["status"] == "unavailable"
    assert len([item for item in calls if item.url.host == "responseforge-core"]) == 1
    submissions = [item for item in calls if item.url.path == "/api/v1/streams"]
    assert len(submissions) == 1
    payload = json.loads(submissions[0].content)
    assert payload["status"] == "FAILURE"
    assert KEY not in payload["result"] and AUTH not in payload["result"] and KEY not in str(answer)


@pytest.mark.parametrize("fault", [httpx.ReadTimeout, httpx.ConnectError])
def test_mutating_core_request_is_not_blindly_retried(tmp_path, fault):
    answer, calls = run_task(tmp_path, fault=fault)
    assert answer["delivery"] == "uncertain" and answer["status"] == "unavailable"
    assert len([item for item in calls if item.url.host == "responseforge-core"]) == 1
    assert KEY not in str(answer) and AUTH not in str(answer)


@pytest.mark.parametrize(
    "change", ["request", "unknown", "unverified", "other_case", "other_proposal", "live"]
)
def test_malformed_or_unverified_core_success_cannot_be_native_success(tmp_path, change):
    value = progress("completed")
    if change == "request":
        value["request"]["correlation_id"] = "forged"
    elif change == "unknown":
        value["status"] = "approved"
    elif change == "unverified":
        value["execution"]["verification"].update(status="pending", checked_at=None)
    elif change == "other_case":
        value["execution"]["incident_id"] = "another-case"
    elif change == "other_proposal":
        value["execution"]["proposal_id"] = "another-proposal"
    else:
        value["execution"]["mode"] = "live"
    answer, calls = run_task(tmp_path, step="dispatch", response=value)
    assert answer["delivery"] != "accepted" and answer["status"] == "unavailable"
    submitted = json.loads(
        [item for item in calls if item.url.path == "/api/v1/streams"][0].content
    )
    assert submitted["status"] == "FAILURE"


def test_private_graph_pin_is_mandatory_for_native_tasks(tmp_path):
    calls = []
    with pytest.raises(ValueError):
        asyncio.run(
            execute_task(
                environment(),
                private_config(tmp_path, workflow_graphs={}),
                transport=httpx.MockTransport(lambda item: calls.append(item)),
            )
        )
    assert not calls


def test_preparation_response_with_other_request_is_rejected(tmp_path):
    answer, calls = run_task(tmp_path, response=plan(request=request(run_id=OTHER)))
    assert answer["delivery"] != "accepted"
    assert len([item for item in calls if item.url.host == "responseforge-core"]) == 1


@pytest.mark.parametrize("change", ["extra_key", "duplicate_json", "nonfinite", "oversized"])
def test_invalid_private_configuration_is_rejected_without_io(tmp_path, change):
    path = private_config(tmp_path)
    if change == "extra_key":
        data = json.loads(path.read_text())
        data["approved"] = True
        path.write_text(json.dumps(data))
    elif change == "duplicate_json":
        path.write_text(
            '{"base_url":"https://responseforge-core:8000","base_url":"https://attacker.invalid"}'
        )
    elif change == "nonfinite":
        data = json.loads(path.read_text())
        data["workflow_graphs"][WF] = float("nan")
        path.write_text(json.dumps(data))
    else:
        path.write_text(" " * 17000)
    calls = []
    with pytest.raises(ValueError):
        asyncio.run(
            execute_task(
                environment(), path, transport=httpx.MockTransport(lambda item: calls.append(item))
            )
        )
    assert not calls


def test_symlink_private_configuration_is_not_followed(tmp_path):
    path = private_config(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    calls = []
    with pytest.raises(ValueError):
        asyncio.run(
            execute_task(
                environment(), link, transport=httpx.MockTransport(lambda item: calls.append(item))
            )
        )
    assert not calls


def test_no_lookup_failure_can_echo_secrets_or_claim_success(tmp_path, caplog, capsys):
    calls = []

    def handler(item):
        calls.append(item)
        raise httpx.ReadTimeout(KEY + AUTH, request=item)

    answer = asyncio.run(
        execute_task(
            environment(), private_config(tmp_path), transport=httpx.MockTransport(handler)
        )
    )
    assert answer["delivery"] == "uncertain" and answer["status"] == "unavailable"
    assert len(calls) == 1
    assert KEY not in str(answer) + caplog.text + str(capsys.readouterr())
    assert AUTH not in str(answer) + caplog.text + str(capsys.readouterr())


def test_completed_core_result_cannot_omit_execution_proof(tmp_path):
    answer, calls = run_task(tmp_path, step="gate", response=progress("completed", execution=None))
    assert answer["delivery"] != "accepted"
    assert (
        json.loads([item for item in calls if item.url.path == "/api/v1/streams"][0].content)[
            "status"
        ]
        == "FAILURE"
    )


@pytest.mark.parametrize(
    "case_id",
    ["../actions/proposal-1/approve", "case-1?provider=attacker", "case-1#ignored", "case-1/other"],
)
def test_execution_argument_cannot_change_the_fixed_core_route(tmp_path, case_id):
    original = execution(results=[])
    original["execution_argument"] = json.dumps(argument(incident_id=case_id))
    from urllib.parse import quote

    answer, calls = run_task(tmp_path, original=original)
    assert answer["delivery"] != "accepted"  # Original fixture reply is for another case.
    core_calls = [item for item in calls if item.url.host == "responseforge-core"]
    assert len(core_calls) == 1
    target = core_calls[0].url
    assert (
        target.raw_path
        == ("/v1/incidents/" + quote(case_id, safe="") + "/playbooks/prepare").encode()
    )
    assert not target.query and not target.fragment
    assert json.loads(core_calls[0].content)["incident_id"] == case_id
