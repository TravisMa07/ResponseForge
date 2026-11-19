"""Actual native app wire boundaries with injected HTTP; not vendor runtime proof."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from responseforge.integrations.shuffle.pilot import execute_app
from tests.rf04.helpers import NOW, RUN, WF, argument

ACTION = "66666666-6666-4666-8666-666666666666"
KEY = "SYNTHETIC_PRIVATE_CALLBACK_CREDENTIAL_NOT_FOR_NETWORK"
EXECUTION_SECRET = "SYNTHETIC_VENDOR_EXECUTION_AUTHORIZATION"
BACKEND = "http://shuffle-backend:5001"


def action(**changes):
    return {
        "id": ACTION,
        "app_id": WF,
        "app_name": "responseforge_callback",
        "app_version": "1.0.0",
        "name": "callback",
        "parameters": [],
    } | changes


def environment(**changes):
    return {
        "ACTION": json.dumps(action()),
        "AUTHORIZATION": EXECUTION_SECRET,
        "EXECUTIONID": RUN,
        "BASE_URL": BACKEND,
    } | changes


def private_config(tmp_path: Path, **changes):
    path = tmp_path / "callback.json"
    path.write_text(
        json.dumps(
            {
                "base_url": "https://responseforge-core:8000",
                "api_key": KEY,
                "workflow_ids": [WF],
                "shuffle_backend": BACKEND,
            }
            | changes
        )
    )
    path.chmod(0o600)
    return path


def execution(**changes):
    return {
        "execution_id": RUN,
        "workflow_id": WF,
        "workflow": {"id": WF},
        "execution_argument": argument().model_dump_json(),
        "status": "EXECUTING",
    } | changes


def core_echo():
    return {
        "schema_version": "1.0",
        "run_id": RUN,
        "incident_id": "case-1",
        "workflow_id": WF,
        "workflow_version": "v1",
        "correlation_id": "correlation-1",
        "status": "succeeded",
        "started_at": NOW.isoformat(),
        "ended_at": NOW.isoformat(),
    }


def test_native_app_fetches_original_execution_and_submits_only_safe_result(tmp_path: Path):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/api/v1/streams/results":
            return httpx.Response(200, json=execution())
        if request.url.path == "/v1/integrations/shuffle/callback":
            return httpx.Response(200, json=core_echo())
        assert request.url.path == "/api/v1/streams"
        return httpx.Response(200, json={"success": True})

    result = asyncio.run(
        execute_app(environment(), private_config(tmp_path), transport=httpx.MockTransport(handler))
    )
    assert result["delivery"] == "accepted"
    assert [request.url.path for request in calls] == [
        "/api/v1/streams/results",
        "/v1/integrations/shuffle/callback",
        "/api/v1/streams",
    ]
    lookup = json.loads(calls[0].content)
    assert lookup["execution_id"] == RUN and lookup["authorization"] == EXECUTION_SECRET
    callback_request = calls[1]
    assert callback_request.headers["Authorization"] == "Bearer " + KEY
    payload = json.loads(callback_request.content)
    assert payload["run_id"] == RUN and payload["workflow_id"] == WF
    submitted = json.loads(calls[2].content)
    assert submitted["action"]["app_id"] == WF
    assert submitted["execution_id"] == RUN
    assert submitted["authorization"] == EXECUTION_SECRET
    safe_result = submitted["result"]
    assert KEY not in str(safe_result) and EXECUTION_SECRET not in str(safe_result)
    assert KEY not in str(result) and EXECUTION_SECRET not in str(result)


@pytest.mark.parametrize(
    "changes",
    [
        {"app_name": "http"},
        {"app_version": "9.9.9"},
        {"name": "curl"},
        {"id": "not-a-uuid"},
        {"id": "00000000-0000-0000-0000-000000000000"},
        {"parameters": [{"name": "url", "value": "https://attacker.invalid"}]},
        {"parameters": [{"name": "command", "value": "RAW_UNTRUSTED_COMMAND"}]},
        {"parameters": [{"name": "outcome", "value": "approved"}]},
        {"parameters": [{"name": "delay_seconds", "value": "NaN"}]},
        {"parameters": [{"name": "delay_seconds", "value": -1}]},
        {"parameters": [{"name": "delay_seconds", "value": 61}]},
        {
            "parameters": [
                {"name": "outcome", "value": "succeeded"},
                {"name": "outcome", "value": "failed"},
            ]
        },
    ],
)
def test_unreviewed_action_rejected_before_any_network(tmp_path: Path, changes):
    calls = []
    payload = environment(ACTION=json.dumps(action(**changes)))
    with pytest.raises(ValueError) as caught:
        asyncio.run(
            execute_app(
                payload,
                private_config(tmp_path),
                transport=httpx.MockTransport(lambda request: calls.append(request)),
            )
        )
    assert str(caught.value) == "Invalid pilot app input"
    assert calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"EXECUTIONID": "not-a-uuid"},
        {"EXECUTIONID": "00000000-0000-0000-0000-000000000000"},
        {"ACTION": "not-json"},
        {"AUTHORIZATION": ""},
        {"BASE_URL": "https://attacker.invalid"},
    ],
)
def test_invalid_worker_environment_rejected_without_echo(tmp_path: Path, changes):
    calls = []
    with pytest.raises(ValueError) as caught:
        asyncio.run(
            execute_app(
                environment(**changes),
                private_config(tmp_path),
                transport=httpx.MockTransport(lambda request: calls.append(request)),
            )
        )
    assert str(caught.value) == "Invalid pilot app input"
    assert calls == []


def test_bad_private_configuration_never_supplies_arbitrary_target(tmp_path: Path):
    calls = []
    path = private_config(tmp_path, base_url="http://attacker.invalid", api_key=KEY)
    with pytest.raises(ValueError) as caught:
        asyncio.run(
            execute_app(
                environment(),
                path,
                transport=httpx.MockTransport(lambda request: calls.append(request)),
            )
        )
    assert str(caught.value) == "Invalid pilot app input"
    assert KEY not in str(caught.value) and not calls


@pytest.mark.parametrize(
    "changes",
    [
        {"execution_id": "44444444-4444-4444-8444-444444444444"},
        {"workflow_id": "22222222-2222-4222-8222-222222222222"},
        {"workflow": {"id": "22222222-2222-4222-8222-222222222222"}},
        {
            "execution_argument": argument(
                run_id="44444444-4444-4444-8444-444444444444"
            ).model_dump_json()
        },
        {"execution_argument": json.dumps({"approved": True, "command": "RAW_UNTRUSTED_COMMAND"})},
    ],
)
def test_execution_scope_mismatch_cannot_reach_core_callback(tmp_path: Path, changes):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=execution(**changes))

    try:
        result = asyncio.run(
            execute_app(
                environment(), private_config(tmp_path), transport=httpx.MockTransport(handler)
            )
        )
    except ValueError as error:
        assert str(error) == "Invalid pilot app input"
    else:
        assert result["delivery"] != "accepted"
    assert not any(request.url.path == "/v1/integrations/shuffle/callback" for request in calls)


def test_lookup_network_failure_safe_uncertain_and_not_retried(tmp_path: Path, caplog, capsys):
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout(KEY + EXECUTION_SECRET, request=request)

    result = asyncio.run(
        execute_app(environment(), private_config(tmp_path), transport=httpx.MockTransport(handler))
    )
    assert result["delivery"] == "uncertain"
    assert len(calls) == 1
    output = str(result) + caplog.text + str(capsys.readouterr())
    assert KEY not in output and EXECUTION_SECRET not in output


def test_lost_callback_ack_is_not_retried_with_new_nonce(tmp_path: Path):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/api/v1/streams/results":
            return httpx.Response(200, json=execution())
        if request.url.path == "/v1/integrations/shuffle/callback":
            raise httpx.ReadTimeout("lost acknowledgement", request=request)
        return httpx.Response(200, json={"success": True})

    result = asyncio.run(
        execute_app(environment(), private_config(tmp_path), transport=httpx.MockTransport(handler))
    )
    assert result["delivery"] == "uncertain"
    assert (
        len(
            [
                request
                for request in calls
                if request.url.path == "/v1/integrations/shuffle/callback"
            ]
        )
        == 1
    )
    assert len([request for request in calls if request.url.path == "/api/v1/streams"]) <= 1


def test_native_app_uses_actual_authenticated_core_and_durable_nonce_guard(tmp_path: Path):
    from datetime import UTC, datetime

    from responseforge.api import create_app
    from tests.rf02.helpers import TOKENS, alert, world

    w = world(tmp_path / "actual-core.sqlite")
    w.clock.now = datetime.now(UTC)
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(intake.incident_id, RUN, WF, "v1", w.actors["analyst"])
    correlated = argument(incident_id=intake.incident_id, correlation_id=intake.correlation_id)
    calls = []
    core = httpx.ASGITransport(app=create_app(w.settings, clock=w.clock))

    def vendor(request):
        if request.url.path == "/api/v1/streams/results":
            return httpx.Response(
                200, json=execution(execution_argument=correlated.model_dump_json())
            )
        assert request.url.path == "/api/v1/streams"
        return httpx.Response(200, json={"success": True})

    backend = httpx.MockTransport(vendor)

    class MixedTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            calls.append(request)
            if request.url.host == "responseforge-core":
                return await core.handle_async_request(request)
            return await backend.handle_async_request(request)

    # Production app identity, without patched randomness or retained app state,
    # must reuse a stable nonce so core replay protection survives app restarts.
    path = private_config(tmp_path, api_key=TOKENS["workflow"])
    result = asyncio.run(execute_app(environment(), path, transport=MixedTransport()))
    assert result["delivery"] == "accepted"
    snapshot = w.service.snapshot(intake.incident_id, w.actors["analyst"])
    assert any(event.operation == "workflow_callback" for event in snapshot.audit)
    assert snapshot.incident.status == "RECEIVED" and w.provider.effect_count == 0
    # A new core/application instance uses the same SQLite nonce state.
    core = httpx.ASGITransport(app=create_app(w.settings, clock=w.clock))
    repeated = asyncio.run(execute_app(environment(), path, transport=MixedTransport()))
    assert repeated["delivery"] == "rejected"
    assert (
        len(
            [
                request
                for request in calls
                if request.url.path == "/v1/integrations/shuffle/callback"
            ]
        )
        == 2
    )

    nonces = [
        request.headers["X-Request-Nonce"]
        for request in calls
        if request.url.path == "/v1/integrations/shuffle/callback"
    ]
    assert len(nonces) == 2 and nonces[0] == nonces[1] and len(nonces[0]) >= 32
    assert TOKENS["workflow"] not in nonces[0] and EXECUTION_SECRET not in nonces[0]
