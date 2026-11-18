"""Independent callback sender expectations; HTTP faults are simulated, not vendor proof."""

import asyncio
import json
from datetime import timedelta

import httpx
import pytest

from responseforge.api import create_app
from responseforge.integrations.shuffle.callback import CallbackConfig, CallbackTransport
from responseforge.integrations.shuffle.models import ShuffleError
from responseforge.runtime import WorkflowCallback
from tests.rf02.helpers import TOKENS, alert, world
from tests.rf04.helpers import NOW, OTHER_RUN, OTHER_WF, RUN, WF

KEY = "SYNTHETIC_WORKFLOW_CALLBACK_SECRET_NOT_FOR_NETWORK"
RAW_SECRET = "SYNTHETIC_RESPONSE_PRIVATE_SECRET"


def config(**changes):
    return CallbackConfig(
        **(
            {"base_url": "https://core.invalid", "api_key": KEY, "workflow_ids": frozenset({WF})}
            | changes
        )
    )


def callback(**changes):
    return WorkflowCallback.model_validate(
        {
            "run_id": RUN,
            "incident_id": "case-1",
            "workflow_id": WF,
            "correlation_id": "correlation-1",
            "status": "succeeded",
        }
        | changes
    )


def echoed(item=None, **changes):
    item = item or callback()
    return {
        "schema_version": "1.0",
        **item.model_dump(mode="json"),
        "workflow_version": "v1",
        "started_at": NOW.isoformat(),
        "ended_at": (NOW + timedelta(seconds=1)).isoformat(),
    } | changes


def wire(status=200, *, body=None, raw=None, headers=None):
    encoded = (
        raw if raw is not None else json.dumps(body if body is not None else echoed()).encode()
    )
    return httpx.Response(status, stream=httpx.ByteStream(encoded), headers=headers)


def send(handler, item=None, **cfg):
    return asyncio.run(
        CallbackTransport(
            config(**cfg),
            transport=httpx.MockTransport(handler),
            clock=lambda: NOW,
            nonce_factory=lambda: "fixed-test-nonce",
        ).send(item or callback())
    )


def test_valid_callback_uses_fixed_authenticated_wire_and_exact_echo():
    calls = []

    def handler(request):
        calls.append(request)
        return wire()

    result = send(handler)
    assert result.delivery == "accepted"
    assert result.callback == callback()
    assert len(calls) == 1
    request = calls[0]
    assert request.method == "POST"
    assert str(request.url) == "https://core.invalid/v1/integrations/shuffle/callback"
    assert request.headers["Authorization"] == "Bearer " + KEY
    assert request.headers["X-Request-Nonce"] == "fixed-test-nonce"
    assert request.headers["X-Request-Timestamp"] in {
        NOW.isoformat(),
        NOW.isoformat().replace("+00:00", "Z"),
    }
    assert json.loads(request.content) == callback().model_dump(mode="json")


def test_sender_reaches_actual_core_with_workflow_role_and_keeps_case_unchanged(tmp_path):
    w = world(tmp_path / "core.sqlite")
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(intake.incident_id, RUN, WF, "v1", w.actors["analyst"])
    item = callback(incident_id=intake.incident_id, correlation_id=intake.correlation_id)
    client = CallbackTransport(
        config(api_key=TOKENS["workflow"]),
        transport=httpx.ASGITransport(app=create_app(w.settings, clock=w.clock)),
        clock=w.clock,
        nonce_factory=lambda: "core-test-nonce",
    )
    result = asyncio.run(client.send(item))
    assert result.delivery == "accepted"
    assert result.callback == item
    assert w.service.get_incident(intake.incident_id, w.actors["analyst"]).status == "RECEIVED"
    assert w.provider.effect_count == 0


@pytest.mark.parametrize(
    "status,expected",
    [
        (200, "accepted"),
        (401, "rejected"),
        (403, "rejected"),
        (409, "rejected"),
        (422, "rejected"),
        (201, "uncertain"),
        (204, "uncertain"),
        (302, "uncertain"),
        (400, "uncertain"),
        (404, "uncertain"),
        (429, "uncertain"),
        (500, "uncertain"),
        (503, "uncertain"),
    ],
)
def test_statuses_never_cause_automatic_retry(status, expected):
    calls = []

    def handler(request):
        calls.append(request)
        return wire(status, headers={"Location": "https://redirect.invalid/private"})

    result = send(handler)
    assert result.delivery == expected
    assert len(calls) == 1


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectError, httpx.ReadError])
def test_network_errors_are_uncertain_and_not_retried_or_echoed(error, caplog, capsys):
    calls = []

    def handler(request):
        calls.append(request)
        raise error(KEY + RAW_SECRET, request=request)

    result = send(handler)
    assert result.delivery == "uncertain" and len(calls) == 1
    output = repr(result) + result.model_dump_json() + caplog.text + str(capsys.readouterr())
    assert KEY not in output and RAW_SECRET not in output


@pytest.mark.parametrize(
    "changes",
    [
        {"run_id": OTHER_RUN},
        {"incident_id": "other-case"},
        {"workflow_id": OTHER_WF},
        {"correlation_id": "other-correlation"},
        {"status": "failed"},
        {"ended_at": None},
        {"status": "running"},
    ],
)
def test_mismatched_or_nonterminal_echo_is_uncertain(changes):
    assert send(lambda request: wire(body=echoed(**changes))).delivery == "uncertain"


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"broken",
        b'{"status":"succeeded","status":"failed"}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"\xff",
    ],
)
def test_malformed_ambiguous_json_is_never_accepted(raw):
    assert send(lambda request: wire(raw=raw)).delivery == "uncertain"


def test_bare_success_and_raw_secret_body_not_accepted_or_exposed(caplog, capsys):
    result = send(lambda request: wire(body={"success": True, "private": RAW_SECRET}))
    assert result.delivery == "uncertain"
    assert RAW_SECRET not in repr(result) + result.model_dump_json() + caplog.text + str(
        capsys.readouterr()
    )


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Encoding": "gzip"},
        {"Content-Length": "99999999"},
        {"Content-Length": "bad"},
        {"Content-Encoding": "br"},
    ],
)
def test_compressed_or_out_of_bounds_response_is_uncertain(headers):
    assert send(lambda request: wire(headers=headers)).delivery == "uncertain"


def test_exact_response_cap_is_accepted_but_one_byte_over_is_uncertain():
    raw = json.dumps(echoed()).encode()
    assert send(lambda request: wire(raw=raw), max_response_bytes=len(raw)).delivery == "accepted"
    assert (
        send(lambda request: wire(raw=raw), max_response_bytes=len(raw) - 1).delivery == "uncertain"
    )


class SlowStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b"{"
        await asyncio.sleep(0.04)
        yield b'"status":'
        await asyncio.sleep(0.04)
        yield b'"succeeded"}'


def test_total_timeout_bounds_slow_stream_and_sends_once():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=SlowStream())

    async def exercise():
        sender = CallbackTransport(
            config(timeout=0.02), transport=httpx.MockTransport(handler), clock=lambda: NOW
        )
        return await asyncio.wait_for(sender.send(callback()), timeout=0.3)

    result = asyncio.run(exercise())
    assert result.delivery == "uncertain" and len(calls) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"run_id": "not-uuid"},
        {"workflow_id": OTHER_WF},
        {"workflow_id": "00000000-0000-0000-0000-000000000000"},
        {"status": "approved"},
        {"run_id": "33333333-3333-4333-8333-33333333333A"},
        {"extra": RAW_SECRET},
    ],
)
def test_bypassed_invalid_model_never_reaches_transport(changes):
    calls = []
    item = callback().model_copy(update=changes)
    with pytest.raises(ShuffleError) as caught:
        send(lambda request: calls.append(request), item)
    assert caught.value.kind == "invalid" and not calls
    assert RAW_SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "nonce", ["", " ", " leading", "trailing ", "bad\nvalue", "\x7f", "é", "a" * 129]
)
def test_invalid_nonce_rejected_before_io(nonce):
    calls = []
    sender = CallbackTransport(
        config(),
        transport=httpx.MockTransport(lambda req: calls.append(req)),
        clock=lambda: NOW,
        nonce_factory=lambda: nonce,
    )
    with pytest.raises(ShuffleError) as caught:
        asyncio.run(sender.send(callback()))
    assert caught.value.kind == "invalid" and not calls


@pytest.mark.parametrize(
    "clock",
    [
        lambda: NOW.replace(tzinfo=None),
        lambda: NOW.astimezone(__import__("datetime").timezone(timedelta(hours=1))),
        lambda: "bad",
    ],
)
def test_invalid_clock_rejected_before_io(clock):
    calls = []
    sender = CallbackTransport(
        config(), transport=httpx.MockTransport(lambda req: calls.append(req)), clock=clock
    )
    with pytest.raises(ShuffleError) as caught:
        asyncio.run(sender.send(callback()))
    assert caught.value.kind == "invalid" and not calls


@pytest.mark.parametrize(
    "changes",
    [
        {"base_url": "http://core.invalid"},
        {"base_url": "https://user:password@core.invalid"},
        {"base_url": "https://core.invalid/path"},
        {"base_url": "https://core.invalid?key=secret"},
        {"api_key": "short"},
        {"workflow_ids": frozenset({"not-uuid"})},
        {"timeout": float("nan")},
        {"timeout": 0},
        {"timeout": True},
        {"max_response_bytes": 0},
        {"max_response_bytes": 1048577},
        {"allow_loopback_http": "true"},
        {"base_url": "http://localhost", "allow_loopback_http": True},
    ],
)
def test_invalid_configuration_rejected_without_private_values(changes):
    with pytest.raises(ShuffleError) as caught:
        config(**changes)
    assert caught.value.kind == "invalid"
    assert KEY not in str(caught.value) and "password" not in str(caught.value)


def test_loopback_http_requires_explicit_opt_in_and_repr_hides_private_fields():
    with pytest.raises(ShuffleError):
        config(base_url="http://127.0.0.1:8000")
    cfg = config(
        base_url="http://127.0.0.1:8000", allow_loopback_http=True, ca_file="/private/CA.pem"
    )
    assert cfg.base_url == "http://127.0.0.1:8000"
    assert KEY not in repr(cfg) and "127.0.0.1" not in repr(cfg) and "CA.pem" not in repr(cfg)


def test_invalid_ca_never_sends_and_does_not_echo_path_or_secret():
    calls = []
    with pytest.raises(ShuffleError) as caught:
        send(lambda request: calls.append(request), ca_file="/does/not/exist/" + RAW_SECRET)
    assert caught.value.kind == "invalid" and not calls
    assert RAW_SECRET not in str(caught.value)


def test_client_enforces_tls_redirect_and_proxy_settings(monkeypatch):
    original = httpx.AsyncClient
    observed = []

    def client(**kwargs):
        observed.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    monkeypatch.setenv("HTTPS_PROXY", "http://poison.invalid")
    assert send(lambda request: wire()).delivery == "accepted"
    assert len(observed) == 1
    assert observed[0]["verify"] is True
    assert observed[0]["follow_redirects"] is False and observed[0]["trust_env"] is False


def core_setup(tmp_path):
    w = world(tmp_path / "callback-core.sqlite")
    intake = w.service.intake(alert(), w.actors["source"])
    w.service.register_workflow(intake.incident_id, RUN, WF, "v1", w.actors["analyst"])
    item = callback(incident_id=intake.incident_id, correlation_id=intake.correlation_id)
    return w, item


def core_sender(w, *, key=None, clock=None, nonce="core-negative-nonce"):
    return CallbackTransport(
        config(api_key=key or TOKENS["workflow"]),
        transport=httpx.ASGITransport(app=create_app(w.settings, clock=w.clock)),
        clock=clock or w.clock,
        nonce_factory=lambda: nonce,
    )


@pytest.mark.parametrize("key", [KEY, TOKENS["analyst"], TOKENS["source"], TOKENS["approver"]])
def test_actual_core_wrong_key_and_roles_reject_without_case_effect(tmp_path, key):
    w, item = core_setup(tmp_path)
    result = asyncio.run(core_sender(w, key=key).send(item))
    assert result.delivery == "rejected"
    assert w.service.get_incident(item.incident_id, w.actors["analyst"]).status == "RECEIVED"
    assert w.provider.effect_count == 0


def test_actual_core_forged_correlation_does_not_consume_valid_nonce(tmp_path):
    w, item = core_setup(tmp_path)
    sender = core_sender(w)
    forged = item.model_copy(update={"correlation_id": "forged-correlation"})
    assert asyncio.run(sender.send(forged)).delivery == "rejected"
    assert asyncio.run(sender.send(item)).delivery == "accepted"
    assert w.provider.effect_count == 0


def test_actual_core_rejects_expired_timestamp_then_valid_delivery(tmp_path):
    w, item = core_setup(tmp_path)
    old = core_sender(w, clock=lambda: w.clock() - timedelta(seconds=301))
    assert asyncio.run(old.send(item)).delivery == "rejected"
    assert asyncio.run(core_sender(w).send(item)).delivery == "accepted"


def test_actual_core_nonce_replay_rejected_across_restart_and_new_nonce_reconciles(tmp_path):
    w, item = core_setup(tmp_path)
    assert asyncio.run(core_sender(w).send(item)).delivery == "accepted"
    # New app/core/store instances read same SQLite, not sender in-memory suppression.
    restarted = core_sender(w)
    assert asyncio.run(restarted.send(item)).delivery == "rejected"
    assert asyncio.run(core_sender(w, nonce="new-nonce").send(item)).delivery == "accepted"
    conflicting = item.model_copy(update={"status": "failed"})
    assert (
        asyncio.run(core_sender(w, nonce="conflict-nonce").send(conflicting)).delivery == "rejected"
    )
    assert w.provider.effect_count == 0


def test_actual_core_scope_denies_workflow_actor_for_other_endpoint(tmp_path):
    from dataclasses import replace

    from tests.rf02.helpers import principal

    w, item = core_setup(tmp_path)
    credentials = dict(w.settings.credentials)
    credentials[TOKENS["workflow"]] = principal(
        "workflow", endpoint_ids=frozenset({"other-endpoint"})
    )
    w.settings = replace(w.settings, credentials=credentials)
    assert asyncio.run(core_sender(w).send(item)).delivery == "rejected"


def test_default_nonce_is_fresh_and_never_part_of_returned_receipt():
    seen = []

    def handler(request):
        seen.append(request.headers["X-Request-Nonce"])
        return wire()

    sender = CallbackTransport(config(), transport=httpx.MockTransport(handler), clock=lambda: NOW)
    for _ in range(2):
        result = asyncio.run(sender.send(callback()))
        assert result.delivery == "accepted"
        assert seen[-1] not in result.model_dump_json()
    assert len(set(seen)) == 2 and all(20 <= len(nonce) <= 128 for nonce in seen)
