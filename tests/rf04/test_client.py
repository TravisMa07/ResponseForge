"""T01-T07: independent source-derived transport contract, not a real vendor run."""

import asyncio
import json

import httpx
import pytest

from responseforge.integrations.shuffle.client import ShuffleTransport
from responseforge.integrations.shuffle.models import ShuffleError
from tests.rf04.helpers import (
    EXECUTION_SECRET,
    KEY,
    ORG,
    OTHER_RUN,
    OTHER_WF,
    RUN,
    WF,
    argument,
    config,
    execution,
    fingerprint,
    workflow,
)


def wire_response(status, *, json=None, text=None, content=None, headers=None):
    # Model a real unread async response. wire_response(json=...) is already
    # consumed and would exercise a MockTransport setup artifact, not streaming.
    raw = (
        content
        if content is not None
        else (text.encode() if text is not None else __import__("json").dumps(json).encode())
    )
    return httpx.Response(status, stream=httpx.ByteStream(raw), headers=headers)


def test_get_uses_exact_origin_route_bearer_and_safe_projection() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(200, json=workflow())

    value = asyncio.run(
        ShuffleTransport(config(), transport=httpx.MockTransport(handler)).get_workflow(WF)
    )
    assert len(calls) == 1
    assert str(calls[0].url) == f"https://shuffle.invalid/api/v1/workflows/{WF}"
    assert calls[0].method == "GET"
    assert calls[0].headers["Authorization"] == "Bearer " + KEY
    assert calls[0].headers["Org-Id"] == ORG
    assert value.workflow_id == WF and value.action_count == 1
    assert value.sha256 == fingerprint(workflow())
    assert KEY not in repr(config()) and EXECUTION_SECRET not in value.model_dump_json()


def test_valid_but_unallowlisted_workflow_rejected_before_network() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(200, json=workflow(id=OTHER_WF))

    client = ShuffleTransport(config(), transport=httpx.MockTransport(handler))
    with pytest.raises(ShuffleError):
        asyncio.run(client.get_workflow(OTHER_WF))
    assert calls == []


@pytest.mark.parametrize(
    "identifier",
    [
        "../workflows",
        WF + "?key=x",
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        "0" * 36,
        "00000000-0000-0000-0000-000000000000",
        "not-a-uuid",
    ],
)
def test_invalid_workflow_ids_never_reach_network(identifier: str) -> None:
    calls = []
    client = ShuffleTransport(
        config(), transport=httpx.MockTransport(lambda request: calls.append(request))
    )
    with pytest.raises((ValueError, ShuffleError)):
        asyncio.run(client.get_workflow(identifier))
    assert not calls


@pytest.mark.parametrize(
    "changes",
    [
        {"base_url": "http://shuffle.invalid"},
        {"base_url": "http://192.168.1.10", "allow_loopback_http": True},
        {"base_url": "https://user:PRIVATE@shuffle.invalid"},
        {"base_url": "https://shuffle.invalid/base"},
        {"base_url": "https://shuffle.invalid?token=PRIVATE"},
        {"base_url": "https://shuffle.invalid#fragment"},
        {"base_url": "file:///tmp/shuffle"},
        {"timeout": 0},
        {"timeout": float("nan")},
        {"timeout": 61},
        {"read_attempts": 0},
        {"read_attempts": 4},
        {"max_response_bytes": 0},
        {"max_response_bytes": 1048577},
        {"api_key": "short"},
        {"workflow_ids": frozenset({"../bad"})},
    ],
)
def test_insecure_configuration_is_rejected(changes: dict) -> None:
    with pytest.raises((ValueError, ShuffleError)):
        config(**changes)


def test_explicit_literal_loopback_http_is_permitted_without_production_tls_bypass() -> None:
    assert config(base_url="http://127.0.0.1:3001", allow_loopback_http=True).base_url.startswith(
        "http://127."
    )


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 404, 429])
def test_read_redirects_auth_and_client_errors_do_not_retry_or_forward(status: int, caplog) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(
            status, headers={"Location": "https://untrusted.invalid"}, text=KEY + EXECUTION_SECRET
        )

    client = ShuffleTransport(config(), transport=httpx.MockTransport(handler))
    with pytest.raises(ShuffleError) as error:
        asyncio.run(client.get_workflow(WF))
    assert len(calls) == 1
    assert KEY not in str(error.value) + repr(error.value) + caplog.text
    assert EXECUTION_SECRET not in str(error.value) + caplog.text


@pytest.mark.parametrize("fault", ["timeout", "500"])
def test_read_only_retries_are_bounded_and_backoff_is_fixed(fault: str) -> None:
    calls, delays = [], []

    async def sleep(delay):
        delays.append(delay)

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            if fault == "timeout":
                raise httpx.ReadTimeout(KEY, request=request)
            return wire_response(503, text=EXECUTION_SECRET)
        return wire_response(200, json=workflow())

    result = asyncio.run(
        ShuffleTransport(
            config(), transport=httpx.MockTransport(handler), sleep=sleep
        ).get_workflow(WF)
    )
    assert result.workflow_id == WF
    assert len(calls) == 3 and delays == [0.1, 0.2]


def test_read_retry_exhaustion_never_becomes_success() -> None:
    calls = []

    async def sleep(_):
        pass

    def handler(request):
        calls.append(request)
        raise httpx.ConnectError(KEY, request=request)

    with pytest.raises(ShuffleError):
        asyncio.run(
            ShuffleTransport(
                config(read_attempts=2), transport=httpx.MockTransport(handler), sleep=sleep
            ).get_workflow(WF)
        )
    assert len(calls) == 2


def test_start_exact_string_argument_and_discarded_execution_secret() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert body["execution_id"] == RUN
        assert isinstance(body["execution_argument"], str)
        assert json.loads(body["execution_argument"]) == argument().model_dump(mode="json")
        assert body["execution_source"] == "responseforge"
        return wire_response(
            200,
            json={
                "success": True,
                "execution_id": RUN,
                "authorization": EXECUTION_SECRET,
                "raw": KEY,
            },
        )

    result = asyncio.run(
        ShuffleTransport(config(), transport=httpx.MockTransport(handler)).start_execution(
            WF, RUN, argument()
        )
    )
    assert len(calls) == 1 and calls[0].method == "POST"
    assert calls[0].url.path == f"/api/v1/workflows/{WF}/execute"
    assert result.accepted is True and result.execution_id == RUN and result.workflow_id == WF
    assert EXECUTION_SECRET not in result.model_dump_json() and KEY not in result.model_dump_json()


@pytest.mark.parametrize("reply", ["timeout", "500", "malformed", "false", "mismatch", "truthy"])
def test_mutating_start_never_retries_ambiguous_failure(reply: str) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        if reply == "timeout":
            raise httpx.ReadTimeout(KEY, request=request)
        if reply == "500":
            return wire_response(500, text=EXECUTION_SECRET)
        if reply == "malformed":
            return wire_response(200, text="{" + KEY)
        return wire_response(
            200,
            json={
                "success": "true" if reply == "truthy" else reply != "false",
                "execution_id": OTHER_RUN if reply == "mismatch" else RUN,
                "authorization": EXECUTION_SECRET,
            },
        )

    with pytest.raises(ShuffleError) as error:
        asyncio.run(
            ShuffleTransport(config(), transport=httpx.MockTransport(handler)).start_execution(
                WF, RUN, argument()
            )
        )
    assert len(calls) == 1 and error.value.kind == "uncertain"
    assert KEY not in str(error.value) and EXECUTION_SECRET not in str(error.value)


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_start_rejections_are_not_success_or_retry(status: int) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(status, text=KEY)

    with pytest.raises(ShuffleError) as error:
        asyncio.run(
            ShuffleTransport(config(), transport=httpx.MockTransport(handler)).start_execution(
                WF, RUN, argument()
            )
        )
    assert len(calls) == 1 and error.value.kind == "rejected"


def test_argument_must_match_reserved_execution_before_network() -> None:
    calls = []
    client = ShuffleTransport(
        config(), transport=httpx.MockTransport(lambda request: calls.append(request))
    )
    with pytest.raises((ValueError, ShuffleError)):
        asyncio.run(client.start_execution(WF, RUN, argument(run_id=OTHER_RUN)))
    assert not calls


def test_specific_lookup_uses_api_bearer_without_execution_secret_and_whitelists_status() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        assert json.loads(request.content) == {"execution_id": RUN}
        assert request.headers["Authorization"] == "Bearer " + KEY
        return wire_response(200, json=execution())

    result = asyncio.run(
        ShuffleTransport(config(), transport=httpx.MockTransport(handler)).get_execution(
            WF, RUN, argument()
        )
    )
    assert calls[0].url.path == "/api/v1/streams/results" and calls[0].method == "POST"
    assert result.vendor_status == "FINISHED"
    assert not hasattr(result, "verified_live")
    assert (
        EXECUTION_SECRET not in result.model_dump_json()
        and "PRIVATE_RESULT" not in result.model_dump_json()
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"execution_id": OTHER_RUN},
        {"workflow_id": OTHER_WF},
        {"workflow": {"id": OTHER_WF}},
        {"execution_argument": "not-json"},
        {"execution_argument": json.dumps({"incident_id": "different-case"})},
        {"execution_argument": argument(correlation_id="different").model_dump_json()},
        {"status": "MYSTERY"},
    ],
)
def test_lookup_correlation_and_unknown_status_fail_closed(changes: dict) -> None:
    client = ShuffleTransport(
        config(),
        transport=httpx.MockTransport(
            lambda request: wire_response(200, json=execution(**changes))
        ),
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.get_execution(WF, RUN, argument()))


@pytest.mark.parametrize("raw", [b"[]", b"null", b'{"id":NaN}', b'{"id":Infinity}', b"x" * 513])
def test_response_size_and_json_shape_are_bounded(raw: bytes) -> None:
    client = ShuffleTransport(
        config(max_response_bytes=512),
        transport=httpx.MockTransport(lambda request: wire_response(200, content=raw)),
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.get_workflow(WF))


def test_create_accepts_server_generated_id_once_and_no_credential_payload_is_returned() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        return wire_response(200, json=workflow(id=OTHER_WF))

    result = asyncio.run(
        ShuffleTransport(config(), transport=httpx.MockTransport(handler)).create_workflow(
            workflow()
        )
    )
    assert len(calls) == 1 and calls[0].url.path == "/api/v1/workflows"
    assert result.workflow_id == OTHER_WF and EXECUTION_SECRET not in result.model_dump_json()


@pytest.mark.parametrize("fault", ["timeout", "500", "bad"])
def test_create_ambiguous_result_is_once_only(fault: str) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        if fault == "timeout":
            raise httpx.ReadTimeout(KEY, request=request)
        return wire_response(500 if fault == "500" else 200, text="not-json")

    with pytest.raises(ShuffleError):
        asyncio.run(
            ShuffleTransport(config(), transport=httpx.MockTransport(handler)).create_workflow(
                workflow()
            )
        )
    assert len(calls) == 1


def test_slow_drip_read_has_total_attempt_deadline_and_bounded_retries() -> None:
    calls = []

    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.Event().wait()
            yield b"never"

    async def no_sleep(_):
        pass

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=SlowStream())

    client = ShuffleTransport(
        config(timeout=0.01, read_attempts=2),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.get_workflow(WF))
    assert len(calls) == 2


def test_duplicate_members_inside_execution_argument_are_not_accepted() -> None:
    raw = argument().model_dump_json()
    # A last-value-wins parser would yield exactly the expected object.
    duplicate = '{"correlation_id":"forged",' + raw[1:]
    client = ShuffleTransport(
        config(),
        transport=httpx.MockTransport(
            lambda request: wire_response(200, json=execution(execution_argument=duplicate))
        ),
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.get_execution(WF, RUN, argument()))


def test_unexpected_compression_is_refused_without_parsing_unbounded_expansion() -> None:
    client = ShuffleTransport(
        config(),
        transport=httpx.MockTransport(
            lambda request: wire_response(
                200, content=b"not-decoded", headers={"content-encoding": "gzip"}
            )
        ),
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.get_workflow(WF))


def test_empty_import_actions_reject_before_any_mutating_request() -> None:
    calls = []
    client = ShuffleTransport(
        config(), transport=httpx.MockTransport(lambda request: calls.append(request))
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.create_workflow(workflow(actions=[])))
    assert not calls


def test_invalid_private_ca_configuration_fails_before_request_without_path_leak(tmp_path) -> None:
    path = tmp_path / "PRIVATE_CA_PATH"
    path.write_text("not a certificate")
    calls = []
    client = ShuffleTransport(
        config(ca_file=path), transport=httpx.MockTransport(lambda request: calls.append(request))
    )
    with pytest.raises(ShuffleError) as error:
        asyncio.run(client.get_workflow(WF))
    assert not calls
    assert "PRIVATE_CA_PATH" not in str(error.value)


def test_invalid_execution_identity_and_bypassed_argument_do_not_reach_network() -> None:
    calls = []
    client = ShuffleTransport(
        config(), transport=httpx.MockTransport(lambda request: calls.append(request))
    )
    with pytest.raises(ShuffleError):
        asyncio.run(client.start_execution(WF, "../execute", argument()))
    with pytest.raises(ShuffleError):
        asyncio.run(
            client.start_execution(WF, RUN, argument().model_copy(update={"mode": "arbitrary"}))
        )
    assert not calls


def test_configuration_repr_omits_private_origin_ca_path_and_api_key(tmp_path) -> None:
    private_origin = "https://PRIVATE-QUALIFICATION-HOST.invalid"
    private_ca = tmp_path / "PRIVATE-TRUST-ANCHOR.pem"
    value = config(base_url=private_origin, ca_file=private_ca)
    shown = repr(value)
    assert private_origin not in shown
    assert str(private_ca) not in shown
    assert KEY not in shown


def test_low_level_lookup_exposes_only_verified_graph_digest_when_snapshot_is_complete() -> None:
    full = execution(workflow=workflow())
    client = ShuffleTransport(
        config(), transport=httpx.MockTransport(lambda request: wire_response(200, json=full))
    )
    value = asyncio.run(client.get_execution(WF, RUN, argument()))
    assert value.workflow_sha256 == fingerprint(workflow())
    assert EXECUTION_SECRET not in value.model_dump_json()
    minimal = ShuffleTransport(
        config(),
        transport=httpx.MockTransport(lambda request: wire_response(200, json=execution())),
    )
    unqualified = asyncio.run(minimal.get_execution(WF, RUN, argument()))
    assert unqualified.workflow_sha256 is None
