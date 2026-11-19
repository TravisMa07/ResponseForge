"""Actual sender/outbox API behavior with original synthetic delivery streams."""

import hashlib
import json
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from responseforge.integrations.wazuh.security import PreparationError
from responseforge.integrations.wazuh.sender import deliver, load_config, resume
from tests.rf07b.helpers import (
    CORRELATION,
    INCIDENT,
    SOURCE_TOKEN,
    alert_file,
    encoded,
    payload,
    receipt,
    sender_config,
)


def response(code=201, value=None, *, raw=None, headers=None):
    if raw is None:
        raw = json.dumps(receipt(duplicate=code == 200) if value is None else value).encode()
    return httpx.Response(
        code,
        headers={"Content-Type": "application/json"} | (headers or {}),
        stream=httpx.ByteStream(raw),
    )


def saved(config):
    root = Path(config.outbox_dir)
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def delivery_directory(config):
    return next(path for path in Path(config.outbox_dir).iterdir() if path.is_dir())


def test_send_uses_exact_native_bytes_fixed_destination_and_source_credential(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    raw = encoded(
        payload(
            hook_url="https://attacker.invalid",
            api_key="UNTRUSTED",
            command="DO-NOT-RUN",
            approved=True,
        )
    )
    path = alert_file(config, raw)
    calls = []

    def observed(request):
        calls.append(request)
        assert str(request.url) == config.destination and request.method == "POST"
        assert request.content == raw
        assert request.headers["Authorization"] == "Bearer " + SOURCE_TOKEN
        assert request.headers["Content-Type"] == "application/json"
        return response()

    result = deliver(config, path, send=True, transport=httpx.MockTransport(observed))
    assert (
        result.status == "accepted"
        and result.incident_id == INCIDENT
        and result.correlation_id == CORRELATION
    )
    assert result.sha256 == hashlib.sha256(raw).hexdigest() and result.byte_count == len(raw)
    assert result.verified_live is False and len(calls) == 1
    directory = delivery_directory(config)
    assert (directory / "payload.bin").read_bytes() == raw
    assert stat.S_IMODE(Path(config.outbox_dir).stat().st_mode) == 0o700
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in directory.iterdir())


def test_acknowledged_exact_delivery_is_cached_and_dryrun_never_mutates(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    calls = []
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    assert deliver(config, path, send=True, transport=transport).status == "accepted"
    before = saved(config)
    assert deliver(config, path, send=True, transport=transport).status == "cached"
    assert deliver(config, path, transport=transport).status == "dry_run"
    identity = delivery_directory(config).name
    assert resume(config, identity, transport=transport).status == "dry_run"
    assert resume(config, identity, send=True, transport=transport).status == "cached"
    assert saved(config) == before and len(calls) == 1


def test_dryrun_does_not_create_journal_or_send_even_when_enabled(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    result = deliver(
        config,
        path,
        transport=httpx.MockTransport(lambda request: pytest.fail("dry-run performed HTTP")),
    )
    assert result.status == "dry_run" and not Path(config.outbox_dir).exists()


def test_send_requires_enabled_not_just_valid_source(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material)
    with pytest.raises(PreparationError):
        deliver(
            config,
            alert_file(config),
            send=True,
            transport=httpx.MockTransport(lambda r: pytest.fail("disabled send")),
        )
    assert not Path(config.outbox_dir).exists()


@pytest.mark.parametrize("code", [401, 403, 409, 429])
def test_server_rejection_is_preserved_without_automatic_retry(tmp_path, material, code):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    calls = []
    transport = httpx.MockTransport(
        lambda request: (
            calls.append(request),
            response(code, raw=b"SENSITIVE UNTRUSTED SERVER ERROR"),
        )[1]
    )
    first = deliver(config, path, send=True, transport=transport)
    assert first.status == "rejected" and first.incident_id is None
    identity = delivery_directory(config).name
    assert deliver(config, path, send=True, transport=transport).status == "rejected"
    assert resume(config, identity, send=True, transport=transport).status == "rejected"
    assert len(calls) == 1 and "SENSITIVE" not in first.model_dump_json()


def test_operator_can_recover_known_rejection_only_with_explicit_retry_after_token_rotation(
    tmp_path, material
):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    calls = []
    states = [response(401), response(200)]
    transport = httpx.MockTransport(lambda request: (calls.append(request), states.pop(0))[1])
    assert deliver(config, alert_file(config), send=True, transport=transport).status == "rejected"
    identity = delivery_directory(config).name
    Path(config.token_file).write_text("ROTATED_ORIGINAL_TEST_TOKEN_1234567890")
    assert resume(config, identity, retry_rejected=True, transport=transport).status == "dry_run"
    assert resume(config, identity, send=True, transport=transport).status == "rejected"
    result = resume(config, identity, send=True, retry_rejected=True, transport=transport)
    assert result.status == "duplicate" and len(calls) == 2
    assert calls[-1].headers["Authorization"] == "Bearer ROTATED_ORIGINAL_TEST_TOKEN_1234567890"


def test_unknown_ack_retains_original_bytes_after_integrator_file_unlink_and_requires_explicit_resume(
    tmp_path, material
):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    raw = encoded()
    path = alert_file(config, raw)
    calls = []

    def unknown(request):
        calls.append(request)
        raise httpx.ReadTimeout("UNTRUSTED PRIVATE FAILURE TEXT", request=request)

    first = deliver(config, path, send=True, transport=httpx.MockTransport(unknown))
    assert first.status == "uncertain" and len(calls) == 1
    assert "PRIVATE FAILURE" not in first.model_dump_json()
    identity = delivery_directory(config).name
    path.unlink()  # Matches native Integrator cleanup; recovery cannot reread it.
    before = saved(config)
    assert resume(config, identity, transport=httpx.MockTransport(unknown)).status == "dry_run"
    assert (
        resume(config, identity, send=True, transport=httpx.MockTransport(unknown)).status
        == "uncertain"
    )
    assert saved(config) == before and len(calls) == 1

    def recovered(request):
        calls.append(request)
        assert request.content == raw
        return response(200)

    result = resume(
        config, identity, send=True, retry_uncertain=True, transport=httpx.MockTransport(recovered)
    )
    assert result.status == "duplicate" and len(calls) == 2


@pytest.mark.parametrize(
    "code,value,raw,headers",
    [
        (500, None, None, None),
        (302, None, None, {"Location": "https://attacker.invalid"}),
        (201, receipt(duplicate=True), None, None),
        (200, receipt(duplicate=False), None, None),
        (201, {"duplicate": False}, None, None),
        (201, receipt() | {"incident_id": "not-a-UUID"}, None, None),
        (201, receipt() | {"duplicate": "false"}, None, None),
        (201, receipt() | {"secret": "private"}, None, None),
        (201, None, b"not JSON PRIVATE", None),
        (201, None, b'{"duplicate":false,"duplicate":true}', None),
        (201, None, None, {"Content-Encoding": "gzip"}),
        (201, None, None, {"Content-Type": "text/plain"}),
    ],
)
def test_untrusted_or_inconsistent_ack_never_becomes_success(
    tmp_path, material, code, value, raw, headers
):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    calls = []
    transport = httpx.MockTransport(
        lambda request: (calls.append(request), response(code, value, raw=raw, headers=headers))[1]
    )
    result = deliver(config, alert_file(config), send=True, transport=transport)
    assert result.status == "uncertain" and result.incident_id is None and len(calls) == 1
    assert "PRIVATE" not in result.model_dump_json()


def test_response_bound_is_enforced_during_raw_stream_not_after_eager_buffer(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    consumed = []

    class Oversized(httpx.SyncByteStream):
        def __iter__(self):
            for index in range(20):
                consumed.append(index)
                yield b"x" * 4096

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            201, headers={"Content-Type": "application/json"}, stream=Oversized()
        )
    )
    result = deliver(config, alert_file(config), send=True, transport=transport)
    assert result.status == "uncertain" and len(consumed) <= 3


def test_changed_source_bytes_under_same_identity_refuse_before_second_network(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    calls = []
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    deliver(config, path, send=True, transport=transport)
    original = saved(config)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    assert saved(config) == original and len(calls) == 1


def test_changed_destination_or_source_binding_cannot_reuse_old_outbox(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    transport = httpx.MockTransport(lambda request: response())
    deliver(config, alert_file(config), send=True, transport=transport)
    identity = delivery_directory(config).name
    altered = config.model_copy(
        update={"destination": "https://another.lab.invalid/v1/integrations/wazuh/alerts"}
    )
    with pytest.raises(PreparationError):
        resume(altered, identity, send=True, retry_uncertain=True, transport=transport)
    altered_source = config.source.model_copy(update={"manager_id": "another-manager"})
    altered = config.model_copy(update={"source": altered_source})
    with pytest.raises(PreparationError):
        resume(altered, identity, send=True, retry_uncertain=True, transport=transport)


@pytest.mark.parametrize("member", ["payload.bin", "receipt.json"])
def test_tampered_outbox_proof_is_not_repaired_from_current_alert(tmp_path, material, member):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    calls = []
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    deliver(config, path, send=True, transport=transport)
    target = delivery_directory(config) / member
    target.write_bytes(target.read_bytes() + b"TAMPERED")
    before = saved(config)
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    assert saved(config) == before and len(calls) == 1


def test_concurrent_same_delivery_serializes_one_request_and_cached_receipts(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    calls = []
    mutex = threading.Lock()

    def observed(request):
        with mutex:
            calls.append(request)
        time.sleep(0.02)
        return response()

    transport = httpx.MockTransport(observed)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: deliver(config, path, send=True, transport=transport), range(8))
        )
    assert len(calls) == 1 and sum(result.status == "accepted" for result in results) == 1
    assert sum(result.status == "cached" for result in results) == 7


@pytest.mark.parametrize("change", ["outside", "name", "symlink", "writable", "agent"])
def test_unsafe_alert_source_refuses_before_network_or_outbox(tmp_path, material, change):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    if change == "outside":
        outside = tmp_path.resolve() / path.name
        path.rename(outside)
        path = outside
    elif change == "name":
        other = path.with_name("arbitrary-host-file.alert")
        path.rename(other)
        path = other
    elif change == "symlink":
        original = path.with_name("original")
        path.rename(original)
        path.symlink_to(original)
    elif change == "writable":
        path.chmod(0o666)
    else:
        path.write_bytes(encoded(payload(agent={"id": "999", "name": "UNKNOWN"})))
    with pytest.raises(PreparationError):
        deliver(
            config,
            path,
            send=True,
            transport=httpx.MockTransport(lambda request: pytest.fail("unsafe source sent")),
        )
    assert not Path(config.outbox_dir).exists()


def test_private_config_file_loads_without_secret_repr_and_rejects_unsafe_access(
    tmp_path, material
):
    config = sender_config(tmp_path.resolve(), material)
    path = tmp_path.resolve() / "config.json"
    path.write_text(config.model_dump_json())
    path.chmod(0o600)
    assert load_config(path) == config
    assert SOURCE_TOKEN not in repr(load_config(path))
    path.chmod(0o644)
    with pytest.raises(PreparationError):
        load_config(path)


@pytest.mark.parametrize("flag", ["false", 1, None])
def test_truthy_nonboolean_cannot_authorize_send(tmp_path, material, flag):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    with pytest.raises(PreparationError):
        deliver(
            config,
            alert_file(config),
            send=flag,
            transport=httpx.MockTransport(lambda r: pytest.fail("nonboolean send")),
        )


def test_nonsticky_writable_ancestor_cannot_redirect_private_outbox_writes(tmp_path, material):
    public = tmp_path.resolve() / "replaceable-parent"
    public.mkdir(mode=0o777)
    public.chmod(0o777)
    config = sender_config(public / "private-leaf", material, enabled=True)
    path = alert_file(config)
    outside = tmp_path.resolve() / "unrelated-sentinel"
    outside.write_bytes(b"original unrelated material")
    calls = []
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    assert calls == [] and not Path(config.outbox_dir).exists()
    assert outside.read_bytes() == b"original unrelated material"


def test_dispatch_reservation_survives_crash_before_request_and_blocks_blind_retry(
    tmp_path, material, monkeypatch
):
    import responseforge.integrations.wazuh.sender as native

    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    original_save = native._save
    calls = []

    def persisted_then_crash(root, item):
        original_save(root, item)
        if item.state == "dispatching":
            raise OSError("injected crash after durable dispatch reservation")

    monkeypatch.setattr(native, "_save", persisted_then_crash)
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    directory = delivery_directory(config)
    assert json.loads((directory / "receipt.json").read_text())["state"] == "dispatching"
    assert calls == []
    monkeypatch.setattr(native, "_save", original_save)
    assert deliver(config, path, send=True, transport=transport).status == "uncertain"
    path.unlink()
    assert resume(config, directory.name, send=True, transport=transport).status == "uncertain"
    assert calls == []
    assert (
        resume(config, directory.name, send=True, retry_uncertain=True, transport=transport).status
        == "accepted"
    )
    assert len(calls) == 1


def test_lost_ack_persistence_retains_uncertainty_and_explicit_retry_receives_duplicate(
    tmp_path, material, monkeypatch
):
    import responseforge.integrations.wazuh.sender as native

    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    original_save = native._save
    calls = []

    def fail_ack_store(root, item):
        if item.state == "accepted":
            raise OSError("injected failure persisting acknowledged result")
        return original_save(root, item)

    def acknowledged(request):
        calls.append(request)
        return response(201 if len(calls) == 1 else 200)

    transport = httpx.MockTransport(acknowledged)
    monkeypatch.setattr(native, "_save", fail_ack_store)
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    directory = delivery_directory(config)
    assert json.loads((directory / "receipt.json").read_text())["state"] == "dispatching"
    assert len(calls) == 1
    monkeypatch.setattr(native, "_save", original_save)
    assert deliver(config, path, send=True, transport=transport).status == "uncertain"
    assert len(calls) == 1
    result = resume(config, directory.name, send=True, retry_uncertain=True, transport=transport)
    assert result.status == "duplicate" and len(calls) == 2


def test_failure_before_dispatch_reservation_leaves_prepared_not_false_accepted(
    tmp_path, material, monkeypatch
):
    import responseforge.integrations.wazuh.sender as native

    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    original_save = native._save
    calls = []
    monkeypatch.setattr(
        native,
        "_save",
        lambda root, item: (_ for _ in ()).throw(OSError("pre-reservation failure")),
    )
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    directory = delivery_directory(config)
    assert json.loads((directory / "receipt.json").read_text())["state"] == "prepared"
    assert calls == []
    monkeypatch.setattr(native, "_save", original_save)
    assert deliver(config, path, send=True, transport=transport).status == "accepted"
    assert len(calls) == 1


def test_dispatch_is_durable_on_disk_before_http_and_token_never_enters_journal(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    raw = encoded()

    def observe(request):
        directory = delivery_directory(config)
        stored = json.loads((directory / "receipt.json").read_text())
        assert stored["state"] == "dispatching" and stored["result"] is None
        assert (directory / "payload.bin").read_bytes() == raw
        return response()

    assert (
        deliver(
            config, alert_file(config, raw), send=True, transport=httpx.MockTransport(observe)
        ).status
        == "accepted"
    )
    assert SOURCE_TOKEN.encode() not in b"".join(saved(config).values())


def test_unrecognized_outbox_material_and_full_retention_refuse_before_request(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    root = Path(config.outbox_dir)
    root.mkdir(mode=0o700)
    unexpected = root / "original-diagnostic.txt"
    unexpected.write_bytes(b"retain original diagnostic")
    calls = []
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    with pytest.raises(PreparationError):
        deliver(config, alert_file(config), send=True, transport=transport)
    assert unexpected.read_bytes() == b"retain original diagnostic" and calls == []
    unexpected.unlink()
    for index in range(1024):
        (root / format(index, "064x")).mkdir(mode=0o700)
    with pytest.raises(PreparationError):
        deliver(config, alert_file(config), send=True, transport=transport)
    assert len(list(root.glob("[0-9a-f]" * 64))) == 1024 and calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"sha256": "0" * 64},
        {"byte_count": 1},
        {"binding": "0" * 64},
        {"identity": "0" * 64},
        {"state": "prepared"},
        {"result": None},
    ],
)
def test_receipt_internal_scope_and_state_conflicts_fail_closed(tmp_path, material, changes):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    path = alert_file(config)
    calls = []
    transport = httpx.MockTransport(lambda request: (calls.append(request), response())[1])
    deliver(config, path, send=True, transport=transport)
    receipt_path = delivery_directory(config) / "receipt.json"
    original = json.loads(receipt_path.read_text())
    receipt_path.write_text(json.dumps(original | changes))
    before = saved(config)
    with pytest.raises(PreparationError):
        deliver(config, path, send=True, transport=transport)
    assert saved(config) == before and len(calls) == 1


def test_native_wrapper_uses_only_fixed_config_and_first_alert_argument(
    tmp_path, material, monkeypatch, capsys
):
    import responseforge.integrations.wazuh.sender as native

    config = sender_config(tmp_path.resolve(), material)
    source = alert_file(config)
    fixed = tmp_path.resolve() / "fixed-private-config.json"
    observed = []
    monkeypatch.setattr(native, "CONFIG_PATH", fixed)
    monkeypatch.setattr(native, "load_config", lambda path: (observed.append(path), config)[1])
    assert (
        native.integrator_main(
            [
                "custom-responseforge",
                str(source),
                "SENSITIVE-APIKEY",
                "https://attacker.invalid",
                "debug",
                "UNTRUSTED-OPTIONS",
                "999",
                "999",
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert observed == [fixed] and '"status": "dry_run"' in output.out
    assert not output.err and "SENSITIVE" not in output.out and "attacker" not in output.out
    assert not Path(config.outbox_dir).exists()


def test_http_client_policy_keeps_ca_hostname_verification_and_ignores_proxy_environment(
    tmp_path, material, monkeypatch
):
    import ssl

    import responseforge.integrations.wazuh.sender as native

    config = sender_config(tmp_path.resolve(), material, enabled=True)
    real_client = native.httpx.Client
    observed = []

    def client(*args, **kwargs):
        observed.append(kwargs.copy())
        return real_client(*args, **kwargs)

    monkeypatch.setattr(native.httpx, "Client", client)
    monkeypatch.setenv("HTTPS_PROXY", "http://UNTRUSTED-PROXY.invalid:9090")
    result = deliver(
        config,
        alert_file(config),
        send=True,
        transport=httpx.MockTransport(lambda request: response()),
    )
    assert result.status == "accepted" and len(observed) == 1
    options = observed[0]
    assert options["trust_env"] is False and options["follow_redirects"] is False
    assert options["timeout"] == config.timeout
    assert isinstance(options["verify"], ssl.SSLContext)
    assert (
        options["verify"].check_hostname is True
        and options["verify"].verify_mode == ssl.CERT_REQUIRED
    )


@pytest.mark.parametrize(
    "token",
    [
        b"short",
        b"PRIVATE TOKEN WITH SPACES 1234567890",
        b"\xff" * 40,
        b"\n" + SOURCE_TOKEN.encode(),
        b"X" * 600,
    ],
)
def test_invalid_private_credential_refuses_without_network_or_secret_echo(
    tmp_path, material, token
):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    Path(config.token_file).write_bytes(token)
    with pytest.raises(PreparationError) as captured:
        deliver(
            config,
            alert_file(config),
            send=True,
            transport=httpx.MockTransport(lambda request: pytest.fail("invalid token sent")),
        )
    assert "PRIVATE TOKEN" not in str(captured.value)
    assert not Path(config.outbox_dir).exists()


def test_invalid_ca_never_falls_back_to_insecure_verification(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material, enabled=True)
    invalid = tmp_path.resolve() / "invalid-ca.pem"
    invalid.write_text("SYNTHETIC INVALID CA; DO NOT DISCLOSE")
    invalid.chmod(0o600)
    config = config.model_copy(update={"ca_file": str(invalid)})
    with pytest.raises(PreparationError) as captured:
        deliver(
            config,
            alert_file(config),
            send=True,
            transport=httpx.MockTransport(lambda request: pytest.fail("invalid CA bypassed")),
        )
    assert "DO NOT DISCLOSE" not in str(captured.value)
    assert not Path(config.outbox_dir).exists()
