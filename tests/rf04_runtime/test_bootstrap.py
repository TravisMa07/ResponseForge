"""Private bootstrap tests use local cryptographic tools only, never Docker/network."""

import json
import shutil
import ssl
import stat
import subprocess
from pathlib import Path

import pytest

from responseforge.integrations.shuffle.operations import initialize
from tests.rf04_runtime.test_deployment import images


def initialize_state(path: Path, **changes):
    return initialize(
        path,
        images(),
        **(
            {
                "context": "reviewed-desktop",
                "engine_id": "synthetic-reviewed-daemon",
                "architecture": "arm64",
            }
            | changes
        ),
    )


def test_bootstrap_does_not_overwrite_existing_state_or_follow_symlinks(tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "private-marker"
    marker.write_text("preserve-existing-private-state")
    link = tmp_path / "link"
    link.symlink_to(existing, target_is_directory=True)
    for path in (existing, link, link / "new-state"):
        with pytest.raises(ValueError):
            initialize_state(path)
        assert marker.read_text() == "preserve-existing-private-state"
        assert not (existing / "new-state").exists()
        assert not (existing / "secrets.env").exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"context": "--host"},
        {"context": "bad\ncontext"},
        {"engine_id": ""},
        {"architecture": "not-a-platform"},
        {"authorized": "true"},
    ],
)
def test_bootstrap_invalid_binding_rejected_before_local_tools(
    tmp_path: Path, monkeypatch, changes
):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    with pytest.raises(ValueError):
        initialize_state(tmp_path / "state", **changes)
    assert calls == [] and not (tmp_path / "state").exists()


@pytest.mark.skipif(
    not shutil.which("openssl") or not shutil.which("htpasswd"),
    reason="Local openssl and htpasswd required for certificate/bootstrap qualification",
)
def test_actual_private_credentials_certificates_and_san_bootstrap(
    tmp_path: Path, monkeypatch, capsys
):
    calls = []
    original = subprocess.run

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.chdir(tmp_path)
    state = tmp_path / "state"
    initialize_state(state)
    assert set(tmp_path.iterdir()) == {state}, "Bootstrap wrote an artifact outside private state"
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "pki").stat().st_mode) == 0o700
    for name in ("secrets.env", "runtime.json", "pki/ca-key.pem"):
        assert stat.S_IMODE((state / name).stat().st_mode) == 0o600
    runtime = json.loads((state / "runtime.json").read_text())
    assert runtime["authorized"] is False
    assert runtime["images"] == images()
    core = json.loads((state / "core.json").read_text())
    assert len(core["credentials"]) == 5
    assert {tuple(value["roles"]) for value in core["credentials"].values()} == {
        (role,) for role in ("source", "analyst", "approver", "executor", "workflow")
    }
    assert len(set(core["credentials"])) == 5
    assert all(len(value) >= 36 for value in core["credentials"])
    callback = json.loads((state / "callback.json").read_text())
    workflow = next(
        token for token, value in core["credentials"].items() if value["roles"] == ["workflow"]
    )
    assert callback["api_key"] == workflow
    assert callback["base_url"] == "https://responseforge-core:8000"
    assert callback["workflow_ids"] == []  # Only reviewed imported workflows may be added later.
    assert core["mode"] == "replay"
    assert core["database_path"].startswith("/var/lib/responseforge/")
    env = dict(line.split("=", 1) for line in (state / "secrets.env").read_text().splitlines())
    secrets = set(core["credentials"]) | {
        env[name]
        for name in (
            "SHUFFLE_DEFAULT_PASSWORD",
            "SHUFFLE_DEFAULT_APIKEY",
            "SHUFFLE_OPENSEARCH_PASSWORD",
            "SHUFFLE_ENCRYPTION_MODIFIER",
            "RF_QUEUE_TOKEN",
        )
    }
    assert len(secrets) == 10
    assert env["RF_QUEUE_TOKEN"] == env["AUTH"]
    assert env["SHUFFLE_OPENSEARCH_PASSWORD"] not in (state / "internal_users.yml").read_text()
    public_plan = (state / "compose.json").read_text()
    command_arguments = str([argv for argv, kwargs in calls])
    output = str(capsys.readouterr())
    assert all(secret not in public_plan + command_arguments + output for secret in secrets)
    assert any(Path(argv[0]).name == "htpasswd" and kwargs.get("input") for argv, kwargs in calls)
    for name, expected_dns in (
        ("frontend", "shuffle-frontend"),
        ("core", "responseforge-core"),
        ("opensearch", "shuffle-opensearch"),
    ):
        certificate = ssl._ssl._test_decode_cert(str(state / "pki" / (name + ".pem")))
        assert ("DNS", expected_dns) in certificate["subjectAltName"]
        if name != "opensearch":
            assert ("DNS", "localhost") in certificate["subjectAltName"]
            assert ("IP Address", "127.0.0.1") in certificate["subjectAltName"]
        verified = original(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(state / "pki/ca.pem"),
                str(state / "pki" / (name + ".pem")),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert verified.returncode == 0
    # A real TLS handshake over in-memory BIOs, without a listener/network.
    client_context = ssl.create_default_context(cafile=str(state / "pki/ca.pem"))
    client_context.verify_flags |= ssl.VERIFY_X509_STRICT
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(state / "pki/core.pem"), str(state / "pki/core-key.pem"))
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname="responseforge-core")
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    complete = set()
    for _ in range(20):
        for name, connection in (("client", client), ("server", server)):
            try:
                connection.do_handshake()
                complete.add(name)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        if client_out.pending:
            server_in.write(client_out.read())
        if server_out.pending:
            client_in.write(server_out.read())
        if len(complete) == 2:
            break
    assert complete == {"client", "server"}
