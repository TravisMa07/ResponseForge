"""Preparation commands make no implicit manager, network or endpoint action."""

import json
from pathlib import Path

import pytest

from scripts.wazuh_prepare import main
from tests.rf07b.helpers import SOURCE_TOKEN, alert_file, sender_config, windows_config


def config_file(path, value):
    path.write_text(value.model_dump_json())
    path.chmod(0o600)
    return path


def test_deliver_command_defaults_to_dryrun_without_printing_private_fields(
    tmp_path, material, capsys
):
    root = tmp_path.resolve()
    config = sender_config(root, material, enabled=True)
    private = config_file(root / "sender.json", config)
    path = alert_file(config)
    assert main(["deliver", "--config", str(private), "--alert", str(path)]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result == {"status": "dry_run", "verified_live": False}
    assert SOURCE_TOKEN not in captured.out and config.destination not in captured.out
    assert not Path(config.outbox_dir).exists() and not captured.err


def test_fetch_command_requires_explicit_opt_in_and_never_creates_false_artifact(tmp_path, capsys):
    output = tmp_path.resolve() / "must-not-be-fetched"
    with pytest.raises(SystemExit) as captured:
        main(["fetch-msi", "--output", str(output)])
    assert captured.value.code == 2 and not output.exists()
    text = capsys.readouterr()
    assert "No live fallback" in text.err and "acquired_and_hash_verified" not in text.out


def test_plan_command_writes_only_new_private_blocked_plan(tmp_path, capsys):
    root = tmp_path.resolve()
    target = root / "target.json"
    target.write_text(
        json.dumps(
            {"architecture": "arm64", "kind": "docker-desktop", "manager_id": "synthetic-manager"}
        )
    )
    target.chmod(0o600)
    output = root / "plan.json"
    assert main(["plan", "--target", str(target), "--output", str(output)]) == 0
    actual = json.loads(output.read_text())
    summary = json.loads(capsys.readouterr().out)
    assert actual["ready"] is False and actual["runtime_qualified"] is False
    assert summary == {"prepared": True, "ready": False, "runtime_qualified": False}
    before = output.read_bytes()
    with pytest.raises(SystemExit):
        main(["plan", "--target", str(target), "--output", str(output)])
    assert output.read_bytes() == before


def test_windows_command_prepares_private_artifacts_without_claiming_native_execution(
    tmp_path, material, capsys
):
    root = tmp_path.resolve()
    private = config_file(root / "windows.json", windows_config(material))
    output = root / "bundle"
    assert main(["windows-bundle", "--config", str(private), "--output", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["prepared"] is True and result["msi_included"] is False
    assert (
        result["enrolled"]
        is result["verified_live"]
        is result["windows_runtime_qualified"]
        is False
    )
    assert {p.name for p in output.iterdir()} == {
        "Install.ps1",
        "bundle.json",
        "root-ca.pem",
        "agent-cert.pem",
        "agent-key.pem",
    }


def test_private_config_error_omits_content_and_commandlike_source_text(tmp_path, capsys):
    root = tmp_path.resolve()
    private = root / "malformed.json"
    private.write_text('{"secret":"SYNTHETIC-SECRET-CONTENT", malformed')
    private.chmod(0o600)
    with pytest.raises(SystemExit) as captured:
        main(["deliver", "--config", str(private), "--alert", str(root / "no-alert")])
    output = capsys.readouterr()
    assert captured.value.code == 2
    assert "SYNTHETIC-SECRET-CONTENT" not in output.out + output.err
