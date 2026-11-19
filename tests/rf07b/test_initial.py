"""Initial valid behavior reds against importable unavailable implementations."""

import json
from pathlib import Path

import httpx
import pytest

from responseforge.integrations.wazuh.deployment import build_plan
from responseforge.integrations.wazuh.preparation_models import DeploymentTarget
from responseforge.integrations.wazuh.sender import deliver
from responseforge.integrations.wazuh.windows import prepare_windows
from tests.rf07b.helpers import alert_file, sender_config, windows_config


def test_valid_sender_defaults_to_readonly_dry_run(tmp_path, material):
    config = sender_config(tmp_path.resolve(), material)
    alert = alert_file(config)
    result = deliver(
        config,
        alert,
        transport=httpx.MockTransport(lambda request: pytest.fail("dry-run made HTTP request")),
    )
    assert result.status == "dry_run" and result.verified_live is False
    assert not Path(config.outbox_dir).exists()


def test_valid_upstream_profile_is_rendered_but_never_runtime_ready():
    lock = json.loads(Path("deploy/wazuh/images.lock.json").read_text())
    result = build_plan(
        DeploymentTarget(
            architecture="arm64", kind="docker-desktop", manager_id="synthetic-manager"
        ),
        lock,
    )
    assert result.ready is False and result.runtime_qualified is False
    assert len(result.compose["services"]) == 3
    assert result.blockers and result.source_requirements


def test_valid_private_windows_bundle_is_prepared_without_installing(tmp_path, material):
    output = tmp_path.resolve() / "bundle"
    prepare_windows(windows_config(material), output)
    assert output.is_dir()
    assert {path.name for path in output.iterdir()} == {
        "bundle.json",
        "Install.ps1",
        "root-ca.pem",
        "agent-cert.pem",
        "agent-key.pem",
    }
    assert json.loads((output / "bundle.json").read_text())["verified_live"] is False
