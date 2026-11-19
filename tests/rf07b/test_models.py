"""Operator configuration cannot silently widen authority or weaken defaults."""

import pytest

from responseforge.integrations.wazuh.preparation_models import (
    DeploymentTarget,
    SenderResult,
)
from tests.rf07b.helpers import CORRELATION, INCIDENT, sender_config, windows_config


@pytest.mark.parametrize(
    "destination",
    [
        "http://rf-core.lab.invalid/v1/integrations/wazuh/alerts",
        "https://user:secret@rf-core.lab.invalid/v1/integrations/wazuh/alerts",
        "https://rf-core.lab.invalid/v1/alerts",
        "https://rf-core.lab.invalid/v1/integrations/wazuh/alerts?token=bad",
        "https://rf-core.lab.invalid/v1/integrations/wazuh/alerts#fragment",
        "file:///tmp/private",
        "https://rf-core.lab.invalid/v1/integrations/wazuh/alerts\n",
        "https://0.0.0.0/v1/integrations/wazuh/alerts",
        "https://224.0.0.1/v1/integrations/wazuh/alerts",
        "https://8.8.8.8/v1/integrations/wazuh/alerts",
    ],
)
def test_sender_destination_is_fixed_verified_private_https(tmp_path, material, destination):
    with pytest.raises(ValueError):
        sender_config(tmp_path.resolve(), material, destination=destination)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), 0, -1, 0.099, 30.001])
def test_timeout_is_positive_finite_and_bounded(tmp_path, material, timeout):
    with pytest.raises(ValueError):
        sender_config(tmp_path.resolve(), material, timeout=timeout)


@pytest.mark.parametrize(
    "change",
    [
        {"enabled": "true"},
        {"alert_uid": True},
        {"alert_uid": -1},
        {"token_file": "relative"},
        {"alert_root": "/tmp/../etc"},
        {"outbox_dir": "/tmp/out\nbox"},
    ],
)
def test_sender_flags_uid_and_paths_do_not_coerce_or_escape(tmp_path, material, change):
    with pytest.raises(ValueError):
        sender_config(tmp_path.resolve(), material, **change)


@pytest.mark.parametrize(
    "ip,subnet,authorized",
    [
        ("0.0.0.0", None, False),
        ("192.168.77.10", "192.168.77.0/24", False),
        ("192.168.77.10", None, True),
        ("192.168.77.10", "192.168.78.0/24", True),
        ("192.168.77.0", "192.168.77.0/24", True),
        ("192.168.77.255", "192.168.77.0/24", True),
        ("8.8.8.8", "8.8.8.0/24", True),
        ("192.168.77.10", "0.0.0.0/0", True),
        ("::1", None, True),
    ],
)
def test_nonloopback_publication_needs_exact_independent_lab_scope(ip, subnet, authorized):
    with pytest.raises(ValueError):
        DeploymentTarget(
            architecture="arm64",
            kind="docker-desktop",
            manager_id="test-manager",
            endpoint_bind_ip=ip,
            lab_subnet=subnet,
            endpoint_publish_authorized=authorized,
        )


def test_loopback_default_and_explicit_private_target_do_not_claim_authorization():
    default = DeploymentTarget(
        architecture="arm64", kind="docker-desktop", manager_id="test-manager"
    )
    assert default.endpoint_bind_ip == "127.0.0.1" and default.endpoint_publish_authorized is False
    explicit = DeploymentTarget(
        architecture="amd64",
        kind="dedicated-vm",
        manager_id="test-manager",
        endpoint_bind_ip="192.168.77.10",
        lab_subnet="192.168.77.0/24",
        endpoint_publish_authorized=True,
    )
    assert explicit.endpoint_bind_ip == "192.168.77.10"


@pytest.mark.parametrize(
    "changes",
    [
        {"target_machine": "bad;cmd"},
        {"target_machine": "A" * 16},
        {"agent_name": 'quoted"name'},
        {"manager_host": "https://manager.invalid"},
        {"manager_host": "manager.invalid;cmd"},
        {"manager_host": "manager.invalid:1515"},
        {"signer_thumbprint": "A" * 39},
        {"signer_thumbprint": "a" * 40},
        {"signer_subject": "CN=bad\nsubject"},
        {"signer_subject": ""},
    ],
)
def test_windows_trust_and_target_are_explicit_data_not_commands(material, changes):
    with pytest.raises(ValueError):
        windows_config(material, **changes)


@pytest.mark.parametrize("status", ["accepted", "duplicate", "cached"])
def test_acknowledged_results_require_canonical_uuid_identities(status):
    good = SenderResult(
        status=status,
        sha256="a" * 64,
        byte_count=1,
        incident_id=INCIDENT,
        correlation_id=CORRELATION,
    )
    assert good.verified_live is False
    for fields in (
        {"incident_id": "secret-like-untrusted-output"},
        {"incident_id": None},
        {"correlation_id": "BAD"},
        {"correlation_id": None},
    ):
        with pytest.raises(ValueError):
            SenderResult.model_validate(good.model_dump() | fields)


@pytest.mark.parametrize("status", ["dry_run", "uncertain", "rejected"])
def test_unacknowledged_results_cannot_invent_ids_or_live_verification(status):
    with pytest.raises(ValueError):
        SenderResult(
            status=status,
            sha256="a" * 64,
            byte_count=1,
            incident_id=INCIDENT,
            correlation_id=CORRELATION,
        )
    with pytest.raises(ValueError):
        SenderResult(status=status, sha256="a" * 64, byte_count=1, verified_live=True)
