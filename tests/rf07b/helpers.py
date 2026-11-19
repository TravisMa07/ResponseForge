"""Original synthetic source and ephemeral test TLS materials; never endpoint proof."""

import json
import os
import subprocess
from pathlib import Path

from responseforge.contracts import EndpointRef
from responseforge.integrations.wazuh.models import WazuhAgentBinding, WazuhConfig
from responseforge.integrations.wazuh.preparation_models import SenderConfig, WindowsBundleConfig

SOURCE_TOKEN = "RF07B_TEST_ONLY_SOURCE_TOKEN_1234567890"
INCIDENT = "11111111-1111-4111-8111-111111111111"
CORRELATION = "22222222-2222-4222-8222-222222222222"
ENDPOINT = EndpointRef(endpoint_id="synthetic-win", hostname="RF07-WIN", agent_id="001")


def source_config():
    return WazuhConfig(
        manager_id="synthetic-manager",
        source_actor_id="synthetic-source",
        agents=(WazuhAgentBinding(agent_id="001", endpoint=ENDPOINT),),
    )


def payload(**changes):
    value = {
        "id": "1770120916.123",
        "timestamp": "2026-02-03T14:15:16.123+0200",
        "agent": {"id": "001", "name": "RF07-WIN"},
        "rule": {"id": "550", "level": 7},
        "full_log": "ORIGINAL SYNTHETIC INERT COMMAND; NEVER EXECUTE",
    }
    value.update(changes)
    return value


def encoded(value=None):
    return (
        json.dumps(payload() if value is None else value, separators=(",", ":")) + "\n"
    ).encode()


def receipt(*, duplicate=False):
    return {
        "schema_version": "1.0",
        "incident_id": INCIDENT,
        "correlation_id": CORRELATION,
        "duplicate": duplicate,
    }


def make_material(root: Path):
    root.mkdir(mode=0o700, parents=True)
    ca_key, ca, key, csr, cert = (
        root / name for name in ("ca.key", "ca.pem", "agent.key", "agent.csr", "agent.pem")
    )
    config = root / "ca.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=RF07B ORIGINAL TEST CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
    )
    extension = root / "agent.ext"
    extension.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n"
    )
    commands = [
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-config",
            str(config),
            "-keyout",
            str(ca_key),
            "-out",
            str(ca),
        ],
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=RF07B ORIGINAL TEST AGENT",
            "-keyout",
            str(key),
            "-out",
            str(csr),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(extension),
            "-out",
            str(cert),
        ],
    ]
    for command in commands:
        subprocess.run(
            command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
        )
    for path in (ca_key, key):
        path.chmod(0o600)
    return ca, cert, key


def sender_config(root: Path, material, **changes):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    alert_root = root / "alerts"
    alert_root.mkdir(mode=0o700, exist_ok=True)
    token = root / "token"
    token.write_text(SOURCE_TOKEN)
    token.chmod(0o600)
    ca, _, _ = material
    value = dict(
        destination="https://rf-core.lab.invalid/v1/integrations/wazuh/alerts",
        ca_file=str(ca),
        token_file=str(token),
        alert_root=str(alert_root),
        alert_uid=os.geteuid(),
        outbox_dir=str(root / "outbox"),
        source=source_config(),
    )
    value.update(changes)
    return SenderConfig(**value)


def alert_file(config, raw=None, suffix="1"):
    path = Path(config.alert_root) / ("custom-responseforge-1770120916-" + suffix + ".alert")
    path.write_bytes(encoded() if raw is None else raw)
    path.chmod(0o600)
    return path


def windows_config(material, **changes):
    ca, cert, key = material
    value = dict(
        target_machine="RF07-WIN",
        agent_name="RF07-WIN",
        manager_host="10.77.0.10",
        signer_subject="CN=INDEPENDENT TEST PUBLISHER",
        signer_thumbprint="A" * 40,
        ca_file=str(ca),
        agent_certificate_file=str(cert),
        agent_key_file=str(key),
    )
    value.update(changes)
    return WindowsBundleConfig(**value)
