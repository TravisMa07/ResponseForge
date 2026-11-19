"""Immutable source-derived planning stays blocked; no daemon is contacted."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from responseforge.integrations.wazuh.deployment import build_plan
from responseforge.integrations.wazuh.preparation_models import DeploymentTarget
from responseforge.integrations.wazuh.security import PreparationError

PINNED = {
    "arm64": {
        "wazuh/wazuh-manager@sha256:471628c2e47cf56d227c170516e7ba89e5aee55bd9fef831384146af0c3ab2e4",
        "wazuh/wazuh-indexer@sha256:407d511477f65cf4d57cc9a0928232c52096baa254dd24032dde3bb92d4149ba",
        "wazuh/wazuh-dashboard@sha256:83560991be21e1cc50f396bd2c8281f903b9a6a33918632057294b2300cfea65",
    },
    "amd64": {
        "wazuh/wazuh-manager@sha256:beda27e1e88bfe5fe5e882eea3b006dfc4a77e19f31d5a0292e5126f23900e75",
        "wazuh/wazuh-indexer@sha256:1780a13d5950deda05860fdb2e2d6cc466a15b341a88de01452d99932e05f610",
        "wazuh/wazuh-dashboard@sha256:2987776f76cbf3d47452a51b0e59792453686e5d37bbff7768ec033987b073a0",
    },
}


def lock():
    return json.loads(Path("deploy/wazuh/images.lock.json").read_text())


def target(**changes):
    return DeploymentTarget(
        architecture="arm64", kind="docker-desktop", manager_id="synthetic-manager", **changes
    )


def published_binding(value):
    if isinstance(value, str):
        host, published, container = value.rsplit(":", 2)
        return host, int(published), int(container.split("/")[0])
    return value["host_ip"], int(value["published"]), int(value["target"])


@pytest.mark.parametrize("architecture", ["arm64", "amd64"])
def test_exact_platform_manifest_and_mandatory_runtime_profile(architecture):
    plan = build_plan(
        DeploymentTarget(
            architecture=architecture, kind="dedicated-vm", manager_id="synthetic-manager"
        ),
        lock(),
    )
    services = plan.compose["services"]
    assert {value["image"] for value in services.values()} == PINNED[architecture]
    assert all(value["platform"] == "linux/" + architecture for value in services.values())
    assert all("rf07-runtime-unqualified" in value["profiles"] for value in services.values())
    assert plan.ready is False and plan.runtime_qualified is False
    assert plan.blockers and plan.source_requirements
    blockers = " ".join(plan.blockers).lower()
    assert "tls" in blockers and "runtime" in blockers and "credential" in blockers
    assert "dashboard" in blockers and ("patch" in blockers or "source" in blockers)


def test_default_ports_are_fully_loopback_and_management_ports_do_not_reuse_shuffle():
    plan = build_plan(target(), lock())
    ports = [
        published_binding(port)
        for service in plan.compose["services"].values()
        for port in service.get("ports", [])
    ]
    assert all(host == "127.0.0.1" for host, _, _ in ports)
    assert {(published, container) for _, published, container in ports} == {
        (1514, 1514),
        (1515, 1515),
        (55001, 55000),
        (9201, 9200),
        (9443, 5601),
    }


def test_explicit_lab_endpoint_binding_does_not_widen_management():
    plan = build_plan(
        target(
            endpoint_bind_ip="192.168.77.10",
            lab_subnet="192.168.77.0/24",
            endpoint_publish_authorized=True,
        ),
        lock(),
    )
    for service in plan.compose["services"].values():
        for value in service.get("ports", []):
            host, published, _ = published_binding(value)
            assert host == ("192.168.77.10" if published in {1514, 1515} else "127.0.0.1")
    assert plan.ready is False


def test_planning_has_no_socket_privilege_host_sysctl_or_stock_secret():
    plan = build_plan(target(), lock())
    for service in plan.compose["services"].values():
        assert not service.get("privileged", False)
        assert service.get("network_mode") != "host" and service.get("pid") != "host"
        assert not service.get("sysctls") and not service.get("devices")
        assert "docker.sock" not in json.dumps(service.get("volumes", []))
        assert "SecretPassword" not in json.dumps(service) and "MyS3cr37P450r" not in json.dumps(
            service
        )
        env = service.get("environment", {})
        if isinstance(env, dict):
            assert all(
                value != "kibanaserver" for key, value in env.items() if "PASSWORD" in key.upper()
            )
    assert plan.compose.get("networks") and plan.compose.get("volumes")


@pytest.mark.parametrize(
    "mutation",
    ["component", "repository", "platform", "digest", "index", "revision", "runtime-claim"],
)
def test_unreviewed_or_mutable_artifact_identity_cannot_render_as_reviewed(mutation):
    value = lock()
    if mutation == "component":
        value["images"].pop("manager")
    elif mutation == "repository":
        value["images"]["manager"]["repository"] = "untrusted/manager:latest"
    elif mutation == "platform":
        value["images"]["manager"]["platforms"].pop("arm64")
    elif mutation == "digest":
        value["images"]["manager"]["platforms"]["arm64"] = "latest"
    elif mutation == "index":
        value["images"]["manager"]["index_digest"] = "not-a-digest"
    elif mutation == "revision":
        value["source_revision"] = "0" * 40
    else:
        value["runtime_qualified"] = True
    with pytest.raises((PreparationError, ValueError)):
        build_plan(target(), value)


def test_output_mutation_cannot_rewrite_original_lock_or_next_plan():
    value = lock()
    original = deepcopy(value)
    first = build_plan(target(), value)
    first.compose["services"].clear()
    assert value == original
    second = build_plan(target(), value)
    assert len(second.compose["services"]) == 3
