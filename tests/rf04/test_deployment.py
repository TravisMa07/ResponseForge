"""P01-P05: immutable, explicitly blocked pure deployment preparation."""

import json
import os
import re
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from responseforge.integrations.shuffle.deployment import (
    DeploymentTarget,
    build_plan,
    compare_targets,
)


def image_lock():
    components = ("frontend", "backend", "orborus", "worker", "opensearch")
    return {
        "schema_version": "1.0",
        "observed_at": "2026-01-01T12:00:00Z",
        "source_revision": "473cc335e5fcc663006d8e5ca16af5ee71fefa68",
        "images": {
            name: {
                "reference": f"registry.invalid/{name}@sha256:" + str(i) * 64,
                "index_digest": "sha256:" + str(i) * 64,
                "platforms": {"amd64": "sha256:" + "a" * 64, "arm64": "sha256:" + "b" * 64},
            }
            for i, name in enumerate(components, 1)
        },
        "gates": [
            "binary_source_correlation_unverified",
            "safe_callback_app_missing",
            "runtime_not_qualified",
        ],
    }


def target(**changes):
    return DeploymentTarget.model_validate(
        {
            "kind": "docker-desktop",
            "architecture": "arm64",
            "engine_id": "synthetic-engine-review-target",
        }
        | changes
    )


def test_default_plan_is_socket_free_unexposed_and_not_runtime_ready() -> None:
    plan = build_plan(image_lock(), target())
    assert plan.ready is False and plan.requires_engine_control is True
    assert plan.blockers
    assert plan.target.engine_control_authorized is False
    content = json.dumps(plan.compose)
    assert "docker.sock" not in content
    assert "seccomp:unconfined" not in content and "privileged" not in content.lower()
    assert "SHUFFLE_SKIPSSL_VERIFY" in content
    for service in plan.compose["services"].values():
        assert not service.get("ports")
        assert "@sha256:" in service["image"]
        assert ":latest" not in service["image"]
        for volume in service.get("volumes", []):
            if isinstance(volume, str):
                assert not volume.startswith(("/", "~", "."))
            elif isinstance(volume, dict):
                assert volume.get("type") != "bind"
    assert "shuffle-security" not in content and "sensor" not in content.lower()


def test_worker_pin_and_no_automatic_app_image_fallback() -> None:
    plan = build_plan(image_lock(), target())
    text = json.dumps(plan.compose)
    assert "SHUFFLE_WORKER_IMAGE" in text
    assert "SHUFFLE_AUTO_IMAGE_DOWNLOAD" in text
    assert "false" in text.lower()


@pytest.mark.parametrize("component", ["frontend", "backend", "orborus", "worker", "opensearch"])
def test_missing_component_cannot_fall_back_to_latest(component: str) -> None:
    lock = image_lock()
    del lock["images"][component]
    with pytest.raises(ValueError):
        build_plan(lock, target())


@pytest.mark.parametrize(
    "changes",
    [
        {"reference": "registry.invalid/backend:latest"},
        {"reference": "registry.invalid/backend@sha256:" + "g" * 64},
        {"index_digest": "sha256:" + "a" * 63},
        {"platforms": {"amd64": "sha256:" + "a" * 64}},
    ],
)
def test_malformed_mutable_or_unsupported_pin_rejects(changes: dict) -> None:
    lock = image_lock()
    lock["images"]["backend"].update(changes)
    with pytest.raises(ValueError):
        build_plan(lock, target())


def test_explicit_target_authority_only_adds_engine_scoped_socket_and_never_readiness() -> None:
    plan = build_plan(image_lock(), target(kind="dedicated-vm", engine_control_authorized=True))
    assert plan.ready is False and plan.blockers
    content = json.dumps(plan.compose)
    assert "docker.sock" in content
    assert plan.target.engine_id == "synthetic-engine-review-target"
    assert "privileged" not in content.lower() and "seccomp:unconfined" not in content
    assert set(image_lock()["gates"]).issubset(set(plan.blockers))


def test_loopback_ui_is_explicit_and_no_backend_indexer_docker_ports_published() -> None:
    plan = build_plan(image_lock(), target(loopback_ui=True))
    published = [
        port for service in plan.compose["services"].values() for port in service.get("ports", [])
    ]
    assert published
    for port in published:
        if isinstance(port, str):
            assert port.startswith("127.0.0.1:")
        else:
            assert port["host_ip"] == "127.0.0.1"
        assert not any(str(number) in str(port) for number in (9200, 5001, 2375, 2376))


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "production"},
        {"architecture": "mips"},
        {"engine_id": ""},
        {"engine_control_authorized": "true"},
        {"loopback_ui": "yes"},
    ],
)
def test_target_is_explicit_strict_and_has_no_implicit_authority(changes: dict) -> None:
    with pytest.raises(ValueError):
        target(**changes)


def test_render_does_not_mutate_input_or_claim_gates_accepted() -> None:
    lock = image_lock()
    before = deepcopy(lock)
    build_plan(lock, target())
    assert lock == before
    comparison = compare_targets()
    text = json.dumps(comparison).lower()
    assert "docker" in text and "vm" in text
    assert any(word in text for word in ("authority", "control", "isolation"))
    assert any(word in text for word in ("resource", "memory", "allocation"))


def test_rendered_compose_config_validates_without_starting_any_service(tmp_path: Path) -> None:
    plan = build_plan(image_lock(), target())
    path = tmp_path / "planning-only.json"
    path.write_text(json.dumps(plan.compose))
    # Required placeholders are synthetic config validation inputs, not credentials
    # for a running service. This invokes only the Compose parser, never up/pull.
    placeholders = re.findall(r"\$\{([A-Z_][A-Z_0-9]*)", path.read_text())
    env = dict(os.environ)
    for variable in placeholders:
        env[variable] = "synthetic-validation-value-no-service"
    result = subprocess.run(
        ["docker", "compose", "-f", str(path), "config", "--format", "json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout)
    assert parsed["services"]
