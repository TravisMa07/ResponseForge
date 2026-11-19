"""Pure runtime topology contracts; no Docker command or network is executed."""

from pathlib import Path

import pytest

from responseforge.integrations.shuffle.runtime_deployment import render_runtime

COMPONENTS = ("backend", "worker", "orborus", "frontend", "opensearch", "core", "app")
PROJECT = "responseforge-rf04"


def images():
    return {component: "sha256:" + str(index) * 64 for index, component in enumerate(COMPONENTS, 1)}


def test_unapproved_runtime_has_no_socket_or_published_interfaces(tmp_path: Path):
    result = render_runtime(images(), tmp_path)
    compose = result["compose"]
    assert compose["name"] == PROJECT
    services = compose["services"]
    assert {"backend", "orborus", "frontend", "opensearch", "core"} <= set(services)
    for service in services.values():
        assert not service.get("ports")
        assert "docker.sock" not in str(service)
        assert service.get("privileged") is not True
        assert "unconfined" not in str(service)
    assert "ssl" in result["frontend_nginx"].lower()
    assert result["opensearch_config"]


def test_authorized_runtime_only_exposes_loopback_ui_and_core(tmp_path: Path):
    result = render_runtime(
        images(), tmp_path, engine_authorized=True, ui_port=3443, core_port=8443
    )
    services = result["compose"]["services"]
    published = {
        name: service.get("ports", []) for name, service in services.items() if service.get("ports")
    }
    assert published == {"frontend": ["127.0.0.1:3443:443"], "core": ["127.0.0.1:8443:8000"]}
    socket_services = {
        name
        for name, service in services.items()
        if "docker.sock" in str(service.get("volumes", []))
    }
    assert socket_services == {"backend", "orborus"}
    orborus = services["orborus"]
    assert orborus["container_name"] == PROJECT + "-orborus"
    assert orborus["environment"]["ORBORUS_CONTAINER_NAME"] == orborus["container_name"]


@pytest.mark.parametrize(
    "reference",
    [
        "registry.invalid/app:latest",
        "app:v1",
        "sha256:abc",
        "sha256:" + "G" * 64,
        "",
        "https://registry.invalid/image",
    ],
)
def test_mutable_or_malformed_image_never_renders(tmp_path: Path, reference):
    values = images()
    values["app"] = reference
    with pytest.raises(ValueError):
        render_runtime(values, tmp_path, engine_authorized=True)


@pytest.mark.parametrize("component", COMPONENTS)
def test_every_execution_component_must_be_pinned(tmp_path: Path, component):
    values = images()
    del values[component]
    with pytest.raises(ValueError):
        render_runtime(values, tmp_path)


def test_extra_unreviewed_service_image_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        render_runtime(images() | {"sensor": "sha256:" + "a" * 64}, tmp_path)


@pytest.mark.parametrize("port", [0, -1, 65536, True, "3443"])
def test_invalid_loopback_ports_rejected_even_before_authority(tmp_path: Path, port):
    with pytest.raises(ValueError):
        render_runtime(images(), tmp_path, ui_port=port)
    with pytest.raises(ValueError):
        render_runtime(images(), tmp_path, core_port=port)


def test_relative_state_path_is_not_allowed():
    with pytest.raises(ValueError):
        render_runtime(images(), Path("relative/private"))


def test_untrusted_authorization_value_cannot_enable_socket(tmp_path: Path):
    for authority in ("true", 1, None):
        with pytest.raises(ValueError):
            render_runtime(images(), tmp_path, engine_authorized=authority)


def test_reviewed_security_and_private_topology_are_explicit(tmp_path: Path):
    result = render_runtime(images(), tmp_path, engine_authorized=True)
    compose = result["compose"]
    services = compose["services"]
    for name, service in services.items():
        assert service.get("privileged") is not True
        assert not service.get("network_mode") == "host"
        assert "unconfined" not in str(service)
        assert PROJECT in service.get("labels", {}).values()
        assert service.get("mem_limit") or service.get("deploy", {}).get("resources", {}).get(
            "limits", {}
        ).get("memory")
        for mount in service.get("volumes", []):
            if isinstance(mount, str) and mount.startswith("/"):
                assert (
                    mount.startswith(str(tmp_path) + "/")
                    or mount == "/var/run/docker.sock:/var/run/docker.sock:rw"
                )
    assert not services["backend"].get("ports")
    assert not services["opensearch"].get("ports")
    assert services["backend"]["environment"]["SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY"] == "false"
    environment = services["orborus"]["environment"]
    assert environment["SHUFFLE_SWARM_CONFIG"] == ""
    assert environment["SHUFFLE_CONTAINER_AUTO_CLEANUP"] == "false"
    assert environment["CLEANUP"] == "false"
    assert environment["SHUFFLE_SKIP_PIPELINES"] == "true"
    assert environment["SHUFFLE_PIPELINE_ENABLED"] == "false"
    assert environment["SHUFFLE_AGENT_MODE"] == "false"
    assert "responseforge-rf04-callback" in compose["volumes"]
    encoded = str(compose)
    assert "SSL_VERIFY': 'true" not in encoded
    assert "SYNTHETIC_PRIVATE_SECRET" not in encoded


def test_immutable_registry_digest_and_local_image_id_both_work(tmp_path: Path):
    values = {
        component: "registry.invalid/" + component + "@sha256:" + "a" * 64
        for component in COMPONENTS
    }
    result = render_runtime(values, tmp_path)
    assert result["compose"]["services"]["backend"]["image"] == values["backend"]
