"""Source-derived safety expectations; no Docker runtime is invoked."""

from itertools import product

import pytest

from responseforge.integrations.shuffle.deployment import build_plan
from tests.rf04.test_deployment import image_lock, target


@pytest.mark.parametrize(
    "kind,authority", tuple(product(("docker-desktop", "dedicated-vm"), (False, True)))
)
def test_plans_do_not_enable_swarm_cleanup_pipelines_or_agent_mode(kind, authority):
    plan = build_plan(image_lock(), target(kind=kind, engine_control_authorized=authority))
    env = plan.compose["services"]["orborus"]["environment"]
    assert env["SHUFFLE_SWARM_CONFIG"] == ""  # Pinned source native standalone default.
    assert env["CLEANUP"] == "false"
    assert env["SHUFFLE_CONTAINER_AUTO_CLEANUP"] == "false"
    assert env["SHUFFLE_SKIP_PIPELINES"] == "true"
    assert env["SHUFFLE_PIPELINE_ENABLED"] == "false"
    assert env["SHUFFLE_AGENT_MODE"] == "false"
    assert plan.ready is False


@pytest.mark.parametrize("authority", (False, True))
def test_desktop_global_cleanup_blocker_cannot_be_removed_by_grant_or_lock(authority):
    lock = image_lock()
    lock["gates"] = []
    plan = build_plan(lock, target(engine_control_authorized=authority))
    assert "shared-daemon-cleanup-unqualified" in plan.blockers
    assert plan.ready is False


def test_valid_opensearch_ca_setting_and_default_socket_restrictions_survive():
    plan = build_plan(image_lock(), target())
    backend = plan.compose["services"]["backend"]
    assert "SHUFFLE_OPENSEARCH_CERTIFICATE_FILE" in backend["environment"]
    for service in plan.compose["services"].values():
        assert not service.get("ports")
        assert "docker.sock" not in str(service)
