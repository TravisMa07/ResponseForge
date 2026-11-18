"""Offline validation of candidate registry pins and blocked, socket-free defaults."""

import json
from pathlib import Path

from responseforge.integrations.shuffle.deployment import DeploymentTarget, build_plan

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    lock = json.loads((ROOT / "deploy/shuffle/images.lock.json").read_text())
    for kind in ("docker-desktop", "dedicated-vm"):
        for architecture in ("arm64", "amd64"):
            target = DeploymentTarget(
                kind=kind, architecture=architecture, engine_id="validation-only-no-grant"
            )
            plan = build_plan(lock, target)
            if plan.ready or not plan.blockers or target.engine_control_authorized:
                raise ValueError("unqualified plan cannot become ready or grant authority")
            environment = plan.compose["services"]["orborus"]["environment"]
            expected = {
                "SHUFFLE_SWARM_CONFIG": "",
                "CLEANUP": "false",
                "SHUFFLE_CONTAINER_AUTO_CLEANUP": "false",
                "SHUFFLE_SKIP_PIPELINES": "true",
                "SHUFFLE_PIPELINE_ENABLED": "false",
                "SHUFFLE_AGENT_MODE": "false",
            }
            if any(environment.get(key) != value for key, value in expected.items()):
                raise ValueError("candidate plan enables unreviewed execution-plane behavior")
            if kind == "docker-desktop" and (
                "shared-daemon-cleanup-unqualified" not in plan.blockers
            ):
                raise ValueError("shared-daemon cleanup must remain blocked")
            for service in plan.compose["services"].values():
                if (
                    service.get("ports")
                    or service.get("privileged")
                    or "unconfined" in json.dumps(service)
                    or "docker.sock" in json.dumps(service)
                ):
                    raise ValueError("default plan exposes authority or management")
    print("PASS: candidate pins, standalone defaults and both socket-free blocked target plans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
