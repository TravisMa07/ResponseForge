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
            for service in plan.compose["services"].values():
                if (
                    service.get("ports")
                    or service.get("privileged")
                    or "unconfined" in json.dumps(service)
                    or "docker.sock" in json.dumps(service)
                ):
                    raise ValueError("default plan exposes authority or management")
    print("PASS: candidate digest/platform pins and both socket-free blocked target plans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
