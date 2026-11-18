"""Render blocked Shuffle planning artifacts; never start services or grant authority."""

import argparse
import json
from pathlib import Path

from responseforge.integrations.shuffle.deployment import (
    DeploymentTarget,
    build_plan,
    compare_targets,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--target", type=Path, help="Explicit target descriptor, no inferred grant")
    parser.add_argument("--lock", type=Path, default=ROOT / "deploy/shuffle/images.lock.json")
    parser.add_argument("--output", type=Path, default=ROOT / ".local/shuffle-plan")
    args = parser.parse_args()
    if args.compare:
        print(json.dumps(compare_targets(), indent=2))
        return 0
    if args.target is None:
        parser.error("--target is required; no engine or authority is selected automatically")
    try:
        target = DeploymentTarget.model_validate_json(args.target.read_text())
        plan = build_plan(json.loads(args.lock.read_text()), target)
        args.output.mkdir(parents=True, exist_ok=True)
        for name, value in (
            ("compose.plan.json", plan.compose),
            ("qualification.plan.json", plan.model_dump(mode="json")),
        ):
            destination = args.output / name
            if destination.exists():
                raise ValueError("refuse overwrite")
            with destination.open("x") as stream:
                stream.write(json.dumps(value, indent=2) + "\n")
            destination.chmod(0o600)
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "Invalid or existing planning artifact; no service operation performed.\n")
    print(
        json.dumps(
            {
                "ready": False,
                "starts_services": False,
                "blockers": plan.blockers,
                "compose_path": str((args.output / "compose.plan.json").resolve()),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
