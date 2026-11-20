"""Prepare/review an image execution packet; explicit owner-scoped execution only."""

import argparse
import json
from pathlib import Path

from responseforge.integrations.wazuh.image_qualification import (
    EngineTarget,
    execute_run,
    preflight_run,
    prepare_run,
    recover_run,
)
from responseforge.integrations.wazuh.security import decode_json, read_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--bundle", type=Path, required=True)
    prepare.add_argument("--fixture", type=Path, required=True)
    prepare.add_argument("--target", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--run-dir", type=Path, required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("--run-dir", type=Path, required=True)
    execute.add_argument("--allow-image-build", action="store_true")
    execute.add_argument("--allow-isolated-fixture", action="store_true")
    recover = sub.add_parser("recover")
    recover.add_argument("--run-dir", type=Path, required=True)
    recover.add_argument("--allow-owned-cleanup", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            target = EngineTarget(**decode_json(read_file(args.target, 8192, private=True)))
            prepare_run(args.bundle, args.fixture, args.output, target)
            result = {"prepared": True, "qualified": False, "execution_authorized": False}
        elif args.command == "preflight":
            result = preflight_run(args.run_dir)
        elif args.command == "execute":
            result = execute_run(
                args.run_dir,
                allow_image_build=args.allow_image_build,
                allow_isolated_fixture=args.allow_isolated_fixture,
            )
        else:
            result = recover_run(args.run_dir, allow_owned_cleanup=args.allow_owned_cleanup)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print(
            json.dumps(
                {
                    "qualified": False,
                    "error": "Image operation refused; inspect private packet/diagnostics",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
