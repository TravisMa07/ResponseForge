"""Opt-in private platform compiler preparation; never starts a Wazuh service."""

import argparse
import json
from pathlib import Path

from responseforge.integrations.wazuh.platform_source import (
    fetch_platform_source,
    load_platform_lock,
    prepare_platform_source,
)
from responseforge.integrations.wazuh.security import PreparationError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--allow-download", action="store_true")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--source", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        lock = load_platform_lock()
        if args.command == "fetch":
            fetch_platform_source(args.output, lock, allow_download=args.allow_download)
        else:
            prepare_platform_source(args.source, args.output, lock)
        print(json.dumps({"prepared": True, "ready": False, "runtime_qualified": False}))
        return 0
    except (PreparationError, OSError, ValueError):
        print(json.dumps({"prepared": False, "ready": False, "error": "Source preparation refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
