"""Prepare a private pinned client overlay; never builds or starts an image."""

import argparse
import json
from pathlib import Path

from responseforge.integrations.wazuh.packaged_client import (
    fetch_packaged_payload,
    load_packaged_lock,
    prepare_packaged_client,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--allow-download", action="store_true")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--cache", type=Path, required=True)
    prepare.add_argument("--source-bundle", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        lock = load_packaged_lock()
        if args.command == "fetch":
            fetch_packaged_payload(args.output, lock, allow_download=args.allow_download)
        else:
            prepare_packaged_client(args.cache, args.source_bundle, args.output, lock)
        print(
            json.dumps(
                {
                    "prepared": True,
                    "ready": False,
                    "image_built": False,
                    "image_executed": False,
                    "runtime_qualified": False,
                }
            )
        )
        return 0
    except (OSError, ValueError):
        print(
            json.dumps({"prepared": False, "ready": False, "error": "Packaged preparation refused"})
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
