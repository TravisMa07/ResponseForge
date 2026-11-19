"""Prepare gated Wazuh artifacts; no Docker, endpoint or implicit network operations."""

import argparse
import json
from pathlib import Path

from responseforge.integrations.wazuh.acquisition import fetch_msi
from responseforge.integrations.wazuh.deployment import build_plan
from responseforge.integrations.wazuh.preparation_models import (
    DeploymentTarget,
    WindowsBundleConfig,
)
from responseforge.integrations.wazuh.security import decode_json, read_file, write_private
from responseforge.integrations.wazuh.sender import deliver, load_config, resume
from responseforge.integrations.wazuh.windows import prepare_windows

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--target", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    windows = sub.add_parser("windows-bundle")
    windows.add_argument("--config", type=Path, required=True)
    windows.add_argument("--output", type=Path, required=True)
    windows.add_argument("--msi", type=Path)
    fetch = sub.add_parser("fetch-msi")
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--allow-download", action="store_true")
    send = sub.add_parser("deliver")
    send.add_argument("--config", type=Path, required=True)
    send.add_argument("--alert", type=Path, required=True)
    send.add_argument("--send", action="store_true")
    retry = sub.add_parser("resume")
    retry.add_argument("--config", type=Path, required=True)
    retry.add_argument("--delivery-id", required=True)
    retry.add_argument("--send", action="store_true")
    retry.add_argument("--retry-uncertain", action="store_true")
    retry.add_argument("--retry-rejected", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            target = DeploymentTarget.model_validate(
                decode_json(read_file(args.target, 65536, private=True))
            )
            lock = decode_json(read_file(ROOT / "deploy/wazuh/images.lock.json", 65536))
            result = build_plan(target, lock)
            write_private(args.output, result.model_dump_json(indent=2).encode() + b"\n")
            print(json.dumps({"prepared": True, "ready": False, "runtime_qualified": False}))
        elif args.command == "windows-bundle":
            cfg = WindowsBundleConfig.model_validate(
                decode_json(read_file(args.config, 65536, private=True))
            )
            print(json.dumps(prepare_windows(cfg, args.output, msi_path=args.msi)))
        elif args.command == "fetch-msi":
            fetch_msi(args.output, allow_download=args.allow_download)
            print(
                json.dumps(
                    {
                        "acquired_and_hash_verified": True,
                        "signature_verified": False,
                        "installed": False,
                    }
                )
            )
        elif args.command == "deliver":
            result = deliver(load_config(args.config), args.alert, send=args.send)
            print(json.dumps({"status": result.status, "verified_live": False}))
            return 0 if result.status in {"dry_run", "accepted", "duplicate", "cached"} else 2
        else:
            result = resume(
                load_config(args.config),
                args.delivery_id,
                send=args.send,
                retry_uncertain=args.retry_uncertain,
                retry_rejected=args.retry_rejected,
            )
            print(json.dumps({"status": result.status, "verified_live": False}))
            return 0 if result.status in {"dry_run", "accepted", "duplicate", "cached"} else 2
    except (ValueError, OSError):
        parser.exit(
            2,
            "Wazuh preparation/delivery refused; inspect private inputs/state. No live fallback.\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
