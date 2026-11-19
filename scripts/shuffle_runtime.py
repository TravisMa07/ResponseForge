"""Build, prepare and explicitly operate the source-pinned RF-04 lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from responseforge.integrations.shuffle.artifacts import prepare_sources
from responseforge.integrations.shuffle.operations import DockerRuntime, initialize

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "deploy/shuffle/runtime"


def docker_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("DOCKER_") and not key.startswith("COMPOSE_")
    }


def engine(context: str, expected_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context):
        raise ValueError("Explicit Docker context required")
    result = subprocess.run(
        ["docker", "--context", context, "info", "--format", "{{json .}}"],
        env=docker_environment(),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    info = json.loads(result.stdout)
    if (
        info.get("ID") != expected_id
        or info.get("OSType") != "linux"
        or info.get("Swarm", {}).get("LocalNodeState") != "inactive"
    ):
        raise ValueError("Docker engine identity, OS or Swarm state differs from reviewed target")
    return dict(info)


def fingerprint() -> str:
    digest = hashlib.sha256()
    paths = (
        sorted((ROOT / "src").rglob("*.py"))
        + sorted(RUNTIME.rglob("*"))
        + sorted((ROOT / "workflows/shuffle").glob("*.json*"))
        + [ROOT / "uv.lock", ROOT / "pyproject.toml", ROOT / "README.md", Path(__file__).resolve()]
    )
    for path in paths:
        if path.is_file():
            digest.update(str(path.relative_to(ROOT)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def build(work: Path, context: str, engine_id: str) -> Path:
    info = engine(context, engine_id)
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        info.get("Architecture")
    )
    if architecture is None:
        raise ValueError("Unsupported engine architecture")
    identity = fingerprint()
    work = work.resolve() / identity
    if work.is_symlink():
        raise ValueError("Build directory cannot be a symlink")
    work.mkdir(parents=True, mode=0o700, exist_ok=True)
    result_path = work / "images.json"
    if result_path.exists():
        previous = json.loads(result_path.read_text())
        if previous.get("source_tree_sha256") != identity or previous.get("engine_id") != engine_id:
            raise ValueError("Build inventory identity differs")
        return result_path
    source = work / "sources"
    if not source.exists():
        prepare_sources(json.loads((RUNTIME / "sources.lock.json").read_text()), source)
    module_lock = json.loads((RUNTIME / "modules.lock.json").read_text())["files"]
    patch_proof = json.loads((source / "patch-manifest.json").read_text())
    if patch_proof.get("input_lock") != json.loads((RUNTIME / "sources.lock.json").read_text()):
        raise ValueError("Cached build source input identity differs")
    for name, expected in patch_proof["patched_files"].items():
        if (
            name not in module_lock
            and hashlib.sha256((source / name).read_bytes()).hexdigest() != expected
        ):
            raise ValueError("Cached patched build source changed")
    for name, expected in module_lock.items():
        value = (RUNTIME / "modules" / name).read_bytes()
        if hashlib.sha256(value).hexdigest() != expected:
            raise ValueError("Resolved Go module lock differs")
        (source / name).write_bytes(value)
    bases = json.loads((RUNTIME / "bases.lock.json").read_text())["images"]
    images: dict[str, str] = {}
    for component in ("backend", "worker", "orborus"):
        engine(context, engine_id)
        tag = "responseforge-rf04-" + component + ":" + identity[:16]
        command = [
            "docker",
            "--context",
            context,
            "build",
            "--label",
            "responseforge.project=responseforge-rf04",
            "--label",
            "responseforge.source-tree-sha256=" + identity,
            "--build-arg",
            "GO_IMAGE=" + bases["go"]["reference"],
            "--build-arg",
            "RUNTIME_IMAGE=" + bases["runtime"]["reference"],
            "-f",
            str(RUNTIME / ("Dockerfile." + component)),
            "-t",
            tag,
            str(source),
        ]
        with (work / (component + "-build.log")).open("w") as output:
            subprocess.run(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=1800,
                check=True,
                env=docker_environment(),
            )
        images[component] = subprocess.run(
            ["docker", "--context", context, "image", "inspect", "--format", "{{.Id}}", tag],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
            env=docker_environment(),
        ).stdout.strip()
        print(json.dumps({"built": component, "image_id": images[component]}), flush=True)
    core = work / "core"
    core.mkdir(exist_ok=True)
    subprocess.run(
        [
            "uv",
            "export",
            "--quiet",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(core / "requirements.txt"),
        ],
        cwd=ROOT,
        timeout=60,
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--offline",
            "--no-build-isolation",
            "--out-dir",
            str(core / "wheels"),
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=60,
        check=True,
    )
    tag = "responseforge-rf04-core:" + identity[:16]
    engine(context, engine_id)
    with (work / "core-build.log").open("w") as output:
        subprocess.run(
            [
                "docker",
                "--context",
                context,
                "build",
                "--label",
                "responseforge.project=responseforge-rf04",
                "--label",
                "responseforge.source-tree-sha256=" + identity,
                "--build-arg",
                "PYTHON_IMAGE=" + bases["python"]["reference"],
                "-f",
                str(RUNTIME / "Dockerfile.core"),
                "-t",
                tag,
                str(core),
            ],
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=600,
            check=True,
            env=docker_environment(),
        )
    images["core"] = subprocess.run(
        ["docker", "--context", context, "image", "inspect", "--format", "{{.Id}}", tag],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        env=docker_environment(),
    ).stdout.strip()
    images["app"] = images["core"]  # reviewed worker supplies the fixed app command
    vendor = json.loads((ROOT / "deploy/shuffle/images.lock.json").read_text())["images"]
    for component in ("frontend", "opensearch"):
        repository = vendor[component]["reference"].split("@")[0]
        images[component] = repository + "@" + vendor[component]["platforms"][architecture]
    manifest = {
        "images": images,
        "engine_id": engine_id,
        "architecture": architecture,
        "context": context,
        "source_tree_sha256": identity,
        "wheel_sha256": hashlib.sha256(
            next((core / "wheels").glob("*.whl")).read_bytes()
        ).hexdigest(),
        "patch_manifest": json.loads((source / "patch-manifest.json").read_text()),
        "module_lock": module_lock,
    }
    result_path.write_text(json.dumps(manifest, indent=2) + "\n")
    result_path.chmod(0o600)
    return result_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "build",
            "prepare",
            "up",
            "status",
            "down",
            "qualify",
            "prepare-playbooks",
            "qualify-playbooks",
            "prepare-recorded",
            "qualify-recorded",
        ),
    )
    parser.add_argument("--context")
    parser.add_argument("--engine-id")
    parser.add_argument("--work", type=Path, default=ROOT / ".local/rf04-build")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--cases", type=Path)
    parser.add_argument("--bundle-root", type=Path)
    parser.add_argument("--state", type=Path, default=ROOT / ".local/rf04-pilot")
    parser.add_argument(
        "--authorize-engine",
        action="store_true",
        help="Operator acknowledgement of separately reviewed engine/socket/loopback scope",
    )
    args = parser.parse_args()
    try:
        if args.command == "build":
            if not args.context or not args.engine_id:
                parser.error("build requires --context and exact --engine-id")
            print(json.dumps({"inventory": str(build(args.work, args.context, args.engine_id))}))
        elif args.command == "prepare":
            if args.inventory is None:
                parser.error("prepare requires --inventory from a successful source build")
            inventory = json.loads(args.inventory.read_text())
            if inventory.get("source_tree_sha256") != fingerprint():
                raise ValueError("Source changed since the image build; rebuild before preparation")
            engine(inventory["context"], inventory["engine_id"])
            initialize(
                args.state.absolute(),
                inventory["images"],
                context=inventory["context"],
                engine_id=inventory["engine_id"],
                architecture=inventory["architecture"],
                authorized=args.authorize_engine,
            )
            shutil.copyfile(args.inventory, args.state / "build-inventory.json")
            (args.state / "build-inventory.json").chmod(0o600)
            print(
                json.dumps(
                    {
                        "prepared": True,
                        "authorized": args.authorize_engine,
                        "starts_services": False,
                    }
                )
            )
        elif args.command == "prepare-playbooks":
            from responseforge.integrations.shuffle.playbook_bootstrap import prepare_playbooks

            proof = json.loads((args.state / "build-inventory.json").read_text())
            if proof.get("source_tree_sha256") != fingerprint():
                raise ValueError("Playbook preparation requires a current source build")
            print(
                json.dumps(
                    prepare_playbooks(
                        args.state.absolute(), ROOT / "workflows/shuffle/replay.jsonl"
                    )
                )
            )
        elif args.command == "prepare-recorded":
            from responseforge.integrations.shuffle.recorded_bootstrap import prepare_recorded
            if args.cases is None or args.bundle_root is None:
                parser.error("prepare-recorded requires --cases and --bundle-root")
            proof = json.loads((args.state / "build-inventory.json").read_text())
            if proof.get("source_tree_sha256") != fingerprint():
                raise ValueError("Recorded preparation requires a current source build")
            print(json.dumps(prepare_recorded(args.state.absolute(), args.cases.absolute(), args.bundle_root.absolute())))
        elif args.command == "qualify-recorded":
            import asyncio

            from responseforge.integrations.shuffle.recorded_qualification import qualify_recorded
            proof = json.loads((args.state / "build-inventory.json").read_text())
            if proof.get("source_tree_sha256") != fingerprint():
                raise ValueError("Recorded qualification requires a current source build")
            print(json.dumps(asyncio.run(qualify_recorded(args.state.absolute())), indent=2))
        elif args.command == "qualify-playbooks":
            import asyncio

            from responseforge.integrations.shuffle.playbook_qualification import qualify_playbooks

            proof = json.loads((args.state / "build-inventory.json").read_text())
            if proof.get("source_tree_sha256") != fingerprint():
                raise ValueError("Playbook qualification requires a current source build")
            print(json.dumps(asyncio.run(qualify_playbooks(args.state.absolute())), indent=2))
        elif args.command == "qualify":
            import asyncio

            from responseforge.integrations.shuffle.qualification import qualify

            proof = json.loads((args.state / "build-inventory.json").read_text())
            if proof.get("source_tree_sha256") != fingerprint():
                raise ValueError("Qualification requires images built from the current source tree")
            print(json.dumps(asyncio.run(qualify(args.state.absolute())), indent=2))
        else:
            runtime = DockerRuntime(args.state.absolute())
            if args.command == "status":
                print(json.dumps(runtime.status()))
            elif args.command == "up":
                runtime.up()
                print(json.dumps({"started": True, "runtime_qualified": False}))
            else:
                runtime.down()
                print(json.dumps({"owned_containers_removed": True, "volumes_preserved": True}))
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(
            2, "RF-04 command failed; inspect private state/build logs. No live fallback.\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
