"""Private reviewed platform compiler inputs; no full-plugin/runtime claim."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from responseforge.integrations.wazuh.security import (
    PreparationError,
    atomic_directory,
    decode_json,
    private_directory,
    read_file,
    write_private,
)
from responseforge.integrations.wazuh.tls_source import SourceMember, fetch_reviewed_members

ROOT = Path(__file__).resolve().parents[4]


@dataclass(frozen=True)
class PlatformLock:
    revision: str
    members: tuple[SourceMember, ...]


def load_platform_lock() -> PlatformLock:
    value = decode_json(read_file(ROOT / "deploy/wazuh/platform-client/source.lock.json", 32768))
    return PlatformLock(value["revision"], tuple(SourceMember(**m) for m in value["members"]))


MEMBERS = {
    "platform-package.json": "package.json",
    "yarn.lock": "yarn.lock",
    "node-version.txt": ".node-version",
    "LICENSE.txt": "LICENSE.txt",
    "NOTICE.txt": "NOTICE.txt",
    "write-server-files.ts": "packages/osd-plugin-helpers/src/tasks/write_server_files.ts",
    "yarn-install.ts": "packages/osd-plugin-helpers/src/tasks/yarn_install.ts",
    "node_preset.js": "packages/osd-babel-preset/node_preset.js",
    "babel-helper.ts": "packages/osd-dev-utils/src/babel.ts",
    "common_preset.js": "packages/osd-babel-preset/common_preset.js",
    "preset-package.json": "packages/osd-babel-preset/package.json",
}


def _validate(lock: PlatformLock) -> None:
    if (
        not re.fullmatch(r"[0-9a-f]{40}", lock.revision)
        or len(lock.members) != len(MEMBERS)
        or {m.name: m.path for m in lock.members} != MEMBERS
        or any(
            type(m.size) is not int
            or not 0 < m.size <= 1048576
            or not re.fullmatch(r"[0-9a-f]{64}", m.sha256)
            for m in lock.members
        )
        or sum(m.size for m in lock.members) > 2097152
    ):
        raise PreparationError("Invalid trusted platform source policy")


def fetch_platform_source(
    output: Path, lock: PlatformLock, *, allow_download: bool = False, transport: Any = None
) -> Path:
    if allow_download is not True:
        raise PreparationError("Explicit platform source download opt-in required")
    _validate(lock)
    return fetch_reviewed_members(
        output,
        "wazuh/wazuh-dashboard",
        lock.revision,
        lock.members,
        allow_download=allow_download,
        transport=transport,
    )


def prepare_platform_source(source: Path, output: Path, lock: PlatformLock) -> Path:
    _validate(lock)
    private_directory(source)
    if {p.name for p in source.iterdir()} != set(MEMBERS):
        raise PreparationError("Exact platform source members required")
    contents = {}
    for member in lock.members:
        raw = read_file(source / member.name, member.size)
        if len(raw) != member.size or hashlib.sha256(raw).hexdigest() != member.sha256:
            raise PreparationError("Pinned platform source integrity mismatch")
        contents[member.name] = raw
    contents["package.json"] = read_file(ROOT / "tools/wazuh-platform/package.json", 32768)
    contents["RESPONSEFORGE_CHANGES.txt"] = (
        b"ResponseForge RF-07C2: original platform files preserved; flattened names and "
        b"reviewed minimum component manifest added. No vendor preset modification. "
        b"Apache LICENSE/NOTICE retained; complete plugin/image/runtime not qualified.\n"
    )
    manifest = {
        "revision": lock.revision,
        "ready": False,
        "runtime_qualified": False,
        "full_plugin_build": False,
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()},
    }
    contents["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    with atomic_directory(output) as stage:
        for name, raw in contents.items():
            write_private(stage / name, raw)
    return output
