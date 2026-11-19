"""Pinned, private dashboard TLS source preparation."""

import hashlib
import json
import re
import urllib.request
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


@dataclass(frozen=True)
class SourceMember:
    path: str
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class SourceLock:
    revision: str
    members: tuple[SourceMember, ...]
    patched_sha256: str


def load_source_lock() -> SourceLock:
    path = Path(__file__).resolve().parents[4] / "deploy/wazuh/tls-client/source.lock.json"
    value = decode_json(read_file(path, 8192))
    return SourceLock(
        value["revision"],
        tuple(SourceMember(**m) for m in value["members"]),
        value["patched_sha256"],
    )


OLD = b"    const httpsAgent = new https.Agent({\n      rejectUnauthorized: false,\n    });\n    this._axios = axios.create({ httpsAgent });"

NEW = b"    const httpsAgent = new https.Agent({\n      rejectUnauthorized: true,\n    });\n    this._axios = axios.create({ httpsAgent, maxRedirects: 0, proxy: false });\n    this._axios.interceptors.request.use(config => {\n      if (typeof config.url !== 'string' ||\n          /[\\u0000-\\u0020\\u007f]/.test(config.url)) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      let target: URL;\n      try {\n        target = new URL(config.url);\n      } catch {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      if (target.protocol !== 'https:' || target.username || target.password || target.hash) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      return config;\n    });"


MEMBERS = {
    "upstream-server-api-client.ts": "plugins/wazuh-core/server/services/server-api-client.ts",
    "cookie.ts": "plugins/wazuh-core/server/services/cookie.ts",
    "LICENSE": "LICENSE",
}


def _validate_lock(lock: SourceLock, *, patched: bool = False) -> None:
    if (
        not re.fullmatch(r"[0-9a-f]{40}", lock.revision)
        or len(lock.members) != 3
        or {m.name: m.path for m in lock.members} != MEMBERS
        or any(
            type(m.size) is not int
            or not 0 < m.size <= 32768
            or not re.fullmatch(r"[0-9a-f]{64}", m.sha256)
            for m in lock.members
        )
        or (patched and not re.fullmatch(r"[0-9a-f]{64}", lock.patched_sha256))
    ):
        raise PreparationError("Invalid trusted source policy")


def _verified(raw: bytes, member: SourceMember) -> bytes:
    if len(raw) != member.size or hashlib.sha256(raw).hexdigest() != member.sha256:
        raise PreparationError("Pinned source integrity mismatch")
    return raw


def patch_client(raw: bytes, expected_sha256: str) -> bytes:
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= 32768
        or hashlib.sha256(raw).hexdigest() != expected_sha256
        or raw.count(OLD) != 1
    ):
        raise PreparationError("Reviewed source and exact unique constructor required")
    return raw.replace(OLD, NEW)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def fetch_tls_source(
    output: Path, lock: SourceLock, *, allow_download: bool = False, transport: Any = None
) -> Path:
    if allow_download is not True:
        raise PreparationError("Explicit source download opt-in required")
    _validate_lock(lock)
    return fetch_reviewed_members(
        output,
        "wazuh/wazuh-dashboard-plugins",
        lock.revision,
        lock.members,
        allow_download=allow_download,
        transport=transport,
    )


def fetch_reviewed_members(
    output: Path,
    repository: str,
    revision: str,
    members: tuple[SourceMember, ...],
    *,
    allow_download: bool = False,
    transport: Any = None,
) -> Path:
    """Trusted policy helper; callers validate their fixed members before entry."""
    if allow_download is not True or repository not in {
        "wazuh/wazuh-dashboard-plugins",
        "wazuh/wazuh-dashboard",
    }:
        raise PreparationError("Explicit reviewed source download required")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    get = transport if transport is not None else lambda url: opener.open(url, timeout=30)
    try:
        with atomic_directory(output) as stage:
            for member in members:
                url = (
                    "https://raw.githubusercontent.com/"
                    + repository
                    + "/"
                    + revision
                    + "/"
                    + member.path
                )
                response = get(url)
                try:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    length = headers.get("content-length")
                    if (
                        response.status != 200
                        or headers.get("content-encoding", "identity").lower() != "identity"
                        or (
                            length is not None
                            and (not length.isdecimal() or int(length) != member.size)
                        )
                    ):
                        raise PreparationError("Source HTTP policy refused")
                    raw = _verified(response.read(member.size + 1), member)
                    write_private(stage / member.name, raw)
                finally:
                    response.close()
    except PreparationError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        raise PreparationError("Source acquisition failed") from None
    return output


def prepare_tls_source(source: Path, output: Path, lock: SourceLock) -> Path:
    _validate_lock(lock, patched=True)
    private_directory(source)
    if set(p.name for p in source.iterdir()) != set(MEMBERS):
        raise PreparationError("Exact source bundle members required")
    contents = {m.name: _verified(read_file(source / m.name, m.size), m) for m in lock.members}
    original = next(m for m in lock.members if m.name == "upstream-server-api-client.ts")
    corrected = patch_client(contents[original.name], original.sha256)
    if hashlib.sha256(corrected).hexdigest() != lock.patched_sha256:
        raise PreparationError("Reviewed corrected source hash mismatch")
    notice = (
        "ResponseForge RF-07C1 modification: explicit verified HTTPS, no redirects or "
        "environment proxies, bounded URL policy. Original upstream source and GPL "
        "license retained. Component preparation only; full plugin/image/runtime "
        "qualification remains open.\n"
    ).encode()
    contents.update({"server-api-client.ts": corrected, "RESPONSEFORGE_CHANGES.txt": notice})
    manifest = {
        "revision": lock.revision,
        "ready": False,
        "runtime_qualified": False,
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()},
    }
    contents["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    with atomic_directory(output) as stage:
        for name, raw in contents.items():
            write_private(stage / name, raw)
    return output
