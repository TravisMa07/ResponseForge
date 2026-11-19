"""Private verified shipped-client overlay; no image build or runtime authority."""

import base64
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

import httpx

from responseforge.integrations.wazuh.security import (
    PreparationError,
    atomic_directory,
    decode_json,
    open_private_directory,
    private_directory,
    read_file,
    write_private,
)
from responseforge.integrations.wazuh.tls_source import SourceLock, load_source_lock, patch_client

ROOT = Path(__file__).resolve().parents[4]


@dataclass(frozen=True)
class BlobSpec:
    name: str
    size: int
    sha256: str
    diff_id: str


@dataclass(frozen=True)
class FileSpec:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class PackagedLock:
    image_digest: str
    blobs: tuple[BlobSpec, ...]
    files: tuple[FileSpec, ...]
    client_path: str
    cookie_path: str
    axios_entry: str
    body_sha256: str
    patched_sha256: str


def load_packaged_lock() -> PackagedLock:
    value = decode_json(
        read_file(ROOT / "deploy/wazuh/packaged-client/source.lock.json", 262144), 262144
    )
    patch = value["compiled_patch"]
    return PackagedLock(
        value["image_digest"],
        tuple(BlobSpec(**b) for b in value["blobs"]),
        tuple(FileSpec(**f) for f in value["files"]),
        patch["client_path"],
        patch["cookie_path"],
        patch["axios_entry"],
        patch["original_body_sha256"],
        patch["patched_sha256"],
    )


OLD = b"    const httpsAgent = new _https.default.Agent({\n      rejectUnauthorized: false\n    });\n    this._axios = _axios.default.create({\n      httpsAgent\n    });"

NEW = b"    const httpsAgent = new _https.default.Agent({\n      rejectUnauthorized: true\n    });\n    this._axios = _axios.default.create({\n      httpsAgent,\n      maxRedirects: 0,\n      proxy: false\n    });\n    this._axios.interceptors.request.use(config => {\n      if (typeof config.url !== 'string' || /[\\u0000-\\u0020\\u007f]/.test(config.url)) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      let target;\n      try {\n        target = new URL(config.url);\n      } catch {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      if (target.protocol !== 'https:' || target.username || target.password || target.hash) {\n        throw new Error('Verified HTTPS manager API URL required');\n      }\n      return config;\n    });"

PREFIX = b"// ResponseForge RF-07C3: verified HTTPS correction; modified 2026-11-19.\n"

MARKER = b"//# sourceMappingURL=data:application/json;charset=utf-8;base64,"

MAX_BLOB = 350000000
MAX_EXPANDED = 2147483648
MAX_ENTRIES = 120000
MAX_FILE = 4194304
MAX_SELECTED = 33554432
MAX_FILES = 2048
BASE = "usr/share/wazuh-dashboard/"
REGISTRY = "https://registry-1.docker.io/v2/wazuh/wazuh-dashboard/blobs/sha256:"
TOKEN = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:wazuh/wazuh-dashboard:pull"
BLOB_NAMES = ("payload.tar.gz", "post-10.tar.gz", "post-11.tar.gz", "post-12.tar.gz")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path(value: str) -> str:
    if value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if value == ".":
        return value
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or len(value.encode("utf8")) > 4096
        or any(c in {"", ".", ".."} for c in value.split("/"))
    ):
        raise PreparationError("Noncanonical archive path refused")
    return value


def _validate(lock: PackagedLock) -> None:
    if (
        not re.fullmatch(r"sha256:[0-9a-f]{64}", lock.image_digest)
        or tuple(b.name for b in lock.blobs) != BLOB_NAMES
        or any(
            type(b.size) is not int
            or not 0 < b.size <= MAX_BLOB
            or not re.fullmatch(r"[0-9a-f]{64}", b.sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", b.diff_id)
            for b in lock.blobs
        )
        or not 0 < len(lock.files) <= MAX_FILES
        or len({f.path for f in lock.files}) != len(lock.files)
        or sum(f.size for f in lock.files) > MAX_SELECTED
        or not re.fullmatch(r"[0-9a-f]{64}", lock.body_sha256)
        or not re.fullmatch(r"[0-9a-f]{64}", lock.patched_sha256)
    ):
        raise PreparationError("Invalid trusted packaged policy")
    for f in lock.files:
        if (
            _path(f.path) != f.path
            or not f.path.startswith(BASE)
            or type(f.size) is not int
            or not 0 < f.size <= MAX_FILE
            or not re.fullmatch(r"[0-9a-f]{64}", f.sha256)
        ):
            raise PreparationError("Invalid selected artifact policy")
    names = {f.path for f in lock.files}
    if (
        not {
            lock.client_path,
            lock.cookie_path,
            lock.axios_entry,
            BASE + "LICENSE.txt",
            BASE + "NOTICE.txt",
        }
        <= names
    ):
        raise PreparationError("Required packaged artifacts absent")
    if any(str(parent) in names for name in names for parent in PurePosixPath(name).parents):
        raise PreparationError("Selected file ancestry conflict")


def _mapped(raw: bytes) -> tuple[bytes, bytes]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536 or raw.count(MARKER) != 1:
        raise PreparationError("One bounded final inline map required")
    body, encoded = raw.split(MARKER)
    if not body.endswith(b"\n"):
        raise PreparationError("Final inline map required")
    try:
        value = decode_json(base64.b64decode(encoded.strip(), validate=True), 65536)
        if (
            value["version"] != 3
            or len(value["sources"]) != 1
            or len(value["sourcesContent"]) != 1
            or not isinstance(value["sourcesContent"][0], str)
        ):
            raise ValueError
        return body, value["sourcesContent"][0].encode("utf8")
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise PreparationError("Invalid original source map") from None


def patch_packaged_client(raw: bytes, expected_sha256: str) -> bytes:
    if not isinstance(raw, bytes) or _sha(raw) != expected_sha256:
        raise PreparationError("Pinned compiled client required")
    body, _ = _mapped(raw)
    if body.count(OLD) != 1:
        raise PreparationError("Unique compiled constructor required")
    return PREFIX + body.replace(OLD, NEW)


def _headers(response: httpx.Response, maximum: int) -> None:
    length = response.headers.get("content-length")
    if (
        response.status_code != 200
        or response.headers.get("content-encoding", "identity").lower() != "identity"
        or length is not None
        and (not length.isascii() or not length.isdecimal() or not 0 < int(length) <= maximum)
    ):
        raise PreparationError("Artifact HTTP policy refused")


def fetch_packaged_payload(
    output: Path,
    lock: PackagedLock,
    *,
    allow_download: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> Path:
    if allow_download is not True:
        raise PreparationError("Explicit packaged download opt-in required")
    _validate(lock)
    try:
        with (
            atomic_directory(output) as stage,
            httpx.Client(
                verify=True,
                trust_env=False,
                follow_redirects=False,
                timeout=60,
                transport=transport,
            ) as client,
        ):
            with client.stream("GET", TOKEN, headers={"Accept-Encoding": "identity"}) as response:
                _headers(response, 65536)
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=65536):
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise PreparationError("Bounded registry token required")
                token = decode_json(bytes(raw))["token"]
                if not isinstance(token, str) or not re.fullmatch(
                    r"[A-Za-z0-9._-]{1,16384}", token
                ):
                    raise PreparationError("Invalid scoped registry token")
            for blob in lock.blobs:
                url = REGISTRY + blob.sha256
                headers = {"Accept-Encoding": "identity", "Authorization": "Bearer " + token}
                for redirects in range(3):
                    with client.stream("GET", url, headers=headers) as response:
                        if response.status_code in {301, 302, 303, 307, 308}:
                            from urllib.parse import urlsplit

                            target = urlsplit(response.headers.get("location", ""))
                            if (
                                redirects == 2
                                or target.scheme != "https"
                                or target.hostname != "production.cloudfront.docker.com"
                                or target.port not in {None, 443}
                                or target.username
                                or target.password
                                or target.fragment
                            ):
                                raise PreparationError("Artifact redirect refused")
                            url = target.geturl()
                            headers = {"Accept-Encoding": "identity"}
                            continue
                        _headers(response, blob.size)
                        digest = hashlib.sha256()
                        total = 0
                        parent = open_private_directory(stage)
                        try:
                            fd = os.open(
                                blob.name,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600,
                                dir_fd=parent,
                            )
                            with os.fdopen(fd, "wb") as stream:
                                for chunk in response.iter_bytes(chunk_size=1048576):
                                    total += len(chunk)
                                    if total > blob.size:
                                        raise PreparationError("Artifact size exceeded")
                                    digest.update(chunk)
                                    stream.write(chunk)
                                stream.flush()
                                os.fsync(stream.fileno())
                        finally:
                            os.close(parent)
                        length = response.headers.get("content-length")
                        if (
                            total != blob.size
                            or digest.hexdigest() != blob.sha256
                            or length is not None
                            and int(length) != total
                        ):
                            raise PreparationError("Pinned artifact integrity mismatch")
                        break
        return output
    except (OSError, ValueError, TypeError, KeyError, httpx.HTTPError):
        raise PreparationError("Packaged acquisition refused") from None


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
    )


@contextmanager
def _blob(cache: Path, spec: BlobSpec) -> Iterator[BinaryIO]:
    parent = open_private_directory(cache)
    try:
        fd = os.open(spec.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_size != spec.size
        ):
            raise PreparationError("Unsafe cached blob refused")
        digest = hashlib.sha256()
        total = 0
        while chunk := stream.read(min(1048576, spec.size - total + 1)):
            total += len(chunk)
            if total > spec.size:
                raise PreparationError("Cached blob grew beyond declared size")
            digest.update(chunk)
        if digest.hexdigest() != spec.sha256:
            raise PreparationError("Cached blob integrity mismatch")
        stream.seek(0)
        yield cast(BinaryIO, _Compressed(stream, spec.size))
        if _identity(before) != _identity(os.fstat(stream.fileno())):
            raise PreparationError("Cached blob changed during inspection")


class _Compressed:
    """Forward-only second pass: growth cannot hide behind empty gzip members."""

    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self.stream = stream
        self.limit = limit
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > 1048576:
            raise PreparationError("Bounded compressed reads required")
        raw = self.stream.read(min(size, self.limit - self.count + 1))
        self.count += len(raw)
        if self.count > self.limit:
            raise PreparationError("Compressed artifact grew during decompression")
        return raw

    def tell(self) -> int:
        return self.count


class _Expanded:
    def __init__(self, stream: Any) -> None:
        self.stream = stream
        self.size = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise PreparationError("Unbounded expanded read refused")
        raw: bytes = self.stream.read(size)
        self.size += len(raw)
        if self.size > MAX_EXPANDED:
            raise PreparationError("Expanded artifact size exceeded")
        self.digest.update(raw)
        return raw


def _layer(
    cache: Path, blob: BlobSpec, selected: dict[str, FileSpec], *, payload: bool
) -> dict[str, bytes]:
    result = {}
    ancestors = {str(p) for name in selected for p in PurePosixPath(name).parents}
    with _blob(cache, blob) as stream, gzip.GzipFile(fileobj=stream) as compressed:
        expanded = _Expanded(compressed)
        with tarfile.open(fileobj=cast(Any, expanded), mode="r|") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_ENTRIES:
                    raise PreparationError("Archive entry limit exceeded")
                name = _path(member.name)
                if member.issparse() or any(part.startswith(".wh.") for part in name.split("/")):
                    raise PreparationError("Sparse/whiteout artifact refused")
                if (not payload and name in selected) or any(
                    str(p) in selected for p in PurePosixPath(name).parents
                ):
                    raise PreparationError("Selected file replaced by directory/descendant")
                if not payload:
                    if not member.isdir():
                        raise PreparationError("Post-payload replacement refused")
                    continue
                if name in ancestors and not member.isdir():
                    raise PreparationError("Selected ancestor replacement refused")
                if name not in selected:
                    continue
                expected = selected[name]
                if name in result or not member.isreg() or member.size != expected.size:
                    raise PreparationError("Selected regular artifact required")
                reader = archive.extractfile(member)
                if reader is None:
                    raise PreparationError("Selected file unavailable")
                with reader:
                    raw = reader.read(expected.size + 1)
                if len(raw) != expected.size or _sha(raw) != expected.sha256:
                    raise PreparationError("Selected artifact integrity mismatch")
                result[name] = raw
            while tail := archive.fileobj.read(1048576):
                if any(tail):
                    raise PreparationError("Nonzero archive trailer refused")
        if expanded.digest.hexdigest() != blob.diff_id:
            raise PreparationError("OCI uncompressed DiffID mismatch")
    return result


def _write_tree(stage: Path, name: str, raw: bytes) -> None:
    leaf = stage
    for part in PurePosixPath(name).parts[:-1]:
        leaf = leaf / part
        if not leaf.exists():
            leaf.mkdir(mode=0o700)
        private_directory(leaf)
    write_private(stage / name, raw)


def prepare_packaged_client(
    cache: Path,
    source_bundle: Path,
    output: Path,
    lock: PackagedLock,
    source_lock: SourceLock | None = None,
) -> Path:
    _validate(lock)
    if output.exists() or output.is_symlink():
        raise PreparationError("Output already exists")
    try:
        private_directory(cache)
        private_directory(source_bundle)
        if {p.name for p in cache.iterdir()} != set(BLOB_NAMES):
            raise PreparationError("Exact cached blobs required")
        sources = source_lock or load_source_lock()
        if {m.name for m in sources.members} != {
            "upstream-server-api-client.ts",
            "cookie.ts",
            "LICENSE",
        } or len(sources.members) != 3:
            raise PreparationError("Reviewed source identity required")
        source_bytes = {}
        for m in sources.members:
            if type(m.size) is not int or not 0 < m.size <= 32768:
                raise PreparationError("Bounded source identity required")
            raw = read_file(source_bundle / m.name, m.size)
            if len(raw) != m.size or _sha(raw) != m.sha256:
                raise PreparationError("Source correspondence integrity mismatch")
            source_bytes[m.name] = raw
        patched_ts = read_file(source_bundle / "server-api-client.ts", 32768)
        original_sha = _sha(source_bytes["upstream-server-api-client.ts"])
        if (
            _sha(patched_ts) != sources.patched_sha256
            or patch_client(source_bytes["upstream-server-api-client.ts"], original_sha)
            != patched_ts
        ):
            raise PreparationError("Corrected source correspondence required")
        source_bytes["server-api-client.ts"] = patched_ts
        selected = {f.path: f for f in lock.files}
        contents = _layer(cache, lock.blobs[0], selected, payload=True)
        for blob in lock.blobs[1:]:
            _layer(cache, blob, selected, payload=False)
        if set(contents) != set(selected):
            raise PreparationError("Selected packaged artifact missing")
        body, original_ts = _mapped(contents[lock.client_path])
        _, cookie_ts = _mapped(contents[lock.cookie_path])
        if (
            _sha(body) != lock.body_sha256
            or original_ts != source_bytes["upstream-server-api-client.ts"]
            or cookie_ts != source_bytes["cookie.ts"]
        ):
            raise PreparationError("Compiled/source correspondence mismatch")
        patched = patch_packaged_client(
            contents[lock.client_path], selected[lock.client_path].sha256
        )
        if _sha(patched) != lock.patched_sha256:
            raise PreparationError("Reviewed compiled correction mismatch")
        output_files = {"root/" + name: raw for name, raw in contents.items()}
        output_files.update(source_bytes)
        output_files["patched/server-api-client.js"] = patched
        output_files["build-context/server-api-client.js"] = patched
        output_files["build-context/Dockerfile"] = (
            "FROM wazuh/wazuh-dashboard@" + lock.image_digest + "\n"
            "COPY --chown=1000:1000 --chmod=0644 server-api-client.js /" + lock.client_path + "\n"
        ).encode()
        for name, raw in source_bytes.items():
            output_files["build-context/source/" + name] = raw
        output_files["build-context/LICENSE.platform"] = contents[BASE + "LICENSE.txt"]
        output_files["build-context/NOTICE.platform"] = contents[BASE + "NOTICE.txt"]
        output_files["build-context/RESPONSEFORGE_CHANGES.txt"] = (
            b"ResponseForge RF-07C3 modified compiled client 2026-11-19: verified HTTPS, "
            b"no redirects/proxies, URL policy; stale source map removed. Original sources, "
            b"maps, GPL license and packaged terms retained. Context only: no image build, "
            b"runtime, manager, endpoint or redistribution clearance.\n"
        )
        manifest = {
            "image_digest": lock.image_digest,
            "ready": False,
            "runtime_qualified": False,
            "image_built": False,
            "image_executed": False,
            "full_plugin_build": False,
            "files": {name: _sha(raw) for name, raw in output_files.items()},
        }
        output_files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        with atomic_directory(output) as stage:
            for name, raw in output_files.items():
                _write_tree(stage, name, raw)
        return output
    except (OSError, ValueError, TypeError, tarfile.TarError, EOFError):
        raise PreparationError("Packaged preparation refused") from None
