"""Selective opt-in acquisition of immutable, reviewed recorded artifacts.

Downloaded telemetry is inert data. A bundle is published only after both its
license and its original source bytes match the detached reviewed manifest.
"""

import ctypes
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import httpx
from pydantic import ValidationError

from responseforge.dataset_contracts import DatasetArtifact
from responseforge.replay import ReplayError

_MAX_BYTES = 1048576
_BUNDLE_FILES = {"source.xml", "LICENSE", "manifest.json"}


def _safe_directory(directory: Path, *, create: bool) -> None:
    """Reject symlinks at every existing path component before any writes."""
    absolute = directory.absolute()
    if ".." in absolute.parts:
        raise ReplayError("Invalid dataset output directory")
    for component in (*reversed(absolute.parents), absolute):
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            if not create:
                raise ReplayError("Incomplete dataset bundle") from None
            component.mkdir(mode=0o700)
            mode = component.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise ReplayError("Invalid dataset output directory")


def _read_regular(path: Path, limit: int) -> bytes:
    """Bound cache reads and refuse links/devices rather than following them."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ReplayError("Invalid dataset bundle member")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ReplayError("Dataset bundle exceeds byte limit")
    return value


def _verify_bytes(value: bytes, expected_hash: str, expected_size: int | None = None) -> None:
    if expected_size is not None and len(value) != expected_size:
        raise ReplayError("Dataset integrity mismatch")
    if not value or hashlib.sha256(value).hexdigest() != expected_hash:
        raise ReplayError("Dataset integrity mismatch")


def _manifest_bytes(artifact: DatasetArtifact) -> bytes:
    return (
        json.dumps(artifact.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _reuse_bundle(bundle: Path, artifact: DatasetArtifact, manifest: bytes) -> Path:
    _safe_directory(bundle, create=False)
    if {member.name for member in bundle.iterdir()} != _BUNDLE_FILES:
        raise ReplayError("Incomplete or conflicting dataset bundle")
    if _read_regular(bundle / "manifest.json", len(manifest)) != manifest:
        raise ReplayError("Conflicting dataset manifest")
    _verify_bytes(
        _read_regular(bundle / "LICENSE", _MAX_BYTES), artifact.rights.license_sha256
    )
    _verify_bytes(
        _read_regular(bundle / "source.xml", artifact.size_bytes),
        artifact.sha256,
        artifact.size_bytes,
    )
    return bundle / "source.xml"


def _download(client: httpx.Client, url: str, limit: int) -> bytes:
    with client.stream("GET", url) as response:
        if response.status_code != 200:
            raise ReplayError("Dataset retrieval refused")
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            raise ReplayError("Encoded dataset response refused")
        length = response.headers.get("content-length")
        if length is not None and (not length.isascii() or not length.isdecimal()):
            raise ReplayError("Invalid dataset response size")
        if length is not None and int(length) > limit:
            raise ReplayError("Dataset response exceeds byte limit")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > limit:
                raise ReplayError("Dataset response exceeds byte limit")
            chunks.append(chunk)
        if length is not None and total != int(length):
            raise ReplayError("Dataset response size mismatch")
        return b"".join(chunks)


def _publish_bundle(staging: Path, bundle: Path) -> None:
    """Atomically publish without replacing even a racing empty directory.

    Darwin RENAME_EXCL and Linux RENAME_NOREPLACE are required. Unsupported
    platforms/filesystems fail closed; ordinary replacing rename is no fallback.
    """
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = library.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(staging), os.fsencode(bundle), 0x00000004)
    elif sys.platform.startswith("linux"):
        rename = library.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(staging), -100, os.fsencode(bundle), 1)
    else:
        raise ReplayError("Atomic dataset publication unavailable")
    if result != 0:
        raise ReplayError("Atomic dataset publication refused")


def fetch_artifact(
    artifact: DatasetArtifact,
    directory: Path,
    *,
    opt_in: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> Path:
    """Return source.xml in a verified private bundle, requiring explicit opt-in.

    Existing complete bundles are reverified without network access. Conflicting
    bundles are retained. Failed downloads never publish a partial final bundle.
    """
    if opt_in is not True:
        raise ReplayError("Explicit dataset acquisition opt-in required")
    staging: Path | None = None
    try:
        artifact = DatasetArtifact.model_validate(artifact.model_dump(mode="json", warnings=False))
        manifest = _manifest_bytes(artifact)
        _safe_directory(directory, create=True)
        bundle = directory / artifact.artifact_id
        if bundle.exists() or bundle.is_symlink():
            return _reuse_bundle(bundle, artifact, manifest)
        with httpx.Client(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=5, read=10, write=10, pool=5),
            headers={"Accept-Encoding": "identity"},
        ) as client:
            license_bytes = _download(client, artifact.license_url, _MAX_BYTES)
            _verify_bytes(license_bytes, artifact.rights.license_sha256)
            source = _download(client, artifact.download_url, artifact.size_bytes)
            _verify_bytes(source, artifact.sha256, artifact.size_bytes)
        staging = Path(tempfile.mkdtemp(prefix=f".{artifact.artifact_id}-", dir=directory))
        for name, value in (
            ("source.xml", source),
            ("LICENSE", license_bytes),
            ("manifest.json", manifest),
        ):
            descriptor = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        # Recheck early, then use an exclusive kernel rename to close the race.
        _safe_directory(directory, create=False)
        if bundle.exists() or bundle.is_symlink():
            raise ReplayError("Dataset bundle appeared during acquisition")
        _publish_bundle(staging, bundle)
        staging = None
        return bundle / "source.xml"
    except ReplayError:
        raise
    except (OSError, httpx.HTTPError, ValidationError, ValueError, TypeError, AttributeError):
        raise ReplayError("Dataset acquisition failed") from None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
