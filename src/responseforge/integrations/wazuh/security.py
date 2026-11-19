"""Bounded descriptor-anchored reads and private no-overwrite publication."""

import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from responseforge.datasets import _publish_bundle
from responseforge.integrations.wazuh.mapping import _bounded, _reject_constant, _unique
from responseforge.integrations.wazuh.preparation_models import MAX_MSI


class PreparationError(ValueError):
    """Safe preparation failed without authority to repair or bypass it."""


class PublicationExists(PreparationError):
    """Only a verified no-replace collision may be treated as a racing creator."""


def _trusted_directory(info: os.stat_result) -> None:
    sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not sticky_root):
        raise PreparationError("Replaceable private directory ancestry refused")


def _directory_fd(path: Path, *, trusted: bool = False, create: bool = False) -> int:
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise PreparationError("Canonical directory required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        if trusted:
            _trusted_directory(os.fstat(descriptor))
        for part in absolute.parts[1:]:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
            os.close(descriptor)
            descriptor = child
            if trusted:
                _trusted_directory(os.fstat(descriptor))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_private_directory(path: Path) -> int:
    descriptor = _directory_fd(path, trusted=True)
    info = os.fstat(descriptor)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(descriptor)
        raise PreparationError("Private owned directory required")
    return descriptor


def sync_directory(path: Path) -> None:
    descriptor = _directory_fd(path, trusted=True)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_file(path: Path, limit: int, *, private: bool = False, owner: int | None = None) -> bytes:
    descriptor = None
    try:
        if not isinstance(limit, int) or limit < 1 or ".." in path.parts:
            raise ValueError
        descriptor = _directory_fd(path.absolute().parent, trusted=private)
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(leaf, "rb") as stream:
            before = os.fstat(stream.fileno())
            owners = {os.geteuid()} if private else {os.geteuid(), 0}
            if owner is not None:
                owners = {owner}
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid not in owners
                or before.st_mode & (0o077 if private else 0o022)
                or before.st_size < 1
                or before.st_size > limit
            ):
                raise ValueError
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())

            def identity(info: os.stat_result) -> tuple[int, ...]:
                return (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                    info.st_nlink,
                    info.st_mode,
                    info.st_uid,
                )

            if (
                len(raw) != before.st_size
                or len(raw) > limit
                or identity(before) != identity(after)
            ):
                raise ValueError
            return raw
    except (OSError, ValueError, TypeError, AttributeError):
        raise PreparationError("Unsafe or inconsistent input file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def private_directory(path: Path) -> None:
    try:
        descriptor = open_private_directory(path)
        os.close(descriptor)
    except (OSError, ValueError):
        raise PreparationError("Private owned directory and trusted ancestry required") from None


def decode_json(raw: bytes, limit: int = 65536) -> Any:
    try:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
            raise ValueError
        result = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant
        )
        _bounded(result)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise PreparationError("Invalid bounded JSON document") from None


@contextmanager
def atomic_directory(output: Path) -> Iterator[Path]:
    stage = None
    parent_fd = None
    try:
        parent_fd = _directory_fd(output.absolute().parent, trusted=True, create=True)
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError
        if output.exists() or output.is_symlink():
            raise PublicationExists("Output already exists")
        stage = Path(tempfile.mkdtemp(prefix=".rf07b-", dir=output.absolute().parent))
        stage.chmod(0o700)
        yield stage
        stage_fd = open_private_directory(stage)
        try:
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        current = output.absolute().parent.lstat()
        if (current.st_dev, current.st_ino) != (parent.st_dev, parent.st_ino):
            raise ValueError
        try:
            _publish_bundle(stage, output.absolute())
        except ValueError:
            if ctypes.get_errno() in {errno.EEXIST, errno.ENOTEMPTY}:
                raise PublicationExists("Atomic output collision") from None
            raise
        stage = None
        # The directory entry and staged files must be durable before a caller
        # can reserve/send. A sync failure retains published private diagnostics.
        os.fsync(parent_fd)
    except PublicationExists:
        raise
    except (OSError, ValueError):
        raise PreparationError("Private atomic publication refused") from None
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if stage is not None:
            shutil.rmtree(stage)


def write_private(path: Path, raw: bytes) -> None:
    parent = open_private_directory(path.parent)
    try:
        descriptor = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(parent)


def verify_file(path: Path, expected_sha512: str) -> bytes:
    raw = read_file(path, MAX_MSI)
    if hashlib.sha512(raw).hexdigest() != expected_sha512:
        raise PreparationError("Pinned artifact integrity mismatch")
    return raw
