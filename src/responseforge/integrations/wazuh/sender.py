"""Explicit native delivery with bounded, immutable, durable byte recovery."""

import fcntl
import hashlib
import json
import os
import re
import ssl
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

from responseforge.integrations.wazuh.mapping import project_alert
from responseforge.integrations.wazuh.preparation_models import (
    DeliveryReceipt,
    SenderConfig,
    SenderResult,
)
from responseforge.integrations.wazuh.security import (
    PreparationError,
    PublicationExists,
    atomic_directory,
    decode_json,
    open_private_directory,
    private_directory,
    read_file,
    sync_directory,
    write_private,
)
from responseforge.runtime import IntakeResult

CONFIG_PATH = Path("/var/ossec/etc/responseforge-sender.json")


def load_config(path: Path) -> SenderConfig:
    try:
        return SenderConfig.model_validate(decode_json(read_file(path, 65536, private=True)))
    except (ValueError, OSError):
        raise PreparationError("Invalid private sender configuration") from None


def _inputs(config: SenderConfig) -> tuple[SenderConfig, str, ssl.SSLContext, str]:
    try:
        cfg = SenderConfig.model_validate(config.model_dump(mode="json"))
        outbox = Path(cfg.outbox_dir)
        if outbox.exists() or outbox.is_symlink():
            private_directory(outbox)
        else:
            private_directory(outbox.parent)
        token = (
            read_file(Path(cfg.token_file), 514, private=True)
            .decode("ascii")
            .removesuffix("\n")
            .removesuffix("\r")
        )
        if re.fullmatch(r"[A-Za-z0-9_-]{32,512}", token) is None:
            raise ValueError
        ca = read_file(Path(cfg.ca_file), 1048576)
        context = ssl.create_default_context(cadata=ca.decode("ascii"))
        binding = hashlib.sha256(
            json.dumps(
                [
                    cfg.destination,
                    cfg.source.model_dump(mode="json"),
                    hashlib.sha256(ca).hexdigest(),
                ],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return cfg, token, context, binding
    except (OSError, ValueError, UnicodeError):
        raise PreparationError("Invalid sender prerequisites") from None


@contextmanager
def _lock(root: Path) -> Iterator[None]:
    if not root.exists() and not root.is_symlink():
        try:
            with atomic_directory(root):
                pass
        except PublicationExists:
            # A simultaneous sender may have atomically published the same
            # empty private outbox. Validate it rather than replace it.
            private_directory(root)
    private_directory(root)
    sync_directory(root.parent)
    fd = os.open(root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        import stat

        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise PreparationError("Unsafe outbox lock")
        deadline = time.monotonic() + 2.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise PreparationError("Outbox is busy; no request sent") from None
                time.sleep(0.02)
        entries = [p for p in root.iterdir() if p.name != ".lock"]
        if len(entries) > 1024:
            raise PreparationError("Outbox retention bound reached")
        for entry in entries:
            if re.fullmatch(r"[0-9a-f]{64}", entry.name) is None:
                raise PreparationError("Unrecognized outbox material retained for inspection")
            private_directory(entry)
        yield
    finally:
        os.close(fd)


def _save(root: Path, receipt: DeliveryReceipt) -> None:
    data = (receipt.model_dump_json() + "\n").encode()
    if len(data) > 8192:
        raise PreparationError("Outbox receipt bound exceeded")
    parent = open_private_directory(root)
    try:
        leaf = ".receipt.pending"
        descriptor = os.open(
            leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(leaf, "receipt.json", src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _read(cfg: SenderConfig, identity: str, binding: str) -> tuple[bytes, DeliveryReceipt]:
    try:
        if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise ValueError
        root = Path(cfg.outbox_dir) / identity
        private_directory(root)
        if {p.name for p in root.iterdir()} != {"payload.bin", "receipt.json"}:
            raise ValueError
        raw = read_file(root / "payload.bin", 262144, private=True)
        receipt = DeliveryReceipt.model_validate(
            decode_json(read_file(root / "receipt.json", 8192, private=True), 8192)
        )
        observation = project_alert(raw, cfg.source)
        if (
            receipt.identity != identity
            or observation.identity_sha256 != identity
            or receipt.binding != binding
            or receipt.sha256 != observation.sha256
            or receipt.byte_count != len(raw)
        ):
            raise ValueError
        if receipt.state in {"accepted", "duplicate", "rejected", "uncertain"}:
            if (
                receipt.result is None
                or receipt.result.status != receipt.state
                or receipt.result.sha256 != receipt.sha256
                or receipt.result.byte_count != receipt.byte_count
            ):
                raise ValueError
        elif receipt.result is not None:
            raise ValueError
        return raw, receipt
    except (ValueError, OSError, TypeError):
        raise PreparationError("Original outbox source or receipt is conflicting") from None


def _result(raw: bytes, status: str) -> SenderResult:
    return SenderResult(status=status, sha256=hashlib.sha256(raw).hexdigest(), byte_count=len(raw))


def _post(
    cfg: SenderConfig,
    token: str,
    context: ssl.SSLContext,
    raw: bytes,
    transport: httpx.BaseTransport | None,
) -> SenderResult:
    try:
        deadline = time.monotonic() + cfg.timeout
        with httpx.Client(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=cfg.timeout,
            transport=transport,
        ) as client:
            with client.stream(
                "POST",
                cfg.destination,
                content=raw,
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response:
                if 400 <= response.status_code < 500:
                    return _result(raw, "rejected")
                if (
                    response.status_code not in {200, 201}
                    or response.headers.get("content-encoding", "identity").lower() != "identity"
                    or response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "application/json"
                ):
                    raise ValueError
                length = response.headers.get("content-length")
                if length is not None and (
                    not length.isascii() or not length.isdecimal() or int(length) > 8192
                ):
                    raise ValueError
                data = bytearray()
                chunks = [response.content] if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    if time.monotonic() > deadline or len(data) + len(chunk) > 8192:
                        raise ValueError
                    data.extend(chunk)
                if length is not None and len(data) != int(length):
                    raise ValueError
                result = IntakeResult.model_validate(decode_json(bytes(data), 8192))
                if result.duplicate != (response.status_code == 200):
                    raise ValueError
                return SenderResult(
                    status="duplicate" if result.duplicate else "accepted",
                    sha256=hashlib.sha256(raw).hexdigest(),
                    byte_count=len(raw),
                    incident_id=result.incident_id,
                    correlation_id=result.correlation_id,
                )
    except (httpx.HTTPError, ValueError, OSError):
        return _result(raw, "uncertain")


def _dispatch(
    cfg: SenderConfig,
    token: str,
    context: ssl.SSLContext,
    raw: bytes,
    receipt: DeliveryReceipt,
    transport: httpx.BaseTransport | None,
) -> SenderResult:
    root = Path(cfg.outbox_dir) / receipt.identity
    reserved = receipt.model_copy(update={"state": "dispatching", "result": None})
    _save(root, reserved)
    result = _post(cfg, token, context, raw, transport)
    _save(root, receipt.model_copy(update={"state": result.status, "result": result}))
    return result


def deliver(
    config: SenderConfig,
    alert_path: Path,
    *,
    send: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> SenderResult:
    try:
        cfg, token, context, binding = _inputs(config)
        if type(send) is not bool or (send and not cfg.enabled):
            raise PreparationError("Native sending is not explicitly enabled")
        path = alert_path.absolute()
        if (
            path.parent != Path(cfg.alert_root)
            or re.fullmatch(r"custom-responseforge-[0-9]{1,20}-[0-9]{1,20}\.alert", path.name)
            is None
        ):
            raise PreparationError("Alert path is outside the fixed Integrator scope")
        raw = read_file(path, 262144, owner=cfg.alert_uid)
        observation = project_alert(raw, cfg.source)
        if not send:
            return _result(raw, "dry_run")
        root = Path(cfg.outbox_dir)
        with _lock(root):
            target = root / observation.identity_sha256
            if target.exists() or target.is_symlink():
                stored, receipt = _read(cfg, observation.identity_sha256, binding)
                if stored != raw:
                    raise PreparationError("Native source identity has conflicting bytes")
                if receipt.state in {"accepted", "duplicate"}:
                    assert receipt.result is not None
                    return receipt.result.model_copy(update={"status": "cached"})
                if receipt.state != "prepared":
                    return _result(raw, "rejected" if receipt.state == "rejected" else "uncertain")
            else:
                if len([p for p in root.iterdir() if p.name != ".lock"]) >= 1024:
                    raise PreparationError("Outbox retention bound reached")
                receipt = DeliveryReceipt(
                    identity=observation.identity_sha256,
                    binding=binding,
                    sha256=observation.sha256,
                    byte_count=len(raw),
                    state="prepared",
                )
                with atomic_directory(target) as stage:
                    write_private(stage / "payload.bin", raw)
                    write_private(stage / "receipt.json", receipt.model_dump_json().encode())
            return _dispatch(cfg, token, context, raw, receipt, transport)
    except (ValueError, OSError, UnicodeError):
        raise PreparationError("Native delivery refused; inspect private state") from None


def resume(
    config: SenderConfig,
    delivery_id: str,
    *,
    send: bool = False,
    retry_uncertain: bool = False,
    retry_rejected: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> SenderResult:
    try:
        cfg, token, context, binding = _inputs(config)
        if (
            type(send) is not bool
            or type(retry_uncertain) is not bool
            or type(retry_rejected) is not bool
            or (send and not cfg.enabled)
        ):
            raise PreparationError("Native recovery is not explicitly enabled")
        # Dry-run does not create a lock file or change a reservation.
        if not send:
            raw, _ = _read(cfg, delivery_id, binding)
            return _result(raw, "dry_run")
        with _lock(Path(cfg.outbox_dir)):
            raw, receipt = _read(cfg, delivery_id, binding)
            if receipt.state in {"accepted", "duplicate"}:
                assert receipt.result is not None
                return receipt.result.model_copy(update={"status": "cached"})
            if receipt.state == "rejected":
                if not retry_rejected:
                    return _result(raw, "rejected")
            elif receipt.state != "prepared" and not retry_uncertain:
                return _result(raw, "uncertain")
            return _dispatch(cfg, token, context, raw, receipt, transport)
    except (ValueError, OSError):
        raise PreparationError("Native recovery refused; inspect original private state") from None


def integrator_main(argv: list[str] | None = None) -> int:
    arguments = sys.argv if argv is None else argv
    try:
        cfg = load_config(CONFIG_PATH)
        if len(arguments) < 2:
            raise PreparationError("Missing native alert argument")
        result = deliver(cfg, Path(arguments[1]), send=cfg.enabled)
        print(json.dumps({"status": result.status, "verified_live": False}))
        return 0 if result.status in {"dry_run", "accepted", "duplicate", "cached"} else 2
    except (ValueError, OSError):
        print("Native sender refused; inspect private configuration or outbox", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(integrator_main())
