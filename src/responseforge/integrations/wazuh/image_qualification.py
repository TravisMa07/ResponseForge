"""Controlled local image qualification; actual execution requires owner scope."""

import base64
import hashlib
import io
import json
import re
import secrets
import shutil
import subprocess
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, Protocol, TypeVar, cast

from responseforge.integrations.wazuh.process_runner import (
    BoundedProcessRunner,
    ProcessFailure,
    ProcessResult,
)
from responseforge.integrations.wazuh.security import (
    PreparationError,
    atomic_directory,
    decode_json,
    private_directory,
    read_file,
    sync_directory,
    write_private,
)

ROOT = Path(__file__).resolve().parents[4]
CODE_FILES = {
    "runner/wazuh-tls/qualify.cjs": "tools/wazuh-tls/qualify.cjs",
    "runner/wazuh-image/qualify.cjs": "tools/wazuh-image/qualify.cjs",
    "deploy/wazuh/tls-client/source.lock.json": "deploy/wazuh/tls-client/source.lock.json",
    "deploy/wazuh/packaged-client/source.lock.json": "deploy/wazuh/packaged-client/source.lock.json",
    "deploy/wazuh/image-qualification/source.lock.json": "deploy/wazuh/image-qualification/source.lock.json",
}
MATERIALS = (
    "trusted.pem",
    "other.pem",
    "good.pem",
    "good.key",
    "untrusted.pem",
    "untrusted.key",
    "wrongname.pem",
    "wrongname.key",
)


@dataclass(frozen=True)
class EngineTarget:
    context: str
    endpoint: str
    engine_id: str


@dataclass(frozen=True)
class ImagePolicy:
    parent_ref: str
    parent_id: str
    rootfs: tuple[str, ...]
    config: dict[str, Any]
    env_sha256: str
    node_path: str
    node_sha256: str
    node_size: int
    node_license_path: str
    node_license_sha256: str
    client_path: str
    client_sha256: str
    source_hashes: dict[str, str]


class Runner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        input_data: bytes = b"",
        timeout: float = 120,
        max_output: int = 1048576,
    ) -> ProcessResult: ...


def load_image_policy() -> ImagePolicy:
    value = decode_json(
        read_file(ROOT / "deploy/wazuh/image-qualification/source.lock.json", 32768)
    )
    value["rootfs"] = tuple(value["rootfs"])
    return ImagePolicy(**{f.name: value[f.name] for f in fields(ImagePolicy)})


MAX_INPUT = 2097152
LIMIT_OUTPUT = 2097152
MEMORY = 1073741824
NANO_CPUS = 2000000000
TMPFS = "rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=1000,gid=1000"
RUNTIME_FILES = tuple(CODE_FILES.values()) + (
    "src/responseforge/integrations/wazuh/image_qualification.py",
    "src/responseforge/integrations/wazuh/process_runner.py",
    "src/responseforge/integrations/wazuh/security.py",
    "scripts/wazuh_image.py",
    "tools/wazuh-image/bootstrap.cjs",
    "tools/wazuh-image/prepare.cjs",
)
SCENARIOS = {
    "original_insecure_baseline",
    "trusted_CA_matching_SAN",
    "missing_CA",
    "different_CA",
    "untrusted_chain",
    "wrong_SAN",
    "environment_TLS_zero",
    "plain_HTTP",
    "URL_credentials",
    "URL_control",
    "HTTPS_redirect",
    "HTTP_redirect",
    "hostile_proxy",
}
LISTENERS = {"good", "untrusted", "wrongname", "plain", "proxy", "redirectHTTPS", "redirectHTTP"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(path: Path, maximum: int = 262144) -> dict[str, Any]:
    value = decode_json(read_file(path, maximum, private=True), maximum)
    if not isinstance(value, dict):
        raise PreparationError("Bounded object required")
    return cast(dict[str, Any], value)


def _record(path: Path, value: Any) -> None:
    write_private(path, _canonical(value) + b"\n")
    sync_directory(path.parent)


def _now() -> datetime:
    return datetime.now(UTC)


def _revision() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=5, text=True
    ).strip()


def _dirty() -> bool:
    return bool(
        subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, timeout=5
        )
    )


def _fingerprint() -> str:
    return _sha(
        _canonical(
            {name: _sha(read_file(ROOT / name, 524288)) for name in sorted(set(RUNTIME_FILES))}
        )
    )


def _target(value: EngineTarget) -> None:
    from urllib.parse import urlsplit

    endpoint = urlsplit(value.endpoint)
    if (
        not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", value.context)
        or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}", value.engine_id)
        or endpoint.scheme != "unix"
        or endpoint.netloc
        or endpoint.query
        or endpoint.fragment
        or not endpoint.path.startswith("/")
        or ".." in Path(endpoint.path).parts
        or any(ord(c) < 32 for c in value.endpoint)
    ):
        raise PreparationError("Explicit local engine identity required")


def _policy(policy: ImagePolicy) -> None:
    if (
        not re.fullmatch(r"wazuh/wazuh-dashboard@sha256:[0-9a-f]{64}", policy.parent_ref)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", policy.parent_id)
        or len(policy.rootfs) != 13
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", f) for f in policy.rootfs)
        or policy.node_path != "/usr/share/wazuh-dashboard/node/bin/node"
        or policy.client_path
        != "/usr/share/wazuh-dashboard/plugins/wazuhCore/server/services/server-api-client.js"
        or type(policy.node_size) is not int
        or not 0 < policy.node_size <= 134217728
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", x)
            for x in (
                policy.env_sha256,
                policy.node_sha256,
                policy.node_license_sha256,
                policy.client_sha256,
            )
        )
        or policy.config.get("OnBuild")
        or policy.config.get("Volumes")
        or policy.config.get("Healthcheck")
        or set(policy.source_hashes)
        != {
            "bundle/upstream-server-api-client.ts",
            "bundle/server-api-client.ts",
            "bundle/cookie.ts",
            "bundle/LICENSE",
            "original/server-api-client.js",
        }
        or any(not re.fullmatch(r"[0-9a-f]{64}", x) for x in policy.source_hashes.values())
    ):
        raise PreparationError("Fixed image policy required")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _fixture(raw: bytes, policy: ImagePolicy) -> dict[str, Any]:
    try:
        if not 0 < len(raw) <= MAX_INPUT:
            raise ValueError
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (
            set(value) != {"schema_version", "files", "material_generator"}
            or value["schema_version"] != "1.0"
            or not isinstance(value["material_generator"], str)
            or len(value["material_generator"]) > 256
            or not isinstance(value["files"], dict)
        ):
            raise ValueError
        expected = (
            set(CODE_FILES) | set(policy.source_hashes) | {"materials/" + n for n in MATERIALS}
        )
        if set(value["files"]) != expected or len(expected) > 32:
            raise ValueError
        total = 0
        for name, encoded in value["files"].items():
            if not isinstance(encoded, str) or len(encoded) > 1048576:
                raise ValueError
            data = base64.b64decode(encoded, validate=True)
            total += len(data)
            if total > 1048576:
                raise ValueError
            if name in CODE_FILES:
                if _sha(data) != _sha(read_file(ROOT / CODE_FILES[name], 524288)):
                    raise ValueError
            elif name in policy.source_hashes:
                if _sha(data) != policy.source_hashes[name]:
                    raise ValueError
            elif not 0 < len(data) <= 16384 or not data.startswith(b"-----BEGIN "):
                raise ValueError
        return cast(dict[str, Any], value)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise PreparationError("Reviewed bounded fixture inputs required") from None


def _binary() -> dict[str, str] | None:
    found = shutil.which("docker")
    if found is None:
        return None
    path = Path(found).resolve(strict=True)
    return {"path": str(path), "sha256": _sha(read_file(path, 134217728))}


def prepare_run(
    bundle: Path,
    fixture: Path,
    output: Path,
    target: EngineTarget,
    policy: ImagePolicy | None = None,
) -> Path:
    selected = policy or load_image_policy()
    _target(target)
    _policy(selected)
    private_directory(bundle)
    raw = read_file(fixture, MAX_INPUT, private=True)
    _fixture(raw, selected)
    patched = read_file(bundle / "patched/server-api-client.js", 65536)
    context_patch = read_file(bundle / "build-context/server-api-client.js", 65536)
    dockerfile = read_file(bundle / "build-context/Dockerfile", 8192)
    expected = (
        "FROM "
        + selected.parent_ref
        + "\nCOPY --chown=1000:1000 --chmod=0644 server-api-client.js "
        + selected.client_path
        + "\n"
    ).encode()
    if (
        _sha(patched) != selected.client_sha256
        or context_patch != patched
        or dockerfile != expected
    ):
        raise PreparationError("Exact private C3 context required")
    bootstrap = read_file(ROOT / "tools/wazuh-image/bootstrap.cjs", 32768)
    run_id = secrets.token_hex(16)
    fingerprint = _fingerprint()
    now = _now()
    files = {
        "context/Dockerfile": dockerfile,
        "context/server-api-client.js": patched,
        "fixture.json": raw,
        "bootstrap.cjs": bootstrap,
    }
    plan = {
        "schema_version": "1.0",
        "run_id": run_id,
        "nonce": secrets.token_hex(32),
        "target": asdict(target),
        "source_revision": _revision(),
        "source_fingerprint": fingerprint,
        "policy_fingerprint": _sha(_canonical(asdict(selected))),
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
        "test_policy": policy is not None,
        "files": {name: _sha(data) for name, data in files.items()},
        "image_tag": "responseforge/rf07-dashboard-tls:" + run_id,
        "container_name": "rf07c4-" + run_id,
        "labels": {
            "io.responseforge.work": "rf07c4",
            "io.responseforge.run": run_id,
            "io.responseforge.source": fingerprint,
        },
        "docker_binary": _binary() if policy is None else None,
    }
    with atomic_directory(output) as stage:
        (stage / "context").mkdir(mode=0o700)
        for name, data in files.items():
            write_private(stage / name, data)
        sync_directory(stage / "context")
        _record(stage / "plan.json", plan)
        write_private(
            stage / "plan.sha256",
            (_sha(read_file(stage / "plan.json", 32768, private=True)) + "\n").encode(),
        )
    return output


def _load(run_dir: Path, policy: ImagePolicy, *, strict: bool = True) -> dict[str, Any]:
    private_directory(run_dir)
    raw = read_file(run_dir / "plan.json", 32768, private=True)
    if read_file(run_dir / "plan.sha256", 128, private=True).decode().strip() != _sha(raw):
        raise PreparationError("Private plan changed")
    plan = _json(run_dir / "plan.json", 32768)
    _policy(policy)
    target = EngineTarget(**plan["target"])
    _target(target)
    if (
        plan.get("schema_version") != "1.0"
        or not re.fullmatch(r"[0-9a-f]{32}", plan["run_id"])
        or not re.fullmatch(r"[0-9a-f]{64}", plan["nonce"])
        or plan["policy_fingerprint"] != _sha(_canonical(asdict(policy)))
        or plan["image_tag"] != "responseforge/rf07-dashboard-tls:" + plan["run_id"]
        or plan["container_name"] != "rf07c4-" + plan["run_id"]
        or plan["labels"]
        != {
            "io.responseforge.work": "rf07c4",
            "io.responseforge.run": plan["run_id"],
            "io.responseforge.source": plan["source_fingerprint"],
        }
    ):
        raise PreparationError("Invalid bound plan")
    if strict:
        created, expires = (
            datetime.fromisoformat(plan["created_at"]),
            datetime.fromisoformat(plan["expires_at"]),
        )
        if (
            created.tzinfo is None
            or expires.tzinfo is None
            or expires - created != timedelta(hours=24)
            or not created <= _now() < expires
            or plan["source_revision"] != _revision()
            or plan["source_fingerprint"] != _fingerprint()
        ):
            raise PreparationError("Expired or changed source plan; reprepare")
        if {p.name for p in (run_dir / "context").iterdir()} != {
            "Dockerfile",
            "server-api-client.js",
        }:
            raise PreparationError("Extra build context refused")
        _verified_inputs(run_dir, plan, policy)
    return plan


def _verified_inputs(run_dir: Path, plan: dict[str, Any], policy: ImagePolicy) -> dict[str, bytes]:
    names = {"context/Dockerfile", "context/server-api-client.js", "fixture.json", "bootstrap.cjs"}
    if not isinstance(plan.get("files"), dict) or set(plan["files"]) != names:
        raise PreparationError("Exact four-file input manifest required")
    data = {name: read_file(run_dir / name, MAX_INPUT, private=True) for name in names}
    if any(_sha(raw) != plan["files"][name] for name, raw in data.items()):
        raise PreparationError("Prepared input changed")
    expected = (
        "FROM "
        + policy.parent_ref
        + "\nCOPY --chown=1000:1000 --chmod=0644 server-api-client.js "
        + policy.client_path
        + "\n"
    ).encode()
    if (
        data["context/Dockerfile"] != expected
        or _sha(data["context/server-api-client.js"]) != policy.client_sha256
        or data["bootstrap.cjs"] != read_file(ROOT / "tools/wazuh-image/bootstrap.cjs", 32768)
    ):
        raise PreparationError("Reviewed executable input identity required")
    _fixture(data["fixture.json"], policy)
    return data


def _context_archive(data: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("Dockerfile", "server-api-client.js"):
            raw = data["context/" + name]
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(raw), 0o644
            archive.addfile(info, io.BytesIO(raw))
    result = output.getvalue()
    if len(result) > MAX_INPUT:
        raise PreparationError("Build context size exceeded")
    return result


class _Docker:
    def __init__(self, run_dir: Path, plan: dict[str, Any], runner: Runner | None) -> None:
        self.run_dir, self.plan = run_dir, plan
        self.native = runner is None
        self.runner: Runner = runner or BoundedProcessRunner()
        if self.native:
            binary = _binary()
            if binary is None or binary != plan["docker_binary"]:
                raise PreparationError("Docker executable identity changed; reprepare")
            executable = binary["path"]
        else:
            executable = "docker"
        self.prefix = [executable, "--context", plan["target"]["context"]]
        logs = run_dir / "logs"
        if not logs.exists():
            logs.mkdir(mode=0o700)
        private_directory(logs)
        self.counter = len(list(logs.glob("*.request.json")))

    def call(self, args: list[str], *, data: bytes = b"", timeout: float = 120) -> ProcessResult:
        self.counter += 1
        name = f"{self.counter:04d}"
        argv = self.prefix + args
        _record(
            self.run_dir / "logs" / (name + ".request.json"),
            {"argv": argv, "stdin_sha256": _sha(data), "stdin_bytes": len(data)},
        )
        try:
            result = self.runner.run(
                argv, input_data=data, timeout=timeout, max_output=LIMIT_OUTPUT
            )
        except ProcessFailure as error:
            write_private(self.run_dir / "logs" / (name + ".stdout"), error.stdout)
            write_private(self.run_dir / "logs" / (name + ".stderr"), error.stderr)
            sync_directory(self.run_dir / "logs")
            raise
        write_private(self.run_dir / "logs" / (name + ".stdout"), result.stdout)
        write_private(self.run_dir / "logs" / (name + ".stderr"), result.stderr)
        sync_directory(self.run_dir / "logs")
        if result.returncode != 0:
            raise PreparationError("Docker operation failed; retained private diagnostics")
        return result

    def obj(self, args: list[str]) -> dict[str, Any]:
        value = decode_json(self.call(args).stdout, LIMIT_OUTPUT)
        if not isinstance(value, dict):
            raise PreparationError("Docker object required")
        return cast(dict[str, Any], value)


def _engine(gateway: _Docker, plan: dict[str, Any]) -> dict[str, Any]:
    target = plan["target"]
    context = gateway.obj(["context", "inspect", target["context"], "--format", "{{json .}}"])
    if context["Endpoints"]["docker"]["Host"] != target["endpoint"]:
        raise PreparationError("Docker endpoint mismatch")
    info = gateway.obj(["info", "--format", "{{json .}}"])
    if (
        info["ID"] != target["engine_id"]
        or info["Architecture"] not in {"aarch64", "arm64"}
        or info["MemTotal"] < 2147483648
        or info["NCPU"] < 2
        or info["Swarm"]["LocalNodeState"] != "inactive"
        or info.get("ServerErrors")
    ):
        raise PreparationError("Docker engine identity/resources mismatch")
    return {
        "engine_id": info["ID"],
        "architecture": info["Architecture"],
        "memory": info["MemTotal"],
        "cpus": info["NCPU"],
        "swarm": "inactive",
    }


def preflight_run(
    run_dir: Path, runner: Runner | None = None, policy: ImagePolicy | None = None
) -> dict[str, Any]:
    selected = policy or load_image_policy()
    plan = _load(run_dir, selected)
    gateway = _Docker(run_dir, plan, runner)
    info = _engine(gateway, plan)
    return {
        "preflight_passed": True,
        "execution_authorized": False,
        "qualified": False,
        "native_adapter": gateway.native,
        "engine": info,
        "run_id": plan["run_id"],
    }


def _image(
    value: dict[str, Any], policy: ImagePolicy, plan: dict[str, Any], *, derived: bool
) -> str:
    config = value["Config"]
    layers = value["RootFS"]["Layers"]
    if (
        value["Os"] != "linux"
        or value["Architecture"] != "arm64"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["Id"])
        or (not derived and value["Id"] != policy.parent_id)
        or tuple(layers[:13]) != policy.rootfs
        or len(layers) != (14 if derived else 13)
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in layers)
        or config.get("OnBuild")
        or config.get("Volumes")
        or config.get("Healthcheck")
        or _sha(_canonical(config["Env"])) != policy.env_sha256
    ):
        raise PreparationError("Immutable image identity/config mismatch")
    for key in ("User", "WorkingDir", "Entrypoint", "Cmd", "ExposedPorts", "Shell", "StopSignal"):
        if config.get(key) != policy.config.get(key):
            raise PreparationError("Image runtime config changed")
    if (config.get("Labels") or {}) != (plan["labels"] if derived else {}):
        raise PreparationError("Image ownership labels mismatch")
    return cast(str, value["Id"])


def _owned(value: dict[str, Any], plan: dict[str, Any], image: str, cid: str | None = None) -> str:
    actual = value["Id"]
    if (
        not re.fullmatch(r"[0-9a-f]{64}", actual)
        or cid is not None
        and actual != cid
        or value["Name"] != "/" + plan["container_name"]
        or value["Image"] != image
        or (value["Config"].get("Labels") or {}) != plan["labels"]
    ):
        raise PreparationError("Container is not bound to this exact private intent")
    return cast(str, actual)


def _contained(value: dict[str, Any], policy: ImagePolicy, bootstrap: str) -> None:
    host, config = value["HostConfig"], value["Config"]
    if (
        config["Entrypoint"] != [policy.node_path]
        or config["Cmd"] != ["-e", bootstrap]
        or config["User"] != "1000:1000"
        or config["WorkingDir"] != "/tmp"
        or config.get("Tty")
        or config.get("Healthcheck", {}).get("Test") != ["NONE"]
        or host["NetworkMode"] != "none"
        or host["ReadonlyRootfs"] is not True
        or host.get("Privileged")
        or host.get("CapAdd")
        or host["CapDrop"] != ["ALL"]
        or host["Memory"] != MEMORY
        or host["NanoCpus"] != NANO_CPUS
        or host["PidsLimit"] != 128
        or host.get("SecurityOpt")
        not in [["no-new-privileges"], ["no-new-privileges:true"], ["no-new-privileges=true"]]
        or host.get("Binds")
        or host.get("PortBindings")
        or host.get("PublishAllPorts")
        or host.get("Devices")
        or host.get("DeviceRequests")
        or host.get("DeviceCgroupRules")
        or host.get("VolumesFrom")
        or host.get("Links")
        or host.get("ExtraHosts")
        or host.get("PidMode")
        or host.get("UTSMode")
        or host.get("UsernsMode")
        or host.get("IpcMode") != "private"
        or host.get("CgroupnsMode") != "private"
        or host.get("AutoRemove")
        or host.get("Tmpfs") != {"/tmp": TMPFS}
    ):
        raise PreparationError("Fixture containment mismatch")
    for mount in value.get("Mounts", []):
        if mount.get("Type") != "tmpfs" or mount.get("Destination") != "/tmp":
            raise PreparationError("Host/volume mount refused")
    if any(v for v in value.get("NetworkSettings", {}).get("Ports", {}).values()):
        raise PreparationError("Published port refused")


def _proof(
    value: dict[str, Any],
    plan: dict[str, Any],
    policy: ImagePolicy,
    image: str,
    input_sha: str,
    fixture: dict[str, Any],
) -> None:
    required = {
        "schema_version": "1.0",
        "passed": True,
        "qualification_run_id": plan["run_id"],
        "qualification_nonce": plan["nonce"],
        "fixture_input_sha256": input_sha,
        "image_id": image,
        "node_executable_sha256": policy.node_sha256,
        "node_license_sha256": policy.node_license_sha256,
        "platform": "linux",
        "architecture": "arm64",
        "uid": 1000,
        "gid": 1000,
        "installed_corrected_module": policy.client_path,
        "packaged_corrected_sha256": policy.client_sha256,
        "selected_files": 297,
        "module_resolution_guard": True,
        "parent_artifact_execution": False,
        "dashboard_started": False,
        "manager_started": False,
    }
    for key, expected in required.items():
        if value.get(key) != expected or type(value.get(key)) is not type(expected):
            raise PreparationError("Native image proof identity mismatch")
    for key, source in (
        ("harness_sha256", "runner/wazuh-tls/qualify.cjs"),
        ("wrapper_sha256", "runner/wazuh-image/qualify.cjs"),
    ):
        if value.get(key) != _sha(base64.b64decode(fixture["files"][source], validate=True)):
            raise PreparationError("Native harness identity mismatch")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?", value.get("node", "")):
        raise PreparationError("Actual bundled Node version required")
    scenarios = value.get("scenarios", {})
    if set(scenarios) != SCENARIOS:
        raise PreparationError("Native case matrix incomplete")
    baseline = scenarios["original_insecure_baseline"]
    if (
        any(
            type(baseline.get(k)) is not int
            for k in ("authHTTP", "requestHTTP", "outside_module_resolutions")
        )
        or baseline.get("loaded") is not True
        or baseline.get("authHTTP") != 1
        or baseline.get("requestHTTP") != 1
        or baseline.get("module_guard") is not True
        or baseline.get("outside_module_resolutions") != 0
        or baseline.get("secure_assertion") != "FAIL: untrusted certificate accepted"
    ):
        raise PreparationError("Genuine original insecurity not reproduced")
    for name in SCENARIOS - {"original_insecure_baseline"}:
        scenario = scenarios[name]
        result, delta = scenario["result"], scenario["delta"]
        if (
            result.get("loaded") is not True
            or result.get("axios") != "1.18.1"
            or result.get("module_guard") is not True
            or type(result.get("outside_module_resolutions")) is not int
            or result.get("outside_module_resolutions") != 0
            or set(delta) != LISTENERS
        ):
            raise PreparationError("Native case setup/guard missing")
        for counters in delta.values():
            if (
                set(counters) != {"auth", "request", "badIdentity"}
                or any(type(v) is not int or v < 0 for v in counters.values())
                or counters["badIdentity"] != 0
            ):
                raise PreparationError("Native HTTP observations invalid")
        success = name in {"trusted_CA_matching_SAN", "hostile_proxy"}
        redirect = name in {"HTTPS_redirect", "HTTP_redirect"}
        for method in ("authenticate", "request"):
            observed = result[method]
            if observed.get("success") is not success:
                raise PreparationError("Native case outcome mismatch")
            if success and observed.get("valid") is not True:
                raise PreparationError("Native application identity mismatch")
            if redirect and (
                type(observed.get("status")) is not int or observed.get("status") != 302
            ):
                raise PreparationError("Native redirect not observed")
            if not success and not redirect:
                if name in {"plain_HTTP", "URL_credentials", "URL_control"}:
                    if observed.get("policy") is not True:
                        raise PreparationError("Expected URL refusal missing")
                elif observed.get("code") != (
                    "ERR_TLS_CERT_ALTNAME_INVALID"
                    if name == "wrong_SAN"
                    else "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
                ):
                    raise PreparationError("Expected actual TLS refusal missing")
        listener = (
            "good"
            if success
            else "redirectHTTPS"
            if name == "HTTPS_redirect"
            else "redirectHTTP"
            if redirect
            else None
        )
        for key, counters in delta.items():
            if counters["auth"] != (1 if key == listener else 0) or counters["request"] != (
                1 if key == listener else 0
            ):
                raise PreparationError("Credential/request routing mismatch")


def _cleanup(gateway: _Docker, plan: dict[str, Any], image: str, cid: str | None = None) -> bool:
    _engine(gateway, plan)
    value = gateway.obj(
        ["container", "inspect", cid or plan["container_name"], "--format", "{{json .}}"]
    )
    owned = _owned(value, plan, image, cid)
    if value["State"]["Running"]:
        gateway.call(["stop", "--time", "5", owned], timeout=15)
    _engine(gateway, plan)
    gateway.call(["rm", owned])
    remaining = gateway.call(
        ["container", "ls", "--all", "--no-trunc", "--filter", "id=" + owned, "--format", "{{.ID}}"]
    )
    if remaining.stdout.strip():
        raise PreparationError("Owned fixture cleanup not observed")
    return True


def execute_run(
    run_dir: Path,
    *,
    allow_image_build: bool = False,
    allow_isolated_fixture: bool = False,
    runner: Runner | None = None,
    policy: ImagePolicy | None = None,
) -> dict[str, Any]:
    if allow_image_build is not True or allow_isolated_fixture is not True:
        raise PreparationError("Separate owner grant and both explicit execution flags required")
    selected = policy or load_image_policy()
    plan = _load(run_dir, selected)
    if (run_dir / "execution.json").exists() or (run_dir / "execution.json").is_symlink():
        raise PreparationError("Execution already reserved; recover without replay")
    inputs = _verified_inputs(run_dir, plan, selected)
    archive = _context_archive(inputs)
    fixture = _fixture(inputs["fixture.json"], selected)
    bootstrap = inputs["bootstrap.cjs"].decode()
    gateway = _Docker(run_dir, plan, runner)
    if gateway.native and (policy is not None or plan["test_policy"] or _dirty()):
        raise PreparationError("Native execution requires clean reviewed default policy")
    _engine(gateway, plan)
    _record(
        run_dir / "execution.json",
        {
            "run_id": plan["run_id"],
            "source": plan["source_fingerprint"],
            "native_adapter": gateway.native,
            "phase": "RESERVED",
            "qualified": False,
        },
    )
    image: str | None = None
    cid: str | None = None
    intent = False
    try:
        _engine(gateway, plan)
        gateway.call(
            ["pull", "--quiet", "--platform=linux/arm64", selected.parent_ref], timeout=240
        )
        parent = gateway.obj(["image", "inspect", selected.parent_ref, "--format", "{{json .}}"])
        _image(parent, selected, plan, derived=False)
        _engine(gateway, plan)
        args = [
            "build",
            "--pull=false",
            "--network=none",
            "--platform=linux/arm64",
            "--iidfile",
            str(run_dir / "image.iid"),
            "--tag",
            plan["image_tag"],
        ]
        for key, value in plan["labels"].items():
            args += ["--label", key + "=" + value]
        write_private(run_dir / "context-archive.tar", archive)
        sync_directory(run_dir)
        gateway.call(args + ["--file", "Dockerfile", "-"], data=archive, timeout=240)
        image = read_file(run_dir / "image.iid", 128).decode().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image) or image == selected.parent_id:
            raise PreparationError("New immutable image identity required")
        inspected_id = _image(
            gateway.obj(["image", "inspect", image, "--format", "{{json .}}"]),
            selected,
            plan,
            derived=True,
        )
        if inspected_id != image:
            raise PreparationError("Inspected image differs from produced IID")
        _record(run_dir / "image.json", {"id": image, "native_adapter": gateway.native})
        fixture["session"] = {"run_id": plan["run_id"], "nonce": plan["nonce"], "image_id": image}
        stdin = _canonical(fixture) + b"\n"
        if len(stdin) > MAX_INPUT:
            raise PreparationError("Runtime input size exceeded")
        write_private(run_dir / "runtime-input.json", stdin)
        sync_directory(run_dir)
        _record(
            run_dir / "container-intent.json",
            {
                "name": plan["container_name"],
                "image_id": image,
                "labels": plan["labels"],
                "input_sha256": _sha(stdin),
            },
        )
        intent = True
        create = [
            "create",
            "--interactive",
            "--name",
            plan["container_name"],
            "--entrypoint",
            selected.node_path,
            "--user",
            "1000:1000",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            str(MEMORY),
            "--cpus",
            "2",
            "--pids-limit",
            "128",
            "--no-healthcheck",
            "--ipc",
            "private",
            "--cgroupns",
            "private",
            "--workdir",
            "/tmp",
            "--tmpfs",
            "/tmp:" + TMPFS,
        ]
        for key, value in plan["labels"].items():
            create += ["--label", key + "=" + value]
        for key in (
            "NODE_OPTIONS",
            "NODE_PATH",
            "NODE_EXTRA_CA_CERTS",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ):
            create += ["--env", key + "="]
        create += ["--env", "NODE_TLS_REJECT_UNAUTHORIZED=1", image, "-e", bootstrap]
        _engine(gateway, plan)
        received_cid = gateway.call(create).stdout.decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", received_cid):
            raise PreparationError("Exact fixture CID required")
        cid = received_cid
        _record(run_dir / "container.json", {"id": cid, "image_id": image})
        before = gateway.obj(["container", "inspect", cid, "--format", "{{json .}}"])
        _owned(before, plan, image, cid)
        _contained(before, selected, bootstrap)
        if before["State"]["Running"]:
            raise PreparationError("Fixture must be inspected before startup")
        _engine(gateway, plan)
        result = gateway.call(["start", "--attach", "--interactive", cid], data=stdin, timeout=240)
        proof = decode_json(result.stdout, LIMIT_OUTPUT)
        if not isinstance(proof, dict):
            raise PreparationError("Native proof object required")
        _proof(proof, plan, selected, image, _sha(stdin), fixture)
        _record(run_dir / "proof.json", proof)
        after = gateway.obj(["container", "inspect", cid, "--format", "{{json .}}"])
        _owned(after, plan, image, cid)
        _contained(after, selected, bootstrap)
        if (
            after["State"]["Running"]
            or after["State"]["ExitCode"] != 0
            or after["State"].get("OOMKilled")
            or after["State"].get("Error")
        ):
            raise PreparationError("Fixture exit proof missing")
        _cleanup(gateway, plan, image, cid)
        report = {
            "phase": "COMPLETE",
            "native_adapter": gateway.native,
            "qualified": gateway.native,
            "image_built": gateway.native,
            "image_executed": gateway.native,
            "image_id": image,
            "cleanup_verified": True,
            "run_id": plan["run_id"],
            "dashboard_started": False,
            "manager_started": False,
            "live_endpoint_verified": False,
        }
        _record(run_dir / "result.json", report)
        return report
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        cleaned = False
        if intent and image is not None:
            try:
                cleaned = _cleanup(gateway, plan, image, cid)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
                pass
        _record(
            run_dir / "failure.json",
            {
                "phase": "UNCERTAIN",
                "qualified": False,
                "native_adapter": gateway.native,
                "cleanup_verified": cleaned,
                "run_id": plan["run_id"],
            },
        )
        raise PreparationError(
            "Execution failed; retained diagnostics and ownership recovery required"
        ) from None


def recover_run(
    run_dir: Path,
    *,
    allow_owned_cleanup: bool = False,
    runner: Runner | None = None,
    policy: ImagePolicy | None = None,
) -> dict[str, Any]:
    if allow_owned_cleanup is not True:
        raise PreparationError("Explicit exact-owned cleanup acknowledgement required")
    selected = policy or load_image_policy()
    plan = _load(run_dir, selected, strict=False)
    reservation = _json(run_dir / "execution.json")
    if (
        reservation.get("run_id") != plan["run_id"]
        or reservation.get("source") != plan["source_fingerprint"]
        or reservation.get("phase") != "RESERVED"
        or reservation.get("qualified") is not False
    ):
        raise PreparationError("Foreign execution reservation refused")
    image = _json(run_dir / "image.json")["id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise PreparationError("Exact recovery image required")
    intent = _json(run_dir / "container-intent.json")
    if (
        intent["name"] != plan["container_name"]
        or intent["image_id"] != image
        or intent["labels"] != plan["labels"]
    ):
        raise PreparationError("Private recovery binding mismatch")
    gateway = _Docker(run_dir, plan, runner)
    if gateway.native and (plan["test_policy"] or reservation.get("native_adapter") is not True):
        raise PreparationError("Synthetic reservation cannot authorize native cleanup")
    recorded_cid = None
    if (run_dir / "container.json").exists():
        record = _json(run_dir / "container.json")
        recorded_cid = record["id"]
        if record["image_id"] != image or not re.fullmatch(r"[0-9a-f]{64}", recorded_cid):
            raise PreparationError("Recovery CID binding mismatch")
    _cleanup(gateway, plan, image, recorded_cid)
    report = {
        "phase": "RECOVERED_CLEANUP",
        "qualified": False,
        "cleanup_verified": True,
        "native_adapter": gateway.native,
    }
    _record(run_dir / "recovery.json", report)
    return report


_P = ParamSpec("_P")
_T = TypeVar("_T")


def _safe(function: Callable[_P, _T]) -> Callable[_P, _T]:
    @wraps(function)
    def guarded(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return function(*args, **kwargs)
        except PreparationError:
            raise
        except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
            raise PreparationError("Image operation refused; inspect private diagnostics") from None

    return guarded


prepare_run = _safe(prepare_run)
preflight_run = _safe(preflight_run)
execute_run = _safe(execute_run)
recover_run = _safe(recover_run)
