"""Explicit-engine, private-state lifecycle for the RF-04 lab only."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from responseforge.__main__ import write_initial_config
from responseforge.integrations.shuffle.runtime_deployment import render_runtime

PROJECT = "responseforge-rf04"
LABEL = "responseforge.project"


def _seed_files(target: Path, source: Path, *, state: Path | None = None) -> None:
    """Atomically replace helper-owned read-only files on the two lab volumes."""
    if target.is_symlink() or source.is_symlink():
        raise ValueError("Invalid private volume seed path")
    for name in ("callback.json", "ca.pem"):
        origin, destination = source / name, target / name
        if origin.is_symlink() or destination.is_symlink() or origin.stat().st_size > 65536:
            raise ValueError("Invalid private volume seed file")
        descriptor, temporary = tempfile.mkstemp(prefix=".seed-", dir=target)
        path = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(origin.read_bytes())
                output.flush()
                os.fsync(output.fileno())
            path.chmod(0o444)
            path.replace(destination)
        finally:
            path.unlink(missing_ok=True)
    if state is not None:
        os.chown(state, 1000, 1000)


def _write(path: Path, value: str, *, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value)


def _tool(argv: list[str], *, data: str | None = None) -> str:
    try:
        result = subprocess.run(
            argv, input=data, capture_output=True, text=True, timeout=60, check=False
        )
        if result.returncode:
            raise ValueError
        return result.stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ValueError("Private bootstrap tool failed; no secret output is displayed") from None


def _certificates(state: Path) -> None:
    pki = state / "pki"
    pki.mkdir(mode=0o700)
    ca_key, ca_cert = pki / "ca-key.pem", pki / "ca.pem"
    ca_config = pki / "ca.cnf"
    _write(
        ca_config,
        "[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n",
    )
    _tool(["openssl", "genrsa", "-out", str(ca_key), "2048"])
    ca_key.chmod(0o600)
    _tool(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-sha256",
            "-key",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "365",
            "-subj",
            "/CN=responseforge-rf04-CA",
            "-config",
            str(ca_config),
            "-extensions",
            "v3_ca",
        ]
    )
    for name, subject, san in (
        ("frontend", "shuffle-frontend", "DNS:shuffle-frontend,DNS:localhost,IP:127.0.0.1"),
        ("core", "responseforge-core", "DNS:responseforge-core,DNS:localhost,IP:127.0.0.1"),
        ("opensearch", "shuffle-opensearch", "DNS:shuffle-opensearch"),
    ):
        key, csr, certificate = (
            pki / (name + "-key.pem"),
            pki / (name + ".csr"),
            pki / (name + ".pem"),
        )
        extension = pki / (name + ".ext")
        _write(
            extension,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\nsubjectAltName="
            + san
            + "\n",
        )
        _tool(["openssl", "genrsa", "-out", str(key), "2048"])
        # OpenSearch requires an unencrypted PKCS8 private key.
        converted = pki / (name + "-converted.pem")
        _tool(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key), "-out", str(converted)])
        converted.replace(key)
        _tool(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key),
                "-out",
                str(csr),
                "-subj",
                "/CN=" + subject,
            ]
        )
        _tool(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-CAserial",
                str(pki / "ca.srl"),
                "-out",
                str(certificate),
                "-days",
                "30",
                "-sha256",
                "-extfile",
                str(extension),
            ]
        )
        csr.unlink()
        extension.unlink()
        # Parent 0700 prevents other host users reading these. Individual binds
        # must be readable by the unprivileged service UID inside its container.
        key.chmod(0o444)
        certificate.chmod(0o444)
    ca_cert.chmod(0o444)


def initialize(
    state_dir: Path,
    images: dict[str, str],
    *,
    context: str,
    engine_id: str,
    architecture: str,
    authorized: bool = False,
) -> None:
    """Create exclusive private credentials/certificates and a concrete plan."""
    if (
        not state_dir.is_absolute()
        or state_dir.exists()
        or state_dir.is_symlink()
        or any(parent.is_symlink() for parent in state_dir.parents)
        or architecture not in {"amd64", "arm64"}
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context)
        or not isinstance(engine_id, str)
        or not 1 <= len(engine_id) <= 128
        or any(ord(c) < 33 or ord(c) > 126 for c in engine_id)
        or type(authorized) is not bool
    ):
        raise ValueError("Invalid or existing private pilot state")
    rendered = render_runtime(images, state_dir, engine_authorized=authorized)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    _certificates(state_dir)
    password = secrets.token_urlsafe(32) + "Aa1!"
    hasher = shutil.which("htpasswd") or "/usr/sbin/htpasswd"
    hashed = _tool([hasher, "-niBC", "12", "admin"], data=password + "\n").strip()
    if not re.fullmatch(r"admin:\$2[aby]\$12\$[./A-Za-z0-9]{53}", hashed):
        raise ValueError("OpenSearch password hash unavailable")
    _write(
        state_dir / "internal_users.yml",
        "_meta:\n  type: internalusers\n  config_version: 2\nadmin:\n  hash: "
        + json.dumps(hashed.partition(":")[2])
        + "\n  reserved: true\n  backend_roles: [admin]\n",
        mode=0o444,
    )
    queue = secrets.token_urlsafe(32)
    env = {
        "SHUFFLE_DEFAULT_USERNAME": "rf04-admin@localhost",
        "SHUFFLE_DEFAULT_PASSWORD": secrets.token_urlsafe(32),
        "SHUFFLE_DEFAULT_APIKEY": secrets.token_urlsafe(32),
        "SHUFFLE_OPENSEARCH_PASSWORD": password,
        "SHUFFLE_ENCRYPTION_MODIFIER": secrets.token_urlsafe(32),
        "RF_QUEUE_TOKEN": queue,
        "AUTH": queue,
        "ORG": "",
    }
    _write(
        state_dir / "secrets.env", "".join(key + "=" + value + "\n" for key, value in env.items())
    )
    write_initial_config(state_dir / "core.json")
    core = json.loads((state_dir / "core.json").read_text())
    core.update(
        database_path="/var/lib/responseforge/cases.sqlite3",
        environment="rf04-docker-pilot",
        revision="rf04-runtime-local",
    )
    for actor in core["credentials"].values():
        if actor["roles"] == ["source"]:
            actor["sources"] = ["synthetic"]
    (state_dir / "core.json").write_text(json.dumps(core, indent=2) + "\n")
    (state_dir / "core.json").chmod(0o444)
    token = next(
        key for key, actor in core["credentials"].items() if actor["roles"] == ["workflow"]
    )
    _write(
        state_dir / "callback.json",
        json.dumps(
            {
                "base_url": "https://responseforge-core:8000",
                "api_key": token,
                "workflow_ids": [],
                "ca_file": "/run/responseforge/ca.pem",
                "shuffle_backend": "http://shuffle-backend:5001",
            },
            indent=2,
        )
        + "\n",
        mode=0o444,
    )
    _write(state_dir / "compose.json", json.dumps(rendered["compose"], indent=2) + "\n")
    _write(state_dir / "frontend-nginx.conf", rendered["frontend_nginx"], mode=0o444)
    _write(state_dir / "opensearch.yml", rendered["opensearch_config"], mode=0o444)
    _write(state_dir / "fault.json", "{}\n", mode=0o444)
    _write(
        state_dir / "runtime.json",
        json.dumps(
            {
                "context": context,
                "engine_id": engine_id,
                "architecture": architecture,
                "authorized": authorized,
                "images": images,
            },
            indent=2,
        )
        + "\n",
    )


class DockerRuntime:
    def __init__(
        self,
        state_dir: Path,
        *,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.state_dir = state_dir
        self._run = run

    def _state(self) -> dict[str, Any]:
        path = self.state_dir / "runtime.json"
        try:
            if (
                not self.state_dir.is_absolute()
                or self.state_dir.is_symlink()
                or any(parent.is_symlink() for parent in self.state_dir.parents)
            ):
                raise ValueError
            if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise ValueError
            value: Any = json.loads(path.read_text())
            if not isinstance(value, dict) or not isinstance(value.get("context"), str):
                raise ValueError
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value["context"]):
                raise ValueError
            # Reuse the strict seven-image immutable inventory check before any
            # engine command. A changed local state cannot enable tag fallback.
            inventory = value.get("images")
            if not isinstance(inventory, dict):
                raise ValueError
            render_runtime(inventory, self.state_dir.resolve())
            return dict(value)
        except (OSError, ValueError, TypeError):
            raise ValueError("Invalid private pilot state") from None

    def _raw(self, state: dict[str, Any], args: tuple[str, ...], *, data: str | None = None) -> str:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("DOCKER_") and not key.startswith("COMPOSE_")
        }
        environment["COMPOSE_FILE"] = str(self.state_dir / "compose.json")
        environment["COMPOSE_PROJECT_NAME"] = PROJECT
        try:
            result = self._run(
                ["docker", "--context", state["context"], *args],
                capture_output=True,
                text=True,
                timeout=300,
                env=environment,
                input=data,
                check=False,
            )
            if result.returncode:
                raise ValueError
            return str(result.stdout) + (str(result.stderr) if args and args[0] == "logs" else "")
        except (OSError, subprocess.SubprocessError, ValueError):
            raise ValueError("Pilot Docker command failed; inspect private state") from None

    def _verified(self, *, mutate: bool) -> dict[str, Any]:
        state = self._state()
        if mutate and state.get("authorized") is not True:
            raise ValueError("Pilot engine/socket/loopback scope is not authorized")
        if mutate:
            try:
                path = self.state_dir / "compose.json"
                if (
                    path.is_symlink()
                    or json.loads(path.read_text())
                    != render_runtime(
                        state["images"], self.state_dir.resolve(), engine_authorized=True
                    )["compose"]
                ):
                    raise ValueError
            except (OSError, ValueError, TypeError):
                raise ValueError(
                    "Pilot Compose differs from the reviewed private topology"
                ) from None
        try:
            current = json.loads(self._raw(state, ("info", "--format", "{{json .}}")))
            architecture = {
                "aarch64": "arm64",
                "arm64": "arm64",
                "x86_64": "amd64",
                "amd64": "amd64",
            }.get(current.get("Architecture"))
            if (
                not state.get("engine_id")
                or current.get("ID") != state["engine_id"]
                or current.get("OSType") != "linux"
                or architecture != state.get("architecture")
                or architecture is None
                or current.get("Swarm", {}).get("LocalNodeState") != "inactive"
            ):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError(
                "Selected pilot engine identity, architecture or Swarm state changed"
            ) from None
        return state

    def command(self, *args: str, mutate: bool = False) -> str:
        """Verify engine binding before every mutation; never change contexts."""
        # The caller cannot bypass mutation classification with mutate=False.
        permitted_read = args in {
            ("ps", "-a", "--filter", "label=" + LABEL + "=" + PROJECT, "--format", "{{json .}}"),
            ("compose", "ps", "--format", "json"),
        }
        permitted_mutation = args in {
            ("compose", "up", "-d"),
            ("compose", "restart", "core"),
            ("compose", "restart", "backend"),
            ("compose", "restart", "orborus"),
        }
        if not permitted_read and not permitted_mutation:
            raise ValueError("Unsupported pilot Docker command")
        if args == ("compose", "up", "-d"):
            return self.up()
        state = self._verified(mutate=mutate or permitted_mutation)
        if permitted_mutation:
            self._check_names(state)
            self._local_images(state)
        return self._raw(state, args)

    def _check_names(self, state: dict[str, Any], *, volumes_only: bool = False) -> None:
        # Fixed names are a convenience, never ownership proof. Refuse collision
        # with existing resources before Compose or seed can write anything.
        for kind, names in (
            (
                "container",
                [
                    PROJECT + "-" + name
                    for name in ("backend", "orborus", "core", "frontend", "opensearch")
                ],
            ),
            (
                "volume",
                [
                    PROJECT + "-" + name
                    for name in (
                        "callback",
                        "core-state",
                        "apps",
                        "files",
                        "database",
                        "opensearch-config",
                    )
                ],
            ),
            ("network", [PROJECT + "-private", PROJECT + "-access"]),
        ):
            if volumes_only and kind != "volume":
                continue
            if kind == "container":
                found = self._raw(state, ("ps", "-a", "--format", "{{.Names}}"))
            elif kind == "volume":
                found = self._raw(state, ("volume", "ls", "--format", "{{.Name}}"))
            else:
                found = self._raw(state, ("network", "ls", "--format", "{{.Name}}"))
            existing = set(found.splitlines())
            for name in names:
                if name in existing:
                    template = (
                        "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
                    )
                    labels = json.loads(
                        self._raw(state, (kind, "inspect", "--format", template, name))
                    )
                    if labels.get(LABEL) != PROJECT:
                        raise ValueError("Pilot resource name belongs to another workload")

    def _local_images(self, state: dict[str, Any]) -> None:
        # Verify all source images before any image pull or volume mutation.
        for name, image in state["images"].items():
            if name not in {"frontend", "opensearch"}:
                actual = self._raw(
                    state, ("image", "inspect", "--format", "{{.Id}}", image)
                ).strip()
                if actual != image:
                    raise ValueError("Pilot source-built image inventory changed")

    def up(self) -> str:
        state = self._verified(mutate=True)
        self._check_names(state)
        self._local_images(state)
        for name in ("frontend", "opensearch"):
            self._raw(self._verified(mutate=True), ("pull", state["images"][name]))
        self.seed()
        return self._raw(self._verified(mutate=True), ("compose", "up", "-d"))

    def seed(self) -> None:
        state = self._verified(mutate=True)
        self._check_names(state, volumes_only=True)
        self._local_images(state)
        # These are generated lab files only. The helper has no socket/capabilities
        # and initializes the two exact named volumes; no host ownership change.
        for name in ("callback", "core-state"):
            self._raw(
                self._verified(mutate=True),
                (
                    "volume",
                    "create",
                    "--label",
                    LABEL + "=" + PROJECT,
                    "--label",
                    "com.docker.compose.project=" + PROJECT,
                    "--label",
                    "com.docker.compose.volume="
                    + (PROJECT + "-callback" if name == "callback" else name),
                    PROJECT + "-" + name,
                ),
            )
        program = "from pathlib import Path; from responseforge.integrations.shuffle.operations import _seed_files; _seed_files(Path('/target'),Path('/seed'),state=Path('/state'))"
        self._raw(
            self._verified(mutate=True),
            (
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--security-opt",
                "no-new-privileges",
                "--label",
                LABEL + "=" + PROJECT,
                "-v",
                str(self.state_dir / "callback.json") + ":/seed/callback.json:ro",
                "-v",
                str(self.state_dir / "pki/ca.pem") + ":/seed/ca.pem:ro",
                "-v",
                PROJECT + "-callback:/target",
                "-v",
                PROJECT + "-core-state:/state",
                state["images"]["core"],
                "python",
                "-c",
                program,
            ),
        )

    def status(self) -> dict[str, Any]:
        output = self.command("compose", "ps", "--format", "json")
        try:
            values = (
                json.loads(output)
                if output.lstrip().startswith("[")
                else [json.loads(line) for line in output.splitlines() if line.strip()]
            )
            return {
                "services": [
                    {
                        "service": item.get("Service"),
                        "state": item.get("State"),
                        "health": item.get("Health"),
                    }
                    for item in values
                ],
                "runtime_qualified": False,
            }
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid pilot status response") from None

    def down(self) -> None:
        state = self._verified(mutate=True)
        raw = self._raw(state, ("ps", "-aq", "--filter", "label=" + LABEL + "=" + PROJECT))
        identities = raw.split()
        if any(not re.fullmatch(r"[0-9a-f]{12,64}", identity) for identity in identities):
            raise ValueError("Invalid owned pilot container inventory")
        for identity in identities:
            current = self._verified(mutate=True)
            labels = json.loads(
                self._raw(current, ("inspect", "--format", "{{json .Config.Labels}}", identity))
            )
            if labels.get(LABEL) != PROJECT:
                raise ValueError("Container ownership changed; refusing teardown")
            self._raw(current, ("rm", "-f", identity))
        # Named volumes deliberately persist. Do not use compose down/prune or
        # image/name heuristics that could broaden deletion across lab resources.
