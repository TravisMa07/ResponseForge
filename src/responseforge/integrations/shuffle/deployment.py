"""Pure, deliberately unqualified Shuffle Compose preparation.

Rendering never changes Docker context, pulls images, starts services or grants
engine authority. A target descriptor records a separately obtained grant.
"""

import hashlib
import re
from typing import Any, Literal

from pydantic import StrictBool, ValidationError

from responseforge.contracts import Contract, Id, UtcDateTime

_Component = Literal["frontend", "backend", "orborus", "worker", "opensearch"]
_Architecture = Literal["arm64", "amd64"]
_COMPONENTS = frozenset({"frontend", "backend", "orborus", "worker", "opensearch"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE_NAME = re.compile(r"[a-z0-9][a-z0-9._:/-]*\Z")
_REQUIRED_GATES = (
    "source-image-correlation-unverified",
    "app-image-inventory-unqualified",
    "callback-logging-unqualified",
    "license-review-open",
    "runtime-unqualified",
    "resource-budget-unmeasured",
    "opensearch-ca-provisioning-unverified",
)


class DeploymentTarget(Contract):
    kind: Literal["docker-desktop", "dedicated-vm"]
    architecture: _Architecture
    engine_id: Id
    engine_control_authorized: StrictBool = False
    loopback_ui: StrictBool = False


class DeploymentPlan(Contract):
    target: DeploymentTarget
    compose: dict[str, Any]
    blockers: tuple[Id, ...]
    ready: Literal[False] = False
    requires_engine_control: Literal[True] = True


class _ImagePin(Contract):
    reference: Id
    index_digest: Id
    platforms: dict[_Architecture, Id]


class _ImageLock(Contract):
    observed_at: UtcDateTime
    source_revision: Id
    images: dict[_Component, _ImagePin]
    gates: tuple[Id, ...]


def _images(lock: _ImageLock, architecture: _Architecture) -> dict[str, str]:
    if set(lock.images) != _COMPONENTS:
        raise ValueError("Image lock must include every required Shuffle component")
    images: dict[str, str] = {}
    for component, pin in lock.images.items():
        parts = pin.reference.rsplit("@", 1)
        if len(parts) != 2:
            raise ValueError("Every Shuffle image must use an immutable digest")
        name, digest = parts
        if (
            _IMAGE_NAME.fullmatch(name) is None
            or "://" in name
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or name.rsplit("/", 1)[-1].split(":")[-1] in {"latest", "nightly", "main"}
            or _DIGEST.fullmatch(digest) is None
            or _DIGEST.fullmatch(pin.index_digest) is None
            or digest != pin.index_digest
            or architecture not in pin.platforms
            or any(_DIGEST.fullmatch(value) is None for value in pin.platforms.values())
        ):
            raise ValueError("Invalid immutable Shuffle image or platform pin")
        # Select the observed platform manifest itself, not a floating tag or
        # architecture-dependent resolution of an unqualified image index.
        images[component] = name + "@" + pin.platforms[architecture]
    return images


def _required(name: str) -> str:
    return "${" + name + ":?Set " + name + " in the private selected-target environment}"


def build_plan(lock: dict[str, Any], target: DeploymentTarget) -> DeploymentPlan:
    """Validate observed pins and render a plan which cannot claim readiness."""
    try:
        pins = _ImageLock.model_validate(lock)
        target = DeploymentTarget.model_validate(target.model_dump(mode="json", warnings=False))
    except (ValidationError, ValueError, TypeError, AttributeError):
        raise ValueError("Invalid Shuffle deployment lock or target") from None
    images = _images(pins, target.architecture)
    platform = "linux/" + target.architecture
    engine_marker = hashlib.sha256(target.engine_id.encode()).hexdigest()

    def service(component: str) -> dict[str, Any]:
        return {
            "image": images[component],
            "platform": platform,
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": ["/tmp"],
            "networks": ["shuffle-private"],
            "labels": {
                "responseforge.plan-only": "true",
                "responseforge.execution-target": target.kind,
                "responseforge.engine-id-sha256": engine_marker,
            },
        }

    frontend = service("frontend")
    frontend["hostname"] = "shuffle-frontend"
    frontend["environment"] = {"BACKEND_HOSTNAME": "shuffle-backend"}
    frontend["tmpfs"] += ["/var/cache/nginx", "/var/run"]
    frontend["depends_on"] = ["backend"]
    if target.loopback_ui:
        frontend["ports"] = ["127.0.0.1:3001:80"]

    common_environment = {
        "SHUFFLE_SKIPSSL_VERIFY": "false",
        "SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY": "false",
        "SHUFFLE_AUTO_IMAGE_DOWNLOAD": "false",
        "SHUFFLE_PASS_WORKER_PROXY": "false",
        "SHUFFLE_PASS_APP_PROXY": "false",
        "SHUFFLE_LOGS_DISABLED": "true",
        "SHUFFLE_STATS_DISABLED": "true",
        "ENVIRONMENT_NAME": "ResponseForge",
        "TZ": "UTC",
    }
    backend = service("backend")
    backend["hostname"] = "shuffle-backend"
    backend["environment"] = common_environment | {
        "BACKEND_HOSTNAME": "shuffle-backend",
        "BASE_URL": "http://shuffle-backend:5001",
        "SHUFFLE_DEFAULT_USERNAME": _required("SHUFFLE_DEFAULT_USERNAME"),
        "SHUFFLE_DEFAULT_PASSWORD": _required("SHUFFLE_DEFAULT_PASSWORD"),
        "SHUFFLE_DEFAULT_APIKEY": _required("SHUFFLE_DEFAULT_APIKEY"),
        "SHUFFLE_ENCRYPTION_MODIFIER": _required("SHUFFLE_ENCRYPTION_MODIFIER"),
        "AUTH_FOR_ORBORUS": _required("SHUFFLE_ORBORUS_AUTH"),
        "SHUFFLE_APP_HOTLOAD_FOLDER": "/shuffle-apps",
        "SHUFFLE_FILE_LOCATION": "/shuffle-files",
        "SHUFFLE_APP_DOWNLOAD_LOCATION": "",
        "SHUFFLE_DOWNLOAD_WORKFLOW_LOCATION": "",
        "SHUFFLE_APP_FORCE_UPDATE": "false",
        "SHUFFLE_OPENSEARCH_URL": "https://shuffle-opensearch:9200",
        "SHUFFLE_OPENSEARCH_USERNAME": "admin",
        "SHUFFLE_OPENSEARCH_PASSWORD": _required("SHUFFLE_OPENSEARCH_PASSWORD"),
        "SHUFFLE_OPENSEARCH_CERTIFICATE_FILE": _required("SHUFFLE_OPENSEARCH_CERTIFICATE_FILE"),
    }
    backend["volumes"] = ["shuffle-apps:/shuffle-apps", "shuffle-files:/shuffle-files"]
    backend["depends_on"] = ["opensearch"]

    orborus = service("orborus")
    orborus["hostname"] = "shuffle-orborus"
    orborus["environment"] = common_environment | {
        "BASE_URL": "http://shuffle-backend:5001",
        "AUTH": _required("SHUFFLE_ORBORUS_AUTH"),
        "ORG": _required("SHUFFLE_ORG_ID"),
        "IS_KUBERNETES": "false",
        "SHUFFLE_SWARM_CONFIG": "run",
        "SHUFFLE_WORKER_IMAGE": images["worker"],
        "SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY": "1",
        "SHUFFLE_APP_REPLICAS": "1",
        "SHUFFLE_CONTAINER_AUTO_CLEANUP": "true",
        "CLEANUP": "true",
    }
    orborus["depends_on"] = ["backend"]
    if target.engine_control_authorized:
        # The bind is resolved within the separately selected target engine.
        # Rendering cannot verify the grant or silently select/change a daemon.
        socket = "/var/run/docker.sock:/var/run/docker.sock:rw"
        backend["volumes"].append(socket)
        orborus["volumes"] = [socket]

    opensearch = service("opensearch")
    opensearch["hostname"] = "shuffle-opensearch"
    opensearch["environment"] = {
        "discovery.type": "single-node",
        "node.name": "shuffle-opensearch",
        "cluster.name": "shuffle-cluster",
        "node.store.allow_mmap": "false",
        "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI": "true",
        "OPENSEARCH_INITIAL_ADMIN_PASSWORD": _required("SHUFFLE_OPENSEARCH_PASSWORD"),
    }
    opensearch["volumes"] = ["shuffle-database:/usr/share/opensearch/data"]
    # Upstream BASE_URL/indexer/frontend targets use these names. Bind explicit
    # network aliases rather than depending on container hostname resolution.
    for component, value in (
        ("frontend", frontend),
        ("backend", backend),
        ("orborus", orborus),
        ("opensearch", opensearch),
    ):
        value["networks"] = {"shuffle-private": {"aliases": ["shuffle-" + component]}}
    blockers = list(dict.fromkeys((*pins.gates, *_REQUIRED_GATES)))
    if not target.engine_control_authorized:
        blockers.append("execution-engine-control-not-authorized")
    compose = {
        "name": "responseforge-shuffle-" + target.kind,
        "services": {
            "frontend": frontend,
            "backend": backend,
            "orborus": orborus,
            "opensearch": opensearch,
        },
        "networks": {"shuffle-private": {"driver": "bridge", "internal": True}},
        "volumes": {"shuffle-apps": {}, "shuffle-files": {}, "shuffle-database": {}},
    }
    return DeploymentPlan(target=target, compose=compose, blockers=tuple(blockers))


def compare_targets() -> dict[str, Any]:
    """Qualitative target tradeoffs; neither choice is automatically authorized."""
    return {
        "docker-desktop": {
            "existing_engine": True,
            "authority": "Docker control applies to the selected existing engine, its containers and accessible host bind mounts.",
            "isolation": "Changing Docker context or adding a socket proxy does not create a separate security boundary.",
            "resources": "Uses the Docker Desktop VM allocation; combined Shuffle and app budget requires measurement.",
            "setup": "No new guest is required, but explicit engine-control authorization and all runtime gates remain necessary.",
            "recovery": "Preserve other workloads; use namespaced resources and a reviewed teardown rather than deleting the daemon.",
        },
        "dedicated-vm": {
            "existing_engine": False,
            "authority": "A separate disposable daemon confines granted Docker control to that guest and its configured mounts.",
            "isolation": "The boundary depends on actual guest configuration, networking and absence of developer-host bind mounts; it is not an automatic safety guarantee.",
            "resources": "Requires an explicit guest CPU, memory and disk allocation; no measured sizing or cost is claimed.",
            "setup": "Guest provisioning, installation and in-guest Docker control require a concrete authorized plan.",
            "recovery": "A dedicated guest can have a scoped snapshot/teardown plan; recovery must be verified on that guest.",
        },
        "shared_gates": list(_REQUIRED_GATES),
        "runtime_qualified": False,
        "starts_services": False,
        "authorization_granted": False,
    }
