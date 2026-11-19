"""Trusted preparation contracts; none grants deployment or endpoint authority."""

import ipaddress
import math
import re
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, StrictBool, StringConstraints, model_validator

from responseforge.contracts import Contract, Sha256
from responseforge.integrations.wazuh.models import ManagerId, WazuhConfig

MSI_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.10-1.msi"
MSI_NAME = "wazuh-agent-4.14.10-1.msi"
MSI_SHA512 = "54f83c01dd35573d8501eab553ebdd72ad4de75383636efb25f01e782521e83281065f8075a369239c13a5a5e3f3599a754eb3204ff56cfce2b2afd9ae911152"
MAX_MSI = 64 * 1024 * 1024
MachineName = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,14}$")
]
AgentName = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
]
Thumbprint = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9A-F]{40}$")]


def safe_host(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or not re.fullmatch(r"[A-Za-z0-9.-]+", value)
    ):
        raise ValueError("Unsupported manager host")
    parts = value.split(".")
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in parts):
        raise ValueError("Invalid manager host")
    if len(parts) == 4 and all(p.isdecimal() for p in parts):
        ip = ipaddress.IPv4Address(value)
        if ip.is_unspecified or ip.is_multicast or not (ip.is_private or ip.is_loopback):
            raise ValueError("Private manager address required")
    return value


class SenderConfig(Contract):
    enabled: StrictBool = False
    destination: str
    ca_file: str
    token_file: str = Field(repr=False)
    alert_root: str
    alert_uid: Annotated[int, Field(strict=True, ge=0)]
    outbox_dir: str
    source: WazuhConfig
    timeout: Annotated[float, Field(strict=True, ge=0.1, le=30)] = 10.0

    @model_validator(mode="after")
    def boundaries(self) -> Self:
        from pathlib import Path

        url = urlsplit(self.destination)
        if (
            not self.destination.isascii()
            or any(ord(c) <= 32 for c in self.destination)
            or url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or url.path != "/v1/integrations/wazuh/alerts"
            or not 1 <= (url.port or 443) <= 65535
        ):
            raise ValueError("Fixed HTTPS native destination required")
        safe_host(url.hostname)
        if not math.isfinite(self.timeout) or not 0.1 <= self.timeout <= 30:
            raise ValueError("Bounded sender timeout required")
        for value in (self.ca_file, self.token_file, self.alert_root, self.outbox_dir):
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in value):
                raise ValueError("Absolute canonical private paths required")
        return self


class SenderResult(Contract):
    status: Literal["dry_run", "accepted", "duplicate", "cached", "uncertain", "rejected"]
    sha256: Sha256
    byte_count: Annotated[int, Field(strict=True, ge=1, le=262144)]
    incident_id: str | None = None
    correlation_id: str | None = None
    verified_live: Literal[False] = False

    @model_validator(mode="after")
    def safe_receipt(self) -> Self:
        acknowledged = self.status in {"accepted", "duplicate", "cached"}
        for value in (self.incident_id, self.correlation_id):
            if acknowledged:
                if value is None or str(UUID(value)) != value:
                    raise ValueError("Canonical receipt UUID required")
            elif value is not None:
                raise ValueError("Unacknowledged delivery has no trusted receipt IDs")
        return self


class DeliveryReceipt(Contract):
    version: Literal["rf07b-outbox-v1"] = "rf07b-outbox-v1"
    identity: Sha256
    binding: Sha256
    sha256: Sha256
    byte_count: Annotated[int, Field(strict=True, ge=1, le=262144)]
    state: Literal["prepared", "dispatching", "accepted", "duplicate", "uncertain", "rejected"]
    result: SenderResult | None = None


class DeploymentTarget(Contract):
    architecture: Literal["amd64", "arm64"]
    kind: Literal["docker-desktop", "dedicated-vm"]
    manager_id: ManagerId
    endpoint_bind_ip: str = "127.0.0.1"
    lab_subnet: str | None = None
    endpoint_publish_authorized: StrictBool = False

    @model_validator(mode="after")
    def network_scope(self) -> Self:
        ip = ipaddress.IPv4Address(self.endpoint_bind_ip)
        if ip == ipaddress.IPv4Address("127.0.0.1"):
            return self
        private = any(
            ip in ipaddress.IPv4Network(n)
            for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        network = ipaddress.IPv4Network(self.lab_subnet) if self.lab_subnet else None
        if (
            not self.endpoint_publish_authorized
            or not private
            or network is None
            or ip not in network
            or ip == network.network_address
            or ip == network.broadcast_address
            or not any(
                network.subnet_of(ipaddress.IPv4Network(n))
                for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
            )
        ):
            raise ValueError("Explicit matching private lab publication scope required")
        return self


class DeploymentPlan(Contract):
    target: DeploymentTarget
    compose: dict[str, Any]
    blockers: tuple[str, ...]
    source_requirements: tuple[str, ...]
    ready: Literal[False] = False
    runtime_qualified: Literal[False] = False


class WindowsBundleConfig(Contract):
    target_machine: MachineName
    agent_name: AgentName
    manager_host: str
    signer_subject: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512)]
    signer_thumbprint: Thumbprint
    ca_file: str
    agent_certificate_file: str
    agent_key_file: str = Field(repr=False)

    @model_validator(mode="after")
    def trusted_inputs(self) -> Self:
        safe_host(self.manager_host)
        if any(ord(c) < 32 for c in self.signer_subject):
            raise ValueError("Canonical independent signer subject required")
        return self
