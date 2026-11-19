"""Trusted Wazuh source configuration and private source-bound observations."""

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from responseforge.contracts import (
    Alert,
    Contract,
    EndpointRef,
    Evidence,
    Id,
    Mode,
    Provenance,
    Sha256,
    UtcDateTime,
)

AgentId = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]{1,8}$")]
NativeId = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]{1,20}\.[0-9]{1,20}$")]
RuleId = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]{1,10}$")]
ManagerId = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
]
Level = Annotated[int, Field(strict=True, ge=0, le=15)]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class WazuhAgentBinding(Contract):
    agent_id: AgentId
    endpoint: EndpointRef

    @model_validator(mode="after")
    def bound(self) -> Self:
        if int(self.agent_id) == 0 or self.endpoint.agent_id != self.agent_id:
            raise ValueError("Exact nonmanager agent identity required")
        return self


class WazuhConfig(Contract):
    manager_id: ManagerId
    source_actor_id: Id
    agents: tuple[WazuhAgentBinding, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({a.agent_id for a in self.agents}) != len(self.agents) or len(
            {a.endpoint.endpoint_id for a in self.agents}
        ) != len(self.agents):
            raise ValueError("Ambiguous configured agent identity")
        return self


class WazuhObservation(Contract):
    manager_id: ManagerId
    native_id: NativeId
    agent_id: AgentId
    endpoint: EndpointRef
    event_time: UtcDateTime
    original_timestamp: str
    rule_id: RuleId
    level: Level
    sha256: Sha256
    raw_json: str = Field(repr=False)

    @property
    def identity_sha256(self) -> str:
        return digest(
            json.dumps([self.manager_id, self.agent_id, self.native_id], separators=(",", ":"))
        )

    @property
    def scenario_id(self) -> str:
        return "wazuh-" + digest(self.manager_id)[:24]

    @property
    def evidence_id(self) -> str:
        return "wazuh-evidence-" + self.identity_sha256

    def to_alert(self, ingested_at: datetime) -> Alert:
        return Alert(
            alert_id="wazuh-" + self.identity_sha256,
            mode=Mode.LIVE,
            source="wazuh",
            scenario_id=self.scenario_id,
            endpoint=self.endpoint,
            event_time=self.event_time,
            ingested_at=ingested_at,
            rule_id="wazuh:" + self.rule_id,
            severity=(
                "low"
                if self.level <= 6
                else "medium"
                if self.level <= 9
                else "high"
                if self.level <= 12
                else "critical"
            ),
            provenance=Provenance(
                source="wazuh-alert",
                source_ref="wazuh://" + digest(self.manager_id) + "/alert/" + self.identity_sha256,
                sha256=self.sha256,
                original_event_ids=(self.native_id,),
            ),
            evidence_refs=(self.evidence_id,),
        )

    def evidence(self, incident_id: str, received_at: datetime) -> tuple[Evidence, Evidence]:
        common = dict(
            incident_id=incident_id,
            mode=Mode.LIVE,
            endpoint=self.endpoint,
            collected_at=received_at,
            classification="sensitive",
        )
        available = Evidence(
            **common,
            evidence_id=self.evidence_id,
            observed_at=self.event_time,
            availability="available",
            provenance=self.to_alert(received_at).provenance,
            unavailable_reason=None,
        )
        gap = Evidence(
            **common,
            evidence_id="wazuh-gap-" + self.identity_sha256,
            observed_at=None,
            availability="unavailable",
            provenance=None,
            unavailable_reason="Only received Wazuh alert is available; endpoint state, process lineage and response effects are not verified",
        )
        return available, gap


class WazuhReceipt(Contract):
    receipt_version: Literal["wazuh-alert-json-v1"] = "wazuh-alert-json-v1"
    manager_id: ManagerId
    incident_id: Id
    alert: Alert
    raw_json: str = Field(repr=False)
    evidence: tuple[Evidence, Evidence]
