"""Original synthetic Wazuh-shaped inputs; never captured endpoint evidence."""

import json
from datetime import UTC, datetime, timedelta

from responseforge.contracts import EndpointRef
from responseforge.integrations.wazuh.models import WazuhAgentBinding, WazuhConfig
from responseforge.runtime import Principal, Settings

NOW = datetime(2026, 11, 19, 17, 0, tzinfo=UTC)
ENDPOINT = EndpointRef(endpoint_id="rf07-one", hostname="rf07-one.example", agent_id="001")
OTHER = EndpointRef(endpoint_id="rf07-two", hostname="rf07-two.example", agent_id="010")
TOKENS = {
    role: ("rf07-original-synthetic-" + role).ljust(48, "x")
    for role in ("source", "analyst", "approver", "executor", "workflow", "other-source")
}


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value

    def advance(self, **arguments):
        self.value += timedelta(**arguments)


def config(**changes):
    value = dict(
        manager_id="rf07-lab-manager",
        source_actor_id="rf07-source",
        agents=(
            WazuhAgentBinding(agent_id="001", endpoint=ENDPOINT),
            WazuhAgentBinding(agent_id="010", endpoint=OTHER),
        ),
    )
    return WazuhConfig(**(value | changes))


def payload(**changes):
    # Shape follows reviewed native fields; every value is newly authored.
    value = {
        "timestamp": "2026-02-03T14:15:16.123+0200",
        "id": "1770120916.123",
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Original synthetic file-change observation",
        },
        "agent": {"id": "001", "name": "rf07-one.example", "ip": "192.0.2.10"},
        "manager": {"name": "untrusted-manager-label"},
        "syscheck": {"path": "C:\\safe\\example.txt", "event": "modified"},
        "full_log": "original synthetic source text, not a real endpoint observation",
    }
    return value | changes


def encoded(value=None):
    return json.dumps(
        payload() if value is None else value, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def principals():
    result = {}
    for role in TOKENS:
        result[role] = Principal(
            actor_id="rf07-" + role,
            roles=frozenset({"source" if role == "other-source" else role}),
            endpoint_ids=frozenset({ENDPOINT.endpoint_id, OTHER.endpoint_id}),
            actions=frozenset() if "source" in role else frozenset({"test_marker"}),
            resources=frozenset() if "source" in role else frozenset({"marker:rf07"}),
            sources=frozenset({"wazuh"}) if "source" in role else frozenset(),
            human=role == "approver",
        )
    return result


def settings(path, **changes):
    actors = principals()
    value = dict(
        database_path=path,
        mode="live",
        endpoints=(ENDPOINT, OTHER),
        credentials={TOKENS[role]: actor for role, actor in actors.items()},
        resource_allowlist={
            ENDPOINT.endpoint_id: frozenset({"marker:rf07"}),
            OTHER.endpoint_id: frozenset({"marker:rf07"}),
        },
        wazuh=config(),
        revision="synthetic-rf07a-test",
        environment="offline-original-synthetic",
    )
    return Settings(**(value | changes))


def auth(role="source", **headers):
    return {"Authorization": "Bearer " + TOKENS[role], "Content-Type": "application/json"} | headers
