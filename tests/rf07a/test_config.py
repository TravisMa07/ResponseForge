"""Trusted Wazuh configuration cannot acquire replay or dispatch authority."""

import json
from dataclasses import replace

import pytest

from responseforge.__main__ import load_settings
from responseforge.contracts import EndpointRef
from responseforge.integrations.wazuh.models import WazuhAgentBinding, WazuhConfig
from responseforge.replay import load_replay
from responseforge.runtime import Settings
from tests.rf07a.helpers import ENDPOINT, OTHER, TOKENS, config, principals, settings


def test_configured_native_source_rejects_replay_mode(tmp_path):
    with pytest.raises(ValueError):
        settings(tmp_path / "replay.sqlite3", mode="replay")


def test_default_config_keeps_wazuh_disabled_and_dry_run(tmp_path):
    configured = Settings(database_path=tmp_path / "default.sqlite3")
    assert configured.mode == "replay" and configured.wazuh is None
    assert not configured.live_dispatch_enabled and configured.providers == {}


@pytest.mark.parametrize(
    "manager",
    [
        "",
        " ",
        "-bad",
        ".bad",
        "../manager",
        "manager/path",
        "manager:port",
        "manager\nsecret",
        "m" * 65,
        "månager",
        1,
        True,
    ],
)
def test_manager_identity_is_operator_safe_bounded_slug(manager):
    with pytest.raises(ValueError):
        config(manager_id=manager)


@pytest.mark.parametrize(
    "identity", ["0", "000", "00000000", "", " 1", "1 ", "-1", "1a", "1.0", "١", "1" * 9, 1, True]
)
def test_agent_identity_is_decimal_string_and_manager_local_is_not_endpoint(identity):
    endpoint = ENDPOINT.model_copy(update={"agent_id": identity})
    with pytest.raises(ValueError):
        WazuhAgentBinding(agent_id=identity, endpoint=endpoint)


def test_leading_zeros_and_one_digit_supported_ids_remain_distinct():
    one = EndpointRef(endpoint_id="a", hostname="a.example", agent_id="1")
    zeros = EndpointRef(endpoint_id="b", hostname="b.example", agent_id="001")
    configured = config(
        agents=(
            WazuhAgentBinding(agent_id="1", endpoint=one),
            WazuhAgentBinding(agent_id="001", endpoint=zeros),
        )
    )
    assert [binding.agent_id for binding in configured.agents] == ["1", "001"]


@pytest.mark.parametrize("changes", [{"agent_id": None}, {"agent_id": "1"}, {"agent_id": "010"}])
def test_binding_requires_exact_full_endpoint_agent_id(changes):
    with pytest.raises(ValueError):
        WazuhAgentBinding(agent_id="001", endpoint=ENDPOINT.model_copy(update=changes))


def test_configuration_rejects_duplicate_agent_or_endpoint_ids_and_bounds():
    first = WazuhAgentBinding(agent_id="001", endpoint=ENDPOINT)
    another = WazuhAgentBinding(
        agent_id="001", endpoint=OTHER.model_copy(update={"agent_id": "001"})
    )
    same_endpoint_id = WazuhAgentBinding(
        agent_id="010", endpoint=OTHER.model_copy(update={"endpoint_id": ENDPOINT.endpoint_id})
    )
    for agents in ((), (first, first), (first, another), (first, same_endpoint_id), (first,) * 129):
        with pytest.raises(ValueError):
            config(agents=agents)


@pytest.mark.parametrize(
    "changes", [{"hostname": "changed.example"}, {"agent_id": "1"}, {"endpoint_id": "missing"}]
)
def test_settings_bindings_require_exact_configured_full_endpoint(tmp_path, changes):
    with pytest.raises(ValueError):
        settings(
            tmp_path / "wrong-endpoint.sqlite3",
            endpoints=(ENDPOINT.model_copy(update=changes), OTHER),
        )


@pytest.mark.parametrize(
    "principal_changes",
    [
        {"roles": frozenset({"source", "analyst"})},
        {"roles": frozenset({"source", "approver"})},
        {"roles": frozenset({"workflow"})},
        {"human": True},
        {"actions": frozenset({"test_marker"})},
        {"resources": frozenset({"marker:rf07"})},
        {"sources": frozenset({"wazuh", "other"})},
        {"sources": frozenset()},
        {"endpoint_ids": frozenset({ENDPOINT.endpoint_id})},
        {"endpoint_ids": frozenset({ENDPOINT.endpoint_id, OTHER.endpoint_id, "extra"})},
    ],
)
def test_native_source_principal_has_only_exact_server_scope(tmp_path, principal_changes):
    actors = principals()
    source = replace(actors["source"], **principal_changes)
    credentials = {
        TOKENS[role]: (source if role == "source" else actor) for role, actor in actors.items()
    }
    with pytest.raises(ValueError):
        settings(tmp_path / "bad-principal.sqlite3", credentials=credentials)


def test_source_actor_must_exist_as_exact_configured_actor(tmp_path):
    with pytest.raises(ValueError):
        settings(tmp_path / "missing-source.sqlite3", wazuh=config(source_actor_id="missing"))


@pytest.mark.parametrize(
    "changes",
    [
        {"live_dispatch_enabled": True},
        {"providers": {"synthetic": object()}, "provider_versions": {"synthetic": "1"}},
        {"evidence_provider": object()},
    ],
)
def test_native_intake_configuration_has_no_response_or_collection_provider(tmp_path, changes):
    with pytest.raises(ValueError):
        settings(tmp_path / "unsafe-live.sqlite3", **changes)


def test_native_intake_cannot_load_legacy_replay_batch(tmp_path):
    with pytest.raises(ValueError):
        settings(
            tmp_path / "mixed.sqlite3",
            replay_batch=load_replay(
                __import__("pathlib").Path("datasets/fixtures/benign.jsonl"), source_id="legacy"
            ),
        )


def test_settings_detaches_config_and_revalidates_model_copy_bypass(tmp_path):
    value = config()
    configured = settings(tmp_path / "good.sqlite3", wazuh=value)
    assert configured.wazuh == value
    invalid = value.model_copy(update={"manager_id": "../outside"})
    with pytest.raises(ValueError):
        settings(tmp_path / "invalid-copy.sqlite3", wazuh=invalid)


def file_value(path):
    configured = settings(path)
    actors = configured.credentials
    return {
        "database_path": str(path),
        "mode": "live",
        "endpoints": [endpoint.model_dump(mode="json") for endpoint in configured.endpoints],
        "credentials": {
            token: {
                "actor_id": actor.actor_id,
                "roles": sorted(actor.roles),
                "endpoint_ids": sorted(actor.endpoint_ids),
                "actions": sorted(actor.actions),
                "resources": sorted(actor.resources),
                "sources": sorted(actor.sources),
                "human": actor.human,
            }
            for token, actor in actors.items()
        },
        "resource_allowlist": {
            key: sorted(values) for key, values in configured.resource_allowlist.items()
        },
        "wazuh": configured.wazuh.model_dump(mode="json"),
    }


def test_private_file_configuration_loads_opt_in_without_creating_provider(tmp_path):
    path = tmp_path / "private-config.json"
    value = file_value(tmp_path / "file.sqlite3")
    path.write_text(json.dumps(value))
    loaded = load_settings(path)
    assert loaded.wazuh == WazuhConfig.model_validate(value["wazuh"])
    assert loaded.mode == "live" and not loaded.live_dispatch_enabled
    assert not loaded.providers and loaded.evidence_provider is None and loaded.replay_batch is None
    assert not loaded.playbook_bindings
