"""Independent native-source projection expectations over original synthetic JSON."""

import hashlib
from datetime import UTC, datetime

import pytest

from responseforge.integrations.wazuh.mapping import WazuhError, WazuhScopeError, project_alert
from tests.rf07a.helpers import ENDPOINT, NOW, config, encoded, payload


def minimal():
    value = payload()
    return {key: value[key] for key in ("timestamp", "id", "rule", "agent")}


def test_valid_projection_preserves_received_bytes_original_time_and_bound_identity():
    raw = encoded()
    observation = project_alert(raw, config())
    assert observation.native_id == "1770120916.123" and observation.agent_id == "001"
    assert observation.endpoint == ENDPOINT and observation.manager_id == "rf07-lab-manager"
    assert observation.event_time == datetime(2026, 2, 3, 12, 15, 16, 123000, UTC)
    assert observation.original_timestamp == "2026-02-03T14:15:16.123+0200"
    assert observation.sha256 == hashlib.sha256(raw).hexdigest()
    assert observation.raw_json.encode() == raw
    assert "original synthetic source text" not in repr(observation)
    expected_identity = hashlib.sha256(b'["rf07-lab-manager","001","1770120916.123"]').hexdigest()
    assert observation.identity_sha256 == expected_identity
    alert = observation.to_alert(NOW)
    assert alert.alert_id == "wazuh-" + expected_identity
    assert alert.scenario_id == "wazuh-" + hashlib.sha256(b"rf07-lab-manager").hexdigest()[:24]
    assert alert.rule_id == "wazuh:550" and alert.severity == "medium"
    assert alert.mode == "live" and alert.source == "wazuh" and alert.ingested_at == NOW
    assert alert.provenance.source == "wazuh-alert"
    assert alert.provenance.sha256 == observation.sha256
    assert alert.provenance.original_event_ids == ("1770120916.123",)
    assert (
        alert.provenance.source_ref
        == "wazuh://"
        + hashlib.sha256(b"rf07-lab-manager").hexdigest()
        + "/alert/"
        + expected_identity
    )
    assert alert.evidence_refs == ("wazuh-evidence-" + expected_identity,)


@pytest.mark.parametrize(
    "level,expected",
    [
        (x, "low" if x <= 6 else "medium" if x <= 9 else "high" if x <= 12 else "critical")
        for x in range(16)
    ],
)
def test_priority_bands_are_explicit_and_never_action_authority(level, expected):
    value = payload(rule={"id": "550", "level": level})
    assert project_alert(encoded(value), config()).to_alert(NOW).severity == expected


@pytest.mark.parametrize("level", [True, False, "7", 7.0, None, -1, 16, [], {}])
def test_level_is_strict_bounded_integer(level):
    with pytest.raises(WazuhError):
        project_alert(encoded(payload(rule={"id": "550", "level": level})), config())


@pytest.mark.parametrize("key", ["id", "timestamp", "rule", "agent"])
def test_missing_required_native_object_field_is_not_invented(key):
    value = payload()
    del value[key]
    with pytest.raises(WazuhError):
        project_alert(encoded(value), config())


@pytest.mark.parametrize(
    "native",
    [
        None,
        1,
        True,
        "",
        "1",
        "1.2.3",
        "1.2x",
        " 1.2",
        "1.2 ",
        "-1.2",
        "1.2\ncommand",
        "١.٢",
        "1" * 21 + ".2",
        "1." + "2" * 21,
    ],
)
def test_native_identity_has_pinned_decimal_seconds_counter_grammar(native):
    with pytest.raises(WazuhError):
        project_alert(encoded(payload(id=native)), config())


@pytest.mark.parametrize(
    "rule", [None, 550, True, "", "abc", "550.0", "-1", " 550", "5\n50", "١", "5" * 11]
)
def test_rule_identity_is_decimal_string_without_coercion(rule):
    with pytest.raises(WazuhError):
        project_alert(encoded(payload(rule={"id": rule, "level": 7})), config())


@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        1770120916,
        1770120916.0,
        True,
        "1770120916",
        "2026-02-03T12:15:16",
        "2026-02-30T12:15:16Z",
        "bad-source-secret",
    ],
)
def test_timestamp_requires_aware_original_iso_string(timestamp):
    with pytest.raises(WazuhError) as captured:
        project_alert(encoded(payload(timestamp=timestamp)), config())
    assert "bad-source-secret" not in str(captured.value)


@pytest.mark.parametrize(
    "agent",
    [
        {},
        {"id": "001"},
        {"name": "rf07-one.example"},
        None,
        [],
        {"id": 1, "name": "rf07-one.example"},
    ],
)
def test_agent_shape_and_id_types_are_required(agent):
    with pytest.raises(WazuhError):
        project_alert(encoded(payload(agent=agent)), config())


@pytest.mark.parametrize("identity", ["0", "000", "00000000", "999", "01", "0010"])
def test_manager_local_or_unmapped_agent_cannot_route_to_a_known_host(identity):
    with pytest.raises(WazuhError):
        project_alert(encoded(payload(agent={"id": identity, "name": ENDPOINT.hostname})), config())


def test_same_agent_wrong_name_is_scope_failure_even_when_ip_matches():
    with pytest.raises(WazuhScopeError):
        project_alert(
            encoded(payload(agent={"id": "001", "name": "other.example", "ip": "192.0.2.10"})),
            config(),
        )


def test_manager_and_extensions_never_choose_scope_or_synthesize_process_facts():
    base = payload()
    changed = base | {
        "manager": {"name": "another-manager", "id": "other"},
        "mode": "replay",
        "approved": True,
        "endpoint_id": "physical-host",
        "provider": "mock-edr",
        "command": "do-not-run",
        "data": {"processId": "999", "parent": "invented"},
        "hook_url": "https://invalid.example/secret",
    }
    observation = project_alert(encoded(changed), config())
    original = project_alert(encoded(base), config())
    assert observation.identity_sha256 == original.identity_sha256
    assert (
        observation.to_alert(NOW).endpoint == ENDPOINT and observation.to_alert(NOW).mode == "live"
    )
    assert observation.sha256 != original.sha256
    assert set(observation.model_dump()) == {
        "schema_version",
        "manager_id",
        "native_id",
        "agent_id",
        "endpoint",
        "event_time",
        "original_timestamp",
        "rule_id",
        "level",
        "sha256",
        "raw_json",
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"null",
        b"[]",
        b"1",
        b"true",
        b"{}{}",
        b'{"secret":',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b'{"x":"\\udfff"}',
    ],
)
def test_malformed_or_nonfinite_or_non_scalar_unicode_input_is_safe(raw):
    with pytest.raises(WazuhError):
        project_alert(raw, config())


@pytest.mark.parametrize("suffix", [b',"id":"1770120916.123"}', b',"padding":{"x":1,"x":1}}'])
def test_duplicate_keys_reject_even_equal_nested_values(suffix):
    with pytest.raises(WazuhError):
        project_alert(encoded()[:-1] + suffix, config())


def test_max_body_boundary_is_accepted_and_one_more_byte_rejects():
    raw = encoded()
    raw += b" " * (262144 - len(raw))
    assert project_alert(raw, config()).sha256 == hashlib.sha256(raw).hexdigest()
    with pytest.raises(WazuhError):
        project_alert(raw + b" ", config())


def test_string_value_and_key_count_codepoints_not_utf8_bytes():
    for value in (payload(padding="é" * 16384), payload() | {"x" * 16384: 1}):
        assert project_alert(encoded(value), config()).native_id == "1770120916.123"
    for value in (payload(padding="x" * 16385), payload() | {"x" * 16385: 1}):
        with pytest.raises(WazuhError):
            project_alert(encoded(value), config())


def test_depth_includes_root_and_every_nested_scalar_value():
    value = 0
    for _ in range(30):
        value = {"x": value}
    assert (
        project_alert(encoded(minimal() | {"padding": value}), config()).native_id
        == "1770120916.123"
    )
    with pytest.raises(WazuhError):
        project_alert(encoded(minimal() | {"padding": {"x": value}}), config())


def test_value_nodes_count_root_containers_and_scalars_but_not_keys():
    # Minimal object has9 values; padding array adds1 plus each scalar element.
    value = minimal()
    value["rule"] = {"id": "550", "level": 7}
    value["agent"] = {"id": "001", "name": ENDPOINT.hostname}
    assert (
        project_alert(encoded(value | {"padding": [0] * 9990}), config()).native_id
        == "1770120916.123"
    )
    with pytest.raises(WazuhError):
        project_alert(encoded(value | {"padding": [0] * 9991}), config())


def test_optional_data_and_decoder_fields_are_not_required():
    value = minimal()
    value["rule"] = {"id": "550", "level": 7}
    value["agent"] = {"id": "001", "name": ENDPOINT.hostname}
    assert project_alert(encoded(value), config()).endpoint == ENDPOINT
