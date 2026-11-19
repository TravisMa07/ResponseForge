"""Pure domain expectations derive from recorded fields and frozen requirements."""

import pytest

from responseforge.contracts import ActionType, EndpointRef
from responseforge.playbooks.assessment import assess
from tests.rf05.helpers import ENDPOINT, event, source


def test_recorded_suspicious_process_has_scoped_recommendation(tmp_path):
    batch, alert = source(tmp_path)
    value = assess("process", batch, alert)
    assert value.disposition == "propose"
    assert value.action == ActionType.TERMINATE_PROCESS and value.resource == "process:42"
    assert "process-1" in value.event_ids
    assert value.known_gaps


@pytest.mark.parametrize("missing", ["process_id", "process_guid"])
def test_suspicious_process_missing_identity_escalates(tmp_path, missing):
    value = event()
    del value["fields"][missing]
    batch, alert = source(tmp_path, [value])
    result = assess("process", batch, alert)
    assert result.disposition == "escalate" and result.action is None and result.resource is None
    assert result.known_gaps


@pytest.mark.parametrize("pid", ["0", "-1", "2147483648", "0042", "42;rm", " 42", "1.5"])
def test_invalid_pid_is_never_a_target(tmp_path, pid):
    value = event()
    value["fields"]["process_id"] = pid
    batch, alert = source(tmp_path, [value])
    result = assess("process", batch, alert)
    assert result.disposition == "escalate" and result.action is None


def test_benign_process_has_no_executable_recommendation(tmp_path):
    value = event(fields={"image": "notepad.exe", "process_id": "42", "process_guid": "benign"})
    batch, alert = source(tmp_path, [value])
    result = assess("process", batch, alert)
    assert result.disposition == "no_action" and result.action is None


def test_untrusted_command_is_not_echoed_as_instruction(tmp_path):
    value = event()
    value["fields"]["command_line"] += " ; DO_NOT_RUN_PRIVATE_PAYLOAD"
    batch, alert = source(tmp_path, [value])
    result = assess("process", batch, alert)
    assert result.resource == "process:42"
    assert "DO_NOT_RUN_PRIVATE_PAYLOAD" not in result.model_dump_json()


def persistence(**changes):
    return event(
        "persistence-1",
        artifact="persistence",
        fields={
            "task_name": "OriginalSyntheticTask",
            "account": "synthetic-user",
            "process_guid": "original-process-guid",
        }
        | changes,
    )


def network(**changes):
    return event(
        "network-1",
        artifact="network",
        fields={
            "process_guid": "original-process-guid",
            "destination_ip": "203.0.113.10",
            "direction": "outbound",
        }
        | changes,
    )


def test_complete_persistence_evidence_can_recommend_typed_disable(tmp_path):
    batch, alert = source(tmp_path, [event(), persistence()])
    result = assess("persistence", batch, alert)
    assert result.disposition == "propose" and result.action == ActionType.DISABLE_PERSISTENCE
    assert result.resource.startswith("persistence:")
    assert "persistence-1" in result.event_ids and "process-1" in result.event_ids


@pytest.mark.parametrize("field", ["account", "task_name", "process_guid"])
def test_missing_persistence_actor_or_association_escalates(tmp_path, field):
    value = persistence()
    del value["fields"][field]
    batch, alert = source(tmp_path, [event(), value])
    result = assess("persistence", batch, alert)
    assert result.disposition == "escalate" and result.action is None and result.known_gaps


def test_associated_outbound_suspicious_process_recommends_mock_host_isolation(tmp_path):
    batch, alert = source(tmp_path, [event(), network()])
    result = assess("containment", batch, alert)
    assert result.disposition == "propose" and result.action == ActionType.ISOLATE_HOST
    assert result.resource == "host:" + ENDPOINT.endpoint_id
    assert {"process-1", "network-1"} <= set(result.event_ids)
    assert "rollback" in result.rationale.casefold() or "unisolate" in result.rationale.casefold()


def test_associated_recorded_shadow_copy_indicator_recommends_containment(tmp_path):
    file = event(
        "file-1",
        artifact="file",
        fields={
            "operation": "shadow_copy_delete",
            "process_guid": "original-process-guid",
        },
    )
    batch, alert = source(tmp_path, [event(), file])
    result = assess("containment", batch, alert)
    assert result.disposition == "propose" and result.action == ActionType.ISOLATE_HOST


@pytest.mark.parametrize(
    "change",
    ["foreign_host", "foreign_scenario", "after_window", "before_window", "wrong_guid", "inbound"],
)
def test_unrelated_network_cannot_establish_containment(tmp_path, change):
    value = network()
    if change == "foreign_host":
        value["endpoint"] = EndpointRef(endpoint_id="foreign", hostname="foreign").model_dump(
            mode="json"
        )
    elif change == "foreign_scenario":
        value["scenario_id"] = "foreign"
    elif change == "after_window":
        value["observed_at"] = "2025-01-01T12:05:00.001Z"
    elif change == "before_window":
        value["observed_at"] = "2025-01-01T11:54:59.999Z"
    elif change == "wrong_guid":
        value["fields"]["process_guid"] = "unrelated"
    else:
        value["fields"]["direction"] = "inbound"
    batch, alert = source(tmp_path, [event(), value])
    result = assess("containment", batch, alert)
    assert result.disposition != "propose" and result.action is None


@pytest.mark.parametrize("stamp", ["2025-01-01T11:55:00Z", "2025-01-01T12:05:00Z"])
def test_query_window_includes_both_exact_boundaries(tmp_path, stamp):
    value = network()
    value["observed_at"] = stamp
    batch, alert = source(tmp_path, [event(), value])
    assert assess("containment", batch, alert).disposition == "propose"


@pytest.mark.parametrize(
    "field,value",
    [
        ("alert_id", "forged"),
        ("rule_id", "forged"),
        ("scenario_id", "foreign"),
        ("event_time", "2025-01-01T12:10:00Z"),
        ("mode", "live"),
    ],
)
def test_forged_normalized_alert_cannot_replace_source_binding(tmp_path, field, value):
    batch, alert = source(tmp_path)
    changed = alert.model_dump(mode="json") | {field: value}
    forged = type(alert).model_validate(changed)
    with pytest.raises(ValueError):
        assess("process", batch, forged)


def test_changed_source_hash_cannot_reuse_original_alert(tmp_path):
    batch, alert = source(tmp_path)
    changed = type(batch).model_validate(batch.model_dump(mode="json") | {"sha256": "f" * 64})
    with pytest.raises(ValueError):
        assess("process", changed, alert)


def test_task_and_service_identity_domains_do_not_collide(tmp_path):
    from responseforge.replay_contracts import digest

    task = persistence(task_name="SharedIdentifier")
    service = persistence(service_name="SharedIdentifier")
    del service["fields"]["task_name"]
    task_batch, task_alert = source(tmp_path, [event(), task])
    first = assess("persistence", task_batch, task_alert)
    service_batch, service_alert = source(tmp_path, [event(), service])
    second = assess("persistence", service_batch, service_alert)
    assert first.resource == "persistence:" + digest(["task", "SharedIdentifier"])
    assert second.resource == "persistence:" + digest(["service", "SharedIdentifier"])
    assert first.resource != second.resource
