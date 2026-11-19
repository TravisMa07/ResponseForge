"""Independent native phase and aggregate oracles from the frozen B2 matrix."""

from copy import deepcopy

import pytest

from responseforge.integrations.shuffle.recorded_evidence import (
    _valid_proof,
    _valid_record,
    validate_summary,
)

# Independent requirement table, never imported from the implementation's EXPECTED.
PHASES = [
    (
        "powershell-awaiting",
        "powershell",
        "process",
        "awaiting_approval",
        "SKIPPED",
        0,
        0,
        "finished",
    ),
    ("powershell-approved", "powershell", "process", "ready", "SUCCESS", 1, 1, "finished"),
    ("powershell-duplicate", "powershell", "process", "completed", "SKIPPED", 1, 0, "finished"),
    ("lsass", "lsass", "process", "no_action", "SKIPPED", 0, 0, "finished"),
    ("task", "task", "persistence", "no_action", "SKIPPED", 0, 0, "finished"),
    ("note-awaiting", "note", "containment", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    ("note-approved", "note", "containment", "ready", "SUCCESS", 1, 1, "finished"),
    ("dns-awaiting", "dns", "containment", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    ("dns-approved", "dns", "containment", "ready", "SUCCESS", 1, 1, "finished"),
    (
        "powershell-negative",
        "powershell-negative",
        "process",
        "no_action",
        "SKIPPED",
        0,
        0,
        "finished",
    ),
    ("lsass-negative", "lsass-negative", "process", "no_action", "SKIPPED", 0, 0, "finished"),
    ("task-negative", "task-negative", "persistence", "no_action", "SKIPPED", 0, 0, "finished"),
    ("note-negative", "note-negative", "containment", "no_action", "SKIPPED", 0, 0, "finished"),
    ("dns-negative", "dns-negative", "containment", "no_action", "SKIPPED", 0, 0, "finished"),
    ("denied-awaiting", "denied", "process", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    ("denied-final", "denied", "process", "denied", "SKIPPED", 0, 0, "finished"),
    ("expired-awaiting", "expired", "process", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    ("expired-final", "expired", "process", "expired", "SKIPPED", 0, 0, "finished"),
    (
        "callback-loss",
        "callback-loss",
        "process",
        "awaiting_approval",
        "SKIPPED",
        0,
        0,
        "uncertain",
    ),
    ("task-failure", "task-failure", "process", "unavailable", "unavailable", 0, 0, "uncertain"),
]
SOURCES = {
    "powershell": (
        "splunk-powershell-create",
        "9200692ad74037b5234fe6f7da733d3e416b0ea8bb7f6d8ebb5bd16fc39b8b22",
    ),
    "lsass": (
        "splunk-lsass-access",
        "a37b69dce32eaff6b5c1fdb4bb9cbea6dec78a4fbd22cd41362ab0e377f075ef",
    ),
    "task": (
        "splunk-task-create",
        "a3ad53ea74a834f1fc90f4844766c0be5ecd688e7768f4b4b5af25eb65a0ecff",
    ),
    "note": (
        "splunk-ransom-note",
        "1183c2dc15b80beb3b80d46f101da9537a9c30240fca3ca86208579865ecf72b",
    ),
    "dns": (
        "splunk-process-dns",
        "ef076704e32f808551a2df65c0c0b09f8b0c34ff93a858d1ef57b0631506b9b9",
    ),
}


def valid_runs():
    values = {}
    for label, profile, kind, gate, native, effects, delta, state in PHASES:
        family = profile.removesuffix("-negative")
        if family in {"denied", "expired", "callback-loss", "task-failure"}:
            family = "powershell"
        artifact, source_hash = SOURCES[family]
        disposition = (
            "no_action"
            if profile.endswith("-negative")
            else ("escalate" if family in {"lsass", "task"} else "propose")
        )
        values[label] = {
            "profile": profile,
            "kind": kind,
            "gate_status": gate,
            "dispatch_native": native,
            "effect_count": effects,
            "effect_delta": delta,
            "delivery_state": state,
            "vendor_status": "FAILURE" if label == "task-failure" else "FINISHED",
            "duplicate_start": True,
            "graph_verified": True,
            "audit_verified": True,
            "source_verified": True,
            "callback_fault_proven": label == "callback-loss",
            "task_failure_proven": label == "task-failure",
            "core_restart_proven": label == "dns-awaiting",
            "artifact_id": artifact,
            "source_sha256": source_hash,
            "plan_disposition": disposition,
        }
    return values


def valid_summary():
    return {
        "runs": valid_runs(),
        "case_count": 14,
        "recorded_sources": 5,
        "recorded_scenarios": 5,
        "domain_workflows": 3,
        "unique_simulated_effects": 3,
        "negative_dispatch_attempts": 2,
        "duplicate_effects": 0,
        "forbidden_effects": 0,
        "expected_uncertain_fault_runs": 2,
        "mode": "replay",
        "verified_live": False,
        "effects_simulated": True,
        "endpoint_effect": "none",
        "runtime_qualified": True,
        "readiness": {
            "run_count": 14,
            "median_seconds": 1.0,
            "p95_seconds": 1.0,
            "failures": 0,
            "samples_seconds": [1.0] * 14,
        },
        "action_timings": [
            {
                "scenario": name,
                "approval_to_dispatch_seconds": 1.0,
                "dispatch_to_verified_seconds": 0.01,
            }
            for name in ("powershell-approved", "note-approved", "dns-approved")
        ],
        "recovery": {
            key: True
            for key in (
                "core_restart",
                "vendor_restart",
                "persistence_down_up",
                "unrelated_sentinel_preserved",
                "configured_execution_secret_scans",
            )
        },
        "revision": "a" * 40,
        "source_tree_sha256": "b" * 64,
        "recorded_source_sha256": "c" * 64,
    }


def test_complete_fixed_phase_record_is_accepted():
    assert _valid_record("powershell-approved", valid_runs()["powershell-approved"])


def test_all_twenty_independently_expected_phases_are_accepted():
    assert _valid_proof(valid_runs())


def test_complete_finite_source_bound_summary_is_accepted():
    assert validate_summary(valid_summary()) is None


@pytest.mark.parametrize("label", [phase[0] for phase in PHASES])
@pytest.mark.parametrize(
    "field",
    [
        "profile",
        "kind",
        "gate_status",
        "dispatch_native",
        "effect_count",
        "effect_delta",
        "delivery_state",
        "vendor_status",
        "artifact_id",
        "source_sha256",
        "plan_disposition",
        "duplicate_start",
        "graph_verified",
        "audit_verified",
        "source_verified",
        "callback_fault_proven",
        "task_failure_proven",
        "core_restart_proven",
    ],
)
def test_any_wrong_phase_field_cannot_qualify(label, field):
    value = valid_runs()[label]
    original = value[field]
    if isinstance(original, bool):
        value[field] = not original
    elif isinstance(original, int):
        value[field] = original + 1
    else:
        value[field] = "RUNNING" if field == "vendor_status" else "incorrect"
    assert _valid_record(label, value) is False


@pytest.mark.parametrize(
    "field",
    [
        "duplicate_start",
        "graph_verified",
        "audit_verified",
        "source_verified",
        "callback_fault_proven",
        "task_failure_proven",
        "core_restart_proven",
    ],
)
@pytest.mark.parametrize("incorrect", [0, 1, "true", None])
def test_proof_flags_require_actual_booleans(field, incorrect):
    value = valid_runs()["powershell-awaiting"]
    value[field] = incorrect
    assert _valid_record("powershell-awaiting", value) is False


@pytest.mark.parametrize(
    "label,value", [("powershell-approved", True), ("powershell-awaiting", False)]
)
@pytest.mark.parametrize("field", ["effect_count", "effect_delta"])
def test_boolean_effect_counts_are_not_integers(label, value, field):
    record = valid_runs()[label]
    record[field] = value
    assert _valid_record(label, record) is False


@pytest.mark.parametrize("record", [None, True, [], {}, "PRIVATE"])
def test_malformed_record_refuses_without_crashing(record):
    assert _valid_record("powershell-awaiting", record) is False


@pytest.mark.parametrize("label", [phase[0] for phase in PHASES])
def test_missing_phase_is_not_complete_coverage(label):
    runs = valid_runs()
    runs.pop(label)
    assert _valid_proof(runs) is False


def test_extra_or_renamed_phase_does_not_fill_required_coverage():
    runs = valid_runs()
    runs["extra"] = deepcopy(runs["powershell-approved"])
    assert _valid_proof(runs) is False
    runs.pop("extra")
    runs["renamed-approved"] = runs.pop("powershell-approved")
    assert _valid_proof(runs) is False


@pytest.mark.parametrize(
    "field",
    [
        "case_count",
        "recorded_sources",
        "recorded_scenarios",
        "domain_workflows",
        "unique_simulated_effects",
        "negative_dispatch_attempts",
        "duplicate_effects",
        "forbidden_effects",
        "expected_uncertain_fault_runs",
    ],
)
@pytest.mark.parametrize("wrong", [-1, 99, True, False, 0.0, "0"])
def test_summary_exact_integer_denominators_cannot_be_coerced(field, wrong):
    summary = valid_summary()
    summary[field] = wrong
    with pytest.raises(ValueError):
        validate_summary(summary)


@pytest.mark.parametrize(
    "field,wrong",
    [
        ("mode", "live"),
        ("verified_live", True),
        ("verified_live", 0),
        ("effects_simulated", False),
        ("effects_simulated", 1),
        ("endpoint_effect", "isolated"),
        ("revision", ""),
        ("revision", "PRIVATE invalid revision"),
        ("source_tree_sha256", "bad"),
        ("recorded_source_sha256", "bad"),
    ],
)
def test_summary_mode_or_source_identity_is_not_assumed(field, wrong):
    summary = valid_summary()
    summary[field] = wrong
    with pytest.raises(ValueError) as captured:
        validate_summary(summary)
    assert "PRIVATE" not in str(captured.value)


@pytest.mark.parametrize(
    "field,wrong",
    [
        ("run_count", 13),
        ("run_count", 20),
        ("failures", 1),
        ("failures", False),
        ("median_seconds", float("nan")),
        ("p95_seconds", float("inf")),
        ("median_seconds", -1),
        ("p95_seconds", True),
        ("median_seconds", 0.0),
        ("p95_seconds", 2.0),
    ],
)
def test_readiness_denominator_and_derived_distribution_are_bound(field, wrong):
    summary = valid_summary()
    summary["readiness"][field] = wrong
    with pytest.raises(ValueError):
        validate_summary(summary)


@pytest.mark.parametrize("wrong", [-1, float("inf"), float("nan"), True, None])
def test_readiness_samples_cannot_drop_or_coerce_bad_values(wrong):
    summary = valid_summary()
    summary["readiness"]["samples_seconds"][3] = wrong
    with pytest.raises(ValueError):
        validate_summary(summary)


def test_nearest_rank_distribution_is_computed_from_all_fourteen_samples():
    summary = valid_summary()
    summary["readiness"] = {
        "run_count": 14,
        "median_seconds": 7.5,
        "p95_seconds": 14.0,
        "failures": 0,
        "samples_seconds": [float(i) for i in range(1, 15)],
    }
    assert validate_summary(summary) is None
    summary["readiness"]["samples_seconds"].pop()
    with pytest.raises(ValueError):
        validate_summary(summary)


@pytest.mark.parametrize("field", ["approval_to_dispatch_seconds", "dispatch_to_verified_seconds"])
@pytest.mark.parametrize("wrong", [-1, float("inf"), float("nan"), False, None])
def test_action_timings_need_finite_nonnegative_real_measurements(field, wrong):
    summary = valid_summary()
    summary["action_timings"][0][field] = wrong
    with pytest.raises(ValueError):
        validate_summary(summary)


def test_three_action_samples_require_three_distinct_expected_approved_cases():
    summary = valid_summary()
    summary["action_timings"] = [summary["action_timings"][0]] * 3
    with pytest.raises(ValueError):
        validate_summary(summary)
    summary = valid_summary()
    summary["action_timings"][0]["scenario"] = "lsass"
    with pytest.raises(ValueError):
        validate_summary(summary)
    summary = valid_summary()
    summary["action_timings"].pop()
    with pytest.raises(ValueError):
        validate_summary(summary)


@pytest.mark.parametrize(
    "field",
    [
        "core_restart",
        "vendor_restart",
        "persistence_down_up",
        "unrelated_sentinel_preserved",
        "configured_execution_secret_scans",
    ],
)
@pytest.mark.parametrize("wrong", [False, 1, None])
def test_recovery_requires_independent_true_proofs(field, wrong):
    summary = valid_summary()
    summary["recovery"][field] = wrong
    with pytest.raises(ValueError):
        validate_summary(summary)
