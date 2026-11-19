"""Independent acceptance of aggregate evidence; not genuine execution evidence."""

from copy import deepcopy

import pytest

from responseforge.integrations.shuffle.playbook_qualification import _distribution, _valid_proof

# Frozen scenario meanings derive from the requirements/design, not helper output.
_EXPECTED = {
    "process-awaiting": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "process-approved": ("process", "ready", "SUCCESS", 1, "finished"),
    "process-duplicate": ("process", "completed", "SKIPPED", 1, "finished"),
    "denied-awaiting": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "denied-final": ("process", "denied", "SKIPPED", 0, "finished"),
    "expired-awaiting": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "expired-final": ("process", "expired", "SKIPPED", 0, "finished"),
    "incomplete": ("process", "no_action", "SKIPPED", 0, "finished"),
    "persistence": ("persistence", "no_action", "SKIPPED", 0, "finished"),
    "containment-awaiting": ("containment", "awaiting_approval", "SKIPPED", 0, "finished"),
    "containment-approved": ("containment", "ready", "SUCCESS", 1, "finished"),
    "callback-loss": ("process", "awaiting_approval", "SKIPPED", 0, "uncertain"),
    "restart": ("process", "awaiting_approval", "SKIPPED", 0, "finished"),
    "task-failure": ("process", "unavailable", "unavailable", 0, "uncertain"),
}


def complete_proof():
    return {
        name: {
            "kind": kind,
            "vendor_status": "FINISHED",
            "delivery_state": state,
            "gate_status": gate,
            "dispatch_native": native,
            "effect_count": effects,
            "graph_verified": True,
            "audit_verified": True,
            "duplicate_start": True,
            "callback_fault_proven": name == "callback-loss",
            "task_failure_proven": name == "task-failure",
            "core_restart_proven": name == "restart",
        }
        for name, (kind, gate, native, effects, state) in _EXPECTED.items()
    }


def test_exact_fourteen_scenario_proof_passes():
    assert _valid_proof(complete_proof()) is True


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_each_scenario_phase_is_required_not_merely_a_safe_gate(label):
    proof = complete_proof()
    proof[label]["gate_status"] = "ready" if _EXPECTED[label][1] != "ready" else "completed"
    proof[label]["dispatch_native"] = (
        "SUCCESS" if proof[label]["gate_status"] == "ready" else "SKIPPED"
    )
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_each_scenario_kind_is_bound(label):
    proof = complete_proof()
    proof[label]["kind"] = "containment" if _EXPECTED[label][0] != "containment" else "process"
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
@pytest.mark.parametrize("status", ["EXECUTING", "WAITING", "unknown", None])
def test_nonterminal_or_unknown_vendor_status_cannot_pass(label, status):
    proof = complete_proof()
    proof[label]["vendor_status"] = status
    assert _valid_proof(proof) is False


@pytest.mark.parametrize(
    "label", [name for name in _EXPECTED if name not in {"callback-loss", "task-failure"}]
)
@pytest.mark.parametrize("status", ["FAILURE", "ABORTED"])
def test_failed_vendor_cannot_establish_ordinary_success(label, status):
    proof = complete_proof()
    proof[label]["vendor_status"] = status
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_missing_any_required_scenario_rejects(label):
    proof = complete_proof()
    del proof[label]
    assert _valid_proof(proof) is False


def test_extra_unknown_scenario_does_not_replace_frozen_matrix():
    proof = complete_proof()
    proof["invented-pass"] = deepcopy(proof["process-approved"])
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
@pytest.mark.parametrize("field", ["graph_verified", "audit_verified", "duplicate_start"])
def test_unproven_graph_audit_or_duplicate_delivery_rejects(label, field):
    proof = complete_proof()
    proof[label][field] = "true"
    assert _valid_proof(proof) is False


@pytest.mark.parametrize(
    "label,field",
    [
        ("callback-loss", "callback_fault_proven"),
        ("task-failure", "task_failure_proven"),
        ("restart", "core_restart_proven"),
    ],
)
@pytest.mark.parametrize("value", [False, None, "true", 1])
def test_fault_or_restart_claim_requires_actual_boolean_proof(label, field, value):
    proof = complete_proof()
    proof[label][field] = value
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_only_expected_action_effect_counts_pass(label):
    proof = complete_proof()
    proof[label]["effect_count"] = 0 if _EXPECTED[label][3] else 1
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_boolean_is_not_a_measured_effect_count(label):
    proof = complete_proof()
    proof[label]["effect_count"] = bool(_EXPECTED[label][3])
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_wrong_native_dispatch_is_not_valid_branch_evidence(label):
    proof = complete_proof()
    proof[label]["dispatch_native"] = "SUCCESS" if _EXPECTED[label][2] != "SUCCESS" else "SKIPPED"
    assert _valid_proof(proof) is False


@pytest.mark.parametrize("label", list(_EXPECTED))
def test_wrong_coordinator_result_rejects(label):
    proof = complete_proof()
    proof[label]["delivery_state"] = (
        "finished" if _EXPECTED[label][4] == "uncertain" else "uncertain"
    )
    assert _valid_proof(proof) is False


@pytest.mark.parametrize(
    "samples", [[], [-0.001], [float("nan")], [float("inf")], [float("-inf")], [0.0, float("nan")]]
)
def test_timestamp_distribution_rejects_missing_negative_or_nonfinite_samples(samples):
    with pytest.raises(ValueError):
        _distribution(samples)


def test_distribution_has_known_median_nearest_rank_p95_and_count():
    measured = _distribution([float(value) for value in range(20, 0, -1)])
    assert measured["run_count"] == 20
    assert measured["median_seconds"] == 10.5
    assert measured["p95_seconds"] == 19.0
    assert measured["failures"] == 0


def test_zero_and_single_timestamp_are_valid_finite_samples():
    measured = _distribution([0.0])
    assert (
        measured["run_count"] == 1 and measured["median_seconds"] == measured["p95_seconds"] == 0.0
    )
