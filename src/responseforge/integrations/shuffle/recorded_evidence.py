"""Frozen recorded runtime case/phase expectations; aggregate is not native proof."""

import math
import re
import statistics
from typing import Any

from responseforge.integrations.shuffle.recorded_bootstrap import _PROFILE

# label -> (profile, kind, gate, native dispatch, case effects, effect delta, delivery)
EXPECTED = {
    "powershell-awaiting": (
        "powershell",
        "process",
        "awaiting_approval",
        "SKIPPED",
        0,
        0,
        "finished",
    ),
    "powershell-approved": ("powershell", "process", "ready", "SUCCESS", 1, 1, "finished"),
    "powershell-duplicate": ("powershell", "process", "completed", "SKIPPED", 1, 0, "finished"),
    "lsass": ("lsass", "process", "no_action", "SKIPPED", 0, 0, "finished"),
    "task": ("task", "persistence", "no_action", "SKIPPED", 0, 0, "finished"),
    "note-awaiting": ("note", "containment", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    "note-approved": ("note", "containment", "ready", "SUCCESS", 1, 1, "finished"),
    "dns-awaiting": ("dns", "containment", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    "dns-approved": ("dns", "containment", "ready", "SUCCESS", 1, 1, "finished"),
    "powershell-negative": (
        "powershell-negative",
        "process",
        "no_action",
        "SKIPPED",
        0,
        0,
        "finished",
    ),
    "lsass-negative": ("lsass-negative", "process", "no_action", "SKIPPED", 0, 0, "finished"),
    "task-negative": ("task-negative", "persistence", "no_action", "SKIPPED", 0, 0, "finished"),
    "note-negative": ("note-negative", "containment", "no_action", "SKIPPED", 0, 0, "finished"),
    "dns-negative": ("dns-negative", "containment", "no_action", "SKIPPED", 0, 0, "finished"),
    "denied-awaiting": ("denied", "process", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    "denied-final": ("denied", "process", "denied", "SKIPPED", 0, 0, "finished"),
    "expired-awaiting": ("expired", "process", "awaiting_approval", "SKIPPED", 0, 0, "finished"),
    "expired-final": ("expired", "process", "expired", "SKIPPED", 0, 0, "finished"),
    "callback-loss": (
        "callback-loss",
        "process",
        "awaiting_approval",
        "SKIPPED",
        0,
        0,
        "uncertain",
    ),
    "task-failure": ("task-failure", "process", "unavailable", "unavailable", 0, 0, "uncertain"),
}


_SOURCE_HASHES = {
    "splunk-powershell-create": "9200692ad74037b5234fe6f7da733d3e416b0ea8bb7f6d8ebb5bd16fc39b8b22",
    "splunk-lsass-access": "a37b69dce32eaff6b5c1fdb4bb9cbea6dec78a4fbd22cd41362ab0e377f075ef",
    "splunk-task-create": "a3ad53ea74a834f1fc90f4844766c0be5ecd688e7768f4b4b5af25eb65a0ecff",
    "splunk-ransom-note": "1183c2dc15b80beb3b80d46f101da9537a9c30240fca3ca86208579865ecf72b",
    "splunk-process-dns": "ef076704e32f808551a2df65c0c0b09f8b0c34ff93a858d1ef57b0631506b9b9",
}


def _valid_record(label: str, item: Any) -> bool:
    if label not in EXPECTED or not isinstance(item, dict):
        return False
    profile, kind, gate, native, effects, delta, delivery = EXPECTED[label]
    artifact, _, _, disposition = _PROFILE[profile]
    statuses = {"FINISHED", "SUCCESS"}
    if label in {"callback-loss", "task-failure"}:
        statuses |= {"FAILURE", "ABORTED"}
    return (
        item.get("profile") == profile
        and item.get("kind") == kind
        and item.get("gate_status") == gate
        and item.get("dispatch_native") == native
        and type(item.get("effect_count")) is int
        and item["effect_count"] == effects
        and type(item.get("effect_delta")) is int
        and item["effect_delta"] == delta
        and item.get("delivery_state") == delivery
        and isinstance(item.get("vendor_status"), str)
        and item.get("vendor_status") in statuses
        and item.get("artifact_id") == artifact
        and item.get("source_sha256") == _SOURCE_HASHES[artifact]
        and item.get("plan_disposition") == disposition
        and all(
            item.get(key) is True
            for key in ("duplicate_start", "graph_verified", "audit_verified", "source_verified")
        )
        and item.get("callback_fault_proven") is (label == "callback-loss")
        and item.get("task_failure_proven") is (label == "task-failure")
        and item.get("core_restart_proven") is (label == "dns-awaiting")
    )


def _valid_proof(runs: dict[str, Any]) -> bool:
    return (
        isinstance(runs, dict)
        and set(runs) == set(EXPECTED)
        and all(_valid_record(label, value) for label, value in runs.items())
    )


def _number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_summary(summary: dict[str, Any]) -> None:
    try:
        counts = {
            "case_count": 14,
            "recorded_sources": 5,
            "recorded_scenarios": 5,
            "domain_workflows": 3,
            "unique_simulated_effects": 3,
            "negative_dispatch_attempts": 2,
            "duplicate_effects": 0,
            "forbidden_effects": 0,
            "expected_uncertain_fault_runs": 2,
        }
        if (
            not _valid_proof(summary["runs"])
            or any(
                type(summary.get(key)) is not int or summary[key] != value
                for key, value in counts.items()
            )
            or summary.get("runtime_qualified") is not True
            or summary.get("mode") != "replay"
            or summary.get("verified_live") is not False
            or summary.get("effects_simulated") is not True
            or summary.get("endpoint_effect") != "none"
            or re.fullmatch(r"[0-9a-f]{40}(?:-dirty)?", summary["revision"]) is None
            or any(
                re.fullmatch(r"[0-9a-f]{64}", summary[key]) is None
                for key in ("source_tree_sha256", "recorded_source_sha256")
            )
            or any(
                summary["recovery"].get(key) is not True
                for key in (
                    "core_restart",
                    "vendor_restart",
                    "persistence_down_up",
                    "unrelated_sentinel_preserved",
                    "configured_execution_secret_scans",
                )
            )
        ):
            raise ValueError
        ready = summary["readiness"]
        samples = ready["samples_seconds"]
        if (
            type(ready["run_count"]) is not int
            or ready["run_count"] != 14
            or type(ready["failures"]) is not int
            or ready["failures"] != 0
            or not isinstance(samples, list)
            or len(samples) != 14
            or any(not _number(value) for value in samples)
            or not _number(ready["median_seconds"])
            or not _number(ready["p95_seconds"])
            or not math.isclose(ready["median_seconds"], statistics.median(samples), abs_tol=1e-9)
            or not math.isclose(
                ready["p95_seconds"],
                sorted(samples)[math.ceil(0.95 * len(samples)) - 1],
                abs_tol=1e-9,
            )
        ):
            raise ValueError
        actions = summary["action_timings"]
        if (
            not isinstance(actions, list)
            or len(actions) != 3
            or {value["scenario"] for value in actions}
            != {"powershell-approved", "note-approved", "dns-approved"}
            or any(
                not _number(value[key])
                for value in actions
                for key in ("approval_to_dispatch_seconds", "dispatch_to_verified_seconds")
            )
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError(
            "Recorded native qualification evidence is incomplete or inconsistent"
        ) from None
