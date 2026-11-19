"""Default-redacted JSON/HTML case reports; no raw telemetry export."""

import html
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from responseforge.contracts import Alert
from responseforge.core import CaseService
from responseforge.replay import make_alerts
from responseforge.replay_contracts import digest
from responseforge.runtime import Principal

_FREE_TEXT = frozenset(
    {
        "assessment",
        "rationale",
        "detail",
        "error",
        "known_gaps",
        "unavailable_reason",
        "no_action_reason",
        "hostname",
        "agent_id",
        "endpoint_id",
        "resource",
        "actor",
        "approver_id",
    }
)
_SENSITIVE = (
    "command",
    "password",
    "secret",
    "token",
    "authorization",
    "environment",
    "raw",
    "fields",
    "credential",
    "api_key",
    "auth",
    "env",
)


# Explicit projection: adding a new source/model field must not silently export it.
_KNOWN_FIELDS = frozenset(
    """schema_version incident_id status mode simulated verified_live
incident alert evidence actions audit metrics workflows redaction_notice decision_summary
known_gap_count source_selection source_transformation alert_id scenario_id endpoint priority assessment created_at source event_time
 ingested_at rule_id severity provenance evidence_refs source_ref sha256 original_event_ids
 evidence_id observed_at collected_at availability unavailable_reason classification proposal
 approval execution proposal_id target action rationale risk expires_at idempotency_key
 approval_id approver_id decision decided_at execution_id provider dispatch_state requested_at
 updated_at verification error checked_at detail event_id correlation_id actor operation
 occurred_at kind revision environment readiness known_gaps proposal_ids no_action_reason
 audit_event_id run_id workflow_id workflow_version started_at ended_at hostname agent_id
 endpoint_id resource""".split()
)


class ReportError(ValueError):
    """The requested report cannot be safely exported."""


def _text(value: str, secrets: tuple[str, ...]) -> str:
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        value = value.replace(secret, "[redacted]")
    value = re.sub(r"(?i)\bbearer\s+[^\s\"<>]+", "Bearer [redacted]", value)
    return value


def _redact(value: Any, secrets: tuple[str, ...], key: str = "") -> Any:
    name = key.lower()
    if (
        name in _FREE_TEXT
        or any(part in name for part in _SENSITIVE)
        or (key and name not in _KNOWN_FIELDS)
    ):
        if isinstance(value, list):
            return ["[redacted]" for _ in value]
        return None if value is None else "[redacted]"
    if isinstance(value, dict):
        return {_text(str(k), secrets): _redact(v, secrets, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, secrets) for v in value]
    if isinstance(value, str):
        return _text(value, secrets)
    return value


def _source_scope(service: CaseService, alert: Alert) -> tuple[str, str]:
    """Expose fixed scope labels only when the registered source matches this case."""
    try:
        if alert.mode == "live" and alert.source == "wazuh":
            from responseforge.integrations.wazuh.service import source_scope
            return source_scope(service, alert)
        if alert.mode != "replay":
            return "unavailable", "unavailable"
        batch = service.settings.source_for_alert(alert)
        if not any(value == alert for value in make_alerts(batch, ingested_at=alert.ingested_at)):
            return "unavailable", "unavailable"
        selected = batch.origin is not None and batch.origin.selected_event_ids is not None
        return (
            "explicit_subset" if selected else "full_registered_source",
            "original-json" if batch.origin is None else batch.origin.transformation,
        )
    except (ValueError, TypeError, AttributeError, OverflowError):
        return "unavailable", "unavailable"


def build_report(
    service: CaseService, incident_id: str, actor: Principal, *, secrets: tuple[str, ...] = ()
) -> dict[str, Any]:
    snapshot = service.snapshot(incident_id, actor)
    value = snapshot.model_dump(mode="json", warnings=False)
    replay = snapshot.incident.mode == "replay"
    value.update(
        schema_version="1.0",
        incident_id=snapshot.incident.incident_id,
        status=snapshot.incident.status.value,
        mode=snapshot.incident.mode.value,
        simulated=replay,
        verified_live=(
            not replay
            and any(
                a.execution is not None and a.execution.verification.verified_live
                for a in snapshot.actions
            )
        ),
    )
    value["decision_summary"] = (
        "awaiting_human_approval"
        if snapshot.incident.status == "AWAITING_APPROVAL"
        else "no_supported_action"
        if not snapshot.actions
        else "human_rejected"
        if any(
            a.approval is not None and a.approval.decision != "approved" for a in snapshot.actions
        )
        else "verified_simulated_effect"
        if replay
        and any(
            a.execution is not None and a.execution.verification.status == "verified"
            for a in snapshot.actions
        )
        else "see_recorded_outcome"
    )
    value["source_selection"], value["source_transformation"] = _source_scope(service, snapshot.alert)
    value["known_gap_count"] = max(
        (len(e.readiness.known_gaps) for e in snapshot.metrics if e.readiness is not None),
        default=0,
    )
    if not replay and snapshot.alert.source == "wazuh":
        value["known_gap_count"] = max(
            value["known_gap_count"],
            sum(item.availability == "unavailable" for item in snapshot.evidence),
        )
    redacted: dict[str, Any] = _redact(value, secrets)
    redacted["redaction_notice"] = (
        "Default redaction: source payloads, commands, credentials, free text, endpoint identity, "
        "resources and actor identities omitted. Simulation is not endpoint proof."
    )
    return redacted


def render_html(report: dict[str, Any]) -> str:
    safe = _redact(report, ())
    payload = html.escape(json.dumps(safe, indent=2, sort_keys=True, ensure_ascii=False))
    mode = html.escape(str(safe.get("mode", "unknown")))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>ResponseForge case report</title><style>"
        "body{font:16px system-ui;margin:2rem auto;max-width:75rem;padding:0 1rem;background:#f4f6f8;color:#172434}"
        "h1{font-size:1.7rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:1.5rem;border:1px solid #ccd4df}"
        "</style></head><body><h1>ResponseForge case report</h1>"
        f"<p>Mode: {mode}. Simulated replay is not live endpoint proof.</p><pre>{payload}</pre></body></html>\n"
    )


def write_report(report: dict[str, Any], directory: str | Path) -> tuple[Path, Path]:
    identity = report.get("incident_id")
    if not isinstance(identity, str) or not identity:
        raise ReportError("Report requires a case identity")
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    name = "case-" + digest(identity)
    safe = _redact(report, ())
    outputs = (
        (directory / (name + ".json"), json.dumps(safe, indent=2, sort_keys=True) + "\n"),
        (directory / (name + ".html"), render_html(safe)),
    )
    for path, content in outputs:
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=directory, delete=False
            ) as stream:
                temporary = stream.name
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None and os.path.exists(temporary):
                os.unlink(temporary)
    return outputs[0][0], outputs[1][0]
