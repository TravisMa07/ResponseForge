"""Atomic source intake reusing the common core's authorized case transaction."""

import json

from pydantic import ValidationError

from responseforge.contracts import Alert, Evidence, Incident, MetricEvent
from responseforge.core import CaseService, ServiceError
from responseforge.integrations.wazuh.mapping import WazuhError, WazuhScopeError, project_alert
from responseforge.integrations.wazuh.models import WazuhReceipt
from responseforge.runtime import IntakeResult, Principal
from responseforge.storage import Transaction


def _key(alert: Alert) -> str:
    return json.dumps(alert.dedup_identity, separators=(",", ":"))


def verify_receipt(core: CaseService, tx: Transaction, incident_id: str) -> WazuhReceipt:
    """Reobserve original bytes and immutable typed proof; never repair it."""
    try:
        config = core.settings.wazuh
        if config is None or core.settings.mode != "live":
            raise ValueError
        receipt = WazuhReceipt.model_validate(tx.get("callbacks", "wazuh-source:" + incident_id))
        observation = project_alert(receipt.raw_json.encode("utf-8"), config)
        expected = observation.to_alert(receipt.alert.ingested_at)
        evidence = observation.evidence(incident_id, expected.ingested_at)
        original = Alert.model_validate(tx.get("alerts", incident_id))
        incident = Incident.model_validate(tx.get("incidents", incident_id))
        if (
            receipt.manager_id != config.manager_id
            or receipt.incident_id != incident_id
            or receipt.alert != expected
            or original != expected
            or receipt.evidence != evidence
            or tx.get_key("intake", _key(expected)) != incident_id
            or incident.incident_id != incident_id
            or incident.alert_id != expected.alert_id
            or incident.mode != expected.mode
            or incident.scenario_id != expected.scenario_id
            or incident.endpoint != expected.endpoint
        ):
            raise ValueError
        accepted = [
            MetricEvent.model_validate(item)
            for item in tx.list("metrics")
            if item.get("incident_id") == incident_id and item.get("kind") == "alert_accepted"
        ]
        if len(accepted) != 1:
            raise ValueError
        metric = accepted[0]
        expected_meta = dict(
            incident_id=incident_id,
            alert_id=expected.alert_id,
            correlation_id=metric.correlation_id,
            scenario_id=expected.scenario_id,
            mode=expected.mode.value,
        )
        if (
            tx.get("case_meta", incident_id) != expected_meta
            or any(getattr(metric, key) != value for key, value in expected_meta.items())
            or metric.occurred_at != incident.created_at
            or expected.ingested_at > incident.created_at
        ):
            raise ValueError
        for item in evidence:
            if Evidence.model_validate(tx.get("evidence", item.evidence_id)) != item:
                raise ValueError
        return receipt
    except (ValueError, TypeError, AttributeError, OverflowError, UnicodeError):
        raise ServiceError(409, "Original native source proof unavailable or conflicting") from None


class WazuhService:
    def __init__(self, core: CaseService) -> None:
        self.core = core

    def intake(self, raw: bytes, actor: Principal) -> IntakeResult:
        core = self.core
        with core._operation(None, actor):
            config = core.settings.wazuh
            if config is None:
                raise ServiceError(404, "Native integration is disabled")
            core._principal(actor, {"source"})
            if (
                core.settings.mode != "live"
                or core.settings.live_dispatch_enabled
                or core.settings.providers
                or actor.actor_id != config.source_actor_id
                or actor.roles != {"source"}
                or actor.human
            ):
                raise ServiceError(403, "Native source actor or mode is not authorized")
            try:
                observation = project_alert(raw, config)
            except WazuhScopeError:
                raise ServiceError(403, "Native agent scope is not authorized") from None
            except (WazuhError, ValidationError):
                raise ServiceError(422, "Invalid native alert") from None
            core._endpoint(observation.endpoint, actor)
            with core.store.transaction() as tx:
                alert = observation.to_alert(core._now())
                existing = tx.get_key("intake", _key(alert))
                if existing is not None:
                    receipt = verify_receipt(core, tx, existing)
                    if receipt.raw_json.encode("utf-8") != raw:
                        raise ServiceError(409, "Native alert identity has conflicting bytes")
                    return core._intake_tx(tx, receipt.alert, actor)
                result = core._intake_tx(tx, alert, actor)
                if result.duplicate:
                    raise ServiceError(409, "Native identity conflict")
                evidence = observation.evidence(result.incident_id, alert.ingested_at)
                for item in evidence:
                    tx.insert("evidence", item.evidence_id, item.model_dump(mode="json"))
                receipt = WazuhReceipt(
                    manager_id=config.manager_id,
                    incident_id=result.incident_id,
                    alert=alert,
                    raw_json=observation.raw_json,
                    evidence=evidence,
                )
                tx.insert(
                    "callbacks",
                    "wazuh-source:" + result.incident_id,
                    receipt.model_dump(mode="json"),
                )
                core._audit(
                    tx,
                    result.incident_id,
                    actor,
                    "wazuh_source_received",
                    "Received integration delivery and explicit evidence gap stored",
                )
                return result


def source_scope(core: CaseService, alert: Alert) -> tuple[str, str]:
    try:
        with core.store.transaction() as tx:
            incident_id = tx.get_key("intake", _key(alert))
            if incident_id is None or verify_receipt(core, tx, incident_id).alert != alert:
                raise ValueError
        return "complete_received_alert", "wazuh-alert-json-v1"
    except (ValueError, TypeError, ServiceError):
        return "unavailable", "unavailable"
