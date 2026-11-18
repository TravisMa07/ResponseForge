"""Durably reserve a Shuffle start once; ambiguous delivery only reconciles."""

from typing import Any

from pydantic import ValidationError

from responseforge.contracts import PlaybookRun
from responseforge.core import CaseService, ServiceError
from responseforge.integrations.shuffle.client import ShuffleTransport
from responseforge.integrations.shuffle.models import (
    DeliveryRecord,
    ShuffleArgument,
    ShuffleError,
    WorkflowBinding,
    canonical_uuid,
)
from responseforge.runtime import Principal
from responseforge.storage import Transaction


class ShuffleCoordinator:
    def __init__(
        self, service: CaseService, client: ShuffleTransport, bindings: dict[str, WorkflowBinding]
    ) -> None:
        self.service = service
        self.client = client
        self.bindings = {
            key: WorkflowBinding.model_validate(value.model_dump(mode="json", warnings=False))
            for key, value in bindings.items()
        }

    def _argument(
        self, tx: Transaction, incident_id: str, run_id: str, actor: Principal
    ) -> ShuffleArgument:
        self.service._principal(actor, {"analyst"})
        incident = self.service._incident(tx, incident_id, actor)
        meta = tx.get("case_meta", incident_id)
        if (
            meta is None
            or meta.get("incident_id") != incident_id
            or meta.get("alert_id") != incident.alert_id
            or meta.get("scenario_id") != incident.scenario_id
            or meta.get("mode") != incident.mode.value
        ):
            raise ServiceError(409, "Stored workflow case correlation is invalid")
        try:
            return ShuffleArgument(
                incident_id=incident_id,
                run_id=run_id,
                correlation_id=meta["correlation_id"],
                mode=incident.mode,
            )
        except (ValueError, TypeError, KeyError):
            raise ServiceError(409, "Stored workflow case correlation is invalid") from None

    def _binding(self, workflow_id: str) -> WorkflowBinding:
        try:
            canonical_uuid(workflow_id)
        except ValueError:
            raise ServiceError(422, "Invalid workflow identity") from None
        binding = self.bindings.get(workflow_id)
        if binding is None or workflow_id not in self.client.config.workflow_ids:
            raise ServiceError(403, "Workflow is not configured and reviewed")
        return binding

    @staticmethod
    def _record(value: dict[str, Any]) -> DeliveryRecord:
        try:
            return DeliveryRecord.model_validate(value)
        except (ValueError, TypeError):
            raise ServiceError(409, "Stored workflow delivery is invalid") from None

    def _bound(self, record: DeliveryRecord, argument: ShuffleArgument, workflow_id: str) -> None:
        binding = self._binding(workflow_id)
        if (
            record.argument != argument
            or record.workflow_id != workflow_id
            or record.workflow_version != binding.version
            or record.workflow_sha256 != binding.sha256
            or record.origin != self.client.config.base_url
        ):
            raise ServiceError(409, "Original workflow delivery scope cannot change")

    def _run(
        self, tx: Transaction, argument: ShuffleArgument, workflow_id: str, *, required: bool
    ) -> PlaybookRun | None:
        value = tx.get("workflows", argument.run_id)
        if value is None:
            if required:
                raise ServiceError(409, "Original workflow run missing")
            return None
        try:
            run = PlaybookRun.model_validate(value)
        except ValidationError:
            raise ServiceError(409, "Stored workflow run is invalid") from None
        binding = self._binding(workflow_id)
        if (
            run.run_id != argument.run_id
            or run.incident_id != argument.incident_id
            or run.correlation_id != argument.correlation_id
            or run.workflow_id != workflow_id
            or run.workflow_version != binding.version
        ):
            raise ServiceError(409, "Stored workflow run scope is invalid")
        return run

    async def start(
        self, incident_id: str, workflow_id: str, run_id: str, actor: Principal
    ) -> DeliveryRecord:
        with self.service._operation(incident_id, actor):
            try:
                canonical_uuid(run_id)
            except ValueError:
                raise ServiceError(422, "Invalid workflow run identity") from None
            binding = self._binding(workflow_id)
            key = "shuffle:" + run_id
            with self.service.store.transaction() as tx:
                argument = self._argument(tx, incident_id, run_id, actor)
                self._run(tx, argument, workflow_id, required=False)
                old = tx.get("callbacks", key)
                if old is not None:
                    record = self._record(old)
                    self._bound(record, argument, workflow_id)
                    self._run(tx, argument, workflow_id, required=True)
                    return record
            try:
                artifact = await self.client.get_workflow(workflow_id)
            except ShuffleError:
                raise ServiceError(503, "Shuffle workflow preflight unavailable") from None
            if artifact.workflow_id != workflow_id or artifact.sha256 != binding.sha256:
                raise ServiceError(409, "Shuffle workflow differs from reviewed artifact")
            with self.service.store.transaction() as tx:
                argument = self._argument(tx, incident_id, run_id, actor)
                self._run(tx, argument, workflow_id, required=False)
                old = tx.get("callbacks", key)
                if old is not None:
                    record = self._record(old)
                    self._bound(record, argument, workflow_id)
                    self._run(tx, argument, workflow_id, required=True)
                    return record
                now = self.service._now()
                run_data = tx.get("workflows", run_id)
                if run_data is not None:
                    try:
                        run = PlaybookRun.model_validate(run_data)
                    except ValidationError:
                        raise ServiceError(409, "Stored workflow run is invalid") from None
                    if (
                        run.run_id != run_id
                        or run.incident_id != incident_id
                        or run.workflow_id != workflow_id
                        or run.workflow_version != binding.version
                        or run.correlation_id != argument.correlation_id
                        or run.status != "running"
                    ):
                        raise ServiceError(409, "Workflow run identity already has another scope")
                else:
                    run = PlaybookRun(
                        run_id=run_id,
                        incident_id=incident_id,
                        workflow_id=workflow_id,
                        workflow_version=binding.version,
                        correlation_id=argument.correlation_id,
                        started_at=now,
                        status="running",
                    )
                    tx.insert("workflows", run_id, run.model_dump(mode="json"))
                record = DeliveryRecord(
                    argument=argument,
                    workflow_id=workflow_id,
                    workflow_version=binding.version,
                    workflow_sha256=binding.sha256,
                    origin=self.client.config.base_url,
                    state="reserved",
                    created_at=now,
                    updated_at=now,
                )
                tx.insert("callbacks", key, record.model_dump(mode="json"))
                self.service._audit(
                    tx, incident_id, actor, "shuffle_reserved", "Workflow start durably reserved"
                )
            try:
                receipt = await self.client.start_execution(workflow_id, run_id, argument)
                if receipt.workflow_id != workflow_id or receipt.execution_id != run_id:
                    raise ShuffleError("uncertain", "Workflow receipt correlation invalid")
                state = "accepted"
            except ShuffleError as error:
                state = "rejected" if error.kind == "rejected" else "uncertain"
            except Exception:
                state = "uncertain"
            return self._save(record, state, None, actor)

    def _save(
        self, original: DeliveryRecord, state: str, vendor_status: str | None, actor: Principal
    ) -> DeliveryRecord:
        with self.service.store.transaction() as tx:
            argument = self._argument(
                tx, original.argument.incident_id, original.argument.run_id, actor
            )
            self._bound(original, argument, original.workflow_id)
            key = "shuffle:" + original.argument.run_id
            value = tx.get("callbacks", key)
            if value is None:
                raise ServiceError(409, "Original workflow reservation missing")
            current = self._record(value)
            self._bound(current, argument, original.workflow_id)
            self._run(tx, argument, original.workflow_id, required=True)
            if current.state in {"finished", "failed", "rejected"}:
                if state in {"finished", "failed", "rejected"} and state != current.state:
                    raise ServiceError(409, "Workflow terminal observations conflict")
                return current
            now = self.service._now()
            if now < current.updated_at:
                return current
            result = DeliveryRecord.model_validate(
                current.model_dump(mode="json")
                | {"state": state, "vendor_status": vendor_status, "updated_at": now}
            )
            run_data = tx.get("workflows", argument.run_id)
            if run_data is None:
                raise ServiceError(409, "Original workflow run missing")
            run = PlaybookRun.model_validate(run_data)
            if (
                run.run_id != argument.run_id
                or run.incident_id != argument.incident_id
                or run.correlation_id != argument.correlation_id
                or run.workflow_id != result.workflow_id
                or run.workflow_version != result.workflow_version
            ):
                raise ServiceError(409, "Stored workflow run scope is invalid")
            target = (
                "succeeded"
                if state == "finished"
                else "failed"
                if state in {"failed", "rejected"}
                else "running"
            )
            if run.status != "running" and target != "running" and run.status != target:
                raise ServiceError(409, "Workflow terminal observations conflict")
            if run.status == "running" and target != "running":
                changed = PlaybookRun.model_validate(
                    run.model_dump(mode="json") | {"status": target, "ended_at": now}
                )
                tx.replace("workflows", run.run_id, changed.model_dump(mode="json"))
            tx.replace("callbacks", key, result.model_dump(mode="json"))
            self.service._audit(
                tx,
                argument.incident_id,
                actor,
                "shuffle_delivery",
                "Workflow transport outcome recorded",
            )
            return result

    async def reconcile(self, incident_id: str, run_id: str, actor: Principal) -> DeliveryRecord:
        with self.service._operation(incident_id, actor):
            with self.service.store.transaction() as tx:
                argument = self._argument(tx, incident_id, run_id, actor)
                value = tx.get("callbacks", "shuffle:" + run_id)
                if value is None:
                    raise ServiceError(409, "No original workflow delivery to reconcile")
                original = self._record(value)
                self._bound(original, argument, original.workflow_id)
                self._run(tx, argument, original.workflow_id, required=True)
                if original.state in {"finished", "failed", "rejected"}:
                    return original
            try:
                observation = await self.client.get_execution(
                    original.workflow_id, run_id, argument
                )
                if (
                    observation.argument != argument
                    or observation.workflow_id != original.workflow_id
                    or observation.execution_id != run_id
                ):
                    raise ShuffleError("invalid", "Workflow observation correlation invalid")
                status = observation.vendor_status
                if (
                    status in {"FINISHED", "SUCCESS", "FAILURE", "ABORTED"}
                    and observation.workflow_sha256 != original.workflow_sha256
                ):
                    raise ShuffleError("uncertain", "Executed workflow artifact is not verified")
                state = (
                    "finished"
                    if status in {"FINISHED", "SUCCESS"}
                    else "failed"
                    if status in {"FAILURE", "ABORTED"}
                    else "accepted"
                )
            except ShuffleError:
                state, status = "uncertain", None
            return self._save(original, state, status, actor)
