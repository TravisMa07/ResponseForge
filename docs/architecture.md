# Architecture

Status: direction accepted from owner requirements; RF-01 contracts and RF-02 authenticated API/SQLite core implemented; see [RF-02 evidence](rf-02-ledger.md). RF-03 replay/report and simulated response are locally qualified; vendor runtime remains open.

```mermaid
flowchart TD
  Replay[Replay CLI / recorded events] --> Intake[Authenticated FastAPI intake]
  Wazuh[Opt-in Wazuh alert adapter] --> Intake
  Intake --> Core[Shared case / policy core]
  Core --> Store[(SQLite + hashed evidence)]
  Core --> Shuffle[Real Shuffle workflows]
  Shuffle --> Evidence[Bounded evidence / enrichment API]
  Shuffle --> Approval[Server-authorized approval gate]
  Approval --> Provider[Capability-checked response provider]
  Provider --> Mock[Simulated stateful EDR]
  Provider --> Live[Allowlisted Wazuh live action]
  Provider --> Audit[Audit / verification / reports]
```

One deployable Python application contains API, domain logic, adapters and replay CLI; SQLite persists cases, approvals, idempotency and audit with migrations. Shuffle owns orchestration, branches and retries. Wazuh retains detection/endpoint responsibilities; its indexer/dashboard are confined to the optional live profile. Velociraptor is deferred until after required replay and live releases.

Replay queries only evidence actually recorded in a bounded scenario/endpoint/time scope. Missing evidence stays unavailable. Response capabilities are explicit and provider/version specific. Wazuh active response does not imply network isolation. The core validates all state transitions and is the final authority for approvals and dispatch even if a workflow is misconfigured.

## RF-01 contracts

The [frozen RF-01 design](rf-01-design.md) defines versioned Pydantic schemas: Alert, Incident, Evidence, Enrichment, PlaybookRun, ActionProposal, Approval, ActionExecution and AuditEvent. UTC observed and ingestion times remain separate. Durable IDs correlate callbacks, reports and actions. Authenticated endpoints include intake, cases/evidence, proposal/approve/reject/execute/status, report and Shuffle callback. Health/readiness disclose service readiness without claiming enrolled endpoint readiness.

Incident states are `RECEIVED → TRIAGING → INVESTIGATING → AWAITING_APPROVAL → RESPONDING → CONTAINED | RESOLVED | FAILED`, with `CLOSED` only after review of a final state. Approval cancellation/expiry and dispatch/ack/effect/rollback states are distinct. Idempotency aims at one observable effect, not a distributed exactly-once guarantee. Unknown provider outcomes require reconciliation before another dispatch.

## Decision register

| Decision | State | Record |
| --- | --- | --- |
| One Python package, SQLite, shared replay/live core | Accepted from handoff | [ADR 0001](decisions/0001-bounded-core.md) |
| Integration version/digest lock and native architecture support | Pending runtime qualification | [Dependencies](dependencies.md) |
| Safe Shuffle worker execution without default Docker socket | Blocking deployment design question | [Plan RF-04](implementation-plan.md) |
| Project license | Owner decision pending | [Limitations](limitations.md) |

The [RF-02 durable design](rf-02-design.md) implements short SQLite transactions, persistent approval snapshots and dispatch reservations. Provider I/O occurs outside transactions; uncertain reservations suppress redispatch and reconcile only through verification. Internal OpenAPI is published, with no claim of vendor-schema compatibility. Actual Shuffle and endpoint integrations still require independent runtime proof.

No Compose file is supplied until a supported, secure configuration is validated. Docker reproducibility is a delivery gate, not established by a diagram.

The [RF-03 design](rf-03-design.md) binds replay alerts/evidence to source bytes and scope, uses a separate SQLite file for durable simulated endpoint state, and produces one authorized, default-redacted report snapshot. The in-process HTTP driver exercises common core authentication/approval/recovery without implying genuine SOAR orchestration. Actual Shuffle and recorded-source qualification remain distinct.
