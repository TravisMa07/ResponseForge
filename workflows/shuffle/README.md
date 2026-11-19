# Native domain workflow catalog

RF-05B generates three original native workflows with the same reviewed four-node
shape: Prepare → Gate → conditional Dispatch, converging on one final Callback.
The server binds each workflow UUID to process, persistence or containment;
workflow data cannot choose a different kind, provider, target or human decision.

`responseforge.integrations.shuffle.graphs.build_workflow(kind, task_app_id,
callback_app_id)` renders the importable JSON using actual registered app UUIDs.
It creates deterministic UUID5 node and branch identities. The bootstrap/import
path assigns the real workflow UUID, validates the stored graph and binds its
normalized executable hash. Original native exports, credentials, source records
and runtime journals remain private. There are no fake app-ID exports to import.

| Kind | Core recommendation |
| --- | --- |
| Process | Scoped source-backed process action or missing-identity/no-action branch |
| Persistence | Recorded task/service association; unsupported disablement escalates |
| Containment | Scoped recorded process/network/file indicator; approved replay isolation |

The branch uses `$Gate.status`, `matches regex`, `^(ready|uncertain)$`. The reviewed
SDK-less task app performs that narrow app-side condition check, matching the
pinned SDK's responsibility, and emits native SKIPPED before any core dispatch on
false. Shuffle owns dependency scheduling, result persistence and convergence;
it waits for both Gate and Dispatch and can reach Callback when Dispatch skips.
The unconditional Gate → Callback parent keeps that convergence reachable.

The task app is `responseforge_tasks:1.0.0` with prepare/gate/dispatch only; the
single final app is `responseforge_callback:1.0.0/callback`. Empty task parameters,
fixed callback parameters, private credential configuration and server-side human
approval remain mandatory. FINISHED or Callback success alone does not prove
successful tasks or an endpoint effect.

Human waiting, rejection, expiry and unsupported capability are explicit business
branches. A later explicit invocation after a separate human decision reuses the
original proposal and expiration; it is not a retry of an uncertain vendor start,
which must reconcile the original run UUID. Actual import/execution and recovery
claims require the [RF-05B ledger](../../docs/rf-05b-ledger.md); graph generation or
offline tests alone do not qualify the three real workflows.
