# Playbook core steps

[RF-05 design](rf-05-design.md) and [RF-05A ledger](rf-05a-ledger.md) own these internal steps. RF-05A qualifies the Python/HTTP boundaries offline. [RF-05B](rf-05b-ledger.md) qualifies three real native Shuffle graphs on Docker Desktop ARM64; the APIs below alone are not that proof. Existing replay CLI behavior is unchanged, and the default server config does not enable these steps.

## Server configuration and caller authority

The trusted application `Settings` binds each already reviewed Shuffle workflow UUID to exactly one kind (`process`, `persistence`, `containment`) in `playbook_bindings`. `playbook_provider` names a configured pinned provider. `playbook_actors` maps `analyst` and `executor` to separate configured technical actor IDs, each with exactly that role and `human=false`. Their existing endpoint/action/resource scopes still apply. These are trusted server settings; the JSON config loader enables a fixed replay/mock provider only through the explicit optional `playbooks` block. Live mode rejects it. [RF-05B](rf-05b-design.md) owns the concrete private lab bootstrap.

The workflow credential has only the `workflow` role, never human/approver or the technical actors' credentials. It supplies the original incident/run/workflow/correlation/mode, not a provider, target, action, command or approval. The facade validates the original core case, reviewed workflow binding and durable Shuffle reservation before operating under the configured technical principals. The server rechecks approval and capabilities at actual dispatch. Human decisions remain separate authenticated core API calls.

## Three evidence-backed recommendations

| Kind | Recorded condition | Proposed response or escalation |
| --- | --- | --- |
| Process | Same-scope hidden encoded PowerShell at the alert time, with canonical PID and recorded process GUID | Targeted `terminate_process`; absent target identity escalates; benign data gives no action |
| Persistence | Recorded task/service identifier, account and GUID linked to an actual same-scope process | `disable_persistence` only for a qualified supporting provider; current mock does not support it and escalates |
| Containment | Recorded process association to an outbound network event plus the narrow PowerShell indicator, or a recorded shadow-copy-delete file indicator | Replay `isolate_host` using `host:<endpoint_id>`; preserve impact/rollback guidance and simulated flags |

These are transparent original test conditions, not broad malware/C2/ransomware detection claims. Queries stay within the exact scenario/endpoint and alert±5minutes. Evidence IDs link to registered source hashes and original event IDs. Missing lineage, actor/association, other artifacts and offline reputation remain gaps; no missing observation is invented. Source command lines are never run.

## API flow

All three POST routes accept the same strict body, with actual existing IDs:

```json
{
  "schema_version": "1.0",
  "incident_id": "existing-case-id",
  "run_id": "33333333-3333-4333-8333-333333333333",
  "workflow_id": "11111111-1111-4111-8111-111111111111",
  "correlation_id": "original-case-correlation",
  "mode": "replay"
}
```

1. `/v1/incidents/{incident_id}/playbooks/prepare` collects the fixed artifact set, computes a recommendation, checks pinned provider capabilities and stores an immutable plan, optional proposal and case-readiness metric. Retrying returns the same plan/proposal/expiry. Failed capability lookup is unavailable, not evidence of unsupported behavior.
2. `/v1/incidents/{incident_id}/playbooks/gate` reads the current server-held decision without dispatch. It reports `awaiting_approval`, `denied`, `expired`, `ready` or an existing response outcome; a no-action/escalation plan reports `no_action`.
3. A separately authenticated human may use the existing `/v1/actions/{proposal_id}/approve`, `/reject` or `/cancel` API. The workflow cannot submit or manufacture this decision.
4. `/v1/incidents/{incident_id}/playbooks/dispatch` uses only the original plan's action and trusted provider. A denied/expired action cannot dispatch; a gate result is not an authorization token. An approval that expires between steps is rejected at dispatch. Existing uncertain execution reconciles the original reservation instead of blindly repeating an effect.

A completed workflow/step does not prove a live endpoint effect. Read the returned ActionExecution verification, simulation flags, durable audit and JSON/HTML report. Unsupported persistence has no action effect. RF-05A remains replay-only and cannot silently select a mock for live mode.

## Recovery and inspection

Plans are stored in the existing private SQLite callbacks namespace, separate from callback nonces/outbox records. Every restored plan is revalidated against source, request, workflow and provider pin. Partial preparation reuses an original deterministic proposal and never renews its approval window. Conflicting immutable readiness or restored scope is rejected for inspection, not overwritten.

Use `make qualify` or `uv run --locked --offline pytest tests/rf05 -q` for the independent offline suite after installing locked dependencies. These commands use temporary core/mock SQLite databases and injected HTTP transports; no Docker daemon, network, live action or genuine Shuffle run is required or claimed. Private runtime journals and original endpoint evidence must not be committed. Merge and release gates remain explicit.

An explicit later workflow invocation can reuse an already prepared case after a human decision: the proposal ID, source evidence, readiness and expiration remain original, and duplicate dispatch still has one simulated effect. This is separate from retrying an uncertain vendor launch, which must retain its original run UUID. RF-05B demonstrates real branch/resume behavior in its bounded synthetic lab; RF-05A only exercises that interface offline.

## Native Shuffle lab

The [native catalog](../workflows/shuffle/README.md) defines process, persistence and containment graphs. Each uses the fixed task app for Prepare/Gate/conditional Dispatch and one final authenticated Callback. Shuffle schedules and persists the nodes; the core retains policy, evidence, approval and effect authority. The SDKless task app evaluates only the reviewed branch predicate, as the pinned vendor SDK does. A vendor FINISHED status alone cannot qualify failed or missing native tasks.

Use the [existing pilot runbook](rf-04-operator.md) for the explicit engine grant, source-bound build, private state, TLS and lifecycle. For a new prepared state with current images, the original replay source is an explicit opt-in:

```bash
uv run --locked --offline python scripts/shuffle_runtime.py prepare-playbooks --state "$rf04_state"
uv run --locked --offline python scripts/shuffle_runtime.py up --state "$rf04_state"
uv run --locked --offline python scripts/shuffle_runtime.py qualify-playbooks --state "$rf04_state"
uv run --locked --offline python scripts/shuffle_runtime.py down --state "$rf04_state"
```

Preparation verifies the checked-in original fixture/manifest, creates its read-only private snapshot and enables only that core mount. Qualification registers the exact private app metadata and three graphs through genuine authenticated APIs, validates their stored semantics/hash, and binds those UUIDs in core and private task configuration. It does not use remote app activation/download/build. Human decisions are separate core calls from an explicitly named synthetic human fixture; no approval credential enters the tasks or graphs.

The private `domain-journal.json` reserves original execution identities before mutation. Resume verifies stored scenario meanings, original vendor/native graph completion and core delivery/audit; unknown acknowledgements do not create replacement runs. A journal cannot inherit a different build's proof. Separate source/database namespaces preserve older diagnostic cases and durable mock receipts rather than resetting them. Replacing a retained state's inventory requires an operator-reviewed exact-engine/image update; initial `prepare` refuses existing state. Never erase a journal to force a fresh start.

The matrix covers approval waiting, approved explicit resume, denial, expiry, incomplete evidence, unsupported persistence, simulated containment, duplicate deliveries, callback acknowledgement loss, a post-commit native task failure, core/vendor restarts and retained state after scoped down/up. Private results include per-node execution exports, domain summary, case audit/report and actual durable mock effects. Only redacted aggregate evidence is suitable for public Git. The [RF-05B ledger](rf-05b-ledger.md) states which runtime gates actually passed; commands and offline tests alone do not establish them. This lab has no live endpoint effects or measured analyst savings.

Qualification paces host core requests to respect the real60/minute per-actor limit. It does not raise that limit or automatically retry mutations. Recorded readiness and action timings include harness pacing and synthetic approval fixtures; they do not measure analyst savings or production throughput. Positive core restart occurs after native completion and before reconciliation; interrupted unacknowledged task HTTP is allowed to remain uncertain.
