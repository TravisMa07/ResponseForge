# Offline replay and simulated response

RF-03 provides a local, deterministic replay path through the authenticated case API, with source-backed evidence, explicit approval, durable simulated response and redacted JSON/HTML reports. It does not run Shuffle, consume vendor-native Wazuh alerts, qualify external attack recordings or modify an endpoint. The three checked-in fixtures are original synthetic observations, not recorded attacks or detector benchmarks.

## Run an original fixture

From the repository with Python 3.12+ and uv:

```bash
uv sync --locked
uv run --locked --offline python -m responseforge \
  --replay datasets/fixtures/suspicious.jsonl --source-id rf03-suspicious \
  --database .local/demo-cases.sqlite3 --mock-database .local/demo-mock.sqlite3 \
  --output-dir reports/demo
```

The default stops at AWAITING_APPROVAL with evidence, known gaps, proposed action, audit and review-ready metrics. There is no automatic approval. An operator can explicitly choose a simulated approval using the same source and state paths:

```bash
uv run --locked --offline python -m responseforge \
  --replay datasets/fixtures/suspicious.jsonl --source-id rf03-suspicious \
  --database .local/demo-cases.sqlite3 --mock-database .local/demo-mock.sqlite3 \
  --output-dir reports/demo --decision approve
```

This uses separate source, analyst, human-approver and executor credentials against the in-process authenticated HTTP API. It does not start a listener, invent a workflow callback or bypass the server approval checks. The simulated process is removed only from the mock SQLite state; no command or process API executes. Repeating the approved command retains one case/action/effect. `--decision reject` instead records rejection with zero effects. First decisions are immutable: a later contradictory decision fails. Undecided proposals expire after 30 minutes; expiry remains a denial, not permission to refresh their scope. Use separate dedicated state paths for a separate lab run; never reset uncertain state to force retry. Keep the case and mock database paths distinct.

Use `benign.jsonl` / source ID `rf03-benign` or `incomplete.jsonl` / `rf03-incomplete` with separate state paths to explore no-action cases. Ordinary PowerShell produces a low-severity observation; the incomplete signal has no process ID and cannot authorize a targeted action. No process identity or missing parent/network evidence is invented. The [manifest](../datasets/fixtures/manifest.json) pins hashes, origins, fields and expected limitations. The project license remains unselected; no third-party corpus is redistributed.

## Replay semantics

Accepted files are local JSON arrays and JSONL using the [replay-record schema](../schemas/replay-record.json). Other vendor/raw/EVTX formats require future adapters. Limits: 1 MiB file, 1000 records and 16 KiB JSONL line; 32 string fields per record, keys at most 128 and values at most 4096 characters. Commands and other fields remain inert strings. Unknown fields, invalid/ambiguous timestamps, invalid records and duplicate conflicts are quarantined with sanitized codes and row positions; identical duplicate records count once. All-invalid input exits nonzero without claiming a case. No downloads or scripts are executed.

Ordering is stable by source timestamp and scoped identity. One normalized alert is generated per scenario/canonical endpoint. The transparent toy rule requires a PowerShell image plus the observed strings `-EncodedCommand` and `-WindowStyle Hidden`; it is not a general behavior detector or an inference from a dataset label. Alert/evidence IDs bind exact file hash and scope. The logical receipt is the latest recorded time plus one second, visibly part of simulated replay; core acceptance/readiness times use the server clock. `--speed 0` emits immediately; positive finite speed paces generated alert groups by original timestamp deltas divided by speed. Changing source bytes or source ID creates a distinct dataset identity. Reusing state with a changed initial endpoint seed fails rather than resetting effects.

## Evidence and response recovery

Evidence collection requires the case's original alert to match the registered replay snapshot, then checks scenario, full endpoint identity, mode, artifact and inclusive bounded time window (at most 24 hours). Every available reference preserves actual file SHA-256, original event ID and timestamp. Missing data yields unavailable evidence and known gaps; no fabricated parent or network process appears. Repeat collection retains the first durable collected_at when all source/scope content matches.

`ReplayEvidenceProvider` implements the shared provider protocol. `MockResponseProvider` uses its own SQLite file for simulated endpoint state and atomic effect/receipt records. It advertises only terminate_process, isolate_host, unisolate_host and test_marker, in replay mode. Unknown targets/resources and unsupported actions fail closed. Canonical reseeding cannot undo effects; duplicate and concurrent calls reuse immutable idempotency receipts. A distinct approved unisolate action demonstrates rollback without deleting prior history. The starter driver deliberately proposes only observed process termination.

Core reservations remain authoritative across crashes. Before-effect failure, effect-then-error and effect-then-timeout tests prove truthful failed/uncertain outcomes, durable effect receipt and verification-only recovery with no redispatch. The CLI resumes an uncertain original execution through reconciliation. There is no force-resend or silent live-to-mock fallback. See [durable API recovery](core-api.md).

## Reports, metrics and sharing

The authenticated `/v1/incidents/{id}/report?format=json|html` export uses one authorized SQLite snapshot. Reports include source integrity references, availability, gaps/counts, proposed actions, human decisions, execution/verification, audit and correlated metrics. Both formats use the same default-redacted content. Free text, raw fields/commands, credentials, endpoint host/agent identity, action resources and actor identities are omitted; an explicit safe field projection prevents future fields from leaking by default. HTML escapes dynamic values, contains no script/remote resource, and uses hashed filenames under the requested output directory. Provisional provenance IDs remain visible; these examples use synthetic identifiers.

Acceptance/readiness metrics persist scenario/mode/correlation, source revision (with dirty-tree suffix when applicable), and Python/SQLite/platform environment. Installed artifacts without a verifiable source checkout explicitly label the source revision unavailable rather than inventing one. These events are not measured analyst savings, detection accuracy or an MTTR claim. RF-09 collects aggregate and paired baseline evidence separately.

Reports and `.local/` databases remain ignored. Preserve both databases to retain idempotency history; deleting simulated state while keeping cases makes effect verification unavailable, not permission to retry. Real recorded-data licensing/scenarios remain RF-06; real Shuffle and live endpoint proof remain RF-04/05 and RF-07/08.


## Selective recorded XML inspection (RF-06A)

The [catalog](../datasets/catalog.json) contains reviewed, pinned metadata for one deliberately bounded source-normalization sample. Source rights review, original byte hash/size and fixed HTTPS origins are checked separately. Acquisition is explicit and selective:

```bash
uv run --locked --offline python scripts/dataset_replay.py fetch \
  --artifact splunk-trickbot-command --allow-download
uv run --locked --offline python scripts/dataset_replay.py inspect \
  --artifact splunk-trickbot-command
```

`--offline` here constrains uv dependency resolution; the explicit `fetch --allow-download` operation itself uses HTTPS. Omitting that flag refuses before network or output mutation. The default ignored bundle is `datasets/downloads/splunk-trickbot-command/` with unchanged source.xml, verified LICENSE and exact manifest.json. Existing verified bundles are reused after explicit opt-in; conflicts and symlinks refuse without overwriting them. Atomic publication requires the no-replace rename primitive on macOS/Linux and fails closed elsewhere; hosted Linux qualification is recorded separately. `inspect` has no network path and prints counts/safe quarantine codes only. All-invalid projections exit nonzero. Neither command executes source commands, starts services or qualifies a scenario.

The Event1-only projection preserves recorded computer, record ID, logging SystemTime (aware UTC), distinct original process UtcTime, process/parent fields actually present and original source SHA-256. Both original timestamp strings survive Python microsecond precision. DTD/entities/processing instructions and structurally invalid XML refuse; unsupported provider/channel/ID and ambiguous/oversized records quarantine. Whole-source bounds are 1MiB, 1,000 events, depth16 and 16KiB/event; normalized fields retain their existing bounds. Additional raw fields remain in the unchanged source bytes, with no completeness claim. [Design](rf-06-design.md) lists the exact projection and failure semantics. Recorded provenance is explicitly `splunk-attack-data`, with a pinned source URL through alerts/evidence/cached plans; original fixture behavior stays unchanged.

Reinspection finds that this sample records a cmd.exe invocation rather than a PowerShell child, duplicates eight records and includes one oversized command in both copies. It is a negative/incomplete source sample for the existing rule; no truncation, broadening or invented child makes it a positive. Five recorded scenarios and genuine Shuffle branch/decision/audit executions remain RF-06B. This source path is not enabled by the existing original-fixture server/lab configuration.
