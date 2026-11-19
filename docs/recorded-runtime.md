# Recorded-source Shuffle qualification

[RF-06B2 design](rf-06b2-design.md), [independent expectations](expectations/rf-06b2.md) and [ledger](rf-06-ledger.md) own the contract, exact proven revision and remaining gates. This runbook extends the [authorized pilot](rf-04-operator.md) and [domain playbooks](playbooks.md). It grants no Docker or endpoint authority. Default CI stays offline and never requires downloaded telemetry or Docker.

## Source preparation

Use the five individually reviewed artifacts from [the catalog](../datasets/catalog.json): splunk-powershell-create, splunk-lsass-access, splunk-task-create, splunk-ransom-note and splunk-process-dns. Selective acquisition is opt-in through `scripts/dataset_replay.py fetch --artifact <ID> --directory <private-root> --allow-download`; inspect each bundle before use. The fixed pinned URL, raw bytes/hash, canonical manifest, root LICENSE hash, attribution and any per-artifact restrictions must match. Do not redistribute raw sources or derivatives merely because their URLs are public. Keep bundles, original IDs, hosts, commands and case manifests local and untracked.

A private JSON RecordedCaseManifest contains qualification_id (a fresh UUID) and cases. Each case has profile, artifact (the complete reviewed DatasetArtifact from the catalog), scenario_id and event_ids (exactly one original normalized channel:rawRecordID). scenario_id is `rf06-<profile>-<qualification_id>`. Freeze selections against independently inspected original XML before execution; never select expected records from policy output. No checked-in example invents source identifiers.

Exactly 14 profiles are required: powershell, lsass, task, note, dns; their five `-negative` variants; denied, expired, callback-loss and task-failure. The latter four use the positive PowerShell record in separate operator scenario namespaces. Each namespace retains the actual source Computer, original ID, distinct original times and raw SHA. A negative is absence of the narrow match, not proven benign; note-negative is source context without the file event. Missing creation/lineage/task execution/encryption/session proof stays missing.

## Reviewed stopped-state deployment

Only the integration owner operates the reviewed stack. Before adoption, verify exact engine/context/resources, inactive Swarm, owned services stopped and loopback ports free. Build current pinned sources with `scripts/shuffle_runtime.py build`, preserving its inventory, module lock, patch hashes, wheel and image identities. README is a wheel/build input. Any changed build input needs a new build and qualification; changed source selections need a distinct source binding and journal. Never relabel older runtime proof.

Privately back up existing runtime/compose/core/callback configuration and inventory before adopting reviewed images into the retained pilot. Preserve credentials/CA, original fixture source ID/path/hash, original mock DB, graph bindings, human grants, images, volumes and all journals. Do not initialize over retained state. Do not reset receipts or overwrite a different prepared scope; archive a completed packet privately and use a fresh qualification UUID/database when a new candidate is required.

Prepare without starting services:

```bash
uv run --locked --offline python scripts/shuffle_runtime.py prepare-recorded \
  --state .local/rf04-pilot --cases .local/private-recorded-cases.json \
  --bundle-root .local/private-source-bundles
```

Preparation verifies all14 cases and five complete immutable bundles, creates a separately fingerprinted private tree and enables the fixed read-only core mount `/run/responseforge/recorded`. The state parent remains private; mounted files are readable by the unprivileged core. It neither downloads nor starts services. Conflicting existing content refuses. No workflow receives a raw file path, arbitrary URL or alert-provided executable command.

Start the already authorized pilot, qualify and stop it explicitly:

```bash
uv run --locked --offline python scripts/shuffle_runtime.py up --state .local/rf04-pilot
uv run --locked --offline python scripts/shuffle_runtime.py qualify-recorded --state .local/rf04-pilot
uv run --locked --offline python scripts/shuffle_runtime.py down --state .local/rf04-pilot
```

Confirm ports closed and retain volumes/evidence. The three genuine graphs are registered/bound to the fixed native task app and callback app. Recorded effects use the same durable mock adapter through a stable opaque server-selected qualification/database alias; legacy receipt reconciliation cannot query the new database. Only actual recorded process-create PIDs seed process state. File/access/DNS observations do not become invented process creation. Workflow credentials cannot approve; the separately scoped qualification human fixture makes explicit decisions outside Shuffle.

## Evidence and interpretation

The20phase matrix checks five positive observations, five source-selected negatives, actual incomplete evidence, approval/denial/expiry, duplicate suppression, callback ACK loss, native post-commit failure, core/vendor restart and scoped down/up. Exact original native graph/node/run/callback/audit/source/plan proof must agree. Host inspection reads an existing native-created plan through authenticated `playbooks/inspect`; it cannot recreate a missing plan. Interrupted starts reconcile the original vendor execution rather than blindly launching another.

Successful business no_action/escalation branches use genuine SKIPPED nodes. Two injected delivery faults remain explicitly uncertain; they are not graph success. Exactly three unique changed mock receipts support three simulated effects; per-case deltas account for shared actual hosts. No endpoint effect is claimed. All reports disclose replay/simulation, source subset/transformation and default raw redaction, then undergo configured and actual per-execution credential scans.

Retain private journal, actual20 execution exports, three workflow exports,14 paired JSON/HTML reports, logs, consistent read-only SQLite backups, installed-module/runtime identities and source/license/case fingerprints. Independent review checks those artifacts and the pre-code oracle, not just a success summary. Publish only a safe aggregate with exact revision/environment/artifact hashes and bounded claims.

Readiness uses14 unique accepted-to-first-case_ready samples with median/nearest-rank p95 and invalid/missing count. Three action samples separate approval-to-dispatch from dispatch-to-verified receipt. Disclose host pacing interval and total wait plus synthetic human decisions. These measurements establish neither analyst savings nor throughput/detection accuracy. Owner acceptance, merge, merged-revision verification, releases, dedicated-VM runtime and live endpoint operation remain separate gates.
