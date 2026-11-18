# Shuffle transport and execution-target decision

RF-04A provides source-derived API transport, durable launch suppression/reconciliation and blocked deployment plans. **No real Shuffle instance was started or workflow imported/executed. Issue #4 remains open.** Offline tests and Compose parsing establish bounded preparation only; see [design](rf-04-design.md) and [qualification ledger](rf-04-ledger.md).

## Docker Desktop and dedicated VM, evaluated

The owner has Docker Desktop and no running dedicated Linux VM. Read-only recheck on 2026-11-18: Docker Engine29.8.0 linux/arm64, Compose5.5.1,15 Docker CPUs,8,318,844,928 bytes (~7.75GiB) memory limit; host24GiB. Zero running containers were observed. Stopped containers, volumes, image assets and future workloads are still under that daemon's authority; zero running does not make a socket grant scoped to Shuffle. Memory allocation is a limit, not measured available capacity.

| Decision factor | Existing Docker Desktop daemon | Dedicated disposable Linux VM/daemon |
| --- | --- | --- |
| Availability/setup | Existing engine; fewer setup steps | Guest/daemon must first be supplied or provisioned under an explicit plan |
| Authority required | Backend/Orborus/workers can control the selected Docker Desktop daemon, including other assets and accessible bind mounts | Same Docker control inside a separate guest, provided no developer-host directories are shared |
| Isolation | Namespace/project names and another Docker context do not restrict engine authority; a broad socket proxy is not a proven boundary | Separate guest/daemon creates a clearer boundary; its network and mounts must still be reviewed |
| Resources | Current shared Docker VM limit ~7.75GiB; Shuffle/app headroom not measured | Explicit extra guest CPU/RAM/disk budget needed; a candidate local lab budget of4vCPU/8GiB/40GiB is a proposal, not a tested minimum or authorization |
| Recovery/teardown | Remove only namespaced lab resources; preserve other images/volumes/workloads; no engine reset or Swarm change implied | Snapshot/teardown can be limited to the guest; recovery still needs proof |
| Practical tradeoff | Fastest route to a pilot if broad daemon authority is acceptable to the owner | More initial setup/resource overhead, clearer separation for repeated automation experiments |
| Remaining technical gates | Source/binary/app pins, safe callback credentials, CA/bootstrap, actual runtime and resource proof | The same gates; creating a VM does not qualify the software |

Integration recommendation: use a dedicated disposable guest for repeated workflow execution, because it confines Docker authority away from the development daemon. Docker Desktop is a viable candidate for a consciously authorized lab pilot; it is not rejected merely because it is Docker Desktop. No invented risk scores, setup times, cloud prices or throughput estimates support this comparison.

Neither route is currently authorized for socket access/startup. A future grant must name the chosen daemon, permit only the agreed lab service/worker/app creation, define any loopback UI/tunnel, preserve unrelated workloads and exclude physical-endpoint actions, arbitrary host binds, public/LAN APIs and host privilege/resource/Swarm changes unless separately approved. A dedicated VM needs a concrete provisioning choice/budget before an agent installs software or creates it. Engine identity labels in generated plans are review markers, not enforcement or a grant. Before any execution tool is added, it must verify the actual selected engine and require the outstanding gates to be handled; this PR intentionally has no up command.

## Inspect the candidate plans

Image identities are pinned in [images.lock.json](../deploy/shuffle/images.lock.json). They are registry metadata observations of upstream mutable tags at the recorded time, not proof those binaries were built from the inspected v2.3.0 source. Both AMD64 and ARM64 platform manifests were observed. Runtime app images and binary/source correlation remain unqualified; the backend image inspected had no OCI source-revision labels. Images were not pulled or run.

```bash
uv run --locked --offline python scripts/shuffle_plan.py --compare
uv run --locked --offline python scripts/shuffle_plan.py \
  --target deploy/shuffle/docker-desktop.target.example.json \
  --output .local/shuffle-desktop-plan
uv run --locked --offline python scripts/shuffle_plan.py \
  --target deploy/shuffle/dedicated-vm.target.example.json \
  --output .local/shuffle-vm-plan

docker compose -f .local/shuffle-desktop-plan/compose.plan.json config --no-interpolate --quiet
```

Examples have engine_control_authorized=false and no exposed UI. Plans always say ready=false, carry all technical gates, select exact platform digests, and never start/pull/install or change Docker context/settings. Default plans are socket-free with private networking, TLS verification flags enabled and secret placeholders. Only a separately authorized target descriptor permits target-engine socket mounts; rendering that descriptor cannot create permission. No default password is supplied. Read-only roots, capability dropping, writable volumes, service-name aliases and CA provisioning still require actual runtime validation; passing config does not prove startup compatibility.

Upstream worker app discovery/download must be qualified independently: top-level service/worker digests alone do not pin dynamically built/pulled apps. Auto-download fallback is disabled in the candidate plan. This deliberately fails closed if required apps are absent. No Shuffle Security/sensor/custom dashboard is enabled.

## Source-derived transport and durable delivery

The client implements inspected Shuffle routes: workflow GET/create, execution POST with a pre-reserved canonical UUID and string-encoded correlation argument, and specific read-only lookup via POST /api/v1/streams/results. API Bearer/optional Org-Id stays in headers, TLS verification is mandatory, redirects/proxy inheritance disabled, and response/time/retry limits enforced. Per-execution authorization secrets/raw bodies are discarded. Only safe IDs/status/fingerprints leave the adapter.

Workflow create always gets a new server UUID; repeat create can create another workflow. Start accepts a client UUID but source does not prove deduplication and can requeue it. **Create/start are never automatically retried.** Ambiguous results remain uncertain. Read-only GET/lookup may retry up to the configured bounded count. The low-level create method is operator-only preparation, not an arbitrary public import endpoint; real bootstrap/import remains unqualified.

The core coordinator atomically registers a workflow run and stores its outbound reservation before start I/O, using the existing private callbacks document collection. Duplicate/concurrent/restarted calls return that exact record without another start. Reconciliation queries only the original UUID. Current analyst scope, full canonical endpoint, case/correlation/mode, workflow/version/hash and origin must match. Stale results cannot overwrite terminal success. A workflow FINISHED/SUCCESS is never endpoint containment or action-effect proof; only the core response provider's separately authorized verification can establish that.

A terminal workflow must also provide the exact reviewed executed-graph fingerprint; absent/changed snapshots remain uncertain. Preflight and vendor start are separate calls, so this detects drift after execution rather than atomically freezing an editable vendor graph. Shuffle workflow editors are part of the trusted administration boundary. Actual runtime normalization of the execution snapshot must be qualified before claiming compatibility; strict offline matching may reject a vendor-expanded snapshot until its semantics are reviewed.

Optional private server config can supply shuffle.base_url, api_key, reviewed workflow_bindings (UUID→version/sha256), trusted CA, Org ID and explicit loopback-HTTP choice. No default connection is configured; file settings cannot dynamically load arbitrary code. The authenticated analyst routes `/v1/incidents/{id}/shuffle/start` and `/shuffle/reconcile` accept only typed IDs, never raw URLs/workflow bodies/actor identities. Report exports also redact the configured Shuffle API key. Existing authenticated callback correlation/nonce/time gates remain authoritative and cannot grant disruptive action approval.

## Real qualification still required

1. Owner selects/authorizes a specific isolated target, or explicitly grants the broader Docker Desktop execution-plane authority. No startup is authorized by RF-03 merge approval.
2. Establish candidate binary/source/version correlation, app identities, resource/CA/private-secret bootstrap, and per-artifact licensing evidence. Separate Orborus artifact terms are unresolved; no source/image is redistributed here.
3. Establish a private core callback route for the selected topology (guest/private core container or reviewed tunnel), without silently rebinding the host API to LAN/public interfaces. Resolve credential logging before a real authenticated callback: inspected stock HTTP1.4.0 logs header text, and its default TLS behavior also needs explicit verification. No real callback token was supplied or logged. A reviewed safe app/image or demonstrated mitigation is required, not an assumption that global logging flags fix it.
4. Actually import/bootstrap a nonempty reviewed workflow, start it once, correlate the real execution snapshot/callback with case/run IDs, and exercise lost acknowledgement, restart, timeout, forged/repeated callback, teardown and retry suppression.
5. Record exact revisions/images/app artifacts/commands and limitations. Only then can RF-04 acceptance close; RF-05 still owns three real playbooks.

[Source evidence](shuffle-source-evidence.md) links exact official revisions and observed hashes. No socket-free working runtime, vendor-compatible image set or genuine workflow success is implied by these plans/stubs.
