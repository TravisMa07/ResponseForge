# Acceptance matrix

Full product gates below remain open. RF-01 contract/pure-policy and [RF-02 durable API/recovery evidence](rf-02-ledger.md) qualify their bounded components, not the complete P1 vertical slice. Foundation checks only validate repository integrity. See [implementation ledger](implementation-ledger.md) for observed evidence.

| Gate | Required evidence | Owner / status |
| --- | --- | --- |
| P0 environment | Host/Docker resources, Python/Git/Compose availability, supported vs unverified platform matrix | RF-00 / inspected |
| P0 dependency/data | Tested version/digest set; minimum dataset fields, hashes and terms verified | RF-00, RF-04, RF-06 / open; references alone do not pass |
| P1 offline core | `make test` without network/VM; one deterministic evidence-backed case/report; benign case; quarantine and duplicate tests | RF-01–03 locally verified using original synthetic fixtures; RF-01–03 merged and merged revisions verified |
| P1 safety | Spoofed/expired/mismatched approvals rejected; authorization enforced; durable idempotency; mock failure/rollback and flags | RF-02/03 enforcement, durable simulated effects, failure/recovery and approved rollback locally verified |
| P2 real SOAR | Three imported workflows; correlated real run, denied approval, failed/lost/replayed callback and retry recovery | RF-04 transport qualified; [RF-05B](rf-05b-ledger.md) passes3 native workflows/14 phase-fault runs/nine synthetic cases; merged as `ec5d80e`; actual merged-revision offline checks pass |
| P3 scenarios | Five licensed evidence-backed scenarios or justified narrowing; positive/negative/incomplete tests and real branch/audit assertions | RF-06 / acquisition and normalization underway; five-scenario runtime not run |
| P4 live | Authorized enrolled VM produces real alert and approved safe effect through common core; recovery and Windows evidence | RF-07/08 / not verified, no VM |
| P5 reproducibility | Fresh clone, doctor/bootstrap/up/status/replay/report/down/rerun; pinned artifacts, persisted case, secret-free reports | RF-09 / not run |
| P5 analyst effort | Record hands-on minutes per eligible case with a matched timed comparison or a clearly labeled, sourced or assumption-based estimate. Keep waiting time separate and disclose the sample or assumptions and limitations. | RF-09 / not run |

## Cross-cutting requirements

- APIs authenticate intake, evidence, actions, human approvals and callbacks; tests include wrong credentials, nonce/timestamp replay, rate limits and arbitrary target/command injection.
- Evidence preserves source hash/IDs, original and receipt times, bounded scenario/host/time query scope and unavailable reasons. Reports must not fabricate missing artifacts or leak credentials.
- State-machine and policy tests cover forbidden transitions, expiry, cancellations, capability mismatch, ambiguous provider outcomes and crash recovery before/after dispatch.
- Compose defaults to loopback, safe secrets, least-privilege containers, validated TLS and no default host Docker socket. Live profiles never silently fall back to replay.
- Scenario coverage: PowerShell/process creation, credential-access/process access, scheduled task/actor, ransomware-like recorded file/process indicator, C2/network-process association. ATT&CK labels are annotations, not proof of detection accuracy.
- Operational demo includes denying then approving a mock action, duplicate suppression, incomplete evidence, JSON/HTML reporting, teardown and clean rerun. Live demo is independent and explicitly authorized.

For each gate record revision, dependency/image identity, environment, exact command/scenario, independently defined expected result, observed result, evidence path and limitations. Missing infrastructure is a blocker, not a pass or a failing product test.

RF-03 qualifies the offline vertical slice with original synthetic observations only; see [exact evidence and limitations](rf-03-ledger.md). It does not pass real SOAR, recorded corpus/scenario, live endpoint or release gates.

RF-04A validates inspected vendor API contracts, durable local launch suppression and syntax/security defaults of blocked plans only. The [ledger](rf-04-ledger.md) keeps real import/start/callback/image/runtime acceptance OPEN. Neither source-matching stubs nor docker compose config is genuine Shuffle execution.

RF-04B adds locally tested outbound callback transport and corrects candidate execution-plane defaults. The [runtime successor](rf-04-runtime-ledger.md) separates authenticated node acknowledgement from vendor graph-verified completion for coordinated runs. Missing or conflicting observations stay uncertain. It owns source-built cleanup corrections, private credentials/TLS and genuine runtime evidence; three domain playbooks remain RF-05.

RF-04's [runtime evidence](evidence/rf-04-runtime.json) passes bounded Docker Desktop ARM64 transport acceptance with five original non-disruptive native callback workflows, authenticated node/native/vendor correlation, real acknowledgement timeouts, restart, duplicate suppression and scoped down/up preservation. This qualifies RF-04, not the P2 requirement for three domain playbooks (RF-05), a dedicated guest, live endpoints or release readiness. PR#16 is owner-authorized merged as9de7907; issue#4 is closed and actual merged checks pass.

RF-05A implements the shared domain steps under independent offline expectations. [Its ledger](rf-05a-ledger.md) owns source/target/approval/recovery proof. RF-05B must still execute all three real multi-node Shuffle workflows; an ASGI/core test or callback fixture does not pass that domain-orchestration gate.

RF-05B [aggregate evidence](evidence/rf-05b-runtime.json) qualifies the three-domain gate on authorized Docker Desktop ARM64: actual node scheduling/branch convergence, approval rejection/expiry, unsupported persistence, two verified simulated effects, duplicate suppression, callback loss, native task failure, durable receipt reconciliation across core restart and scoped down/up preservation. Two expected fault runs remain uncertain. The ledger preserves interrupted-request and rate-limit diagnostics; none are silently reclassified as success. Timings include host harness pacing and synthetic human decisions. This does not qualify RF-06 recorded attack scenarios, a dedicated VM, live effects, analyst savings or release readiness.
