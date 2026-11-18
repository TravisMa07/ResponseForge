# Acceptance matrix

Full product gates below remain open. RF-01 contract/pure-policy and [RF-02 durable API/recovery evidence](rf-02-ledger.md) qualify their bounded components, not the complete P1 vertical slice. Foundation checks only validate repository integrity. See [implementation ledger](implementation-ledger.md) for observed evidence.

| Gate | Required evidence | Owner / status |
| --- | --- | --- |
| P0 environment | Host/Docker resources, Python/Git/Compose availability, supported vs unverified platform matrix | RF-00 / inspected |
| P0 dependency/data | Tested version/digest set; minimum dataset fields, hashes and terms verified | RF-00, RF-04, RF-06 / open; references alone do not pass |
| P1 offline core | `make test` without network/VM; one deterministic evidence-backed case/report; benign case; quarantine and duplicate tests | RF-01–03 locally verified using original synthetic fixtures; RF-01–03 merged and merged revisions verified |
| P1 safety | Spoofed/expired/mismatched approvals rejected; authorization enforced; durable idempotency; mock failure/rollback and flags | RF-02/03 enforcement, durable simulated effects, failure/recovery and approved rollback locally verified |
| P2 real SOAR | Three imported workflows; correlated real run, denied approval, failed/lost/replayed callback and retry recovery | RF-04/05 / not run |
| P3 scenarios | Five licensed evidence-backed scenarios or justified narrowing; positive/negative/incomplete tests and real branch/audit assertions | RF-06 / not run |
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

RF-04B adds locally tested outbound callback transport and corrects candidate execution-plane defaults. Whole-vendor completion must reconcile callback-reported PlaybookRun status with coordinator graph-verified delivery; a terminal callback alone is insufficient. Shared-daemon cleanup, credential injection/logging and actual runtime evidence remain open.
