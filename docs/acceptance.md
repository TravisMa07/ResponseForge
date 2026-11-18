# Acceptance matrix

All product gates are **NOT RUN**. Foundation checks only validate repository integrity. See [implementation ledger](implementation-ledger.md) for observed evidence.

| Gate | Required evidence | Owner / status |
| --- | --- | --- |
| P0 environment | Host/Docker resources, Python/Git/Compose availability, supported vs unverified platform matrix | RF-00 / inspected |
| P0 dependency/data | Tested version/digest set; minimum dataset fields, hashes and terms verified | RF-00, RF-04, RF-06 / open; references alone do not pass |
| P1 offline core | `make test` without network/VM; one deterministic evidence-backed case/report; benign case; quarantine and duplicate tests | RF-01–03 / not run |
| P1 safety | Spoofed/expired/mismatched approvals rejected; authorization enforced; durable idempotency; mock failure/rollback and flags | RF-02/03 / not run |
| P2 real SOAR | Three imported workflows; correlated real run, denied approval, failed/lost/replayed callback and retry recovery | RF-04/05 / not run |
| P3 scenarios | Five licensed evidence-backed scenarios or justified narrowing; positive/negative/incomplete tests and real branch/audit assertions | RF-06 / not run |
| P4 live | Authorized enrolled VM produces real alert and approved safe effect through common core; recovery and Windows evidence | RF-07/08 / not verified, no VM |
| P5 reproducibility | Fresh clone, doctor/bootstrap/up/status/replay/report/down/rerun; pinned artifacts, persisted case, secret-free reports | RF-09 / not run |

## Cross-cutting requirements

- APIs authenticate intake, evidence, actions, human approvals and callbacks; tests include wrong credentials, nonce/timestamp replay, rate limits and arbitrary target/command injection.
- Evidence preserves source hash/IDs, original and receipt times, bounded scenario/host/time query scope and unavailable reasons. Reports must not fabricate missing artifacts or leak credentials.
- State-machine and policy tests cover forbidden transitions, expiry, cancellations, capability mismatch, ambiguous provider outcomes and crash recovery before/after dispatch.
- Compose defaults to loopback, safe secrets, least-privilege containers, validated TLS and no default host Docker socket. Live profiles never silently fall back to replay.
- Scenario coverage: PowerShell/process creation, credential-access/process access, scheduled task/actor, ransomware-like recorded file/process indicator, C2/network-process association. ATT&CK labels are annotations, not proof of detection accuracy.
- Operational demo includes denying then approving a mock action, duplicate suppression, incomplete evidence, JSON/HTML reporting, teardown and clean rerun. Live demo is independent and explicitly authorized.

For each gate record revision, dependency/image identity, environment, exact command/scenario, independently defined expected result, observed result, evidence path and limitations. Missing infrastructure is a blocker, not a pass or a failing product test.
