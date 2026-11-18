# Security boundaries

This is a defensive lab integration project. Controls below remain requirements for vendor/live deployment. RF-02 implements local API authentication/roles/scopes, durable approvals/idempotency, callback nonce/time and rate checks; its bounded evidence is in the [RF-02 ledger](rf-02-ledger.md).

Replay is default and all mock outcomes must say simulated, never verified live. Live is explicit opt-in and dry-run by default, with enrolled endpoint and action allowlists. Never target the physical developer workstation or arbitrary IPs. Never interpret telemetry, filenames, IOC strings or webhook fields as shell commands.

All intake/evidence/proposal/approval/callback endpoints require server-validated authentication. Separate integration identities from human approvers. Bind approval to immutable action, target, scope and expiry. Protect webhook replay with authenticated correlation, nonce/timestamp where supported, durable idempotency and bounded retries/rate limits. Audit before and after dispatch; uncertain effects need reconciliation.

Loopback/private lab bindings, TLS verification and scoped secrets are required. Do not commit tokens, private certificates, real endpoint data or downloaded corpora. Containers should be non-root/read-only where supported, with minimal mounts and no exposed Docker socket by default. Shuffle worker execution is a specific open design issue, not an automatic exception.

Agent installs, privileged host changes, network exposure and disruptive endpoint actions require explicit authorization. Scope a live test to a user-supplied isolated VM with a harmless action and documented teardown. Isolation requires out-of-band recovery and proof of full network effects; Wazuh script dispatch alone is insufficient.

Future implementation must document retention/deletion, credential rotation, report redaction, artifact integrity and dependency/license review. RF-02 offline tests cover local enforcement and recovery; vendor TLS, container execution isolation, real transport and live hardening remain unqualified. See the [local API runbook](core-api.md) for private configuration, credential rotation, retention and limitations.

RF-04A keeps transport credentials/response authorization out of public receipts/reports, verifies origin/UUID/graph scope and blocks blind mutation retries. No engine grant is inferred by a plan descriptor or by RF-03 merge authorization. [Proposed execution boundary](decisions/0002-shuffle-execution-boundary.md) and [stock callback logging caveat](shuffle.md) remain explicit gates before real runtime qualification.
