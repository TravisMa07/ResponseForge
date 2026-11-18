# Security boundaries

This is a defensive lab integration project. Controls below are requirements, not implemented security guarantees.

Replay is default and all mock outcomes must say simulated, never verified live. Live is explicit opt-in and dry-run by default, with enrolled endpoint and action allowlists. Never target the physical developer workstation or arbitrary IPs. Never interpret telemetry, filenames, IOC strings or webhook fields as shell commands.

All intake/evidence/proposal/approval/callback endpoints require server-validated authentication. Separate integration identities from human approvers. Bind approval to immutable action, target, scope and expiry. Protect webhook replay with authenticated correlation, nonce/timestamp where supported, durable idempotency and bounded retries/rate limits. Audit before and after dispatch; uncertain effects need reconciliation.

Loopback/private lab bindings, TLS verification and scoped secrets are required. Do not commit tokens, private certificates, real endpoint data or downloaded corpora. Containers should be non-root/read-only where supported, with minimal mounts and no exposed Docker socket by default. Shuffle worker execution is a specific open design issue, not an automatic exception.

Agent installs, privileged host changes, network exposure and disruptive endpoint actions require explicit authorization. Scope a live test to a user-supplied isolated VM with a harmless action and documented teardown. Isolation requires out-of-band recovery and proof of full network effects; Wazuh script dispatch alone is insufficient.

Future implementation must document retention/deletion, credential rotation, report redaction, artifact integrity and dependency/license review. No security hardening has been runtime-tested at foundation stage.
