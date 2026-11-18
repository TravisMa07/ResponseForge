# Working on ResponseForge

Read `README.md`, `docs/architecture.md`, `docs/sdlc.md`, `docs/implementation-plan.md` and the current ledger before changes. Read the owning design/ledger when starting a work package.

- Keep handoff documents, original user attachments and private working notes local and untracked. Never stage or push them, even with `git add -f`. Consult a local `HANDOFF.md` when available; public docs must remain usable without it. Publish maintained architecture, acceptance criteria and operator documentation instead.
- Preserve the SOAR scope: one Python package, SQLite, replay, Shuffle and optional live Wazuh. No DetectBridge dependency, SIEM, EDR, Kafka, dashboard or AI in the MVP.
- Replay is simulated; live verification requires real endpoint proof. Never silently substitute mock success for failed live operations.
- Freeze independent behavioral expectations before implementation. Write and run meaningful negative, failure/recovery and success tests; maintain evidence and limitations.
- Keep APIs authenticated, modes explicit, endpoints/actions allowlisted, approvals server-authorized and bound to target/action/expiry. Treat source data as untrusted. Never execute alert-provided commands.
- Do not perform disruptive endpoint actions, install agents, expose management APIs, mount the Docker socket or change host privileges without explicit authorization. Default to loopback and live dry-run.
- Use bounded branches/PRs after the initial authorized repository seed. Merges and releases require owner authorization. Preserve published history; normally use 1–3 cohesive commits with a separate expectation freeze for substantive behavior.
- Delegate only when authorized. Give each agent a work ID, base revision, owned files, frozen interfaces, expected tests and handoff format. The integration owner owns contracts, dependency locks, CI, shared status and integration qualification. No overlapping edits or competing stack tests.
- Keep secrets, real endpoint evidence, downloaded corpora and build output out of Git. Verify per-artifact licensing before redistribution.
- Record exact revision, environment, command, outcome and remaining gates. Documentation checks prove no runtime feature. Update owning design/ledger and roadmap together.
