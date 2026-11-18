# Implementation plan

Initial scope: establish and publish the repository, complete feasible Phase 0 research, and expose remaining qualification gates. RF-01 contracts and RF-02 durable API/core are now implemented with bounded local qualification; RF-03 now qualifies the offline replay/report slice; vendor integrations follow. No time estimate or feature completion is inferred from parallelism.

## Work packages

| ID / phase | Behavior and owned area | Dependencies | Acceptance evidence |
| --- | --- | --- | --- |
| RF-00 / 0 | Repository, host audit, upstream/data feasibility, architecture and safety plan | Handoff | Foundation checks, doctor output, upstream references; full Phase 0 waits for verified artifact rights/fields and compatibility evidence |
| RF-01 / 1 | Freeze v1 schemas, state transitions, provider protocols, API auth roles and policy invariants; lock Python tooling | RF-00 foundation | Independent schema/transition/auth expectations; pytest/Ruff/type checks; reject invalid inputs, UTC ambiguity and spoofed approvals |
| RF-02 / 1 | SQLite migrations, case intake, audit, approval/expiry/idempotency and durable dispatch state | RF-01 | Transaction/restart/concurrency tests; duplicate alert produces one case; target/action/TTL mismatch denied; uncertain dispatch reconciled |
| RF-03 / 1 | Replay parser/clock/quarantine, scoped evidence, stateful mock, JSON/HTML report, one suspicious and benign original fixture | RF-01; integrate RF-02 | Offline deterministic golden test; no duplicate effects; failure/timeout/rollback; missing evidence and simulation flags; report redaction |
| RF-04 / 2 | Upstream-derived Shuffle Compose, import/bootstrap, authenticated trigger/callback and durable retry | RF-01; qualification needs RF-02/03 | Pin tested images/digests, validate Compose, run real workflow, correlate run ID, reject forged/replayed callback; resolve Docker socket boundary first |
| RF-05 / 2 | Process, persistence and containment workflow exports, approval branches and recovery | RF-02/03/04 | Three real imported workflows; denied/expired approval cannot dispatch; callback loss/restart/timeout audited; unsupported capability escalates |
| RF-06 / 3 | Selective licensed dataset fetch, manifest/checksums, five scenario mappings and negative/incomplete cases | RF-03/05; dataset research can proceed after RF-01 | Per-artifact rights/fields/hash; each scenario verifies evidence, actual SOAR branch, decision and audit; offline CI skips downloads |
| RF-07 / 4 | Wazuh upstream Compose profile, live alert auth/mapping and safe Windows installer bundle | RF-05/06 acceptance | Captured schema contracts, enrollment target allowlist, signature/hash verification, dry-run defaults; no claim of live support from these checks |
| RF-08 / 4 | Authorized VM enrollment, real alert, approved harmless marker action, effect verification/recovery | RF-07 + explicit administrator authorization and supplied VM | Real sensor→Wazuh→same Shuffle/core flow; dispatch/ack/effect distinguished; restore/teardown proof; Windows qualified separately |
| RF-09 / 5 | Fresh-clone Docker automation, runbooks, reports/demo and measured metrics | RF-01–08 for full release; replay release may precede live | Reproducible offline starter, actual version report, persistence/teardown/rerun; measured claims only |

## RF-01 contract foundation

The [RF-01 design](rf-01-design.md) and [expectations](expectations/rf-01.md) are frozen before application code. Own `src/responseforge/contracts/`, provider protocols, configuration/auth design, `pyproject.toml`, dependency lock and test tooling. Use Python 3.12 as baseline, Pydantic v2 and FastAPI after exact compatible dependency resolution. Define strict versioned schemas and source/scenario/mode-scoped identity; distinguish provider dispatch from effect verification. Specify proposal immutability, human identity verification, TTL, callback nonce/time validation, rate limits and idempotency retention.

Tests must derive expected allowed/rejected transitions and action approval decisions from the handoff, including forged identity, changed endpoint/action, expired approval, unsupported capability and replay/live mismatch. No Docker, external datasets, endpoint enrollment or UI in this package. Acceptance is contracts/tooling only, not a working response platform.

## Measure analyst time saved

RF-01 defines the events and correlation IDs for alert acceptance and case readiness. A case is ready for review when it contains source-linked evidence, any known evidence gaps, a proposed action or a documented reason for no action, and an audit record. Later packages capture the events as their paths land. Elapsed alert-to-case time is measured separately from active analyst work.

RF-09 records hands-on investigation and documentation minutes per eligible case. Prefer a matched lab comparison using the owner or another test analyst. Use equivalent scenarios and the same evidence, decision, and report requirements for manual and assisted runs. Vary the order where possible to reduce familiarity bias. Record paired durations, the number of cases and analysts, and the median paired difference. Record waiting for approval or automation separately.

If a timed manual baseline is unavailable, use a documented estimate drawn from a comparable source or explicit task-by-task assumptions. Record the source or assumptions, range, and how closely the baseline matches the scenarios. Label any resulting savings as estimated. Publish aggregate, redacted results with the tested revision and environment. A measured improvement claim requires measured timings for both paths.

## Parallel-agent execution plan

The integration owner freezes RF-01 and records the exact base SHA before allocating work. After that, use at most three implementation lanes:

- **Core lane (RF-02):** storage/core/API; owns migrations and durable policy integration. Does not change shared contracts without integration review.
- **Replay lane (RF-03):** replay/evidence/mock/reports and local synthetic fixtures; tests against frozen protocols. Coordinates API routing through the integration owner.
- **SOAR lane (RF-04):** deployment and Shuffle adapter/import spike; no core changes. Runtime qualification waits for integrated RF-02/03 and approved execution architecture.

Each lane receives explicit paths, expected tests, exclusions and base revision. Shared contracts, dependency locks, CI and status documents have one writer. Keep all commits reviewable; do not merge incomplete interfaces. RF-05 workflow authoring may split by workflow only after common auth/callback conventions freeze; one owner integrates exports. RF-06 data research may run separately, but scenario qualification uses the integrated real workflow. A read-only reviewer checks security and acceptance evidence before milestone claims. No agent may authorize endpoint impact for another agent.

## Decisions and blockers

Confirm vendor image architecture and runtime compatibility before declaring a tested version set. Resolve Shuffle worker requirements versus no-default-Docker-socket policy before startup. Inspect minimum selected dataset fields, redistribution terms and checksums before fixture inclusion. Public project license remains unselected. Windows/ARM virtualization and Wazuh compatibility need explicit verification on the chosen guest; no VM was supplied. Do not install or provision one implicitly.

## RF-02 durable core

The [RF-02 design](rf-02-design.md), [independent expectations](expectations/rf-02.md), [ledger](rf-02-ledger.md) and [API runbook](core-api.md) own this package. RF-03 now integrates through the authenticated case/evidence/action API and frozen response protocols. It must return deterministic `exec-<proposal_id>` execution identities, preserve reserved-request chronology and support verification of an original action after unknown outcome. RF-04 actual transport remains independently qualified.

## RF-03 offline slice

[Design](rf-03-design.md), [expectations](expectations/rf-03.md), [ledger](rf-03-ledger.md) and [runbook](replay.md) own bounded synthetic replay/evidence/simulated-response/report acceptance. RF-04 must now resolve Shuffle isolation and immutable image/worker compatibility, then qualify actual transport against this integrated path. No synthetic run closes the real-SOAR gate.

## RF-04 staged delivery

RF-04A freezes and locally verifies [source-derived transport/durable suppression and blocked deployment plans](rf-04-design.md), with [independent expectations](expectations/rf-04.md) and [evidence](rf-04-ledger.md). [Target comparison](shuffle.md) and [proposedADR0002](decisions/0002-shuffle-execution-boundary.md) precede any engine/socket grant. A partial PR uses Refs#4. Real import/bootstrap, safe app credentials/image inventory, execution/callback/restart/teardown evidence and measured resources must pass in a separately authorized environment before full RF-04 completion.
