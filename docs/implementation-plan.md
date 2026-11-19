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

RF-04A freezes and locally verifies [source-derived transport/durable suppression and blocked deployment plans](rf-04-design.md), with [independent expectations](expectations/rf-04.md) and [evidence](rf-04-ledger.md). [Target comparison](shuffle.md) and [ADR0002](decisions/0002-shuffle-execution-boundary.md) precede any engine/socket grant. A partial PR uses Refs#4. Real import/bootstrap, safe app credentials/image inventory, execution/callback/restart/teardown evidence and measured resources must pass in a separately authorized environment before full RF-04 completion.

RF-04B [design](rf-04b-design.md)/[ledger](rf-04b-ledger.md) owns the next bounded callback sender and candidate safety correction slice after RF-04A merge. Docker Desktop is selected for the pilot. A scoped execution image/enforced cleanup boundary and private credential/CA/app bootstrap must qualify before real runtime; full RF-04 stays open before RF-05 real playbook acceptance.

The [RF-04 runtime successor](rf-04-runtime-design.md) starts at owner-authorized #15 mergee53002a. Its [expectations](expectations/rf-04-runtime.md) freeze source-built cleanup controls, private TLS/credentials, native callback app, checked lifecycle and five actual recovery scenarios. [Ledger](rf-04-runtime-ledger.md) and [operator runbook](rf-04-operator.md) record the now-explicit Desktop pilot grant and observed results. Historical blocked plans remain planning-only; use the checked runtime CLI. No RF-05 domain workflow or live effect is implied.

## RF-05 staged delivery

[RF-05 design](rf-05-design.md) splits shared domain authority from vendor execution. RF-05A implements pure recorded-evidence recommendations and bound prepare/gate/dispatch APIs, with independent [expectations](expectations/rf-05a.md) and [ledger](rf-05a-ledger.md); it uses Refs#5. Separate configured technical principals reuse the existing core while workflow credentials never obtain human approval authority. RF-05B owns actual multi-node Shuffle graphs, native task adapter/worker allowlist review and real three-workflow approval/failure/restart qualification. Passing RF-05A offline tests does not close the real-SOAR gate. The [step runbook](playbooks.md) documents configuration and limitations.


## RF-06 staged delivery

[Design](rf-06-design.md) separates RF-06A selective pinned acquisition, rights/provenance and strict Event1 XML projection from RF-06B source-specific five-scenario mappings and genuine native Shuffle qualification. Source inspection showed the original PowerShell candidate cannot satisfy the existing rule; this boundary prevents source parsing from masquerading as a successful scenario. The [ledger](rf-06-ledger.md) retains exact source findings, red/green and independent review. Partial PRs use Refs#6; offline CI never downloads telemetry. RF-06B depends on the reviewed A interfaces and needs its own expectation freeze, source-bound runtime build and actual branch/decision/audit/effect/metric evidence.


[RF-06B design](rf-06b-design.md) bounds B1 source-specific Windows projection/selection/policy before B2 runtime configuration and genuine recorded-source native qualification. This makes source interpretation reviewable before changed container execution artifacts. B1 remains Refs#6 with zero qualified runtime scenarios; B2 must freeze/review actual cases, preserve journals and rebuild/verify images before genuine runs.


RF-06B2 implementation and genuine Desktop recorded-source qualification are now observed in the [ledger](rf-06-ledger.md) and [aggregate](evidence/rf-06b2-runtime.json):20 phases/14 cases/five narrowed observations with source/rights/missing-evidence boundaries, full approval/audit/receipt/report proof and retained recovery. Separate B1/B2 review kept source interpretation distinct from changed execution artifacts. Offline checks need no downloads. Owner acceptance/merge and merged-revision verification remain open; next feature lane RF-07 requires its own design/expectation freeze and explicit live lab authority before endpoint work.


## RF-07 staged delivery

[Design](rf-07-design.md), [A expectations](expectations/rf-07a.md) and [ledger](rf-07-ledger.md) start from merged/verified RF-06B2. A reviews native JSON authentication, configured manager/agent identity, atomic common-core intake, immutable private source evidence and no-dispatch reports. B owns the separately reviewed optional upstream manager profile and signed/hash-checked Windows enrollment bundle. Both use Refs#7 until full acceptance passes; actual enrolled endpoint/sensor/live Shuffle/effect and recovery remain separately authorized RF-08. Offline A tests use original synthetic JSON and never need downloads or deployment.
