# Roadmap

The [implementation plan](implementation-plan.md) owns detailed work packages. The [acceptance matrix](acceptance.md) owns exit gates.

| Phase | Outcome | Status |
| --- | --- | --- |
| 0 | Environment, upstream review, architecture, roadmap, public repository | Foundation prepared; dependency compatibility and selected-data qualification remain open |
| 1 | Offline authenticated case/replay/policy/report vertical slice | RF-01/02 merged; RF-03 locally qualified, owner review/merge open |
| 2 | Three real Shuffle workflows with recovery tests | Planned: RF-04–05 |
| 3 | Five evidence-backed scenarios with opt-in public data | Planned: RF-06 |
| 4 | Real Wazuh alert and approved safe VM action | Planned: RF-07–08; blocked on authorized lab and prior replay gates |
| 5 | Fresh-clone reproducibility, docs, and [analyst effort evidence](implementation-plan.md#measure-analyst-time-saved) | Planned: RF-09 |
| 6 | Optional read-only AI investigation | Deferred until phases 1–5 qualify |

RF-01/02 are merged and their merged revisions verified. RF-03 offline replay/report is locally qualified in the [RF-03 ledger](rf-03-ledger.md). RF-04 deployment/transport investigation is next; actual Shuffle execution remains open. No replay scenario, SOAR execution or live response has passed acceptance yet.


## GitHub delivery tracking

The baseline is nine issues and nine implementation PRs through full release readiness. A package can need more than one PR when its work benefits from separate review. Phase 0 follow-up qualifications are tracked in their owning packages below.

| Package | GitHub issue | PR |
| --- | --- | --- |
| RF-01 · Contracts and tooling | [#1](https://github.com/TravisMa07/ResponseForge/issues/1) | [#11](https://github.com/TravisMa07/ResponseForge/pull/11) · merged; issue closed; merged checks pass |
| RF-02 · Durable core | [#2](https://github.com/TravisMa07/ResponseForge/issues/2) | [#12](https://github.com/TravisMa07/ResponseForge/pull/12) · merged; issue closed; merged checks pass |
| RF-03 · Offline replay | [#3](https://github.com/TravisMa07/ResponseForge/issues/3) | Pending |
| RF-04 · Shuffle deployment and transport | [#4](https://github.com/TravisMa07/ResponseForge/issues/4) | Pending |
| RF-05 · Shuffle playbooks | [#5](https://github.com/TravisMa07/ResponseForge/issues/5) | Pending |
| RF-06 · Scenario and dataset qualification | [#6](https://github.com/TravisMa07/ResponseForge/issues/6) | Pending |
| RF-07 · Wazuh adapter and enrollment bundle | [#7](https://github.com/TravisMa07/ResponseForge/issues/7) | Pending |
| RF-08 · Authorized live verification | [#8](https://github.com/TravisMa07/ResponseForge/issues/8) | Pending |
| RF-09 · Release readiness | [#9](https://github.com/TravisMa07/ResponseForge/issues/9) | Pending |

After RF-01, RF-02 and RF-03 can run in parallel alongside RF-04 discovery. RF-04 runtime qualification needs the integrated core and replay path. RF-06 dataset discovery can overlap those lanes.

The next lanes have [bounded preparation and ownership](next-packages.md) from proven RF-01 revision `6d8b4ec`; their implementation and runtime gates remain open.
