# Roadmap

The [implementation plan](implementation-plan.md) owns detailed work packages. The [acceptance matrix](acceptance.md) owns exit gates.

| Phase | Outcome | Status |
| --- | --- | --- |
| 0 | Environment, upstream review, architecture, roadmap, public repository | Foundation prepared; dependency compatibility and selected-data qualification remain open |
| 1 | Offline authenticated case/replay/policy/report vertical slice | RF-01–03 merged; merged-revision checks pass |
| 2 | Three real Shuffle workflows with recovery tests | RF-04 transport and RF-05B three native domain workflows qualified locally on Docker Desktop; #18 merged; actual merged-revision checks pass |
| 3 | Five evidence-backed scenarios with opt-in public data | RF-06A #19 merged and merged checks pass; RF-06B1 #20 merged and merged checks pass; RF-06B2 #21 merged; issue#6 closed; actual merged-revision checks pass; five narrowed recorded scenarios qualified |
| 4 | Real Wazuh alert and approved safe VM action | RF-07A actual main merge verified; RF-07B and C1 merged to main with actual merged checks passing; RF-07C2 merged and actual main checks pass; RF-07C3 shipped-client overlay locally qualified; manager/endpoint gates open |
| 5 | Fresh-clone reproducibility, docs, and [analyst effort evidence](implementation-plan.md#measure-analyst-time-saved) | Planned: RF-09 |
| 6 | Optional read-only AI investigation | Deferred until phases 1–5 qualify |

RF-01–03 are merged and their merged revisions verified. Original synthetic replay and five narrowed recorded-observation scenarios are locally qualified; RF-06 is merged and verified; live response remains separately gated. RF-04A/B are merged and their merged checks pass. The [runtime ledger](rf-04-runtime-ledger.md) and [redacted evidence](evidence/rf-04-runtime.json) record five genuine Docker Desktop execution/recovery scenarios passing. [Both target options](shuffle.md) are retained; the explicitly authorized pilot is stopped with volumes retained. Runtime #16 is merged and its merged checks pass; dedicated-VM runtime remains unqualified; RF-05 domain proof is recorded separately below.


## GitHub delivery tracking

The baseline is nine issues and nine implementation PRs through full release readiness. A package can need more than one PR when its work benefits from separate review. Phase 0 follow-up qualifications are tracked in their owning packages below.

| Package | GitHub issue | PR |
| --- | --- | --- |
| RF-01 · Contracts and tooling | [#1](https://github.com/TravisMa07/ResponseForge/issues/1) | [#11](https://github.com/TravisMa07/ResponseForge/pull/11) · merged; issue closed; merged checks pass |
| RF-02 · Durable core | [#2](https://github.com/TravisMa07/ResponseForge/issues/2) | [#12](https://github.com/TravisMa07/ResponseForge/pull/12) · merged; issue closed; merged checks pass |
| RF-03 · Offline replay | [#3](https://github.com/TravisMa07/ResponseForge/issues/3) | [#13](https://github.com/TravisMa07/ResponseForge/pull/13) · merged; issue closed; merged checks pass |
| RF-04 · Shuffle deployment and transport | [#4](https://github.com/TravisMa07/ResponseForge/issues/4) | [#14](https://github.com/TravisMa07/ResponseForge/pull/14) · RF-04A merged and merged checks pass; [RF-04B #15](https://github.com/TravisMa07/ResponseForge/pull/15) merged and merged checks pass; [runtime #16](https://github.com/TravisMa07/ResponseForge/pull/16) merged; issue#4 closed; merged revision9de7907 checks pass |
| RF-05 · Shuffle playbooks | [#5](https://github.com/TravisMa07/ResponseForge/issues/5) | [RF-05A #17](https://github.com/TravisMa07/ResponseForge/pull/17) merged and merged checks pass; [RF-05B #18](https://github.com/TravisMa07/ResponseForge/pull/18) qualifies3 genuine native workflows/14 runs/nine synthetic cases; merged as `ec5d80e`; issue closed; actual merged-revision checks pass |
| RF-06 · Scenario and dataset qualification | [#6](https://github.com/TravisMa07/ResponseForge/issues/6) | [RF-06A #19](https://github.com/TravisMa07/ResponseForge/pull/19) · merged as6e3ecb4; merged checks pass; [RF-06B1 #20](https://github.com/TravisMa07/ResponseForge/pull/20) · merged as2ff84b8; merged checks pass; [RF-06B2 #21](https://github.com/TravisMa07/ResponseForge/pull/21) merged as2f5e204; issue closed; actual merged checks pass |
| RF-07 · Wazuh adapter and enrollment bundle | [#7](https://github.com/TravisMa07/ResponseForge/issues/7) | A/B/C1 merged and merged checks pass; [C1 TLS](rf-07c1-design.md) native component qualified; [C2 platform compiler](rf-07c2-design.md) merged/verified; [C3 shipped-client overlay](rf-07c3-design.md) passes89 offline cases/13 shipped-component scenarios; runtime/Windows/capture gates open |
| RF-08 · Authorized live verification | [#8](https://github.com/TravisMa07/ResponseForge/issues/8) | Pending |
| RF-09 · Release readiness | [#9](https://github.com/TravisMa07/ResponseForge/issues/9) | Pending |

After RF-01, RF-02 and RF-03 can run in parallel alongside RF-04 discovery. RF-04 runtime qualification needs the integrated core and replay path. RF-06 dataset discovery can overlap those lanes.

The next lanes have [bounded preparation and ownership](next-packages.md) from proven RF-01 revision `6d8b4ec`; the current RF-04 source/runtime boundary is maintained in its owning design/ledger.
