# Roadmap

The [implementation plan](implementation-plan.md) owns detailed work packages. The [acceptance matrix](acceptance.md) owns exit gates.

| Phase | Outcome | Status |
| --- | --- | --- |
| 0 | Environment, upstream review, architecture, roadmap, public repository | Foundation prepared; dependency compatibility and selected-data qualification remain open |
| 1 | Offline authenticated case/replay/policy/report vertical slice | Planned: RF-01–03 |
| 2 | Three real Shuffle workflows with recovery tests | Planned: RF-04–05 |
| 3 | Five evidence-backed scenarios with opt-in public data | Planned: RF-06 |
| 4 | Real Wazuh alert and approved safe VM action | Planned: RF-07–08; blocked on authorized lab and prior replay gates |
| 5 | Fresh-clone reproducibility, docs, measured evidence | Planned: RF-09 |
| 6 | Optional read-only AI investigation | Deferred until phases 1–5 qualify |

Current delivery scope is repository creation and publication. The next coding package is RF-01. No replay scenario, SOAR execution or live response has passed acceptance yet.
