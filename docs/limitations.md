# Current limitations

- RF-01 contracts and RF-02 authenticated case API/SQLite core are implemented and locally verified. RF-03 adds locally qualified replay, a durable simulated response provider and redacted JSON/HTML reports. Real Shuffle workflows, recorded-data coverage, Compose deployment and endpoint integration remain unqualified; simulation does not substitute for those gates.
- Upstream documentation review is not runtime compatibility verification. No vendor image set has passed integration acceptance, and no supported-platform claim is made.
- No recorded attack telemetry is redistributed. Dataset-specific rights, selected-file integrity and evidence coverage must pass before inclusion. Synthetic fixtures will be visibly labeled and cannot substitute for recorded-data qualification.
- No live endpoint VM was supplied; no agent installation, endpoint response, firewall change or live containment has been executed.
- Offline contract/API/durability tests do not establish Docker startup, real SOAR execution or live behavior. No performance or detection metrics have been measured.
- Public GitHub publication does not select an open-source license. Project licensing remains an owner decision before describing this as licensed open source.
- Optional Velociraptor, AI, richer UI and additional providers are deferred.

- RF-02 first decisions are immutable; cancel records an initial cancellation, not revocation of a prior grant. No force-resend exists for uncertain reservations. Persistence uses local SQLite, not a network-filesystem guarantee; audit triggers are not cryptographic tamper evidence. Retention is currently indefinite. See [API recovery and retention](core-api.md).

- Replay currently accepts bounded original JSON/JSONL records, with a transparent toy observation rule. It is not a vendor log parser, SIEM detector, recorded attack validation or general maliciousness classifier. Default reports preserve provenance IDs while omitting raw telemetry and sensitive/free-text fields. See [replay limitations](replay.md).

- RF-04A source-derived client/coordinator and candidate Compose planning are locally tested; full issue#4 remains open. There is no qualified Shuffle instance/imported workflow/callback or engine authority; Docker Desktop is selected for the pilot. Header logging in the inspected stock HTTP app, unresolved app/image/source compatibility and separate-artifact terms are explicit gates. See [the comparison and runtime packet](shuffle.md).

- Further RF-04B source inspection found the original candidate selected Swarm and the upstream standalone cleanup scans containers beyond the project. Candidate flags are corrected, but shared-daemon startup remains blocked until cleanup is scoped/enforced. The outbound callback sender does not constitute an installed Shuffle app or solve upstream SDK/worker credential logging/injection. See [source evidence](shuffle-source-evidence.md).
