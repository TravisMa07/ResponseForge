# Current limitations

- RF-01 contracts and RF-02 authenticated case API/SQLite core are implemented and locally verified. Replay, production mock EDR, reports, real Shuffle workflows, Compose deployment and endpoint integration remain unimplemented/unqualified; test adapters do not substitute for these gates.
- Upstream documentation review is not runtime compatibility verification. No vendor image set has passed integration acceptance, and no supported-platform claim is made.
- No recorded attack telemetry is redistributed. Dataset-specific rights, selected-file integrity and evidence coverage must pass before inclusion. Synthetic fixtures will be visibly labeled and cannot substitute for recorded-data qualification.
- No live endpoint VM was supplied; no agent installation, endpoint response, firewall change or live containment has been executed.
- Offline contract/API/durability tests do not establish Docker startup, real SOAR execution or live behavior. No performance or detection metrics have been measured.
- Public GitHub publication does not select an open-source license. Project licensing remains an owner decision before describing this as licensed open source.
- Optional Velociraptor, AI, richer UI and additional providers are deferred.

- RF-02 first decisions are immutable; cancel records an initial cancellation, not revocation of a prior grant. No force-resend exists for uncertain reservations. Persistence uses local SQLite, not a network-filesystem guarantee; audit triggers are not cryptographic tamper evidence. Retention is currently indefinite. See [API recovery and retention](core-api.md).
