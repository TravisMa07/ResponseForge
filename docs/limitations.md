# Current limitations

- This repository contains specification, engineering plans and foundation scripts only. No API, cases, replay, mock EDR, reports, Shuffle workflow, Compose deployment or endpoint integration is implemented.
- Upstream documentation review is not runtime compatibility verification. No vendor image set has passed integration acceptance, and no supported-platform claim is made.
- No recorded attack telemetry is redistributed. Dataset-specific rights, selected-file integrity and evidence coverage must pass before inclusion. Synthetic fixtures will be visibly labeled and cannot substitute for recorded-data qualification.
- No live endpoint VM was supplied; no agent installation, endpoint response, firewall change or live containment has been executed.
- Python foundation checks do not establish Docker startup, real SOAR execution or live behavior. No performance or detection metrics have been measured.
- Public GitHub publication does not select an open-source license. Project licensing remains an owner decision before describing this as licensed open source.
- Optional Velociraptor, AI, richer UI and additional providers are deferred.
