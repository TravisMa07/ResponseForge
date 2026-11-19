# RF-05B independent expectation freeze

Origin: issue#5, owner specification§7, independently reviewed RF05A authority boundaries and pinned SDK/worker/shared source documented in the design. Freeze before native/graph/source implementation; root alone runs real Docker qualification.

- Three graphs have Prepare→Gate, predicate-gated Dispatch and one converged callback. Native app metadata/enums, original IDs, graph source hash, empty-only parameters and private transport stay bound. No arbitrary URL/key/command/action/approval/provider input.
- Gate statuses ready|uncertain select Dispatch; awaiting_approval/denied/expired/no_action/completed/failed skip it. Invalid gate/native result is never ready. Genuine SKIPPED receipt and zero core dispatch on false are required.
- Core response must be strict typed exact-request Plan/Progress. Completed means verified replay/simulated and matching action/case; never live. Core failure/timeout/invalid JSON results in safe failed/uncertain native receipt, no blind mutation retry or raw data leak.
- Original execution and graph node mismatch, malicious origin, forged credentials/config, mode mismatch and nonempty params reject before core I/O. Wrong core200 response correlation/proof cannot become nativeSUCCESS.
- Successful final callback plus failed/missing/duplicate native task must remain uncertain/running. Whole vendor completion, exact task results, authenticated core node and endpoint effect are separate observations.
- Unknown worker apps/versions/functions/modules/images/volumes/host modes remain rejected; all RF04 cleanup/ownership/read-only guards stay intact.
- Default FileConfig/renderer do not enable domain providers/mounts. Explicit replay source hash and distinct mock DB are required; live configuration rejects without fallback. Repeated startup seeds preserve simulated receipts and existing core cases.
- Real imports/executions of all3 kinds, no-effect denial/expiry/unsupported/missing identity, approved process/containment simulated effects, duplicate suppression, explicit human resume, genuine callback loss and restart audits are required. Mocks and exported JSON alone cannot pass.
- Exact source/image binding and journal reservations survive uncertainty. No blind create/start repeat after unknown ACK; no unrelated cleanup; logs/reports redact configured and actual execution secrets. Publish only aggregate synthetic evidence; live=false, domain count and limitations explicit.
