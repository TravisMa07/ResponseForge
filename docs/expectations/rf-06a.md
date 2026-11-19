# RF-06A independent expectations

Issue [#6](https://github.com/TravisMa07/ResponseForge/issues/6). This expectation set is derived before implementation from the owner requirements, [acceptance matrix](../acceptance.md), [dataset discovery evidence](../dependencies.md), existing replay contracts, and the [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Integration owns the [design](../rf-06-design.md) and production interfaces. Original test records must be authored independently; downloading telemetry is never part of offline CI.

RF-06A qualifies selective acquisition, integrity/provenance handling and bounded source normalization only. Five scenario decisions and genuine Shuffle executions remain separate RF-06 gates. A parsed event or ATT&CK label alone does not qualify a scenario, source completeness or detection accuracy.

## Acquisition expectations

| Case / input fact | Required observable result | Rationale / origin |
| --- | --- | --- |
| No explicit acquisition opt-in | Refuse before network or output mutation | Owner requirement: downloads selective and opt-in |
| Reviewed manifest entry with exact immutable revision/path, expected bytes/hash and artifact rights | Retrieve only that artifact, verify original bytes, retain source identity and rights metadata | Issue #6; existing pinned PowerShell discovery |
| Missing, ambiguous or unreviewed rights; mutable revision; incomplete integrity metadata | Refuse rather than silently treating repository-wide terms as artifact clearance | Per-artifact rights requirement; unresolved OTRF conflict |
| Changed source path, revision, size or SHA-256 | Reject; no successful final artifact is published | Source bytes bind evidence |
| HTTP failure, redirect, timeout, invalid encoding/compression or oversized body | Fail safely without executable behavior, automatic corpus fallback or partial final artifact | Untrusted source and bounded acquisition |
| Unsupported origin, credentials/query/fragment, path traversal or unexpected URL form | Refuse before network; manifest data cannot select arbitrary network/file targets | Allowlisted source acquisition |
| Existing valid artifact | Verify it before reuse; do not overwrite unrelated bytes | Preserve existing work and reproducibility |
| Existing conflicting artifact or output symlink | Refuse and preserve original state | Owner preservation requirement |
| Error source includes credentials, commands or raw telemetry | Return a bounded safe error without source content | Report/privacy boundary |
| Offline test suite | Use original synthetic bytes and controlled HTTP transport only; require no daemon, VM, downloaded corpus or internet | Issue #6 acceptance |

## XML normalization expectations

The adapter treats source text as inert recorded data. RF-06A accepts only the explicitly frozen XML export shape, provider Microsoft-Windows-Sysmon, Event ID 1 and channel Microsoft-Windows-Sysmon/Operational. Other formats, providers and IDs must be rejected or quarantined with a stable reason; they must never become fabricated supported evidence.

| Case / source fact | Required observable result | Rationale / origin |
| --- | --- | --- |
| Namespaced or unnamespaced Windows Event 1 XML with valid System identity/time and EventData | Deterministic normalized record with original record identity, host, timestamp and mapped recorded fields | Existing RecordedEvent/ReplayBatch semantics |
| Original byte content changes while semantic fields stay equal | Raw-source SHA-256 changes | Provenance is exact-byte integrity, not canonicalized XML hash |
| Events presented out of order | Deterministic chronological order with stable tie-breakers | Replay ordering contract |
| Exact duplicate record | Count duplicate; emit one event | Existing replay duplicate behavior |
| Same scoped record identity with conflicting content | Quarantine conflict; do not silently replace original | Existing duplicate_conflict semantics |
| Missing/malformed record ID, computer, provider, channel, SystemTime or ambiguous EventData | Quarantine with source location and safe code, without synthesized identity/time | Owner requirement: no invented source facts |
| Ambiguous repeated required System element or duplicate named EventData field | Quarantine ambiguity; do not select first/last value | Untrusted data cannot choose oracle by ordering |
| UTC timestamp with recorded subsecond precision | Preserve the represented instant; retain original source text where normalization loses representation | Original time vs receipt time distinction |
| Missing zone in SystemTime, impossible date or nonfinite numeric value | Quarantine; do not use current time or assume local zone | Existing timezone-aware contract |
| XML entity/DTD declaration, external entity or unsupported processing instruction | Reject before external access/expansion | Source text is untrusted; no external reads |
| Broken XML envelope or invalid UTF-8 | Safe refusal; do not certify a partially parsed source | Integrity and bounded parser contract |
| Excessive bytes/events/depth/field length | Refuse or quarantine according to frozen bound, with no truncation presented as complete | Existing replay/model resource limits |
| Command line contains shell substitutions, HTML, encoded payload or script paths | Preserve as inert data; never decode/execute or shell-interpolate | Explicit owner safety constraint |
| Event 1 has process GUID/PID and parent reference | Map only actual fields; missing parent record remains missing | Recorded lineage is not invented |
| Event 3 network record | Quarantine unsupported ID in RF-06A; future mapping must derive direction from Initiated, not guessed destination | Process-associated communication requires actual fields |
| Event 10 process-access record | Quarantine unsupported ID in RF-06A; never model it as creation of the target process | Credential-access indicators require process access facts |
| Command mentions schtasks or vssadmin without task/file telemetry | Keep command observation; do not fabricate task creation, encryption or shadow-copy deletion effect | Owner-approved scenario narrowing |
| Normalized events from distinct hosts/scenarios | Preserve separate scope; do not correlate by PID or label alone | Existing evidence scope contract |
| Optional process fields absent | Keep absent; valid source event does not imply a canonical actionable target | No invented PID, GUID, image or parent |
| SystemTime and EventData.UtcTime differ | Retain their distinct recorded values; never force equality or synthesize a timestamp | SystemTime is the event timestamp; UtcTime describes process creation |
| Mapped field longer than existing 4096-character bound | Quarantine entire record without truncation | Existing RecordedEvent bound; preserved raw bytes remain available |
| Additional unmapped EventData fields | Leave in unchanged hash-bound source.xml; normalized projection is explicitly documented | Bounded projection does not imply full source-field representation |
| Adapter output passed toward alerts/reports | Retain recorded dataset provenance; existing synthetic-fixture labels cannot certify recorded source | Existing make_alerts provenance is synthetic-specific |

## Failure, recovery and remaining gates

A failed acquisition must preserve previous artifacts and permit an explicit corrected invocation. Parser errors may not become empty successful scenario qualification. Errors and quarantine entries must be countable and safe for public summaries. Tests must cover at least one valid success, intended missing behavior, integrity refusal and partial-failure preservation with independently stated outcomes.

RF-06A does not change approval authority, provider capabilities, response effects, Shuffle launch semantics, live behavior or dataset rights. Later RF-06 scenario qualification must preserve these expectations and add source-specific positive/negative/incomplete cases, actual native branch/decision/audit proof and exact source/image/revision identity. Simulated effects remain explicitly simulated; no analyst-savings claim follows.

## Inspected candidate facts before implementation

At upstream Splunk revision `eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c`, the previously inspected `T1059.001/trickbot_cmd_powershell/windows-sysmon.log` contains 16 Event 1 records and eight distinct record IDs, each repeated twice. Independently parsing the unchanged XML finds record 195808 with Image `cmd.exe`, a 7502-character command and recorded `-w hidden` syntax. SystemTime is `2021-03-24T12:42:25.372907600Z` while EventData.UtcTime is `2021-03-24 12:42:25.368`. These are distinct legitimate recorded times. Existing field bounds require quarantining that oversized mapped command; the artifact cannot establish a positive match for the existing image-specific PowerShell rule. It is an integrity/negative/incomplete candidate until another reviewed source supports the intended scenario. This finding must not be corrected by truncation, invented PowerShell child records, broadened rules or timestamp equality.
