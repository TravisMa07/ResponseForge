# RF-07A independent expectations

Issue [#7](https://github.com/TravisMa07/ResponseForge/issues/7); [owning design](../rf-07-design.md). Base: RF-06B2 merge `2f5e204243469fa0fe67ac596cde3fd66d05f1bd`. These requirements precede RF-07A production implementation and derive from the owner scope, existing core authorization/durability contracts and independently inspected upstream Wazuh source. Exact interfaces and bound-count conventions are integration-owned and frozen in the design before test/production GO.

RF-07A is authenticated native-alert intake, source-faithful projection and private durable provenance in the existing Python/SQLite core. It does not deploy Wazuh, enroll an agent, provide a live response capability, qualify a Windows endpoint or run a live Shuffle policy. Offline source-derived/synthetic contract tests do not become captured endpoint or genuine runtime proof. A completing issue #7 delivery still needs its separately reviewed deployment/enrollment work and captured contract gates; this partial PR uses Refs #7.

## Source basis and bounded claims

Pinned Wazuh v4.14.10 source commit `6e7835b4880c3210ef30e855a6bb43432be792e1` defines the native JSON shape in [to_json.c](https://github.com/wazuh/wazuh/blob/6e7835b4880c3210ef30e855a6bb43432be792e1/src/analysisd/format/to_json.c). Alert id is a string formed from epoch seconds, a dot and a global counter; rule.id is a decimal string; rule.level is a number; agent.id is a string with meaningful leading zeroes. manager.name is source metadata, not authenticated manager authority. Optional decoder-specific fields such as data or syscheck cannot be assumed present.

The pinned [Integrator](https://github.com/wazuh/wazuh/blob/6e7835b4880c3210ef30e855a6bb43432be792e1/src/os_integrator/integrator.c) parses and reserializes JSON before writing its temporary alert file. The receiver SHA therefore identifies the exact received integration payload bytes; it must not claim byte identity with upstream alerts.json. Published documentation examples, including [FIM alerts with an offset timestamp](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/fim-threat-detection-rules.html), establish example contracts only. They are not lab-captured endpoint evidence. [Integration retry configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html) makes durable idempotency and conflict handling necessary.

## Trusted configuration and authentication

| Boundary / input | Independent expected result and rationale |
| --- | --- |
| Default original replay configuration with no Wazuh opt-in | Existing behavior remains unchanged; no manager connection, native source registration, response provider or live claim appears |
| Explicit Wazuh configuration | Live mode only, live dispatch disabled, no replay source/mock response provider; exactly reviewed manager identity, allowed agent-to-full-endpoint bindings and one nonhuman source actor come from server configuration |
| Duplicate/conflicting agent binding, missing endpoint, mismatched endpoint.agent_id, duplicate configured full endpoint or ambiguous source actor | Reject configuration instead of choosing first/last; runtime scope cannot depend on dict ordering |
| Request lacks valid bearer credential | Authentication fails before payload processing or private case/source mutation; raw body/token never appears in error |
| Valid unrelated source/analyst/executor/approver/workflow credential | Native intake fails; only the configured exact nonhuman source actor with Wazuh source and endpoint scopes may use it |
| Source actor also carries elevated human/approver/executor authority | Reject configuration; integration credentials cannot grant decisions or dispatch |
| Request exceeds the existing actor rate limit | Reject without changing the limit to accommodate a test; no alert/provenance/effect mutation |
| Generic normalized `/v1/alerts` request claims reserved Wazuh source | Reject even with a valid configured Wazuh source credential; the authenticated native route must establish raw source binding |
| Payload supplies mode, manager identity, host, endpoint, provider, approval, workflow, URL, executable or command | None changes server mode/manager/scenario/agent routing or grants authority; unsupported metadata remains inert private source data |

The configured manager identity scopes deduplication. Two different trusted managers may emit the same native alert id; payload manager.name cannot switch that scope. Agent ids contain one to eight decimal digits, preserve leading zeroes and reject all-zero forms including `000`; manager-local events are not endpoint events in this slice. Unknown agent ids and a known agent id with a different agent.name reject. A matching IP alone is never enrolled endpoint proof or a routing key. Preserve leading zeroes and the exact allowed source hostname. The source principal has exactly the source role, Wazuh source, exact configured endpoint id set, no actions/resources and no human authority. Its configured actor id is not supplied by the payload.

## Strict payload projection

| Input / transformation | Independent expected observable result |
| --- | --- |
| Valid UTF-8 JSON object within bounds with native id, aware timestamp, rule.id, strict integer rule.level and allowed agent.id/name | Deterministic source-faithful observation; available evidence points to exact received-byte SHA, native original id and original event time |
| Missing agent/data/syscheck in an upstream-valid event class | Unsupported endpoint event is explicitly rejected if required agent identity is absent; optional decoder fields remain optional and cannot be invented |
| Root array/scalar/null, malformed/trailing JSON, invalid UTF-8/BOM, nonfinite number, duplicate object key at any depth, invalid Unicode scalar or excessive resource bound | Safe refusal with no successful case/provenance/effect; no raw field/secret echo or uncontrolled parser exception |
| Body larger than 256 KiB; excessive JSON depth, node count or string/key length | Refuse rather than truncate or ignore extra bytes; HTTP stream handling must enforce body size before unbounded buffering |
| Wrong content type or content encoding | Refuse unsupported representation rather than silently decompress or reinterpret bytes |
| Missing/boolean/float/string/out-of-range rule.level | Reject; booleans are not integer severity values |
| Level 0–6 / 7–9 / 10–12 / 13–15 | Map to low / medium / high / critical exactly, as an explicit ResponseForge priority projection, not an upstream detection-confidence claim |
| Numeric or naive/malformed timestamp | Reject; an offset timestamp including `+0200` is accepted and normalized to UTC while its original text remains privately preserved |
| Native id or rule id wrong type, empty, oversized, ambiguous or outside pinned source grammar | Reject instead of coercing; source identifiers must not become arbitrary free-text report fields |
| Extra decoder, syscheck, full_log, data, manager, location or command-like fields | Source remains hash-bound and private; absence adds no guessed process creation, PID/GUID, lineage, response target or action |
| Caller mutates input/config/output after projection | Registered/configured behavior remains detached or rejects conflict; a later mutation cannot alter an earlier accepted observation |

The frozen source grammar is native id `[0-9]{1,20}\.[0-9]{1,20}` and rule id `[0-9]{1,10}`. Configuration uses a manager slug of one to64 ASCII letters/digits/underscore/dot/hyphen, beginning with a letter or digit, and one to128 unique agent/full-endpoint bindings. The JSON root is depth1; every nested value adds1, with maximum32. At most10,000 value nodes count containers/scalars/root but not object keys. Keys and string values are limited to16,384 Unicode codepoints; escaped lone surrogates and nonfinite float overflow are invalid anywhere. Exact observation fields are frozen in the owning design. Expected accepted and rejected boundary examples must be independently constructed, not generated from mapper output. SHA is computed over the exact received bytes, including whitespace. This deliberate byte-bound contract means changed whitespace under the same original identity conflicts; no normalization can hide a changed provenance hash.

## Atomic common-core intake and recovery

`WazuhService(core).intake(raw,actor)` creates one common-core case plus typed immutable WazuhReceipt, exactly two evidence objects (sensitive available delivery provenance and fixed unavailable endpoint-state/lineage/effect gap), acceptance audit and acceptance metric in one SQLite transaction. Receipt uses `callbacks` key `wazuh-source:<incidentID>`, retains the exact original Alert and both Evidence objects, and has receipt_version `wazuh-alert-json-v1`. It retains the original native timestamp separately from the server-assigned first receipt time. A source observation is not a verified response effect. No response execution/proposal/readiness event or Shuffle completion is invented merely by accepting an alert.

| Delivery / failure | Independent expected result |
| --- | --- |
| First authorized delivery | 201 with durable incident/correlation; original source/hash/time/native identity and exact configured endpoint agree across alert, evidence and private receipt |
| Exact bytes repeated for same manager+agent+native id | 200 duplicate, original incident/correlation/first receipt time/evidence/audit/metric unchanged; no extra case, proposal, readiness or effect |
| Same original id for another allowed agent or configured manager | Distinct deterministic native namespace, no cross-endpoint collision or reuse |
| Same identity but changed raw bytes, rule/time/agent data or hidden decoder metadata | 409 and original records remain unchanged, including when only unprojected metadata/whitespace changed |
| SQLite failure after any partial insert | Whole transaction rolls back; a later valid retry creates one complete case rather than accepting a partial receipt or orphan evidence |
| Process restart / new app and Store instances | Same exact duplicate resolves the original case, receipt and evidence; immutable original first receipt and provenance survive |
| Concurrent duplicate deliveries | At most one new case and one original acceptance set; another valid delivery returns that same case as duplicate, never another effect/case |
| Missing, changed or internally inconsistent original raw receipt/alert/evidence/provenance on retry or source inspection | Fail closed rather than reconstruct source proof from the submitted body or overwrite retained records |
| Configuration changes manager/agent/endpoint bindings | Old source proof cannot silently be relabeled as the new endpoint/source; unavailable/conflict is preferable to cross-case fallback |

Shared generic core intake behavior and prior replay/recorded/native expectations remain mandatory regressions. Any core transaction extraction preserves existing authorization, idempotency, audit/metric chronology and safe error semantics; this package cannot introduce a separate weaker case store.

## Reports, dry-run and limits

Default JSON and HTML reports retain `mode=live`, `simulated=false` and `verified_live=false` for this intake-only path. They cannot label an accepted Wazuh alert as simulated replay or claim verified live effect. Safe source-selection/transformation labels `complete_received_alert` / `wazuh-alert-json-v1` may be exposed only after exact stored source proof agrees; missing/conflicting proof is unavailable, not certified by the alert label alone.

Raw source JSON, full_log, decoder fields, original commands, credentials, private config and source receipt payloads remain outside default report projections/errors/logs. Test with configured bearer values and malicious HTML/command text in source metadata. HTML must be escaped, and report redaction remains common-core behavior. Private source retention is bounded per alert and uses the existing private SQLite state; no captured endpoint material enters Git.

Live dispatch defaults false and RF-07A registers no live response capability. A direct action attempt, forged approval/provider field, unsupported core collection or use of a replay mock as a live fallback cannot perform an effect. Existing replay mock and genuine recorded Shuffle proof stay attributed to their tested modes/revisions. Tests prove in-process contract behavior only; real manager delivery, endpoint enrollment, Windows signature/hash verification, live Shuffle execution and endpoint action/recovery remain explicit later gates.

## Qualification

Before production GO, preserve the independent expectation/design freeze and demonstrate meaningful reds for missing valid native projection and authenticated atomic intake against importable fail-closed scaffolds. Parse/setup/import failures are not behavioral red. Run focused success, negative, recovery, conflict and security tests, then full offline checks/schema/build/archive hygiene. Independent artifact review inspects actual implementation, source contracts, tests and evidence; passing this document or synthetic tests does not satisfy captured-payload or live endpoint qualification.
