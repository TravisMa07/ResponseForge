# Wazuh intake and remaining live gates

[RF-07 design](rf-07-design.md), [independent expectations](expectations/rf-07a.md) and [ledger](rf-07-ledger.md) own exact contracts, revisions and qualification. RF-07A adds native alert intake to the existing case API. It does not install/start Wazuh, enroll a machine, run a live Shuffle policy or provide a response adapter. An accepted alert is not proof of endpoint connectivity or an action effect.

## Explicit private configuration

Default generated configuration remains replay-only. For an intake-only live configuration, use FileConfig.mode=live, no playbooks/recorded fields, an explicit WazuhConfig and existing private credentials/endpoints. The [Wazuh configuration schema](../schemas/wazuh-config.json) specifies manager_id, source_actor_id and agents. Each binding includes the exact agent.id string (leading zeros matter) and full EndpointRef with matching agent_id and original agent.name as hostname. Binding endpoints must also occur identically in the top-level endpoints array. Duplicate mappings and all-zero manager-local agent IDs refuse.

manager_id is a trusted operator namespace for the actual manager instance; payload manager.name/IP never selects authority. Use a separate nonhuman integration principal with exactly roles=[source], sources=[wazuh], endpoint_ids equal to the binding IDs, actions=[] and resources=[]. Keep analyst credentials separate; do not give the source actor human, approval, executor or workflow authority. Generate independent credentials of at least32 characters into a0600 private file under a0700 directory. Never check in credentials or use example values as deployed secrets.

No response provider is registered. live_dispatch_enabled remains false; replay/mock/provider/playbook configuration cannot coexist with enabled Wazuh intake in this slice. The existing CLI loads an explicit private configuration with `python -m responseforge --config <private-file>` and binds only127.0.0.1. Local API inspection is not a deployed manager integration. Remote/container sender delivery requires separately reviewed verified TLS and private routing; do not expose this listener or disable certificate checks to make a test pass.

## Native delivery boundary

POST `/v1/integrations/wazuh/alerts` takes the JSON alert object produced by a Wazuh custom integration, with the configured Bearer credential. Authentication/rate/actor scope runs before reading the streamed body. Use application/json with UTF-8 (optional charset=utf-8); compressed/other encodings/media types refuse. Native route is disabled unless configured. Generic normalized `/v1/alerts` cannot claim source wazuh and bypass raw provenance validation.

Required fields are original id, aware timestamp, rule.id, strict integer rule.level and agent.id/name. Decoder-specific data/syscheck/full_log is optional. The adapter supports the bounded numeric source ID grammar documented in the design. It maps severity to a local case priority; it does not infer attack correctness or response authorization. A matching source field cannot install a provider, launch a workflow, approve an action or execute a command. Unknown endpoint/name mappings reject.

The body limit is256KiB with bounded depth/value count/string length, no duplicate JSON keys, nonfinite numbers, invalid UTF-8 or Unicode surrogates. Errors omit raw source/secret values. Accepted delivery returns201 with the common incident/correlation IDs; exact duplicate returns200 with duplicate=true. Same configured manager+agent+nativeID with any changed byte, even whitespace, returns409. Preserve original delivery bytes for retry; do not reserialize between attempts and expect identical provenance.

Wazuh Integrator itself may reserialize queue JSON before writing its alert file. Our SHA identifies **received integration-delivery bytes**, not guaranteed original alerts.json bytes. Identity includes the server manager namespace and exact agent/native IDs, so different managers/agents do not collide. Endpoint names/IDs/time are never substituted to force a match.

## Durable evidence and reports

A single SQLite transaction stores the common case, first accepted metric/audit, exact original Alert, sensitive delivery-provenance evidence, an explicit unavailable endpoint-state/lineage/effect gap and private raw source receipt. It creates no proposal, approval, execution or case-ready claim. A restart/exact duplicate preserves original ingestion time and all original proof. Missing/corrupt stored raw/evidence/receipt conflicts; it is not repaired from a new submission. Storage failure rolls back the whole native acceptance.

Raw source is retained privately in the case SQLite file under the existing indefinite local retention policy. Restrict DB/backups with filesystem permissions; they can contain credentials or sensitive commands supplied as untrusted telemetry. No raw source, actual endpoint evidence, upstream example or private source receipt belongs in Git. Default JSON/HTML reports use the existing redaction projection and never include raw receipt JSON. Safe labels complete_received_alert/wazuh-alert-json-v1 require exact current source/configuration/receipt/evidence agreement; otherwise unavailable.

An intake-only report says mode=live, simulated=false and verified_live=false. This describes the configured source mode, not proof of a live response. The available evidence establishes only the received source alert; process lineage, endpoint state, sessions and action effects remain unavailable. Collection APIs do not query a live endpoint in RF-07A. Health/readiness prove the local API/DB only.

## Remaining RF-07B / RF-08 work

The optional manager profile must derive from pinned upstream topology and independently reviewed image/resource/platform identities, replace stock example credentials, preserve TLS and restrict management to loopback/private lab scope. Do not start stock Compose, reuse Shuffle OpenSearch, change host sysctl/resources or open enrollment ports implicitly. Current Desktop allocation is not a qualified combined Shuffle/Wazuh capacity result.

The Windows-first bundle must pin official MSI/hash metadata, verify actual downloaded bytes and native signature/publisher before authorized installation, handle private enrollment material and document teardown. Published checksums are not proof of an installed/signed artifact. Windows/ARM, Sysmon compatibility and guest routing need their own observed evidence; no endpoint VM is currently supplied.

A custom sender must use fixed private operator destination/credential/CA configuration, bound regular-file handling and safe diagnostics. Do not adopt alert-provided URLs/commands or expose Wazuh api_key/hook_url arguments in logs. Deployment/retry qualification remains separate from receiver idempotency.

RF-08 requires explicit administrator authorization and a supplied isolated endpoint: real sensor alert→Wazuh→same case/Shuffle flow, approved harmless supported action, separate dispatch/ack/effect proof and recovery. Wazuh active response is not automatic full network isolation. No manager startup, installation, agent enrollment, live response, merge or release is authorized by this runbook.
