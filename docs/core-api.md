# Local case API and durable recovery

RF-02 implements one authenticated FastAPI application with file-backed SQLite cases, immutable action proposals/approval decisions, append-only audit/metrics, callback correlation and conservative dispatch recovery. These are ResponseForge's internal normalized contracts, not a Wazuh, ECS/OCSF or Shuffle-native schema. Vendor adapters and actual vendor executions remain RF-04/07 gates. RF-03 supplies the [replay/evidence/mock/report path](replay.md); the ordinary server configuration still registers no provider by default.

## Local setup

Requires the locked Python environment (qualified with Python 3.12.12 and uv 0.13.6):

```bash
uv sync --locked
uv run --locked --offline python -m responseforge --init-config .local/config.json
uv run --locked --offline python -m responseforge --config .local/config.json
```

The first command may install dependencies from the network. The config generator writes a mode-0600 private file with separate random source, analyst, human approver, executor and workflow credentials. It never overwrites an existing file or prints tokens. `.local/` is ignored; keep it private and untracked. The example endpoint/resource are explicitly synthetic. No alert, case or provider effect is generated automatically. The server binds **127.0.0.1:8000**; `--port` changes only the local port. There is no host/exposure override. Access logging is disabled. Stop with Ctrl-C and restart using the same config/database path to preserve state. Delete local data only when intentionally resetting the lab; there is no automatic cleanup of case/action/nonce evidence.

Configuration is explicit: register canonical endpoint identities, source names, per-actor roles and endpoint/action/resource scopes, plus a server resource allowlist. There are no default credentials or providers. File configuration cannot enable live dispatch or dynamically import providers. Programmatic provider injection is for later trusted adapters and tests; live dispatch defaults disabled. Revoke/rotate credentials by editing the private configuration and restarting. Approval subjects must still have current human approver authority at dispatch, independently of the executor credential.

Public `/healthz` and `/readyz` describe the application only. All `/v1` calls require `Authorization: Bearer <private token>` and enforce a persistent 60-request UTC-minute window per actor. OpenAPI/Swagger/ReDoc HTTP endpoints are disabled. A secret-free internal API description is checked into [schemas/internal-api.json](../schemas/internal-api.json); export from your configuration without starting a server:

```bash
uv run --locked --offline python -m responseforge --config .local/config.json --export-openapi .local/openapi.json
```

## Case and response sequence

1. A source posts a normalized v1 Alert to `POST /v1/alerts`. Identical deliveries return the original case/correlation (201 new, 200 duplicate); changed data under the same scoped identity conflicts. Receipt metrics use server time while source timestamps are retained.
2. An analyst reads the case, transitions RECEIVED→TRIAGING→INVESTIGATING, adds scoped evidence and proposes an allowlisted action. A proposal is an immutable exact snapshot with a maximum one-hour TTL and stable idempotency key. New proposals move the case to AWAITING_APPROVAL.
3. A human approver posts only `expires_at` to `/v1/actions/{id}/approve`, `/reject` or `/cancel`. Identity and target/action scope come from server credentials and the stored proposal. The first decision is immutable: these endpoints record a first decision, not revocation of a prior approved decision. A conflicting decision needs a new scoped proposal; expired actions are never dispatched.
4. An executor posts the configured provider name to `/execute`. RF-02's default configuration has no provider, so it cannot produce an action effect. A trusted adapter must advertise the exact provider/version/mode/action and pass all approval/scope checks before a reservation is committed.
5. A reservation is durable before provider I/O. Duplicate delivery returns that original execution without another execute call. Unknown outcomes remain pending/uncertain and block redispatch, including after restart or expiry. `/reconcile` queries only the original execution via provider.verify; it never calls execute. A crash before provider execution also consumes the reservation conservatively. Operators must investigate unresolved reservations; RF-02 deliberately provides no force-resend endpoint.
6. Only separately verified isolation can produce CONTAINED. Other verified actions produce RESOLVED. Definitive failure produces FAILED; uncertain/timeout stays RESPONDING. A provider's dispatch success or execute-returned success flag alone is insufficient. CLOSED requires explicit analyst review of a final state.

Every response remains explicit about simulation and live verification. Controlled test adapters qualify the core contract only; real endpoint proof is required for any live claim. The system aims to prevent duplicate effects through durable delivery suppression and adapter idempotency; it makes no distributed exactly-once guarantee.

## Evidence, metrics and callbacks

Evidence must match case/mode/endpoint and preserve provenance or explicit unavailable reason. `/ready` accepts a review packet only when its available evidence, proposed action or no-action reason, and audit references resolve to the case. Known gaps are explicit. Acceptance and readiness metrics share stable alert/case/correlation/scenario/mode fields; these are measurement events, not measured analyst savings. See the [measurement plan](implementation-plan.md#measure-analyst-time-saved).

Analysts register a workflow run before a callback. The reserved `/v1/integrations/shuffle/callback` path authenticates the workflow actor, requires `X-Request-Timestamp` (aware ISO time within ±300 seconds) and `X-Request-Nonce` (nonempty, at most 128 characters), and checks case/run/workflow/correlation. Nonces are durable across restart. A callback records only the orchestration result; it cannot grant approval, dispatch an action or establish endpoint effect. RF-04 must qualify actual Shuffle transport compatibility.

## Storage and failure behavior

SQLite initializes empty files atomically at application schema version 1 and refuses foreign or future-version files. Short BEGIN IMMEDIATE transactions commit or fully roll back; provider calls occur outside them. Audit/metrics reject updates/deletes at repository and SQLite trigger boundaries. These protections do not defend against an administrator rewriting the database/schema; they are not cryptographically tamper-proof. Use a local filesystem and protect the private directory, database and backups. Test-backed concurrency covers independent connections/process restarts on the qualification host; no network-filesystem or high-volume guarantee is made.

Dedup keys are retained at least seven days (currently indefinitely), action tombstones for case lifetime, and callback nonces indefinitely. Retention/migration tooling beyond initial version 1 is future work. Structured errors avoid echoing supplied secrets, bodies or provider exception text. `make qualify` verifies offline behavior; the [RF-02 ledger](rf-02-ledger.md) records exact evidence and remaining gates.

RF-03 adds authenticated `/v1/incidents/{id}/collect` with full registered-source/case/window checks, and `/v1/incidents/{id}/report?format=json|html` with one consistent default-redacted case snapshot. Programmatic evidence configuration requires both an evidence provider and the trusted source snapshot; no live fallback is available. Ordinary server files do not automatically load replay state or providers.
