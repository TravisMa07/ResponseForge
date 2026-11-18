# RF-04B: callback transport and shared-daemon safety corrections

Refs [issue #4](https://github.com/TravisMa07/ResponseForge/issues/4). Base `2e1c95b3af3bb5820859ab31a3646eb54c465a6a` is the owner-authorized RF-04A #14 merge. Both final-head hosted checks passed, no reviews or unresolved threads; `make qualify` passes 562 tests and all tooling checks on the actual merged revision. Issue #4 remains open. This slice preserves both deployment targets and common product semantics; real Shuffle acceptance remains open.

## Source-driven scope

Inspected Orborus `adcc814cb355b7f4b6cb869e0d8d5eed3c6baa95` interprets `SHUFFLE_SWARM_CONFIG=run|swarm` as Swarm, calls SwarmInit, and unconditionally invokes broad container cleanup outside Swarm. Disabling CLEANUP does not disable zombiecheck. Therefore the existing pinned binary cannot yet satisfy preservation of unrelated Docker Desktop workloads. Correct candidate environment flags and keep an unavoidable shared-daemon cleanup blocker; no permission request or startup can solve this code boundary by itself.

The stock HTTP app logs headers; inspected SDK `abe5f4a14f876b68d2a82274dc033a99eca2f409` persists action parameters/results/logs. Implement an outbound callback sender with configuration supplied only by trusted Python/bootstrap, never by workflow parameters. This is reusable application code, not an installed Shuffle app: private credential provisioning into worker-created apps, safe SDK/runtime logs and genuine app execution remain open. No SDK dependency or new service is added.

## Frozen sender interface

One writer owns `src/responseforge/integrations/shuffle/callback.py`, containing:

- Frozen `CallbackConfig(base_url:str, api_key:str, workflow_ids:frozenset[str], timeout:float=5.0, max_response_bytes:int=65536, ca_file:str|Path|None=None, allow_loopback_http:bool=False)`. Same strict origin/UUID/key/timeout/size/TLS validation as ShuffleConfig, but a separate workflow-role credential and fixed core callback path. Origin/key/CA hidden in repr. No Org-Id or read retries.
- `CallbackReceipt(callback:WorkflowCallback, delivery:Literal['accepted','rejected','uncertain'])` immutable Contract. Contains no HTTP body, token, headers, nonce, errors or endpoint-effect claim.
- `CallbackTransport(config:CallbackConfig, *, transport:httpx.AsyncBaseTransport|None=None, clock:Callable[[],datetime]=UTC-now, nonce_factory:Callable[[],str]=cryptographic-random)` with async `send(item:WorkflowCallback)->CallbackReceipt`.
- Revalidate typed input (including model_copy bypass), require canonical nonnil UUID run/workflow IDs and allowlisted workflow before I/O. Reject malformed callback/status, non-UTC clock, invalid nonce (printable ASCII, nonempty, <=128), invalid CA through fixed safe ShuffleError(kind='invalid') without echo. The method accepts no URL/header/credential/verify option.
- One POST only to `/v1/integrations/shuffle/callback`, Bearer plus generated X-Request-Timestamp and X-Request-Nonce; exact JSON model body. TLS verified, optional trusted CA, no redirects/environment proxy inheritance. Entire attempt bounded by timeout, streamed bytes capped, compressed/duplicate-key/nonfinite/malformed JSON rejected.
- Require HTTP200 and a valid PlaybookRun whose run/incident/workflow/correlation/status exactly match and which has an ended_at. Only then accepted. 401/403/409/422 are rejected; all other HTTP statuses, I/O timeout/errors, malformed/mismatched/oversize/compressed results are uncertain. Never retry, including timeout or lost acknowledgement; never generate a second nonce automatically. Callers must reconcile with trusted core state before an explicit new delivery.
- No raw exception/body/header logging or return. These controls do not promise secret-free upstream SDK/worker logs. Callback acknowledgement proves stored correlated node outcome, not full vendor graph completion or endpoint effects. Existing coordinator polling/graph checks remain separate.

## Frozen deployment corrections

One writer owns only `deployment.py`. Set explicit empty SHUFFLE_SWARM_CONFIG (source default standalone), CLEANUP=false and SHUFFLE_CONTAINER_AUTO_CLEANUP=false; set SHUFFLE_SKIP_PIPELINES=true, SHUFFLE_PIPELINE_ENABLED=false and SHUFFLE_AGENT_MODE=false. Preserve existing immutable pins, no default socket/ports, required TLS/CA and always-blocked readiness. Add mandatory `shared-daemon-cleanup-unqualified` for docker-desktop even when target engine authority=true and lock gates are empty. This blocker does not declare the VM runtime qualified. Keep the valid SHUFFLE_OPENSEARCH_CERTIFICATE_FILE: pinned shared db-connector.go reads it; SHUFFLE_CERT_DIR is a different external-client CA path.

## Ownership, evidence and gates

Primary owns design/freeze, shared docs/CI/scripts/locks and qualification. Independent test writer owns only `tests/rf04b/**`; callback writer only callback.py; deployment writer only deployment.py. Freeze precedes substantive code. Tests derive from [independent cases](expectations/rf-04b.md), source and existing authenticated core. Handback must include changed files, revision/dirty scope, commands, actual results/failures and objections. No agent commits/pushes or starts a runtime. Independent read-only review follows integration.

No image pulls, containers, management listeners, socket mounts, Swarm/host setting changes, live enrollment/actions or release are authorized by this slice. A future safe execution image/app inventory, credential injection, CA/bootstrap, explicit scoped engine permission and actual runtime evidence remain required. Partial PR uses Refs #4.
