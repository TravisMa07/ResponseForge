# RF-04B independent behavioral expectations

Frozen before code, derived from existing core callback policy, owner workload-preservation requirement, inspected Shuffle/SDK source and RF-04A TLS/transport limits. [Design and interfaces](../rf-04b-design.md). No expected result is generated from the implementation.

| Case | Independent expected result and rationale |
| --- | --- |
| Valid registered run and workflow-role credential | One fixed-path POST with exact typed body, fresh UTC timestamp and random nonce; accepted receipt only after exact terminal PlaybookRun echo |
| Wrong credential/role/scope or forged correlation | Actual in-process core rejects; sender returns rejected, no case/effect change |
| Duplicate nonce, expired timestamp, conflicting terminal outcome | Durable core enforcement returns rejected, including after core restart; legitimate new delivery does not waive correlation |
| Invalid/bypassed model, UUID, allowlist, nonce or clock | Fixed safe invalid error and zero network calls; caller cannot choose arbitrary destination or secret |
| Non-HTTPS/private arbitrary HTTP origin, credentials/query/path URL | Rejected configuration; only explicitly opted-in literal-loopback HTTP; same behavior on either deployment target |
| Normal/timeout/network/5xx/redirect/unknown status | At most one HTTP request per send, no blind retry; 401/403/409/422 rejected, every other non200 uncertain |
| Malformed/duplicate-key/nonfinite/oversize/compressed response, wrong identity/status or missing terminal timestamp | Uncertain; never accepted from a bare success flag, no raw body/secret output |
| Slow streaming | Total deadline enforced even when individual chunks arrive; exact cap accepted, cap+1 rejected |
| Configuration/results/errors/captured output | No synthetic callback key/raw response secret, sensitive origin/CA in repr, or arbitrary command/body logging |
| TLS and proxy behavior | verify true or trusted CA, follow_redirects false, trust_env false; no incoming workflow setting changes these |
| Both targets, both authority flags | Empty standalone flag, both cleanup flags false, both pipeline opt-out flags and agent mode false; default no sockets/exposure persists |
| Docker Desktop authority granted or gates omitted | Mandatory shared-daemon-cleanup-unqualified remains; ready=false; permission does not repair unconditional vendor cleanup |
| Dedicated VM | Same callback/core logic and safe plan defaults; its own technical/runtime gates remain; no automatic qualification |

Tests must exercise the production sender against the actual in-process authenticated core and use streamed fault responses for wire failures. These tests qualify application behavior only, never real Shuffle execution, installed app compatibility or endpoint effects. Record meaningful red before green; harness/import failures do not count.
