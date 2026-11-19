# RF-05A independent behavioral freeze

Origin: owner specification §7, issue#5, existing RF01/RF02 policy and RF03 source contracts; independent read-only requirements review at9de7907. This freeze precedes production implementation. RF05B real Shuffle acceptance remains separate.

| Case | Required observation |
| --- | --- |
| Recorded hidden encoded process with canonical PID/GUID | Scoped deterministic proposal, evidence refs, missing-parent/reputation gaps; never execute command_line |
| Benign, wrong endpoint/scenario, beyond±5minutes | No proposal based on unrelated evidence |
| Suspicious process missing PID/GUID or PID boundary invalid | Escalate, no fabricated process target |
| Persistence task/service with actor and recorded process association | Preserve source IDs; disable only if trusted capability supports it |
| Current mock disable_persistence unsupported | Explicit escalation, zero proposal/effect; no imaginary capability |
| Associated outbound suspicious process or shadow-copy-delete indicator | Replay host-isolation proposal; simulation and rollback guidance explicit |
| Missing network/process association | Gap/escalation; no invented linkage |
| Replay source bytes or stored normalized alert mismatch | Reject before collection/proposal/dispatch |
| Case/run/workflow/correlation/mode, configured graph/version/origin or principal mismatch | Reject before mutation; no approval privilege inherited by workflow |
| Caller injects action/provider/approved/target/command or unknown fields | Schema422, never execute/infer authority |
| Duplicate prepare and process restart | Same plan/proposal ID, original creation/expiry/source refs/readiness metric |
| Interrupted prepare after proposal | Reuse original immutable proposal; never refresh expiration |
| Missing human decision, denied/cancelled or expired approval | Await/deny/expire; no provider execute/effect, audit |
| Approval expires after gate but before dispatch | Existing core rejects on fresh server check |
| Unsupported versus failed capability lookup | Unsupported escalation differs from unavailable503; neither dispatches |
| Approved response | Core capability/approval revalidation and actual durable simulated verification; endpoint live remains false |
| Duplicate dispatch or retry after uncertain effect/restart | Same original execution; reconcile only; at most one effect |
| Corrupt/restored plan changes target/source/provider/run | Reject; never reuse unrelated action or current config silently |
| Review-ready metric | Available provenance, explicit gaps, proposal or no-action reason, audit, revision/environment/correlation |
| Offline unit/ASGI test success | No claim of real Shuffle graph execution or RF05 closure |
