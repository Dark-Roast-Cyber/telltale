# Detection from hooks and native session stores

**Proposed developer contract.** An organization can use live hooks, local session files and databases, or both. A rule has one definition and runs wherever the observations supply the evidence it requires. Enabling live evaluation preserves the rule's existing scan and replay behavior.

Today hooks evaluate a pending call by scanning a bounded, hook-built journal window through the embedding facade. The tested Claude Code transcript can omit the pending call at decision time. Hook journals already have distinct source identities and are host-fed. The in-memory input and retention choices below are proposals. See [ADR 0002](hooks/adr/0002-pending-action-evaluation.md), [hook architecture](hooks/architecture.md), and the [embedding contract](embedding.md).

## Ownership

| Owner | Proposed responsibility |
| --- | --- |
| Hook adapter and runtime | Capture the request, prompt, result or settlement the harness actually reports. Supply a bounded window to core, apply host policy, and return any enforcement decision within the hook deadline. Publish eligible findings asynchronously, including in observe mode. |
| Native session collector | Own source discovery, parsing, cursors, incremental reads and reconciliation. Support retrospective scans when hooks were absent. A lifecycle hint can wake the collector. The collector validates the source inside configured stores, coalesces hints, and advances its own cursor after successful processing. |
| Detection core | Evaluate canonical observations with the existing rule definitions, scoring and finding semantics. Preserve provenance, action stage, occurrence identity and evidence quality across ingestion paths. Keep hook policy decisions outside rule matching. |
| Forensic acquisition | Place opt-in preservation and replay workflows in the forensics tooling. Reuse native readers for interpretation. Preserve available source-native content, including material the detection projection omits, when the operator requests full capture. Record acquisition time, integrity digest and known gaps. |

## When a detection belongs on the hook path

Start with an existing rule and list the facts it consumes, the stage at which those facts become available, and the history it needs. Qualify live coverage per harness. A request containing a matching command may support a finding before execution. A rule requiring a result must wait for a reported result. The OpenCode request-only pilot can support the first case and leaves the second unresolved. A multi-step rule can run live when both steps fit the retained window. Session acquisition can still find the chain later if both steps survive in the store.

Adapters translate harness-specific facts once. Give the existing evaluation pipeline a bounded host-supplied input so the live path can avoid writing and reopening a scratch transcript. Preserve the same acquisition limits, quarantine handling and per-harness tool semantics. For equivalent facts, expect equivalent rule IDs, anchors and scores. Different evidence can legitimately yield different findings.

Admit a rule to live evaluation after measuring representative short and full windows, concurrent sessions, hook latency, peak memory and disk I/O against the journal baseline. If the required history or latency is too expensive, keep file-based coverage and document the live limit. Keep one rule ID across both paths.

## Deployment and retention

Choose inputs independently of what Telltale persists. Session-only deployments can detect and replay surviving activity with hooks disabled. Hook-only deployments can emit findings with native reads disabled. Combined deployments can fill gaps and attach further evidence.

| Retention choice | Behavior |
| --- | --- |
| Alerts only | Keep transient context bounded by bytes, age and active sessions. Persist redacted findings and only the evidence explicitly selected for a match. A memory-only configuration covers fallback and error paths too. Surface context loss after eviction or evaluator restart. |
| Full available transcript | Acquire incrementally during the session, including supported child sessions. Preserve hook-only attempts separately. Apply explicit access and expiry policies to raw material and keep ordinary alert exports redacted. |
| Retrospective acquisition | Read surviving native stores on demand. Record the acquisition boundary and any observed truncation, rotation, rewrite or deletion. Lossless compression can preserve captured bytes. An acquired summary cannot restore discarded turns. |

## Evidence and acceptance

Keep a matched rule, the host verdict, the decision actually returned and the harness-reported outcome independently observable. A deny verdict in observe mode can coexist with a completed call. A missing outcome stays unknown. When both inputs describe one call, link observations using scoped, stable occurrence identifiers where available. Keep both provenance records. Repeated identical inputs or nearby timestamps alone cannot establish identity.

1. Run one synthetic action and one multi-call chain through hooks and native replay independently. Assert semantic parity for equivalent facts and explicit coverage differences for missing results or history.
2. In combined mode, deliver the same observations twice, then run two distinct calls with identical inputs. Verify retry-safe alert counting and preservation of both genuine occurrences.
3. Exercise memory-only operation across capacity eviction, restart, evaluator failure and sink outage. Check for raw-content files, visible context or delivery loss, and bounded hook latency.
4. Exercise targeted collection after a missed stop signal, a late file append and an in-place database update. Verify periodic reconciliation and cursor behavior before claiming coverage. See [OpenCode ingestion limits](opencode-live-ingestion.md).
5. Replay a preserved source after the original disappears. Verify its digest and identify any missing turns or child sessions.

Implement direct hook finding delivery first, then qualify in-memory evaluation against the current journal path. Add targeted native collection and continuous forensic preservation as independently selectable capabilities.
