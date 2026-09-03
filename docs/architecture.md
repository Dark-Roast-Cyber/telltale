# Architecture

> **Website:** For an approachable architecture overview, see [AgentArchaeology.ai/telltale/architecture](https://agentarchaeology.ai/telltale/architecture/).

The authoritative development principles live in
[development-principles.md](development-principles.md).

### Conceptual flow

```text
Observation -> Normalization -> Detection -> Signals -> Policy -> Decision -> Action -> Audit/Telemetry
```

These responsibilities stay distinct. Today, session-store scanning is the
shipped observation adapter; signals, policy, decision, and action are the
conceptual core stages defined in the principles. Until a policy/decision
runtime is separately implemented, current decisions remain the deterministic
response metadata carried by emitted Event 3.0 events.

## Accepted future architecture

The accepted future semantic contracts are documented in the [semantic
foundation](semantic-foundation.md), [Event4](event4.md), [Canonical Observation
v2](canonical-observation-v2.md), [Detection v2](detection-v2.md), and
[telemetry/output architecture](telemetry-output-architecture.md) pages. They
are accepted architecture, not current implementation. Event4, Detection v2,
and Telemetry/Output v2 are not implemented. Canonical Observation v2 core
types/scaffolding are implemented in `telltale-schema`; the Claude Code
(`claude.projects`) and Codex v2 reference projections are implemented, while
production adapter migration/cutover has not started.
Event 3.0 remains the frozen current compatibility contract. The pipeline below
continues to describe the shipped implementation.

## Pipeline

Telltale runs a repeatable batch pipeline:

1. **Discover**: enumerate known session stores for enabled clients.
2. **Ingest**: read new or changed files/databases using offsets, mtimes, or content fingerprints.
3. **Parse**: convert client-specific transcript formats into normalized conversation records.
4. **Context Window**: attach bounded preceding user/assistant messages to each tool call.
5. **Detect**: run static regex filters over tool names, command strings, arguments, paths, URLs, and adjacent messages.
6. **Score**: aggregate rule scores and modifiers into a risk result.
7. **Review metadata**: preserve deterministic response guidance and top-level
   timeline anchors for downstream analyst review when thresholds are crossed.
8. **Emit**: send canonical events through an event sink. The default sink appends
   local JSONL for SIEM shippers; optional delivery paths wrap the same event
   payload for Splunk HEC or Elastic-compatible export.

The current scanner still uses `NormalizedRecordV1`; production remains on this
path and Canonical Observation v2 cutover has not started. The Claude Code and
Codex v2 reference projections are implemented but are not wired into parsing,
detection, CLI, or scan execution.

## Module Boundaries

- `discovery`: knows where each agent stores sessions.
- `parser`: client-specific transcript/database parsing. See
  [Adding an Agent Source](adding-agent-source.md) for the current checklist and
  [Source Adapter Refactor Plan](source-adapter-refactor-plan.md) for the
  recommended adapter-module refactor path.
- `normalizer`: creates common records with stable field names.
- `rules`: loads and evaluates regex rules.
- `scoring`: combines matches, context, and thresholds.
- `event`: redaction, schema-shaped event builders, evidence hashes, and local JSONL serialization.
- `sink`: vendor-neutral event delivery boundary. Sink-specific envelopes belong here, while the canonical event payload stays unchanged.
- `state`: scan checkpoints and duplicate suppression.

## Normalized Record Types

- `conversation.message`: user, assistant, system, developer, or tool-result content.
- `tool.call`: tool name plus normalized arguments and raw evidence hash.
- `tool.result`: exit status, stdout/stderr summary, file metadata, or error.
- `detection.event`: rule matches, deterministic score, timeline anchors, and response metadata.

## Analyst Review Context

Detection events retain bounded context for downstream analyst review:

- client, agent, model, provider, session id, and timestamps;
- matched tool call details;
- matched rule ids and explanations;
- redacted file paths, command lines, URLs, and tool results;
- timeline anchors and prior related detections from the same scan window.

No outbound model or guard request is made by the scanner. Native Event 3.0
contains no embedded triage fields or historical product-version marker;
historical Event 1.0 and 2.0 imports retain their original review fields when
read.
