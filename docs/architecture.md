# Architecture

> **Website:** For an approachable architecture overview, see [AgentArchaeology.ai/telltale/architecture](https://agentarchaeology.ai/telltale/architecture/).

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
