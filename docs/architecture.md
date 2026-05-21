# Architecture

## Pipeline

ADR runs a repeatable batch pipeline:

1. **Discover**: enumerate known session stores for enabled clients.
2. **Ingest**: read new or changed files/databases using offsets, mtimes, or content fingerprints.
3. **Parse**: convert client-specific transcript formats into normalized conversation records.
4. **Context Window**: attach bounded preceding user/assistant messages to each tool call.
5. **Detect**: run static regex filters over tool names, command strings, arguments, paths, URLs, and adjacent messages.
6. **Score**: aggregate rule scores and modifiers into a risk result.
7. **Triage**: call Llama Guard and a small triage model only above configured thresholds.
8. **Emit**: send canonical events through an event sink. The default sink appends
   local JSONL for SIEM shippers; optional delivery paths wrap the same event
   payload for Splunk HEC or Elastic-compatible export.

## Module Boundaries

- `discovery`: knows where each agent stores sessions.
- `parsers`: client-specific transcript/database parsing.
- `normalizer`: creates common records with stable field names.
- `rules`: loads and evaluates regex rules.
- `scoring`: combines matches, context, and thresholds.
- `triage`: OpenAI-compatible client and prompts.
- `event`: redaction, schema-shaped event builders, evidence hashes, and local JSONL serialization.
- `sink`: vendor-neutral event delivery boundary. Sink-specific envelopes belong here, while the canonical event payload stays unchanged.
- `state`: scan checkpoints and duplicate suppression.

## Normalized Record Types

- `conversation.message`: user, assistant, system, developer, or tool-result content.
- `tool.call`: tool name plus normalized arguments and raw evidence hash.
- `tool.result`: exit status, stdout/stderr summary, file metadata, or error.
- `detection.event`: rule matches and score before optional triage.
- `triage.event`: LLM/guard decision with model metadata and redacted rationale.

## Triage Context Package

The triage agent receives:

- client, agent, model, provider, workspace, session id, and timestamps;
- matched tool call details;
- matched rule ids and explanations;
- preceding bounded user/assistant messages;
- redacted file paths, command lines, URLs, and tool results;
- prior related detections from the same scan window.

It does not receive full raw transcripts unless a future explicit mode enables that.
