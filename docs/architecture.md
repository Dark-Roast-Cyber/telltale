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
are accepted architecture, with experimental Detection v2 and Event4 contract
foundations now implemented non-production. Event4 production persistence and
output are not implemented; neither is Telemetry/Output v2.

`observation_match`, bounded Tool-derived parent/child and standalone
`process_chain` evaluation, `DetectorResult` -> `Signal` -> atomic `Finding`, and
the Rule v1 compiler are implemented for Detection v2. The process-chain path
parses canonical Tool command evidence into private matcher working state; it
does not manufacture Canonical Process observations. The fixture-only offline
shadow harness is an offline measurement seam, not a scanner or activation path.
Process-chain repeat suppression and entity correlation remain on the legacy
production path; advanced detector runtime and a Detection Content v2 loader
are not implemented.

Canonical Observation v2 core types/scaffolding are implemented in
`telltale-schema`. Non-production reference projections exist for Claude Code
(`claude.projects`), the principal Codex session identities, OpenCode
(`opencode.sqlite`), OpenClaw (`openclaw.agents`), Qwen (`qwen.projects`), and
Copilot (`copilot.process_log`). Offline deterministic shadow coverage includes
Copilot across 15 cases, 17 reviewed sessions, and 306 detector evaluations,
with one reviewed match-set difference plus 28 reviewed capability-driven
indeterminate outcomes and zero unexplained differences. Copilot native-v2
capabilities are ToolCall **Supported**, UserContext **Unsupported**, and
ToolExecution **Unknown**.

Production adapter migration/cutover has not started. Event 3.0 remains the
frozen current compatibility contract. The pipeline below continues to describe
the shipped implementation until the coordinated production cutover occurs.
Event4 remains inactive. Direct runtime telemetry, including any future
OpenShell source that reports Process, Network, Runtime, policy, enforcement, or
action-result evidence, remains separate from command-derived Tool
interpretation; no OpenShell integration exists today.

## 0.7 convergence boundary

The 0.7 production migration is intentionally scoped to the source families that
matter for the long-lived baseline:

| Agent family | Required 0.7 source identity |
| --- | --- |
| Claude Code | `claude.projects` |
| Codex | `codex.sessions`, `codex.archived_sessions`, `codex.headless_sessions` |
| OpenCode | `opencode.sqlite` |
| OpenClaw | `openclaw.agents` |
| Qwen | `qwen.projects` |
| GitHub Copilot | `copilot.process_log` |

Claude and Codex desktop-app-specific acquisition is deferred when it needs a
separate source contract.

`gemini.tmp`, `opencode.legacy_json`, `opencode.project_json`, `roocode.tasks`,
`kilocode.tasks`, and `codex.project_sessions` are retired. They are not hidden
production paths, parser registrations, or migration candidates.

The production migration order is:

1. contract the supported production denominator to the target set;
2. move Rule v1 compiled evaluation, modifiers, contributions, and scoring onto
   the Detection v2 runtime while retaining Rule v1 as a content format;
3. move shipped process-chain matching and correlation onto the Detection v2
   result path without converting parsed command text into directly observed
   Process evidence;
4. make target source adapters produce Canonical Observation v2 directly, plus
   only the acquisition/checkpoint metadata required by scan/watch operation;
5. cut scan, watch, and the supported embedding facade over to Canonical
   Observation v2 -> Detection v2 as one coordinated production boundary;
6. delete the legacy NormalizedRecord-centered detector path, duplicate
   scoring/grouping code, shadow/equivalence migration machinery, and stale
   migration-only tests and documentation;
7. decide the remaining Event4 and telemetry activation gates after the internal
   semantic/detection path is singular.

Production must not converge by creating a permanent
`CanonicalObservationV2 -> NormalizedRecord` bridge or a permanent
`NormalizedRecord -> CanonicalObservationV2` bridge. Event3 and Event4 are
projections from accepted internal semantics, not conversion stages between the
old and new internal models.

## Pipeline

Telltale currently runs a repeatable batch pipeline:

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
path and Canonical Observation v2 cutover has not started. The target Claude
Code, Codex, OpenCode SQLite, OpenClaw, Qwen, and Copilot v2 reference projections
are implemented but are not wired into production normalization, detection, CLI,
or scan execution. The experimental Detection v2 foundation and fixture-only
offline harness are likewise not wired into the scanner; production detection
remains the existing Rule v1 path. Its `compat.v1.url` view remains truthfully
absent without URL/path/network manufacturing; focused synthetic harness
coverage demonstrates the compatibility gap.

## Module Boundaries

- `discovery`: knows where each agent stores sessions.
- `parser`: client-specific transcript/database parsing. See
  [Adding an Agent Source](adding-agent-source.md) for the current checklist and
  exact parser-registration architecture.
- `normalizer`: creates common records with stable field names in the current
  production path; Canonical Observation v2 replaces this architectural center
  at the production cutover.
- `rules`: loads and validates detection content; Rule v1 remains a content
  compatibility format during Detection v2 convergence.
- `scoring`: combines matches, context, and thresholds in the current production
  path; duplicate legacy scoring ownership is removed after Detection v2 cutover.
- `event`: redaction, schema-shaped event builders, evidence hashes, and local JSONL serialization.
- `sink`: vendor-neutral event delivery boundary. Sink-specific envelopes belong here, while the canonical event payload stays unchanged.
- `state`: scan checkpoints and duplicate suppression.

## Normalized Record Types

The current production compatibility model includes:

- `conversation.message`: user, assistant, system, developer, or tool-result content.
- `tool.call`: tool name plus normalized arguments and raw evidence hash.
- `tool.result`: exit status, stdout/stderr summary, file metadata, or error.
- `detection.event`: rule matches, deterministic score, timeline anchors, and response metadata.

These are current-path concepts, not the intended 0.7 semantic center. Canonical
Observation v2 is the accepted internal evidence model for the converged path.

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
