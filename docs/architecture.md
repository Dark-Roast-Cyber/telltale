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
are accepted architecture, with the Detection v2 runtime now authoritative for
the canonical scan/watch/embedding path. Event4 production persistence and
output are not implemented; neither is Telemetry/Output v2. The public
`telltale_sources::acquisition` module owns authoritative cross-source
Canonical Observation v2 acquisition for all eight target identities. It is the
single router: source-native extraction flows into source-owned canonical
mapping and then an acquisition batch consumed by the shared runtime.

`observation_match`, bounded Tool-derived parent/child and standalone
`process_chain` evaluation, `DetectorResult` -> `Signal` -> atomic `Finding`, and
the Rule v1 compiler are implemented for Detection v2. The process-chain
session evaluator parses canonical Tool command evidence into
private matcher working state and delegates to one pure repeat/correlation semantic
kernel before Event3 compatibility projection; it does not manufacture Canonical Process
observations. Advanced detector runtime and a
Detection Content v2 loader are not implemented.

Canonical Observation v2 core types are implemented in `telltale-schema`.
Source-native production projections exist for Claude Code
(`claude.projects`), the principal Codex session identities, OpenCode
(`opencode.sqlite`), OpenClaw (`openclaw.agents`), Qwen (`qwen.projects`), and
Copilot (`copilot.process_log`). Copilot native-v2
capabilities are ToolCall **Supported**, UserContext **Unsupported**, and
ToolExecution **Unknown**.

Production adapter acquisition convergence now covers all eight identities at the
public `telltale_sources::acquisition` boundary, satisfying and completing
ROADMAP step 4. Source mappers remain crate-private; acquisition is the single
cross-source router and there is no parallel canonical facade. Event 3.0 remains
the frozen current compatibility contract. The pipeline below describes the
activated canonical runtime.
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
production paths or migration candidates. OpenCode retains only `opencode.sqlite`.

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
6. retire the remaining legacy NormalizedRecord-centered detector path and
   duplicate scoring/grouping code while retaining deliberate record-level
   compatibility APIs;
7. select Event3-only production output for 0.7 and defer Event4 production
   activation after the internal semantic/detection path is singular.

Steps 1 through 6 established the singular source/acquisition and Detection v2
path. Step 7's output decision is Event3-only for 0.7; the remaining Issue #55
cleanup and validation are not yet complete. Scanner-owned processing
success gates OpenCode cursor eligibility; parse success alone cannot advance that
cursor. CLI scan/watch and supported embedding use Canonical Observation v2 ->
Detection v2 -> Event3 compatibility/activity. Event 3.0 is frozen and Event4 is
inactive.

Acquisition is direct source-native extraction followed by source-owned canonical
mapping; it is not a conversion bridge. Production must not converge by creating
a permanent `CanonicalObservationV2 -> NormalizedRecord` bridge or a permanent
`NormalizedRecord -> CanonicalObservationV2` bridge. Event3 and Event4 are
projections from accepted internal semantics, not conversion stages between the
old and new internal models.

## Pipeline

Telltale currently runs a repeatable batch pipeline:

1. **Discover**: enumerate known session stores for enabled clients.
2. **Ingest**: read new or changed files/databases using offsets, mtimes, or content fingerprints.
3. **Acquire**: map source-native facts directly to Canonical Observation v2 plus separate accounting/progress metadata.
4. **Evaluate**: apply the Detection v2 Rule v1 compatibility plan and bounded process-chain semantics.
5. **Project**: build Event 3.0 compatibility detections and canonical activity without converting through legacy records.
6. **Score**: aggregate rule scores and modifiers into a risk result.
7. **Review metadata**: preserve deterministic response guidance and top-level
   timeline anchors for downstream analyst review when thresholds are crossed.
8. **Emit**: send canonical events through an event sink. The default sink appends
   local JSONL for SIEM shippers; optional delivery paths wrap the same event
   payload for Splunk HEC or Elastic-compatible export.

The canonical runtime acquires source-native facts, evaluates Canonical
Observation v2 with Detection v2, and projects Event 3 activity/detections. Rule
v1 remains a content-compatibility view. `NormalizedRecordV1` and
`NormalizedRecord` remain supported for record-level compatibility APIs such as
`detect_records` and `evaluate_session`; they are not the scanner's detection
handoff. `observed_at` is explicit caller input. OpenCode-only bounded read
controls and high-water progress are operational metadata, not evidence; the
other seven identities return no progress. Copilot's local state is rebuilt per
acquisition and is not durable. The `compat.v1.url` view remains truthfully
absent without URL/path/network manufacturing; focused synthetic harness
coverage demonstrates the compatibility gap.

## Module Boundaries

- `discovery`: knows where each agent stores sessions.
- `sources`: per-agent native extraction and canonical mapping. See
  [Adding an Agent Source](adding-agent-source.md) for the current checklist.
  There is no parser registration table and no source-backed record projection.
- `acquisition`: the public `telltale_sources::acquisition` single router for
  source-native extraction, source-owned canonical mapping, and acquisition
  batches across the supported identities. Its source mappers are crate-private.
- `normalizer`: retains `NormalizedRecord` compatibility APIs; canonical
  acquisition is the production semantic center.
- `rules`: loads and validates detection content; Rule v1 remains a content
  compatibility format during Detection v2 convergence.
- `scoring`: legacy record-level compatibility scoring remains available while
  canonical runtime scoring is owned by Detection v2.
- `event`: redaction, schema-shaped event builders, evidence hashes, and local JSONL serialization.
- `sink`: vendor-neutral event delivery boundary. Sink-specific envelopes belong here, while the canonical event payload stays unchanged.
- `state`: scan checkpoints and duplicate suppression.

## Normalized Record Types

The record-level compatibility model includes:

- `conversation.message`: user, assistant, system, developer, or tool-result content.
- `tool.call`: tool name plus normalized arguments and raw evidence hash.
- `tool.result`: exit status, stdout/stderr summary, file metadata, or error.
- `detection.event`: rule matches, deterministic score, timeline anchors, and response metadata.

These remain available to explicit record-level callers, not to the production
source runtime. Canonical Observation v2 is the active source evidence model.

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
