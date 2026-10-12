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

## Current runtime and future boundaries

The [semantic foundation](semantic-foundation.md), [Canonical Observation
v2](canonical-observation-v2.md), and [Detection v2](detection-v2.md) describe
the active canonical scan/watch/embedding path. [Event4](event4.md) and
[telemetry/output architecture](telemetry-output-architecture.md) describe
accepted future boundaries: production Event4 persistence/output and
Telemetry/Output v2 are not implemented. The public
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

The inference and runtime acquisition document (`docs/inference-runtime-acquisition.md`)
covers an implemented experimental local normalizer and deferred production
integration for Issue #49. It is not shipped production behavior and does not
change the supported source denominator or Event3-only output.

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

The migration established one source/acquisition and Detection v2 path for
CLI scan/watch and supported embedding, including Rule v1 modifiers,
contributions, scoring, and process-chain semantics. Event 3.0 remains frozen;
Event4 production activation is deferred. Scanner-owned processing success
gates OpenCode cursor eligibility; parse success alone cannot advance it.

Acquisition is direct source-native extraction followed by source-owned canonical
mapping; it is not a conversion bridge. Production must not converge by creating
a bridge between Canonical Observation v2 and a flattened record type, in either
direction. Event3 and Event4 are
projections from accepted internal semantics, not conversion stages between the
old and new internal models.

## Pipeline

The opt-in [local session investigation backend](../crates/telltale/README.md#local-session-investigation-opt-in)
is separate from scan/watch, detection, Event3 production, and LocalEventFeed.
It correlates a consumed Event3 by exact client/path hash and terminal session
identity, reads current supported JSONL context,
and projects canonical observations directly into a content-free
`ExportedSessionTimeline`. It creates no persistent state and restores no legacy
source-record conversion. OpenCode investigation fails closed before discovery,
source I/O, or spawning: native export initializes/checkpoints/migrates the store
and cannot satisfy the no-mutation contract. Issue #42 remains incomplete pending
a genuinely read-only OpenCode capability; production OpenCode scanning is unchanged.
The four investigation outcomes retain their names; unavailable outcomes carry
closed, content-free reasons distinguishing provider deferral, observed read
failures, incomplete discovery, and exact correlation/session failures. Operator
actions and limits are documented with the embedding API; there is no retry state.

After discovery, the CLI selects new or changed sources using scanner state.
CLI scan/watch and `Pipeline::scan_root` then use the shared
`telltale_core::canonical_runtime::process_source` path:

```text
telltale_sources::acquisition -> Detection v2 evaluation/scoring -> Event3 projection/activity
```

The caller owns event policy, checkpoints, and delivery. The default sink appends
local JSONL; optional Splunk HEC and Elastic exports wrap the same canonical
payload. Rule v1 remains a content-compatibility view evaluated over canonical
observations; there is no record-level detection API. `observed_at` is explicit caller input. OpenCode-only bounded read
controls and high-water progress are operational metadata, not evidence; the
other seven identities return no progress. Copilot's local state is rebuilt per
acquisition and is not durable. The `compat.v1.url` view reads URL-keyed tool
arguments only, without URL/path/network manufacturing from other facts.

## Module Boundaries

Start at the boundary that owns the behavior, then read its callers and nearby
tests. These are code navigation links, not an additional public API promise;
[embedding](embedding.md) defines the supported host surface.

| Boundary | Code entry point | Responsibility |
| --- | --- | --- |
| CLI scan/watch | [src/cli/scan.rs](../src/cli/scan.rs), [scan modules](../src/cli/scan/) | Configuration, changed-source selection, watch lifecycle, and orchestration. |
| Embedding | [core facade](../crates/telltale/src/lib.rs), [canonical runtime](../crates/telltale/src/canonical_runtime.rs) | `Pipeline` returns values to hosts; shared source processing is an internal cross-crate seam, not an embedding API. |
| Sources | [acquisition](../crates/telltale-sources/src/acquisition.rs), [source modules](../crates/telltale-sources/src/sources/) | One exact-identity router to native extraction and canonical mapping. See [adding a source](adding-agent-source.md). |
| Content | [rules crate](../crates/telltale-rules/README.md) | Loads and validates Rule v1 content, evaluated by Detection v2 rather than a second engine. |
| Detection | [Detection v2](../crates/telltale-detect/src/v2/) | Canonical evaluation, findings, scoring, and Event3 compatibility projection. Record-level scoring APIs were removed. |
| Schema and privacy | [schema crate](../crates/telltale-schema/README.md), [event module](../crates/telltale-schema/src/event/) | Observation/event types, contribution types, redaction, hashes, validation, and serialization. |
| Delivery and checkpoints | [sinks](../src/sink/), [state](../src/state.rs) | CLI-owned delivery, persistence, and duplicate suppression; vendor envelopes do not change canonical payloads. |
| Tests | [CLI tests](../tests/cli/), [evaluation corpus](../tests/evaluation/README.md) | End-to-end behavior and synthetic characterization; crate-local tests cover semantic boundaries. |

Dependencies point from applications and consumers toward the reusable crates.
The core does not depend on the CLI, Console, or downstream integrations. Shared
semantics belong in their owning crate, not in parallel CLI and host implementations.

## Normalized Record Types

The record-level types and record evaluation were removed in 0.7.0. Canonical
Observation v2 is the only source evidence model; Rule v1 content is evaluated
over it. See the [migration guide](migrations/0.7.0.md).

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
