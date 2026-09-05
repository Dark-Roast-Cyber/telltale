# copilot-process-log-canonical-observation-v2-adapter Specification

## Purpose
Define the bounded, non-production Canonical Observation v2 interpretation of
the GitHub Copilot process log while preserving the existing legacy parser and
keeping Event 3.0 and production NormalizedRecordV1 unchanged.
## Requirements
### Requirement: Stateful source-owned interpretation

The Copilot process-log adapter MUST read the source into one source-owned
native event interpretation for each projection invocation. The native stream
MUST distinguish workspace initialization, accumulated output items, session
completion, and malformed structured output. Plain operational lines MUST NOT
become canonical observations. Control phrases MUST be recognized only in the
trusted Copilot log prefix/control position before an accumulated structured
payload; phrases in assistant content, tool arguments, direct tool messages or
results, embedded JSON, heartbeat/object values, and arbitrary operational text
MUST NOT change either session state. Here, "trusted" means the top-level
source-record/control position only; it MUST NOT be treated as authentication of
the leading timestamp token, which remains metadata and may be opaque or
invalid. A legitimate control and accumulated-output payload on one line MUST
remain supported. Native types MUST remain crate-private, MUST NOT retain
structured payload text in workspace events, and MUST NOT retain
`encrypted_content`.

#### Scenario: Legacy and canonical share native facts

- **WHEN** the legacy or canonical Copilot projection processes a valid log
- **THEN** it consumes the native interpretation and does not reconstruct
  canonical observations from flattened `ParsedRecord` values

#### Scenario: Non-object output fails native extraction

- **WHEN** a successfully parsed accumulated-output array contains a non-object
- **THEN** native extraction fails with the existing bounded SchemaDrift error
  and no partial projection is returned

#### Scenario: Control phrases require the trusted log position

- **WHEN** either control phrase appears in an accumulated item, assistant
  content, tool arguments or results, embedded JSON, heartbeat/object value, or
  arbitrary plain operational text
- **THEN** native extraction does not create, replace, or clear legacy or
  canonical session state, while a legitimate control followed by accumulated
  output remains consumable

#### Scenario: Workspace events stop at structured payload

- **WHEN** a legitimate workspace control shares a line with an accumulated
  payload containing reasoning or `encrypted_content`
- **THEN** the workspace event retains only the trusted control prefix and no
  structured payload or sensitive suffix

### Requirement: Dual session state and ordinals

The adapter MUST maintain separate legacy effective and canonical active session
state. Legacy state MUST start at the filename stem or `unknown`, update on
workspace initialization, and remain set after session completion. Canonical
state MUST start absent, use only the source-reported workspace ID, and clear on
session completion. Every accumulated-output item MUST consume the next
zero-based ordinal for its source-reported session, including ignored variants;
reactivation MUST continue the existing ordinal.

#### Scenario: Completion clears only canonical context

- **WHEN** a session completes and an accumulated-output item occurs before the
  next workspace initialization
- **THEN** the legacy projection retains its effective session while canonical
  projection fails closed as replay unverifiable

#### Scenario: Repeated activation continues sequence

- **WHEN** the same source-reported session is initialized, completed, and
  initialized again in one log
- **THEN** its later accumulated-output item receives the next ordinal rather
  than ordinal zero

### Requirement: Legacy compatibility projection

The legacy projection MUST preserve current Copilot behavior: workspace lines
produce SessionMeta, function calls produce ToolCall with missing names as
`unknown`, direct string messages additionally produce ToolResult, reasoning
and message items are omitted, explicit unknown types produce the bounded Other
content, malformed arrays are ignored, and missing types are ignored. It MUST
NOT expose assistant message text that the current parser omits. It MUST NOT
map `status: completed` to execution or success.

#### Scenario: Malformed structured output remains legacy-readable

- **WHEN** a recognized accumulated-output array is invalid, truncated, or not
  an array and workspace metadata exists
- **THEN** legacy projection ignores the structured output and returns the same
  workspace record as before

### Requirement: Exact canonical identity and provenance

The canonical projector MUST accept only ClientId Copilot, source ID
`copilot.process_log`, and SourceKind CopilotProcessLog. It MUST use
SessionStore, PartialStructured, adapter type `copilot`, and adapter ID
`copilot.process_log`. A source-reported active session and its per-session
ordinal MUST be the identity-scoped source sequence. It MUST NOT use filename,
path, PID, item ID, call ID, content, arguments, time, or random identity
fallbacks. Caller-provided `observed_at` MUST be retained; no wall clock may be
consulted. Valid leading RFC3339 tokens MAY populate occurred_at, while invalid
or missing tokens MUST be absent.

#### Scenario: Stable identity is content-independent

- **WHEN** two Copilot facts have the same source-reported session, ordinal,
  family, stage, and child ordinal but different semantic content or artifact
  path
- **THEN** their observation IDs are equal

#### Scenario: Item IDs do not collide across sessions

- **WHEN** two sessions report the same native item ID at the same ordinal
- **THEN** their observation IDs differ because identity uses the session-scoped
  ordinal rather than the native item ID

### Requirement: Canonical tool and message mapping

An explicit `function_call` with a meaningful name or raw arguments MUST emit
one ToolRequested observation. A missing name MAY be omitted when another
meaningful tool fact exists; a function call with no meaningful facts MUST fail
closed. A non-empty function-call message MUST emit one ToolResultReturned
child, but status alone MUST NOT emit a result. Source call IDs MUST be
optional source-reported `correlations.call_id` values, never fabricated.
Valid JSON argument strings MUST become bounded parsed `tool.arguments` with
Parsed metadata and retain the original string as reported
`tool.searchable_arguments`. Invalid JSON MUST retain the same source string in
both fields with Reported metadata. Only explicit top-level command/cmd and
path/file_path object keys MAY create parsed command/resource facets.

`type: message` with role assistant MUST emit MessageObserved with ordered
`output_text` content parts. User messages MUST NOT be fabricated. Unknown
roles, unsupported content-block types, and unknown explicit output item types
MUST fail closed without copying their payloads. Reasoning items MUST consume
their ordinal and emit nothing. No Process, File, Network, Inference, Session,
ToolProposed, ToolExecutionStarted, ToolExecutionCompleted, or ToolStatus fact
MAY be projected by this adapter.

#### Scenario: Tool request and direct result are separate children

- **WHEN** a function_call has a name, arguments, call ID, and non-empty direct
  message
- **THEN** the adapter emits ToolRequested child zero and ToolResultReturned
  child one with the same session and item ordinal

#### Scenario: Completed status is not a result

- **WHEN** a function_call reports `status: completed` but has no non-empty
  message
- **THEN** only ToolRequested is emitted and no execution or result observation
  is created

#### Scenario: Assistant output is structured

- **WHEN** a message item reports role assistant and ordered output_text parts
- **THEN** one assistant MessageObserved preserves those parts and legacy
  projection contains none of that assistant text

#### Scenario: Unsupported structured output fails closed

- **WHEN** canonical projection encounters an unknown explicit output item type,
  an unknown message content-block type, or an accumulated item without an
  active source-reported session
- **THEN** it returns a bounded privacy-safe mapping failure and exposes no raw
  payload, source ID, call ID, argument, assistant text, path, URL, or encrypted
  reasoning

### Requirement: Explicit capability context

Every Copilot canonical observation MUST report ToolCall Supported, UserContext
Unsupported, and ToolExecution Unknown. These capabilities MUST remain
independent of fact provenance and fidelity.

#### Scenario: Copilot capability gaps remain visible

- **WHEN** a Copilot tool or assistant observation is projected
- **THEN** its capability context resolves UserContext to Unsupported and
  ToolExecution to Unknown rather than treating either gap as a clean absence

### Requirement: Exact non-production facade route

The source facade MUST route exactly `(ClientId::Copilot,
"copilot.process_log")` to the Copilot projector and MUST preserve the caller's
observed time. Wrong client, source ID case, or source ID MUST be rejected
before source I/O. The Copilot projector itself MUST reject a wrong source kind
before source I/O. No other new identity MAY be routed.

#### Scenario: Exact Copilot route preserves observed time

- **WHEN** the exact Copilot identity and source kind are projected with a fixed
  observed time
- **THEN** the native Copilot projector is used and every observation retains
  that observed time

#### Scenario: Wrong identity is rejected without reading the path

- **WHEN** a wrong-case or wrong-client Copilot-looking source points at a
  missing path
- **THEN** the facade returns unsupported_source_identity without exposing or
  reading the path

### Requirement: Offline shadow expansion remains private and deterministic

The fixture-only shadow harness MUST add only the mixed-format, multi-session,
and uc001 existing Copilot fixtures. It MUST group canonical observations only
by source-reported session, review every non-equivalent relation with the exact
existing mismatch vocabulary, retain multiplicity, and add no broad waiver.
Reports MUST remain deterministic and MUST contain no raw Copilot session IDs,
call IDs, assistant text, encrypted content, paths, URLs, process filenames,
arguments, results, or source paths. The v1 baseline report MUST remain
unchanged.

#### Scenario: Copilot capability differences are evidence

- **WHEN** Copilot observations are evaluated by the existing shadow detector
- **THEN** required UserContext unsupported and ToolExecution unknown outcomes
  remain visible as bounded non-evaluation evidence rather than being hidden by
  changing adapter capabilities

#### Scenario: Repeated shadow generation is byte-identical

- **WHEN** the same Copilot fixture set is shadowed twice
- **THEN** the report bytes and reviewed mismatch multiset are identical

