# codex-canonical-observation-v2-adapter Specification

## Purpose
This specification covers the Codex adapter path. The authoritative public
acquisition API reuses its native interpretation and Canonical Observation v2
mapping for production source evaluation. Source-backed legacy record projection
is retired; Event 3.0 remains the external projection.
## Truthful messages preserve order evidence

Public role evidence at commit `47379efd5289cba801c5a66273064fbe3bf92f60`
includes developer instruction construction in
`codex-rs/core/src/context/developer_instructions.rs`, response-item persistence
in `codex-rs/core/src/session/mod.rs` and `codex-rs/rollout/src/policy.rs`, and
the serialized system-role resumed-history fixture in
`codex-rs/core/tests/suite/client.rs`.

## Truthful messages preserve order evidence

The fixture establishes a public shape,
not production generation of system messages on every turn.

## Closed auxiliary envelopes produce no canonical observations evidence

This bounded compatibility evidence is public `openai/codex` commit
`47379efd5289cba801c5a66273064fbe3bf92f60`, specifically
`codex-rs/protocol/src/protocol.rs` (EventMsg and TurnContextItem),
`codex-rs/protocol/src/models.rs` (ResponseItem::Reasoning),
`codex-rs/protocol/src/items.rs` (distinct typed TurnItems), and
`codex-rs/rollout/src/policy.rs` (persistence selection).

## Closed auxiliary envelopes produce no canonical observations evidence

Pinned world-state evidence is public commit
`47379efd5289cba801c5a66273064fbe3bf92f60`,
`codex-rs/protocol/src/protocol.rs:3272-3287`,
`codex-rs/history/src/rollout_payload.rs:30-58`, and
`codex-rs/core/src/session/mod.rs:3592-3619,4625-4673`, where full/patch comparison
state persists separately after conversation items.

## Closed auxiliary shape inventory

outer `turn_context` with
an object payload containing neither a `type` nor a `payload` key (regardless of
the keys' value types, including null); outer `response_item` with an object payload whose direct
`type` is `reasoning`; and outer `event_msg` with an object payload whose direct
`type` is one of `task_started`, `task_complete`, `token_count`, `agent_reasoning`,
`agent_reasoning_raw_content`, `agent_reasoning_section_break`,
`reasoning_content_delta`, or `reasoning_raw_content_delta`; and exact outer
`world_state` with object payload, required boolean `full` and object `state`,
containing neither a payload `type` nor a `payload` key even when null.

## Requirements
### Requirement: One Codex-native interpretation

The Codex adapter MUST read each registered Codex JSONL source once into one
bounded Codex-specific native interpretation containing only source facts needed
for canonical mapping and native accounting. It MUST NOT retain `ParsedRecord`,
`NormalizedRecordV1`, or compatibility-only flattened fields.

#### Scenario: One read feeds canonical semantics

- **WHEN** a valid Codex JSONL source is acquired
- **THEN** canonical observations and accounting are derived from the same native
  interpretation without constructing a legacy record projection

### Requirement: Three source identities remain distinct

The canonical projection MUST accept only `ClientId::Codex` with the matching
source identities and kinds `codex.sessions`/`Jsonl`,
`codex.archived_sessions`/`ArchivedJsonl`, and
`codex.headless_sessions`/`HeadlessJsonl`. It MUST use adapter type `codex`, the
actual source ID as adapter ID, `SessionStore` ingestion, no adapter version or
path identity, and `PartialStructured` fidelity. It MUST NOT deduplicate
observations across source IDs.

#### Scenario: Source identity is represented

- **WHEN** the same native shape is projected through the archived source
- **THEN** provenance uses `codex.archived_sessions`, `ArchivedJsonl`, and no
  live/archive deduplication is attempted

### Requirement: Canonical session identity is source-reported

For legacy records in each registered Codex source, the v2 projection MUST use
`effective_session_id` as the namespace for that record's zero-based JSONL
ordinal.
The effective value MUST come only from a source-reported
`session_id`, `sessionID`, or `sessionId` on the record, or from a prior
`session_meta` that explicitly supplied one.
A bare producer ordinal MUST remain
provenance only.

#### Scenario: Session metadata scopes later records

- **WHEN** a Codex `session_meta` reports a session ID and a later record omits
  it
- **THEN** the later v2 ordinal is scoped by that source-reported ID and its
  canonical session correlation remains source-reported

#### Scenario: Truthful absence fails closed

- **WHEN** `session-a.jsonl` contains no source-reported session ID
- **THEN** canonical mapping returns `replay_unverifiable` and creates no
  collision-prone ID

#### Scenario: Session metadata is inherited

- **WHEN** a session metadata record reports `session_id` and a later message
  omits it
- **THEN** the later canonical message carries that source-reported session ID

#### Scenario: Truthful absence is preserved

- **WHEN** a source has no source-reported session ID
- **THEN** canonical mapping does not derive `session_id` from the file stem

### Requirement: Codex session identity has no fabricated fallback

If no truthful session ID exists, v2 MUST not use a filename,
path, project directory, or compatibility fallback and MUST fail with
`replay_unverifiable`.

#### Scenario: Codex session identity has no fabricated fallback

- **WHEN** no truthful effective session ID exists
- **THEN** replay_unverifiable is returned without filename or path-derived identity

### Requirement: Truthful messages preserve order

Supported message records MUST produce `MessageObserved` observations with
truthful roles.
Exact explicit `system`, `developer`, `user`, and `assistant`
roles MUST retain their corresponding canonical MessageRole; the existing
`model` alias MUST retain assistant semantics.
Simple records, event-message payloads, and
response-item messages MUST be supported.

#### Scenario: Public instruction response items retain roles without context leakage

- **WHEN** any of the three exact Codex identities contains response-item
  messages with explicit system/developer roles and supported text parts
- **THEN** canonical messages retain those roles and ordered parts, plain
  instruction records count as native Other rather than user/assistant messages,
  and shared user/assistant-context analytics do not match their content or
  add role-specific risk to Event 3.0
- **AND** ordering and replay identity remain deterministic, Event 3.0 remains
  unchanged, and a later unsupported role or unknown content block rejects the
  whole source without partial observations or accounting

#### Scenario: Response item retains ordered message parts

- **WHEN** a response item contains output text followed by a tool-use block
- **THEN** one assistant Message retains both parts and precedes the requested
  Tool observation

### Requirement: Codex message and tool children retain native order

Ordered `input_text`, `output_text`,
and supported tool content blocks MUST remain ordered content parts.
Unknown
roles and in-scope unknown content blocks MUST fail closed.
When one source
record emits a message and tools, the message MUST be emitted first, followed
by tools in native content order.

#### Scenario: Codex message and tool children retain native order

- **WHEN** one record emits a message and tools
- **THEN** content parts remain ordered and message output precedes tool children

### Requirement: Codex explicit roles govern native accounting

Explicit system/developer roles on plain messages MUST take precedence over
user/assistant discriminator aliases for native `Other` accounting.
Tool-bearing records MUST retain existing tool accounting.

#### Scenario: Codex explicit roles govern native accounting

- **WHEN** a plain message reports system or developer explicitly
- **THEN** that role outranks user/assistant aliases while tool accounting remains unchanged

### Requirement: Tool lifecycle is conservative

`tool_call`, `custom_tool_call`, `function_call`, and content-block `tool_use`
MUST map to Tool with `ToolRequested`.
`tool_result`,
`custom_tool_call_output`, `function_call_output`, and supported content-block
results MUST map to Tool with `ToolResultReturned` when a result
or explicit error state is returned.

#### Scenario: Generic completion does not claim success

- **WHEN** a generic tool reports `state.status: completed` without an explicit
  result
- **THEN** v2 does not emit an execution-completed or successful tool stage

### Requirement: Codex generic tool state does not imply execution

Generic `type:tool` running state MUST map
to a conservative request; completed/error or explicit output/error MUST map to
`ToolResultReturned`.
The adapter MUST NOT emit ToolProposed,
ToolExecutionStarted, ToolExecutionCompleted, inferred success, or a
source-success status except the bounded completed-command observation below.
A state-only generic record MAY use parsed canonical
`Unknown` status solely to satisfy the Tool body's minimum without claiming
execution or success.

#### Scenario: Codex generic tool state does not imply execution

- **WHEN** a generic tool record has running, terminal or state-only data
- **THEN** only conservative request/result mapping or Unknown status applies without invented execution

### Requirement: Structured tool values and optional linkage are preserved

Structured tool arguments and results MUST remain structured `JsonValue` values
when the source provides objects or arrays; source strings MUST remain strings.
`custom_tool_call.input` MUST remain its native JSON-encoded string in
`tool.arguments`; a parsed derivative may be used only for a separate governed
facet.

#### Scenario: Native string input is not replaced

- **WHEN** a custom tool call has `input` equal to a JSON-encoded string
- **THEN** `tool.arguments` is a JSON string and any parsed command facet is
  separate from that native value

### Requirement: Codex call linkage is optional source-reported data

Source call IDs from custom calls/outputs and content-block IDs MUST be
copied as `SourceReported` correlation when present.
Missing IDs MUST be valid
absence and MUST NOT be hashed, fabricated, or treated as a mapping error.

#### Scenario: Codex call linkage is optional source-reported data

- **WHEN** a call ID is absent
- **THEN** absence remains valid without fabrication or mapping failure

### Requirement: Metadata and facets remain bounded

Every populated canonical body field and facet MUST have exactly one matching
`FactMetadata` entry. The adapter MAY add only clear `command.text` and
`resource.path` Tool facets, with parsed provenance, except the closed completed-item
facets and reported cwd specified below, and MUST never emit File,
Process, Network, Session, or Inference observations from those facets or from
Codex metadata. `payload.source` is metadata only and MUST NOT imply execution.

#### Scenario: Command and path facets do not create activity

- **WHEN** a tool argument contains a command or `file_path`
- **THEN** the values remain Tool facets and no File, Process, or Network family
  is emitted

### Requirement: Capabilities and time are explicit

Every v2 observation MUST require the provided `ObservedAt`, preserve valid
source timestamp as `occurred_at` only, and use capability overrides exactly as
ToolCall supported, UserContext supported, and ToolExecution unsupported.
Model/provider/agent metadata MUST NOT emit Inference observations.

#### Scenario: Acceptance and source clocks differ

- **WHEN** the source timestamp and explicit observed time are different valid
  RFC3339 values
- **THEN** `occurred_at` uses the source value and `observed_at` uses the option

### Requirement: Deterministic replay identity

Legacy Codex v2 IDs MUST use the coordinate-only tuple and MUST remain unchanged for
semantic content, adapter-version provenance, or privacy-key epoch changes under
the same effective session and ordinal. Semantic comparison MUST use the
separate local comparison state; different comparison epochs are incomparable,
not mutation. Artifact path and filename MUST not participate.

#### Scenario: Same ordinal in different sessions is distinct

- **WHEN** two Codex artifacts each begin at ordinal zero but report different
  effective session IDs
- **THEN** their v2 observation IDs differ

#### Scenario: Artifact rename or move is harmless

- **WHEN** identical synthetic Codex JSONL bytes are projected from two
  filenames or directories with the same truthful source session
- **THEN** corresponding v2 IDs are identical

#### Scenario: Replay is stable

- **WHEN** a Codex source is projected twice with the same `ObservedAt`
- **THEN** observation IDs, source sequences, and child ordinals are identical

### Requirement: Closed auxiliary envelopes produce no canonical observations

The adapter MUST accept only the exact shapes in Closed auxiliary shape inventory.

#### Scenario: World-state metadata is opaque auxiliary evidence

- **WHEN** any of the three exact identities acquires a full or patch world_state with empty or tool/message/discriminator-looking state between public metadata and completed user input
- **THEN** state remains unretained and excluded from all analytics, the native unit counts as Other with zero contributions, owner/replay and consecutive ordinals remain truthful, and no privacy marker reaches native retained fields or exported events
- **AND** malformed world-state envelopes, late unknown records, ordinal gaps/duplicates or referenced prefixes reject the whole source without successful observations, accounting or progress

#### Scenario: World-state state cannot provide or inherit ownership

- **WHEN** world_state reports a validated direct envelope owner or contains only nested state identifiers and top-level session_meta poison
- **THEN** only direct outer/payload ownership can scope that unit's accounting, and no auxiliary establishes/replaces inherited identity for later messages
- **AND** conflicting or invalid direct envelope ownership rejects even when state contains plausible identifiers

#### Scenario: Auxiliary records surround conversation and tools

- **WHEN** accepted auxiliaries occur before or after valid messages and tool requests/results
- **THEN** all three source identities retain the message/tool semantics, call linkage, source ordinals, deterministic replay, and native `Other` counts without duplicate observations

#### Scenario: Wrong wrappers and unsupported control records fail closed

- **WHEN** an auxiliary tag is bare, under an unknown/wrong/nested wrapper, or has a malformed payload envelope, or an unsupported event such as `exec_command_begin`, `exec_command_end`, or an `item_completed` outside the bounded shape below follows accepted auxiliaries
- **THEN** acquisition rejects the whole source without partial successful observations or progress
- **AND** aliases `turn_started` and `turn_complete` remain unsupported

#### Scenario: Conversational unknown blocks remain errors

- **WHEN** an unknown conversational content block follows accepted auxiliaries
- **THEN** acquisition returns `unknown_content_block` without partial success

#### Scenario: Turn context cannot hide a discriminator or nested wrapper

- **WHEN** a `turn_context` payload contains a `type` or `payload` key, including action, message, tool, unknown, null, or malformed values
- **THEN** acquisition fails with a typed source-schema error without fallback observations or partial successful acquisition

#### Scenario: Auxiliary identity does not become inherited identity

- **WHEN** an auxiliary reports session `b` and a top-level `session_meta` field before an identity-less message
- **THEN** the auxiliary accounts to `b` but the message retains prior supported metadata session `a`, or fails `replay_unverifiable` if no prior namespace exists

### Requirement: Codex auxiliary accounting and inherited ownership remain distinct

These native units
MUST count as `Other` and emit zero canonical observations, irrespective of
additional role/tool-shaped fields.
Existing session ownership validation and
metadata attestation MUST remain active, including model/provider metadata in
`turn_context.payload`.
Source ordinals MUST include auxiliary units.

#### Scenario: Codex auxiliary accounting and inherited ownership remain distinct

- **WHEN** a closed auxiliary unit has a direct session ID
- **THEN** it counts as Other without establishing inherited session identity

### Requirement: Codex auxiliaries cannot establish inherited session ownership

An auxiliary's direct session ID MAY scope its own validated accounting but MUST
NOT establish or replace inherited session identity, including when a top-level
`session_meta` field is present.
Existing supported session metadata behavior
alone MUST establish the inherited namespace.

#### Scenario: Codex auxiliaries cannot establish inherited session ownership

- **WHEN** an auxiliary reports its own session ID
- **THEN** it may scope only its own accounting, never the inherited session namespace

### Requirement: Codex auxiliaries never expose private reasoning or completion messages

Analytics MUST intentionally exclude private reasoning, including response-item
summary/content arrays, and completion `last_agent_message`/`error`.
The adapter
MUST NOT use completion as a message fallback, infer terminal success, or
manufacture Message, Inference, or execution observations from auxiliaries.
Persistence or transience alone MUST NOT authorize ignoring other variants.

#### Scenario: Codex auxiliaries never expose private reasoning or completion messages

- **WHEN** reasoning or completion auxiliary content is present
- **THEN** no message fallback, success or execution observation is manufactured

### Requirement: Codex world-state contents remain opaque

World-state arbitrary state keys SHALL be opaque and excluded, never traversed
for ownership, attestation, discriminator, message or tool interpretation, and
never retained in native records.
Only direct outer/payload fields SHALL enter
existing envelope ownership/attestation validation.
Nested state/message and
top-level session_meta lookalikes SHALL NOT supply ownership or attestation.

#### Scenario: Codex world-state contents remain opaque

- **WHEN** world_state contains nested ownership or message lookalikes
- **THEN** nested state is not traversed or retained as semantic evidence

### Requirement: Codex world-state classification precedes conversational matching

Classification of exact world_state SHALL precede permissive conversational
discriminator matching; payload discriminator/wrapper keys SHALL reject rather
than manufacture completed items.
Full snapshots and patches SHALL produce zero
canonical observations and contributions, count as native Other, and SHALL NOT
establish/replace inherited identity.
Their ordinals SHALL validate exactly like
all other records.

#### Scenario: Codex world-state classification precedes conversational matching

- **WHEN** an exact world_state snapshot or patch arrives
- **THEN** it is counted as Other without canonical observations or inherited identity

### Requirement: Codex malformed world-state wrappers fail atomically

Missing/null/wrong full or state types and bare/wrong/nested
wrappers SHALL reject atomically.
No world-state context model, patch replay or
generic metadata ignore mechanism SHALL be added.

#### Scenario: Codex malformed world-state wrappers fail atomically

- **WHEN** full, state or wrapper shape is invalid
- **THEN** the source rejects without adding a world-state model or generic ignore path

### Requirement: Bounded typed completed items have one native owner

All three Codex identities SHALL accept only exact outer `event_msg`, direct
object payload `type: item_completed`, and object `item` tagged exactly
`AgentMessage`, `UserMessage`, `Reasoning`, or `CommandExecution`.

#### Scenario: Typed coordinates preserve replay without retaining reasoning

- **WHEN** any exact Codex identity acquires completed text messages and reasoning for a child thread distinct from the root
- **THEN** ordered roles and long-message semantics remain supported, typed replay identity uses owner/turn/item rather than physical position, and reasoning emits no facts
- **AND** missing/empty/conflicting coordinates, wrong wrappers, unknown late variants, invalid native ordinal mode or inherited-prefix metadata reject atomically without observations, accounting or progress

#### Scenario: Self-contained public ordinal rollout preserves native coordinates

- **WHEN** any of the three identities acquires a zero-start contiguous paginated public rollout including metadata, auxiliary, mirrored message, completed user and terminal command units with optional blank lines
- **THEN** every native unit accounts once, canonical source_sequence uses the validated reported ordinal, typed replay identity remains owner/turn/item scoped, and child ordinals remain independent
- **AND** a late gap, duplicate, descent, missing or malformed ordinal rejects the entire source with no successful observations, accounting or progress, while no-ordinal legacy sequences and IDs remain unchanged

### Requirement: Codex completed content accepts only exact text variants

Agent content
SHALL preserve ordered exact `Text` string parts.
User content SHALL support
only exact lowercase `text` UserInput string parts; unknown/nontext parts SHALL
reject the whole source.
Reasoning SHALL validate coordinates, count as native
Other, and retain no reasoning text, canonical facts or analytics.
Interpretation
SHALL remain in the existing native owner rather than a parallel parser.

#### Scenario: Codex completed content accepts only exact text variants

- **WHEN** typed agent, user or reasoning content is completed
- **THEN** supported text remains ordered and unsupported content rejects without retaining reasoning

### Requirement: Codex completed owner is established by public session metadata

Nonempty source `thread_id`, `turn_id` and `item.id` SHALL be required.
Public
SessionMeta.id SHALL establish the owning thread, independently of root
SessionMeta.session_id.
Owner aliases at outer/payload/item SHALL agree with
the completed owner and established metadata owner; root differing from child
SHALL NOT conflict.
Stray metadata SHALL NOT establish inherited ownership.

#### Scenario: Codex completed owner is established by public session metadata

- **WHEN** a typed item supplies owner aliases
- **THEN** thread, turn and item are required and aliases agree with established ownership

### Requirement: Codex typed identity is separate from rollout position

Typed native identity SHALL encode `[thread_id, turn_id, item.id]` with existing
adapter/family/stage scoping; position SHALL remain source provenance, not typed
identity.
Turn and message response IDs SHALL remain source-reported correlations.
Root correlation MAY be retained only as reported `session.root_id` on typed
facts.
Legacy identities SHALL remain unchanged; no filename fallback is allowed.

#### Scenario: Codex typed identity is separate from rollout position

- **WHEN** a typed completed fact is constructed
- **THEN** owner/turn/item identity is scoped independently of source position and reported correlations

### Requirement: Codex native ordinals require all-record self-contained history

Native `ordinal` SHALL be supported only in strict self-contained mode.
Presence
of the key on any nonblank JSONL record SHALL require a valid u64 ordinal on every
nonblank record, including metadata, auxiliaries and suppressed mirrors.
The
sequence SHALL start at zero and advance strictly consecutively using checked
arithmetic.

#### Scenario: Codex native ordinals require all-record self-contained history

- **WHEN** any nonblank record has an ordinal key
- **THEN** every nonblank record has a consecutive checked u64 starting at zero

### Requirement: Codex paginated history rejects invalid initial metadata or coordinates

The first record SHALL be exact public session_meta with object
payload, exact history_mode paginated and a truthful nonempty owning id.
The
entire source SHALL reject mixed absent/null/malformed, negative, fractional,
overflowing, duplicate, descending or gapped coordinates, invalid first metadata,
and nonzero-start slices before returning any observations, accounting or progress.

#### Scenario: Codex paginated history rejects invalid initial metadata or coordinates

- **WHEN** paginated history is not a complete zero-start self-contained sequence
- **THEN** the whole source rejects before returning observations, accounting or progress

### Requirement: Codex reported ordinal does not replace typed item identity

Validated reported ordinal SHALL supply source_sequence, never positional fallback
in this mode.
Blank lines SHALL NOT consume ordinals.
Typed owner/turn/item identity
and emitted child ordinal SHALL remain independent.
With no ordinal key, legacy
identities and sequences SHALL remain exactly unchanged.

#### Scenario: Codex reported ordinal does not replace typed item identity

- **WHEN** strict ordinal mode is valid
- **THEN** reported sequence is used without positional fallback or consuming blank lines

### Requirement: Codex referenced history remains unsupported

Non-null history_base or
subagent_history_start_ordinal, even zero, SHALL remain unsupported.
Referenced
history and inherited prefixes SHALL NOT be supported or guessed.
No acquisition
progress, cursor or public API changes SHALL be introduced.

#### Scenario: Codex referenced history remains unsupported

- **WHEN** history_base or subagent_history_start_ordinal is non-null
- **THEN** referenced history is rejected without guessing prefixes or adding progress APIs

### Requirement: Mirror authority is narrowly coordinate-proven

The native owner SHALL suppress an assistant raw-response mirror only for a
nonempty shared native response ID, same owning thread, explicit truthful payload
`internal_chat_message_metadata_passthrough.turn_id` and equivalent ordered
text-only message facts.
This SHALL be the sole raw-message mirror turn authority,
matching the pinned public ResponseItem::Message field.

#### Scenario: Proven mirrors and ambiguous repetition differ

- **WHEN** raw and typed assistant messages share owner/turn/nonempty native ID and text facts, and paginated user representations share owner/explicit public passthrough turn coordinate but have different IDs
- **THEN** only the proven assistant mirror and turn-paired raw user representation are suppressed from canonical analytics
- **AND** identical content with distinct IDs, other turns, absent metadata, missing assistant IDs, and legacy-mode user representations remain distinct

#### Scenario: Harness metadata cannot authorize raw mirror suppression

- **WHEN** an otherwise matching raw message has only unrelated metadata.turn_id or an outer passthrough-like field rather than the exact payload public passthrough turn coordinate
- **THEN** both raw and typed facts remain distinct for assistant and paginated user messages across all three identities
- **AND** malformed, empty, oversized or contradictory present public raw turn coordinates reject the whole source without successful observations, accounting or progress

### Requirement: Codex mirror coordinates use only public passthrough metadata

Outer rollout metadata
SHALL remain separate harness metadata.
Outer/payload `metadata.turn_id`, outer
passthrough-like fields and stray direct turn coordinates SHALL NOT establish
mirror authority or be accepted as aliases.

#### Scenario: Codex mirror coordinates use only public passthrough metadata

- **WHEN** outer metadata resembles a turn authority
- **THEN** it is not accepted as a mirror alias

### Requirement: Codex explicit mirror coordinates are bounded and consistent

Non-null passthrough metadata SHALL
be an object; a non-null turn ID SHALL be a nonempty bounded string without
control characters.
Missing/null optional metadata or turn IDs SHALL preserve
absence.
Contradictory explicit outer/payload turn coordinates SHALL reject the
whole source atomically rather than override the public coordinate.

#### Scenario: Codex explicit mirror coordinates are bounded and consistent

- **WHEN** passthrough metadata or explicit coordinates are present
- **THEN** invalid or contradictory coordinates reject atomically while null preserves absence

### Requirement: Codex mirror suppression requires proven equivalent coordinates

Conflicting proven mirrors SHALL reject atomically.
Missing coordinates, distinct
IDs, tool-bearing facts and distinct turns SHALL NOT content-deduplicate.

#### Scenario: Codex mirror suppression requires proven equivalent coordinates

- **WHEN** mirror candidates lack coordinates or conflict
- **THEN** conflicts reject and distinct facts are not content-deduplicated

### Requirement: Codex user mirrors require explicit paginated history authority

Only in explicit paginated history mode, completed text-only user messages SHALL
be authoritative over text-only raw user response messages with the same owner
and explicit truthful public passthrough turn coordinate.
User item IDs SHALL NOT
be treated as shared.

#### Scenario: Codex user mirrors require explicit paginated history authority

- **WHEN** a completed user message and raw user response share owner and public turn
- **THEN** only paginated history may suppress the raw text-only representation

### Requirement: Codex mirror policy retains ambiguity and physical accounting

This representation policy MAY discard raw contextual text; it SHALL NOT claim
universal losslessness.
Ambiguous pairing SHALL preserve distinct facts and
document possible duplicate analytics, or reject, never silently erase them.
Native unit accounting SHALL count all physical native units including mirrors.
Request, result and completion facts SHALL never be deduplicated together.

#### Scenario: Codex mirror policy retains ambiguity and physical accounting

- **WHEN** mirror pairing is ambiguous or drops raw contextual text
- **THEN** distinct facts remain or reject, accounting counts physical units and lifecycle facts do not merge

### Requirement: Completed commands are conservative terminal results

Completed CommandExecution SHALL require structured string argv and terminal
status completed, failed or declined; in_progress and unknown status SHALL reject
atomically.

#### Scenario: Diagnostic completion does not fabricate execution

- **WHEN** a declined or failed command returns a diagnostic, missing output, explicit exit value or persistence-truncated capture
- **THEN** its result preserves argv, source status, result presence and conservative fidelity with source call linkage
- **AND** native invocation contribution stays zero, distinct raw requests/results remain, Event 3.0 privacy is preserved and timeline completion is a result

### Requirement: Codex completed command identity and arguments remain native

It SHALL map to ToolResultReturned with native ToolResult accounting,
not ToolCall, execution stages or invocation contributions. item.id SHALL supply
call_id independently of raw response.id. argv SHALL remain structured
tool.arguments, never space-joined, with no invented tool name or command-text
facet.

#### Scenario: Codex completed command identity and arguments remain native

- **WHEN** a terminal CommandExecution is projected
- **THEN** it is a ToolResult with native call ID and structured argv, not a ToolCall

### Requirement: Codex completed command output preserves absence and values

Optional exit_code and aggregated_output SHALL preserve absent/null/empty
and returned values in tool.result.

#### Scenario: Codex completed command output preserves absence and values

- **WHEN** exit_code or aggregated_output is absent, null, empty or populated
- **THEN** its exact returned representation is preserved

### Requirement: Codex command status and output fidelity do not claim OS effects

Exact source status SHALL remain reported
tool.source_status; completed/failed/declined SHALL map to reported
Succeeded/Failed/Denied without asserting actual execution, intended effects,
user refusal or zero effects. tool.output_fidelity SHALL report not_captured,
truncated for the exact known persistence marker, diagnostic_or_capture for
failed/declined output, or capture_completeness_unknown otherwise. cwd MAY only
be reported resource.path metadata.

#### Scenario: Codex command status and output fidelity do not claim OS effects

- **WHEN** a completed command reports completed, failed or declined
- **THEN** reported status and capture fidelity remain conservative about actual execution and effects

### Requirement: Codex completed commands preserve unsupported execution and output bounds

ToolExecution SHALL remain Unsupported, and
no Process/File/Network observations SHALL be manufactured.
Existing structured
limits SHALL remain unchanged; oversize SHALL reject without truncation.
Timeline
SHALL label completions as results rather than requests, with call linkage only
when unambiguous.

#### Scenario: Codex completed commands preserve unsupported execution and output bounds

- **WHEN** a completed command enters analytics or timeline
- **THEN** no OS facts are invented, oversize rejects and timeline labels it a result

### Requirement: Unknown input fails closed without leakage

Unknown explicit discriminators MUST return `unknown_discriminator`, and
unknown content blocks MUST return `unknown_content_block`. Source parse/schema errors MUST remain
isolated source errors. Canonical error `Display` and `Debug` MUST NOT contain
prompts, tool arguments/results, paths, secrets, or arbitrary source payloads.

#### Scenario: Unknown discriminator is safe

- **WHEN** a record contains an unsupported explicit discriminator and synthetic
  source text
- **THEN** canonical mapping rejects it with a safe mapping code

### Requirement: Canonical production and Event 3.0 compatibility

Production scanning MUST consume Codex Canonical Observation v2 through the
shared runtime. Exact source identity, Event3 schema and privacy behavior, and
already-persisted Event3 data MUST remain compatible.
New canonical evidence, hashes, severity, and constructor-generated IDs/times
need not be byte-identical to legacy output.

#### Scenario: Production uses canonical acquisition

- **WHEN** the normal Codex scanner processes a registered source
- **THEN** it acquires Canonical Observation v2 directly without constructing
  normalized compatibility records

### Requirement: Codex conformance evidence exists

The repository MUST contain test-only canonical conformance vectors comparing
Codex with Claude for equivalent message/tool semantics, truthful missing call
IDs, parsed facets, capability visibility, and the absence of inferred lifecycle
stages. The suite MUST remain test infrastructure and MUST NOT add a provider-
neutral native model, adapter trait, registry, or production cutover.

#### Scenario: Tool lifecycle meaning remains conservative

- **WHEN** equivalent synthetic tool request/result records are projected
- **THEN** requested/result-returned stages, structured values, source call IDs
  when present, and absence of execution stages compare consistently

### Requirement: Codex acquisition preserves all three source identities

The authoritative public acquisition API MUST accept exactly the three Codex
identity/kind pairs specified above, validating them before I/O.
Each call
reaching extraction MUST invoke the existing native extractor exactly once and
map those records through the existing canonical semantics without a legacy
record conversion.

#### Scenario: Three identities acquire native evidence independently

- **WHEN** the same valid native input is acquired as live, archived, and headless
  Codex sources with their respective kinds and a fixed observed time
- **THEN** each returns reference-equivalent observations with its own adapter ID
  and stable replay identity, source-derived occurrence time, and no progress
  coordinate

#### Scenario: Invalid identity and kind fail before I/O

- **WHEN** a Codex source has a wrong client/source pair or another identity's kind
- **THEN** acquisition rejects it before opening the path and does not leak the
  path or native error

#### Scenario: Source session and tool semantics remain unchanged

- **WHEN** acquired native records inherit an explicit session from session metadata
  and contain structured tool calls or results
- **THEN** acquisition preserves source session and call linkage, structured values,
  and request/result stages without manufacturing execution evidence or restoring
  a filename-derived canonical session

### Requirement: Codex acquisition has no scanner progress or private diagnostics

Shared
acquisition input MUST be caller-owned `observed_at`, without SQLite read
controls.
Each identity MUST return `AcquisitionProgress::None`; acquisition
MUST NOT persist scanner state or return successful progress on failure.
Source-read, mapping, and validation failures MUST remain bounded and privacy-safe.

#### Scenario: Codex acquisition has no scanner progress or private diagnostics

- **WHEN** a Codex source is acquired
- **THEN** caller time, None progress and bounded source/mapping/validation failures are preserved

### Requirement: Codex canonical bound diagnostics are closed and content-free

Existing Codex canonical JSON conversion and builder bound failures SHALL retain
an optional typed canonical field category and bound dimension through acquisition
and runtime source failure.
Schema SHALL own limits and failure dimensions; source
mapping SHALL own conversion attribution.

#### Scenario: Scalar and assembled bounds retain safe context

- **GIVEN** a synthetic late scalar message, ordered content part, tool argument,
  tool result, or assembled field/facet exceeds an existing canonical bound
- **WHEN** any of the three exact Codex identities is acquired
- **THEN** the existing first failure reports only its closed canonical category
  and dimension, without source content or a successful prefix
- **AND** exact-bound accepted payloads and Event3 failure projection are unchanged

#### Scenario: Earlier native accounting failure is not relabeled

- **GIVEN** a synthetic source has both an invalid native attestation and an
  oversized canonical value
- **WHEN** acquisition performs native accounting before canonical mapping
- **THEN** it returns the native accounting failure with no canonical bound context
### Requirement: Codex bound diagnostic taxonomy is closed

Categories SHALL be limited to
MessageContent, MessageContentParts, ToolName, ToolArguments, ToolResult,
CommandText, ResourcePath, SemanticField, and SemanticFacet.
Dimensions SHALL be
limited to StringBytes, EncodedBytes, Depth, ArrayItems, ObjectMembers, and KeyBytes.

#### Scenario: Codex bound diagnostic taxonomy is closed

- **WHEN** a canonical field or dimension is attributed
- **THEN** only the listed field categories and bound dimensions are accepted

### Requirement: Codex bound diagnostics retain no source-controlled context

Context SHALL NOT retain or render raw keys, values, paths, identifiers, indices,
measured sizes, or underlying errors.
`code()` and Display SHALL preserve
`unbounded_value`; Debug MAY expose only the closed context and code.

#### Scenario: Codex bound diagnostics retain no source-controlled context

- **WHEN** a bound failure is rendered
- **THEN** code remains unbounded_value and no raw values or identifiers appear

### Requirement: Codex attribution consumes existing ordered failures

Limits, first-failure check order, UTF-8 and escaped encoded-size accounting, and
existing NFC behavior SHALL remain unchanged.
Attribution SHALL consume existing
failures, without another parser, reread, or parallel validation.
Native accounting
SHALL precede mapping and SHALL NOT have its failures relabeled.

#### Scenario: Codex attribution consumes existing ordered failures

- **WHEN** a canonical conversion or builder fails
- **THEN** existing limits and NFC/failure order remain unchanged without rereads or relabeling native accounting

### Requirement: Codex contextual bound errors preserve atomicity and declare source break

Rejection SHALL
remain source-atomic with no successful observations, accounting, or progress.
Event3 scanner error projection SHALL remain generic `canonical_acquisition_failed`.
The existing public code-only CanonicalValidation variant SHALL remain available;
the new contextual variant SHALL be documented as a Rust exhaustive-match source
break, not full source compatibility.

#### Scenario: Codex contextual bound errors preserve atomicity and declare source break

- **WHEN** contextual canonical validation rejects a source
- **THEN** no successful batch survives, scanner_error stays generic and exhaustive-match compatibility is documented
