# roocode-kilocode-source-contract-repair Specification

## Purpose

Define the evidence-bounded source-owned parser contract for the exact RooCode
`roocode.tasks` and legacy-writer KiloCode `kilocode.tasks` `ui_messages.json`
identities. Roo is pinned to RooCode commit
`b867ec9145750d0ae1ff7f02d35406e9bf2a0b16`; Kilo's registered writer is pinned
to `Kilo-Org/kilocode-legacy@ae046acafd17993bdf12dce0f81d9ac948e17ee8`.
The current Kilo product at
`31f1f3118ccba73e9d9fdc6cac78f6644e9c23ef` only reads/diagnoses the legacy
anchor for migration. The contract preserves legacy parsing while making
subtype, metadata, privacy, and identity limits explicit. It does not add
canonical projectors, protected assignment, Detection v2 behavior, or new Kilo
sources.

## ADDED Requirements

### Requirement: Exact source ownership and generation boundary

The implementation MUST retain the exact registered identities
`(RooCode, roocode.tasks, UiMessagesJson)` and
`(KiloCode, kilocode.tasks, UiMessagesJson)`. Roo MUST use the registered
`ConfigHome/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/**` anchor;
Kilo MUST use the registered
`ConfigHome/Code/User/globalStorage/kilocode.kilo-code/tasks/**` legacy
migration anchor. `ui_messages.json` MUST remain the discovered body anchor.
Current Kilo SQLite, server, and CLI stores MUST NOT be routed by these
identities.

#### Scenario: Exact identity selects the modeled source

- **WHEN** a discovered `ui_messages.json` is supplied with the exact client
  and source ID
- **THEN** its client-owned modeled parser is selected and no generic JSON
  document fallback is invoked

#### Scenario: Wrong identity is terminal before alternate routing

- **WHEN** a Kilo-looking source has a wrong-case source ID or a current Kilo
  SQLite-looking path
- **THEN** the exact registration does not route it to Roo, Kilo, or another
  generic parser

### Requirement: Source-owned root and record schema

Each modeled parser MUST read one JSON document whose root is an array of
objects. Roo records MUST follow the verified `ClineMessage` shape with
`type: ask | say`, the matching verified subtype, numeric epoch-millisecond
`ts`, optional text, and optional boolean `partial`. Kilo MUST remain limited to
the legacy-writer `ui_messages.json` anchor and MUST use its independently
pinned `ClineMessage`/MCP contract rather than assuming Roo behavior. Kilo MUST
NOT import current Kilo SQLite/server/CLI semantics or Roo companion metadata.
Non-array roots,
non-object records, wrong field types, and unsupported explicit variants MUST
return a bounded terminal source-schema failure.

#### Scenario: Realistic ClineMessage records are modeled

- **WHEN** a synthetic document contains ordered `ask` and `say` records with
  verified subtypes and numeric timestamps
- **THEN** the source-owned native model retains their order, subtype, text
  presence, timestamp, and partial/final state

#### Scenario: Structural drift does not fall back

- **WHEN** the root or a known record violates the modeled schema
- **THEN** parsing returns one bounded schema failure and does not retry generic
  JSON semantics or another source parser

### Requirement: Verified subtype and legacy semantic mapping

The Roo modeled source MUST recognize only the verified ask and say subtype sets in
the active design. It MUST map explicit source facts to legacy kinds as follows:
user feedback to `UserMessage`, assistant text/follow-up and explicit result
text to `AssistantMessage`, tool approval/request asks to `ToolCall`, explicit
command/MCP output to `ToolResult`, and bounded control metadata to
`SessionMeta` or `Other` according to the design table. It MUST NOT infer a
tool request/result from arbitrary text or map an unknown subtype by coincidental
fields.

Kilo MUST additionally recognize its pinned control subtypes
`payment_required_prompt`, `unauthorized_prompt`,
`promotion_model_sign_up_required_prompt`, `invalid_model`, `report_bug`,
`condense`, `checkpoint_restore`, `browser_action_launch`, `browser_action`,
`browser_action_result`, and `browser_session_status`, mapping them to
`SessionMeta` or `Other`. Kilo MUST reject Roo-only `say:tool` and
`say:too_many_tools_warning` as unknown subtypes rather than importing them.

#### Scenario: User and assistant actors remain distinct

- **WHEN** a record is `say:user_feedback` or `say:user_feedback_diff`
- **THEN** its legacy kind is `UserMessage`, while `say:text` and
  `ask:followup` are not reclassified as user content

#### Scenario: Tool request and result remain separate

- **WHEN** records contain `ask:command` followed by `say:command_output`
- **THEN** the legacy projection contains a `ToolCall` followed by a
  `ToolResult`, without claiming execution success or failure

#### Scenario: Roo unknown source semantics remain bounded

- **WHEN** an explicit subtype or tool shape has no verified mapping
- **THEN** it is returned as a bounded failure or the design-approved
  `RecordKind::Other`, and no tool fact is fabricated

#### Scenario: Kilo MCP semantics use the legacy writer contract

- **WHEN** a Kilo `ui_messages.json` record matches the legacy writer's
  `ask:use_mcp_server` or `say:mcp_server_response` encoding
- **THEN** the source-owned parser emits a truthful tool request/result, with
  stringified completed arguments, partial object arguments only for
  `partial: true`, resource requests named `access_mcp_resource`, and no
  result-side tool-name inference

### Requirement: Native provenance, content, and partial behavior

The native model MUST preserve source order and retain actor/content/tool facts
only when their source subtype establishes them. Source call/tool IDs MUST be
correlation-only and optional. `ts` MUST remain source timestamp metadata and
MUST NOT become identity or a wall-clock substitute. `partial: true` MUST remain
an in-progress snapshot; `partial: false` MUST mean only that persisted record
is final. Parsers MUST NOT coalesce records by timestamp or infer execution
stages from final/control status.

Agent, provider, and model fields MUST remain absent unless a versioned,
source-reported variant is proven by evidence and fixtures. Adapter/client names
MUST NOT be synthesized as source-reported provenance.

The existing legacy `ParsedRecord.session_id` field is required and is used for
compatibility grouping. The native model MUST keep the optional distinction
between a Roo source-reported session namespace and that compatibility fallback;
the parser MAY place the direct Roo namespace in the required legacy field when
it is valid, and MUST otherwise use the fallback solely for compatibility. Kilo's
required legacy field remains compatibility-only. Neither value is a per-message
coordinate, and this bounded change MUST NOT broaden the core record schema.

#### Scenario: Partial updates are not identity updates

- **WHEN** two persisted records share a timestamp and differ in `partial` or
  text
- **THEN** both source records retain their order and neither is silently
  replaced or treated as a stable message identity

#### Scenario: Missing provenance stays missing

- **WHEN** a verified Roo or Kilo UI record has no agent, provider, or model
  field
- **THEN** the corresponding legacy fields remain absent rather than being
  filled from the client name, API protocol, path, or a current Kilo store

### Requirement: Bounded metadata lookup and disagreement policy

Metadata lookup MUST be limited to named upstream companions. Roo MAY inspect
`history_item.json` at the task root and `_index.json` at the task-store root,
because the pinned `TaskHistoryStore` proves those files. Only a valid direct
non-empty Roo `history_item.json.id` MAY establish a session namespace. A valid
`_index.json` entry may corroborate that ID but cannot override it. Kilo MUST NOT
inspect or use `history_item.json` or `_index.json` for this legacy-writer
identity. `api_conversation_history.json` MUST remain a separate legacy
alternate body and MUST NOT be merged into or used as a fallback for
`ui_messages.json`. A task-directory name MUST remain legacy compatibility only.

Missing optional metadata MUST produce no source-reported namespace. Malformed
Roo metadata, wrong root or field types, empty or duplicate index IDs, and
disagreement between the direct history ID and its index corroboration MUST
produce one deterministic bounded diagnostic and no source namespace. Kilo
companion files MUST have no effect on its result.

#### Scenario: Roo direct metadata ID is bounded

- **WHEN** `history_item.json` supplies a non-empty ID and, when present,
  exactly one valid `_index` entry supplies the same ID
- **THEN** that direct ID may be retained as a session namespace, while the
  path and directory name remain locators only

#### Scenario: Roo index alone is insufficient

- **WHEN** `_index.json` contains an ID equal to the task directory but
  `history_item.json` is absent
- **THEN** the parser uses only the legacy parent fallback and assigns no
  metadata namespace

#### Scenario: Roo metadata mismatch fails closed

- **WHEN** `_index.json` is malformed, contains duplicate matching IDs, or
  disagrees with `history_item.json`
- **THEN** no canonical namespace is assigned and the parser emits no raw
  metadata, path, or record content in its bounded diagnostic

#### Scenario: Kilo companion files are not source evidence

- **WHEN** a Kilo UI-message task is accompanied by Roo-shaped history or index
  files
- **THEN** the Kilo parser retains only its compatibility grouping fallback and
  does not promote either companion into source-reported identity

#### Scenario: Alternate legacy body does not rescue UI drift

- **WHEN** `ui_messages.json` is malformed and
  `api_conversation_history.json` is present
- **THEN** the UI source returns its terminal schema failure without switching
  parsers or merging the alternate body

### Requirement: Identity readiness rejects unsafe candidates

The parser and its readiness evidence MUST reject path, filename, parent
directory, timestamp, content hash, random value, mutable ordinal, unproven
message ID, and unproven tool ID as canonical identity. Roo array sequence and
ordinal MUST be rejected because middle deletion/insertion/reorder can change
them. Kilo array sequence and ordinal MUST be rejected because the legacy writer
rewrites the whole array and provides no middle-delete stability proof. Roo's
direct history `id`, when valid under the metadata requirement, MAY identify only
a session namespace; Kilo has no source-reported session namespace. Neither
source currently has an approved per-message coordinate. A missing coordinate
MUST remain replay-unverifiable until a separately designed protected assignment
exists.

#### Scenario: Roo middle deletion does not preserve ordinal identity

- **WHEN** a Roo writer removes a middle array element and rewrites the file
- **THEN** the parser does not treat the shifted ordinal as the same message
  coordinate and does not use the parent directory as a replacement

#### Scenario: Kilo lacks a native per-message coordinate

- **WHEN** a Kilo UI message has no proven native ID, tool ID, stable sequence,
  offset, or ordinal contract
- **THEN** readiness reports no per-message coordinate and does not fabricate
  one from `ts`, content, path, or randomness

### Requirement: Privacy-safe structural failure and no retry

Unknown variants, schema failures, metadata failures, and identity failures
MUST use bounded stable categories. Display, Debug, test diagnostics, and
support reports MUST NOT expose source paths, parent names, task/message IDs,
timestamps, user or assistant text, tool arguments/results, URLs, credentials,
raw JSON, or unnecessary host paths. A known source/schema failure MUST NOT
silently fall through to a generic parser.

#### Scenario: Malformed synthetic input remains private

- **WHEN** a malformed synthetic source contains text or a credential-shaped
  marker
- **THEN** the error reports only its bounded structural category and contains
  neither marker nor source location

#### Scenario: Known parser failure is terminal

- **WHEN** the modeled Roo or Kilo parser recognizes its source identity but
  encounters a known schema failure
- **THEN** it returns that failure and does not guess another record kind or
  invoke generic JSON parsing

#### Scenario: Native debug output is redacted

- **WHEN** a native Roo or Kilo record contains synthetic secret markers in
  message text, metadata, tool names, arguments, results, timestamps, or IDs
- **THEN** formatting the native model with `Debug` reveals none of those
  values

### Requirement: Fixture, support-gate, documentation, and stop boundaries

The implementation MUST add realistic synthetic Roo and Kilo legacy-writer
UI-message fixtures, benign/unknown/malformed/identity mutation coverage, and
the applicable discovery, parse, negative, and capability documentation gates.
Roo and Kilo may claim tool-call/tool-result and positive deterministic UC-001
support only from their respective exact writer evidence. Fixture reports MUST
remain privacy-safe and deterministic. This change MUST NOT add canonical projectors,
facade/conformance, Detection v2 or shadow cases, protected-assignment
implementation, current Kilo sources, Event3/Event4, gateway behavior, or a
parser framework.

Implementation MUST stop for review if truthful tool/UC-001 support cannot be
established, a parser change creates an evaluation golden delta, discovery
would require a new source bundle, or an exact ownership/privacy/identity
boundary is found to be defective.

#### Scenario: Support gates use realistic source evidence

- **WHEN** the source fixtures and deterministic support checks run
- **THEN** Roo and Kilo each have bounded discovery, benign parsing, truthful
  tool request/result, UC-001 positive, negative, and capability evidence
  without changing Detection v2 authority; Roo's session namespace is READY only
  from direct `history_item.json.id`, Kilo's session namespace is NOT READY, and
  per-message identity remains NOT READY for both

#### Scenario: A forbidden adjacent change stops the tranche

- **WHEN** implementation requires a canonical projector, Detection v2 shadow
  update, current Kilo source, protected assignment storage, or discovery
  redesign
- **THEN** the P17R tranche stops for review rather than expanding scope
