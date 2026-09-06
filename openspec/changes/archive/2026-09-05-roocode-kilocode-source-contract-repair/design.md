# Design: RooCode and KiloCode source-contract repair

## Context

The repository already has the right exact source identities and discovery
anchors:

- `crates/telltale-sources/src/sources/roocode/mod.rs:10-19` registers
  `roocode.tasks` as recursive `ui_messages.json` below
  `Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks`.
- `crates/telltale-sources/src/sources/kilocode/mod.rs:10-19` registers the
  corresponding Kilo path as `kilocode.tasks`.
- `crates/telltale-sources/src/parser.rs:231-296` owns exact parser lookup by
  `(ClientId, source_id)` but currently registers both identities with the
  generic JSON-document fallback.
- `crates/telltale-sources/src/parser.rs:398-423` flattens arbitrary JSON
  records and uses parent-directory fallback. That is not sufficient for the
  source contracts below.

The current source documentation deliberately records both clients as
JSON-document fallbacks. This change corrects that characterization without
turning the source layer into a generic framework.

### Upstream evidence

Roo evidence is pinned to commit
[`b867ec9145750d0ae1ff7f02d35406e9bf2a0b16`](https://github.com/RooCodeInc/Roo-Code/tree/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16):

- [`packages/types/src/message.ts#L238-L276`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/packages/types/src/message.ts#L238-L276)
  defines `ClineMessage` as an object with `ts`, `type: ask | say`, optional
  subtype, text, and partial fields. There is no message ID field.
- [`packages/types/src/message.ts#L27-L177`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/packages/types/src/message.ts#L27-L177)
  defines the registered ask and say subtype sets used by the taxonomy below.
- [`src/core/task-persistence/taskMessages.ts#L17-L55`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/task-persistence/taskMessages.ts#L17-L55)
  reads and safely rewrites the complete `ui_messages.json` array.
- [`src/core/task-persistence/TaskHistoryStore.ts`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/task-persistence/TaskHistoryStore.ts)
  writes the full `HistoryItem` to `tasks/<taskId>/history_item.json` as the
  source of truth and rebuilds `tasks/_index.json` as a debounced cache. The
  direct `HistoryItem.id` is the source-native task/session namespace; the
  index is not an authority.
- [`src/core/checkpoints/index.ts#L244-L267`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/checkpoints/index.ts#L244-L267)
  locates a message by `ts` and rewinds the following records; the
  `ClineProvider` deletion path also persists only the prefix. These are
  affirmative mutation facts, not evidence that `ts` is a stable ID.
- [`src/utils/storage.ts#L50-L57`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/utils/storage.ts#L50-L57)
  shows that task directories are beneath the extension's supplied global
  storage root. The local registered path is the discovery contract.
- [`packages/types/src/vscode-extension-host.ts#L771-L777`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/packages/types/src/vscode-extension-host.ts#L771-L777)
  defines the inner `ClineAskUseMcpServer` JSON fields. The pinned writer in
  [`src/core/tools/UseMcpToolTool.ts#L54-L63`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/tools/UseMcpToolTool.ts#L54-L63)
  persists `ask:use_mcp_server` text as a JSON object with
  `type: "use_mcp_tool"`, `serverName`, `toolName`, and an optional
  **stringified** `arguments` value for a completed request. The partial writer
  at [`UseMcpToolTool.ts#L83-L92`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/tools/UseMcpToolTool.ts#L83-L92)
  preserves the in-progress arguments object directly, so the parser accepts
  both exact persisted states. The same pinned request type and
  [`src/core/tools/accessMcpResourceTool.ts#L38-L44`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/tools/accessMcpResourceTool.ts#L38-L44) writer persist an
  `access_mcp_resource` request with `serverName` and `uri`; it has no
  `toolName` or arguments field. The pinned result writer at
  [`UseMcpToolTool.ts#L320-L349`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/core/tools/UseMcpToolTool.ts#L320-L349)
  persists `say:mcp_server_response` text as the plain formatted result string;
  it does not persist a JSON `toolName`/`content` envelope. The webview reader
  parses the request JSON and the command consolidator attaches plain response
  text at [`packages/core/src/message-utils/consolidateCommands.ts#L38-L74`](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/packages/core/src/message-utils/consolidateCommands.ts#L38-L74).

Kilo has two distinct upstream evidence pins. The current product
[`Kilo-Org/kilocode@31f1f3118ccba73e9d9fdc6cac78f6644e9c23ef`](https://github.com/Kilo-Org/kilocode/tree/31f1f3118ccba73e9d9fdc6cac78f6644e9c23ef)
uses
[`packages/kilo-vscode/src/legacy-migration/task-store.ts`](https://github.com/Kilo-Org/kilocode/blob/31f1f3118ccba73e9d9fdc6cac78f6644e9c23ef/packages/kilo-vscode/src/legacy-migration/task-store.ts)
to read and diagnose the legacy `ui_messages.json` file. It is not the writer
for that registered VS Code identity.

The writer for the registered identity is
[`Kilo-Org/kilocode-legacy@ae046acafd17993bdf12dce0f81d9ac948e17ee8`](https://github.com/Kilo-Org/kilocode-legacy/tree/ae046acafd17993bdf12dce0f81d9ac948e17ee8),
publisher `kilocode`, package `kilo-code`:

- [`src/core/task-persistence/taskMessages.ts`](https://github.com/Kilo-Org/kilocode-legacy/blob/ae046acafd17993bdf12dce0f81d9ac948e17ee8/src/core/task-persistence/taskMessages.ts)
  writes the complete `ClineMessage[]` to `GlobalFileNames.uiMessages`, which
  is `ui_messages.json`.
- Records have numeric epoch-millisecond `ts`, `type: ask | say`, matching
  `ask`/`say` subtypes, and optional `text`, `images`, and `partial`. Partials
  are persisted; completion changes `partial` to false and persists again.
- `ask:use_mcp_server` stores a JSON request whose `type` is
  `use_mcp_tool`, with `serverName`, `toolName`, and stringified `arguments`
  after completion. A partial request may retain an object-valued `arguments`.
  `access_mcp_resource` requests contain `serverName` and `uri` and map to the
  bounded resource tool name. `say:mcp_server_response` stores plain result
  text and has no result-side tool-name envelope.
- Kilo's additional known control subtypes are
  `payment_required_prompt`, `unauthorized_prompt`,
  `promotion_model_sign_up_required_prompt`, `invalid_model`, `report_bug`,
  `condense`, `checkpoint_restore`, `browser_action_launch`, `browser_action`,
  `browser_action_result`, and `browser_session_status`. They map to
  `SessionMeta` or `Other`; unknown variants still fail closed. Kilo's writer
  does not include Roo's `say:tool` or `say:too_many_tools_warning` variants.

The current product's migration reader also recognizes
`api_conversation_history.json`, `history_item.json`, and `_index.json`; those
files are migration-reader evidence, not the legacy writer contract registered
here. The pinned Kilo legacy writer writes `ui_messages.json` but no
`history_item.json` or `_index.json`. Current Kilo SQLite/server/CLI storage is
explicitly outside this source contract and does not change the `kilocode.tasks`
discovery anchor. This Kilo interpretation is independently duplicated in
`kilocode/native.rs`; it does not share a generic UI adapter or infer semantics
from Roo.

## Goals / Non-Goals

### Goals

1. Model each exact source in its own native module and project it to the
   existing legacy `ParsedRecord` without a second semantic interpretation.
2. Keep `ui_messages.json` as the discovered anchor, with bounded Roo companion
   lookup only where the pinned Roo writer proves the file.
3. State actor, content, tool request, tool result, timestamp, partial/final,
   provenance, unknown-variant, and failure semantics explicitly.
4. Make identity readiness honest: accept only source-reported session metadata
   where it is proven, reject all unsafe per-message candidates, and require a
   future protected assignment when no coordinate exists.
5. Add realistic synthetic fixture and support-gate requirements without
   changing detection or canonical projector behavior.

### Non-goals

Canonical projectors/facade/conformance, Detection v2 or shadow changes,
protected assignment implementation, current Kilo sources, Event3/Event4,
gateway/framework work, and discovery bundle redesign are excluded. No parser
retry is permitted.

## Decisions

### 1. Keep exact ownership and the discovered source anchor

The two registrations remain exactly:

| Client | Exact source ID | Kind | Registered root and path | Anchor | Generation boundary |
| --- | --- | --- | --- | --- | --- |
| RooCode | `roocode.tasks` | `UiMessagesJson` | `ConfigHome/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/**` | `ui_messages.json` | Current Roo VS Code extension task persistence at the pinned Roo commit |
| KiloCode | `kilocode.tasks` | `UiMessagesJson` | `ConfigHome/Code/User/globalStorage/kilocode.kilo-code/tasks/**` | `ui_messages.json` | Legacy Kilo/Roo migration store; current Kilo SQLite/server/CLI is out of scope |

The path locates the anchor and, for Roo only, the two named task-history
companions. It is never a source-reported or canonical identity. The
task-directory name may remain the legacy session fallback required for
compatibility, but it is never a canonical session namespace or message
coordinate.

The alternative of widening discovery to a source bundle was rejected: the
registered `ui_messages.json` anchor is the strongest common evidence and a
bundle redesign would make this bounded parser repair unreviewable. If Stage 2
finds that the anchor cannot support truthful parsing, it stops at the
discovery-redesign gate.

### 2. One source-owned native interpretation per client

Each parser SHALL read one `ui_messages.json` document into a client-owned
native record model containing, at minimum:

- source array position as non-identity provenance;
- exact `type`, subtype, text/content presence, numeric `ts`, and `partial`;
- source-reported Roo session metadata when present in the supported direct
  task-history companion;
- direct agent/provider/model fields only when a verified source variant reports
  them; no inheritance or client-name synthesis;
- explicit semantic classification used by the legacy projection;
- tool request/result facts only when the subtype/source payload establishes
  them, with source call/tool IDs retained as correlation only;
- a bounded indication of final versus partial state.

The legacy parser SHALL map this native model to `ParsedRecord`. It SHALL NOT
re-read the source or reconstruct meaning from an already flattened record.
`ParsedRecord.session_id` is a required legacy grouping field, not a separate
provenance channel. Roo's native model therefore retains an optional direct
history namespace and the parser places it in that required field only when
validated; otherwise it places the locator-derived compatibility fallback there.
Kilo always uses that compatibility fallback because its pinned writer reports no
session companion. No core record-schema expansion is needed or permitted in
this bounded repair.
The alternative of retaining the generic parser was rejected because it guesses
from arbitrary fields, loses `partial` and subtype meaning, and cannot enforce
the metadata/identity boundary. A shared provider-neutral native type was
rejected to preserve per-source semantics.

### 3. Verified record schema and subtype taxonomy

The root document is a JSON array. Each record is an object with a required
`type` of `ask` or `say`; the corresponding subtype is `ask` or `say` from the
verified set below; `ts` is a numeric epoch-millisecond source timestamp;
`text`, `partial`, and other fields are optional according to the source
schema. A non-array root, non-object element, wrong subtype field, wrong field
type, or explicit unsupported variant is a terminal source-schema error.

The verified Roo subtype sets are:

| Type | Verified upstream values |
| --- | --- |
| `ask` | `followup`, `command`, `command_output`, `completion_result`, `tool`, `api_req_failed`, `resume_task`, `resume_completed_task`, `mistake_limit_reached`, `use_mcp_server`, `auto_approval_max_req_reached` |
| `say` | `error`, `api_req_started`, `api_req_finished`, `api_req_retried`, `api_req_retry_delayed`, `api_req_rate_limit_wait`, `api_req_deleted`, `text`, `image`, `reasoning`, `completion_result`, `user_feedback`, `user_feedback_diff`, `command_output`, `shell_integration_warning`, `mcp_server_request_started`, `mcp_server_response`, `subtask_result`, `checkpoint_saved`, `rooignore_error`, `diff_error`, `condense_context`, `condense_context_error`, `sliding_window_truncation`, `codebase_search_result`, `user_edit_todos`, `too_many_tools_warning`, `tool` |

Kilo uses the same persisted `ClineMessage` base fields but has its own pinned
known-subtype set. In addition to the common control values, Kilo recognizes
`ask:payment_required_prompt`, `ask:unauthorized_prompt`,
`ask:promotion_model_sign_up_required_prompt`, `ask:invalid_model`,
`ask:report_bug`, `ask:condense`, `ask:checkpoint_restore`,
`ask:browser_action_launch`, `say:browser_action`,
`say:browser_action_result`, and `say:browser_session_status`. These are
bounded `SessionMeta`/`Other` activity. Kilo does not recognize Roo's
`say:tool` or `say:too_many_tools_warning`; those remain terminal unknown
subtype failures for Kilo.

For Roo, the following is the bounded semantic mapping to existing
`ParsedRecord` kinds. It is a compatibility mapping, not a claim that a legacy
kind is a complete canonical lifecycle fact:

| Source fact | Actor/content interpretation | Legacy kind | Tool semantics |
| --- | --- | --- | --- |
| `say:user_feedback`, `say:user_feedback_diff` | user-provided text | `UserMessage` | none |
| `say:text`, `ask:followup` | assistant text or assistant request for user input | `AssistantMessage` | none |
| `ask:tool`, `ask:command`, `ask:use_mcp_server` | assistant/harness request awaiting approval or invocation | `ToolCall` | request only |
| `ask:command_output`, `say:command_output`, `say:mcp_server_response` | harness/tool output | `ToolResult` | result only; correlate only when explicitly reported |
| `say:completion_result`, `say:subtask_result` | assistant-produced result text | `AssistantMessage` | no execution-success inference |
| `say:reasoning`, `say:image`, `say:tool` | known source activity without a safe, complete legacy semantic contract | `Other` unless a focused fixture proves a narrower mapping | never fabricate request/result |
| API, retry, error, checkpoint, condensation, warning, todo, and other control subtypes | bounded source/control metadata | `SessionMeta` when no body text is required; otherwise `Other` | none |

`ask` is not automatically user content: an ask is an agent request that may
need a user response. Conversely, `say:user_feedback*` is the verified user
content form. `say:text` is assistant text unless a stateful source-owned
prompt-echo rule is separately proven; this change does not infer such a rule.
The Stage 2 fixtures must prove each non-`Other` mapping before enabling it.
An unverified subtype is never mapped by coincidental `text`, `tool`, or
`content` fields.

Kilo is limited to the legacy migration-store boundary and the independently
pinned legacy writer above. Its MCP parsing is duplicated in the Kilo native
module and is justified by `kilocode-legacy@ae046acafd17993bdf12dce0f81d9ac948e17ee8`,
not by assuming Roo behavior. It must not import semantics from current Kilo
SQLite/server/CLI records or from `api_conversation_history.json` into the
UI-message projection.

### 4. Actor, content, tools, timestamps, and partial/final behavior

Actor and content are explicit native facts:

- `say:user_feedback*` is user content; `say:text`, `ask:followup`, and
  explicitly supported result text are assistant content; control-only records
  do not become messages merely because `text` is present.
- Tool request facts come only from the three request asks. Tool names and
  structured arguments may be retained when the source payload explicitly
  identifies them; text parsing may not promote arbitrary text to a tool call.
- Tool result facts come only from explicit command/MCP output subtypes. A
  result does not imply that execution succeeded, completed, or was prevented.
- A source call/tool ID, if a future supported variant reports one, is a
  correlation field only. No current Roo `ClineMessage` field proves such an
  ID, and no Kilo migration evidence proves a stable one.
- `ts` is retained as a source timestamp only after numeric/bounds validation.
  It is not an ID, sequence, or occurrence-time substitute. No wall clock is
  consulted.
- `partial: true` is retained as an in-progress source snapshot. It is not
  coalesced with another record by `ts`, and it does not create a final record.
  `partial: false` is final for that persisted record only; it does not prove
  tool execution success. Existing source array order remains the compatibility
  order.

The upstream CLI uses `ts` for in-process deduplication and event IDs, and
upstream tests demonstrate equal timestamps. That operational use is not a
writer-level stable identity contract and is intentionally not promoted.

### 5. Agent/provider/model provenance

The verified Roo `ClineMessage` schema has no agent, provider, or model fields.
The Kilo migration UI-message evidence likewise does not establish them.
Therefore:

- direct fields are retained only when a source-owned, versioned variant and
  fixture prove them;
- omitted fields remain omitted; `roocode`, `kilocode`, an API protocol, a
  provider name, or a model name must not be synthesized as source-reported
  provenance;
- adapter/client identity remains separate source provenance and may not be
  copied into a source actor field;
- current Kilo SQLite model/provider fields remain out of scope.

The old repository fixtures containing synthetic `agent`, `provider`, and
`model` fields are characterization inputs, not upstream evidence. Stage 2 must
replace or explicitly label them while retaining a parity assertion for any
legacy behavior that is intentionally preserved.

### 6. Bounded metadata lookup and policy

`ui_messages.json` remains the only discovered body anchor. Companion lookup is
bounded to the exact names proven by the corresponding source:

| Client | Store-level metadata | Task-level metadata | Legacy alternate body | Canonical use |
| --- | --- | --- | --- | --- |
| RooCode | `_index.json` with `version: 1`, numeric `updatedAt`, and `HistoryItem[]` `entries` | direct non-empty `history_item.json.id` from the full `HistoryItem` | none selected | direct history ID may establish a session namespace; index only corroborates it; no per-message coordinate |
| KiloCode | none in the pinned legacy-writer contract | none in the pinned legacy-writer contract | `api_conversation_history.json` | no source-reported session namespace or per-message coordinate; alternate body is not selected |

Roo lookup is deterministic: the anchor parent identifies the task directory,
its parent identifies the task-store directory, and only the exact
`history_item.json` and `_index.json` locations are read. A direct non-empty
history `id` is authoritative. If an index exists, its bounded structure and
unique ID set must corroborate that direct ID; an index mismatch or duplicate is
a terminal metadata diagnostic, not permission to select the index ID. If
history metadata is absent, a valid index is checked for bounded structure but
contributes no namespace, even when an entry ID equals the directory name. A
directory name is a locator/compatibility fallback only. Kilo reads no
companions for this adapter; its alternate API body is never a retry or merge
source.

The policy is fail-closed and bounded:

- missing optional metadata means no metadata fact, not a path fallback;
- malformed history/index JSON, wrong root type, wrong field type, empty ID,
  duplicate index IDs, or disagreement between Roo `_index` and direct history
  yields one deterministic bounded metadata diagnostic and no source namespace;
- presence of `api_conversation_history.json` does not trigger a fallback or
  merge when `ui_messages.json` is malformed or unknown;
- Roo's legacy parent grouping value may support the required flat record field
  but may not become source-reported identity; Kilo's parent grouping value has
  the same compatibility-only status;
- a known source/schema failure is terminal. There is no generic parser retry.

The Kilo upstream reader's permissive `[]`/fallback behavior is migration
behavior, not permission to import Roo companions into this adapter. The source
parser must keep raw metadata, paths, and record text out of errors.

### 7. Formal identity candidate matrix

The matrix evaluates candidates against replay, append, edit, tail truncation,
middle deletion, insertion, and reorder. `Y` means the property is evidenced
for the stated purpose; `N` means it is not safe; `—` means the candidate is
not applicable because the source does not report it. A session namespace is
not a per-message coordinate.

#### RooCode (`roocode.tasks`)

| Candidate | Evidence / namespace | Replay | Append | Edit | Tail truncation | Middle delete | Insert | Reorder | Decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| session namespace | direct `history_item.id`; `_index.entries[*].id` only corroborates | Y† | Y† | Y† | Y† | Y† | Y† | Y† | READY only when direct history ID is valid and metadata checks pass; never from path |
| message ID | no field in `ClineMessage` | — | — | — | — | — | — | — | reject; absent |
| tool ID | no proven native call/tool ID | — | — | — | — | — | — | — | reject; correlation unavailable |
| source sequence | JSON array order, no writer contract | N | Y* | N | Y* | N | N | N | reject; producer order only |
| byte offset | no persisted offset | — | — | — | — | — | — | — | reject; absent |
| ordinal | array position; middle splice is supported | N | Y* | N | Y* | N | N | N | reject; explicitly unsafe |
| `ts` | numeric epoch-ms; operational dedup only | N | N | N | N | N | N | N | reject; no stable uniqueness/namespace |

#### KiloCode (`kilocode.tasks` legacy migration store)

| Candidate | Evidence / namespace | Replay | Append | Edit | Tail truncation | Middle delete | Insert | Reorder | Decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| session namespace | no session field in pinned legacy writer | — | — | — | — | — | — | — | NOT READY; parent path is compatibility-only |
| message ID | no proven native UI-message ID; API type optionality is not writer proof | — | — | — | — | — | — | — | reject; absent/unproven |
| tool ID | no proven native tool/call ID | — | — | — | — | — | — | — | reject; correlation unavailable |
| source sequence | whole-array legacy writer rewrite; no mutation coordinate contract | N | Y* | N | Y* | N | N | N | reject; producer order only |
| byte offset | no persisted offset | — | — | — | — | — | — | — | reject; absent |
| ordinal | whole-array rewrite; no middle-delete stability proof | N | N | N | N | N | N | N | reject; per-message identity NOT READY |
| `ts` | optional legacy timestamp; not unique/immutable | N | N | N | N | N | N | N | reject; source time only |

`*` A prefix can remain byte-for-byte stable in a particular append/truncate
operation, but the source contract does not promise that operation or preserve
the coordinate across rewrites. `†` A direct Roo history ID identifies a session
namespace only after the deterministic history/index checks pass; it does not
identify a message and does not make array order safe. Without direct history
metadata, an index entry that matches the directory name remains untrusted.

**Identity conclusion:** Roo has a READY session namespace only from a valid
direct `history_item.json.id`; `_index.json` is cache corroboration and the task
directory is a locator/compatibility fallback. Kilo's pinned legacy writer has
no source-reported session namespace, so its parent directory is compatibility
only. Neither source has an approved per-message coordinate, and both writers'
array order is unsafe across rewrites. Any future canonical projection therefore
requires protected assignment for every message lacking a native coordinate.
Protected-assignment implementation is outside P17R.

Rejected identity bases for both clients are paths, filenames, parent names,
timestamps, content hashes, random values, mutable ordinals, and unproven tool
or message IDs. A source coordinate must never be fabricated to make replay
appear verifiable.

### 8. Unknown variants, structural errors, and privacy

Unknown explicit `type`, ask/say subtype, malformed root/record, invalid
timestamp, contradictory metadata, and unsupported tool shapes are terminal
source-contract failures with stable code/detail vocabulary. The error's
Display/Debug and test diagnostics MUST contain only bounded categories; they
must not contain source paths, parent names, IDs, timestamps, message text,
tool arguments/results, URLs, credentials, raw JSON, or host paths.

Known records with a semantically unsupported subtype may be retained as
`RecordKind::Other` only where the mapping table says so; a known schema failure
must not be converted to `Other` and must not invoke another parser. Tool
requests and results are never inferred from text, and status/control messages
never upgrade a tool to execution success/failure.

### 9. Identity-readiness follow-up, bounded only

Because no per-message coordinate is proven, a separately reviewed protected
assignment design must later specify only these inputs and boundaries before
canonical projection work begins:

1. key inputs and how the protected key is provisioned;
2. the stable session namespace and assignment namespace;
3. the replay boundary and the source mutation boundary;
4. the semantic commitment covered by assignment;
5. local persistence class and crash consistency;
6. mutation and collision handling;
7. privacy and error/debug redaction;
8. artifact moves and source-root changes;
9. garbage collection and retention;
10. outbox interaction;
11. canonical-body construction timing;
12. the projector seam;
13. failure and offline behavior.

This list is a readiness contract, not an implementation plan. No generic
assignment framework, retry, or canonical projector is introduced here.

## Risks / Trade-offs

- **Source drift:** The canonical taxonomy is pinned to upstream evidence.
  Unknown variants fail closed instead of silently becoming messages or tools.
- **Legacy parity pressure:** The old fixture shape is not the pinned Roo
  schema. Realistic synthetic fixtures must replace it, and any intentional
  compatibility accommodation must be explicit and bounded rather than a
  generic fallback.
- **Identity incompleteness:** Roo can supply a direct task-history session
  namespace in the narrow checked case, while Kilo's pinned legacy writer
  cannot. Neither client supplies a proven per-message coordinate. This limits
  future canonical replay until protected assignment is separately designed.
- **Partial records:** Preserving partial snapshots can produce multiple legacy
  records where a live UI would show one updated row. Coalescing by `ts` would
  hide mutations and is therefore rejected for the source parser.
- **Metadata disagreement:** Failing closed may omit a legacy-compatible record,
  but silently choosing between Roo `_index`, direct history, and directory state
  would make replay and identity non-deterministic.
- **Kilo generation boundary:** The registered UI anchor is a legacy
  `kilocode-legacy` writer contract. The current Kilo product's migration reader
  is not evidence for Roo companion metadata, and current Kilo SQLite/server/CLI
  data remains out of scope.

## Migration Plan

There is no production canonical migration. Stage 2 replaces only the two
source-owned parser implementations, adds realistic synthetic fixtures and
focused source tests, updates source/support documentation, and preserves the
existing exact registrations and Event 3.0 output contract. Existing generic
fallback tests become characterization/parity tests or are replaced with
realistic records; they do not authorize a fallback parser.

The implementation must stop and request review if any of these gates fail:

1. **Truthful tool/UC-001 gate:** source evidence cannot establish truthful
   request/result mapping or the existing deterministic UC-001 support gate;
2. **Evaluation golden-delta gate:** a parser change alters an evaluation golden
   or Detection v2 shadow case—no golden or shadow update is in this change;
3. **Discovery-redesign gate:** `ui_messages.json` cannot remain the anchor or
   metadata requires a new source bundle;
4. **Foundational-defect gate:** exact parser ownership, privacy, structural
   failure, or identity boundaries cannot be preserved.

## Open Questions

No source-contract question is deferred beyond the bounded protected-assignment
readiness list. Whether a future source release adds a stable message/tool ID,
or whether Kilo publishes affirmative ordinal writer guarantees, requires new
upstream evidence and a separately reviewed change.
