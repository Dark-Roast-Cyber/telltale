# openclaw-qwen-canonical-observation-v2-adapters Specification

## Purpose

Define the completed P15 adapter contract for OpenClaw and Qwen JSONL sources.
The contract covers source-owned native interpretation, exact legacy
compatibility, Canonical Observation v2 projections, authoritative acquisition
routing, cross-adapter conformance, and offline shadow evidence. The reviewed
13-session corpus has zero unexplained mismatches. Production source evaluation
uses canonical acquisition and Detection v2 with Rule v1 content compatibility.
## Requirements
### Requirement: One source-owned native interpretation

Each in-scope adapter MUST read its JSONL source once into a source-owned native
record model that retains enough ordered source structure for both the exact
legacy projection and the Canonical Observation v2 projection. The model MUST
distinguish direct source-reported agent/provider/model values from effective
legacy inherited values, and MUST retain a zero-based source-record sequence.

#### Scenario: OpenClaw native record feeds both projections

- **WHEN** an OpenClaw JSONL source is read
- **THEN** the native records retain ordered content/tool structure and direct
  metadata, while the production parser maps those records to legacy output
  without independently rereading or reinterpreting the JSONL

#### Scenario: Inherited metadata is not direct metadata

- **WHEN** an OpenClaw record reports provider/model/agent and the next record
  omits them
- **THEN** the legacy projection inherits the first observed values, while the
  canonical projection does not mark those values as directly reported on the
  next record

### Requirement: Legacy projections remain unchanged

OpenClaw and Qwen legacy extraction MUST preserve existing record count/order,
session fallback, metadata inheritance, `RecordKind` classification, tool name,
legacy argument stringification, content flattening, empty-source behavior, and
schema/JSON failure behavior. Canonical mapping failures MUST NOT become legacy
parse failures.

#### Scenario: OpenClaw compatibility remains available after canonical failure

- **WHEN** an OpenClaw record has an unknown canonical content block
- **THEN** canonical projection fails closed, while the legacy parser retains its
  existing result or `RecordKind::Other` behavior

### Requirement: OpenClaw canonical source identity is bounded

The OpenClaw canonical projector MUST accept exactly `ClientId::OpenClaw`,
source ID `openclaw.agents`, and JSONL source kind. It MUST use
`SessionStore`, `PartialStructured`, adapter type `openclaw`, and adapter ID
`openclaw.agents`. It MUST require caller-controlled observed time and MUST NOT
  use a wall clock.

#### Scenario: Wrong OpenClaw identity is rejected

- **WHEN** a source has the wrong client, source ID, or source kind
- **THEN** canonical projection returns a bounded unsupported identity/kind
  error without reading the source path

### Requirement: Canonical session and coordinate identity are truthful

Canonical OpenClaw and Qwen observations MUST use a source-reported
`session_id`, `sessionId`, or `sessionID` as the session correlation and as the
scope for source sequence identity. A truthful source-native envelope/record ID
MUST take precedence when explicitly present. Call IDs, timestamps, content,
paths, filenames, project names, and hashes MUST NOT be observation identity.
When neither a truthful native ID nor a source-reported session-scoped sequence
is available, canonical construction MUST fail closed with the existing
`replay_unverifiable` vocabulary. Legacy filename fallback remains permitted
only for legacy output.

#### Scenario: Source session makes an ordinal stable

- **WHEN** two OpenClaw artifacts report the same source session and contain the
  same source ordinal with changed content or different paths
- **THEN** the corresponding canonical observation IDs are equal and semantic
  comparison is separate from identity

#### Scenario: Filename fallback is legacy-only

- **WHEN** an OpenClaw record omits source session identity and has no truthful
  native record ID
- **THEN** legacy parsing uses its existing filename fallback, while canonical
  projection fails closed rather than using that fallback

### Requirement: OpenClaw and Qwen canonical lifecycle is evidence-bounded

Truthful OpenClaw and Qwen user/assistant records MUST map to Message with
`MessageObserved`. Direct tool requests MUST map to Tool with `ToolRequested`.
Direct returned result/error facts MUST map to Tool with `ToolResultReturned`.
These JSONL adapters MUST emit only those three stages, MUST NOT emit
`ToolProposed`, `ToolExecutionStarted`, or `ToolExecutionCompleted`, and MUST
NOT infer execution success/failure from a completed/error UI or source status
alone.

#### Scenario: OpenClaw request and result remain separate

- **WHEN** an OpenClaw source contains a tool request and a returned result
- **THEN** canonical output contains separate requested and result-returned Tool
  observations and no invented execution stages

### Requirement: Ordered structured content is preserved

Known text, tool-use, and tool-result content blocks MUST retain source order.
Direct assistant `tool_calls` arrays MUST produce ToolRequested observations
without changing legacy flattening. A record containing only a tool result MUST
not produce a duplicate empty Message observation. Unknown explicit content
blocks or unsupported roles MUST fail closed rather than being reinterpreted as
messages or arbitrary `Other` bodies.

#### Scenario: Mixed assistant content has ordered children

- **WHEN** one assistant record contains text followed by a tool-use block
- **THEN** one ordered Message observation retains the content parts and a
  ToolRequested observation retains the structured request with deterministic
  child ordinals

### Requirement: Source call IDs are correlation only

Canonical tool observations MUST preserve a source call ID only when explicitly
reported by the source. Supported forms MUST be justified by source fixtures or
adapter tests, including OpenClaw tool-call array IDs, tool-result references,
and explicitly supported `call_id`/`callID`/`callId`/`toolCallId` forms. Missing
call IDs MUST remain absent; they MUST NOT be hashed, derived, or promoted to
native observation identity.

#### Scenario: Missing OpenClaw call ID is valid absence

- **WHEN** a directly represented OpenClaw tool request or result has no call ID
- **THEN** canonical projection may succeed with no `correlation.call_id` and
  does not fabricate one

### Requirement: Structured values and parsed facets are bounded

Canonical tool arguments and results MUST preserve source JSON object, array,
string, number, and allowed null structure through the existing bounded
source-value helper. A JSON-encoded source string MUST remain a string unless
the source type explicitly declares structured JSON. Explicit command/path
fields MAY produce Parsed `command.text`/`resource.path` facets, but MUST NOT
produce Process, File, Network, URL-scanning, or execution observations.

#### Scenario: Structured OpenClaw arguments remain structured

- **WHEN** an OpenClaw tool request has an object argument and a result has an
  object value
- **THEN** the canonical Tool bodies retain those values as bounded JSON and
  any direct path facet is marked Parsed

### Requirement: Canonical provenance and capability gaps are explicit

Every OpenClaw and Qwen canonical observation MUST carry source provenance and
capabilities. For both adapters, ToolCall MUST be Supported, UserContext MUST
be Supported, and ToolExecution MUST be Unknown. Tool results, output, or
statuses MUST NOT upgrade ToolExecution. Populated body fields and facets MUST
have exactly one matching FactMetadata entry with Reported or Parsed provenance
as appropriate.

#### Scenario: OpenClaw output does not claim execution

- **WHEN** an OpenClaw tool result contains output or an error status
- **THEN** capability resolution remains ToolExecution Unknown and the result is
  represented only as ToolResultReturned

### Requirement: Canonical errors are bounded and private

Canonical source, identity, mapping, unknown-discriminator, unknown-block, role,
and validation failures MUST use bounded error codes/details. Display and Debug
MUST NOT expose source paths, prompt/assistant text, arguments, results, URLs,
secrets, raw JSON, or unnecessary host paths. Unknown input MUST fail closed.

#### Scenario: Unknown input does not leak content

- **WHEN** canonical mapping rejects an unknown OpenClaw or Qwen record carrying
  synthetic text
- **THEN** error output contains only the bounded category/detail and no source
  content

### Requirement: Qwen follows the contract only after source evidence

The Qwen slice MUST select native IDs, supported content blocks, metadata paths,
call-ID forms, capabilities, and lifecycle semantics from source evidence. It
MUST preserve record-level compatibility output and provide canonical mapping
consistent with direct Qwen evidence.

#### Scenario: Qwen unsupported evidence is not copied silently

- **WHEN** Qwen source evidence cannot establish a stable native ID or stronger
  tool execution contract
- **THEN** the Qwen canonical slice fails closed or retains Unknown rather than
  inventing identity or lifecycle meaning

### Requirement: Conformance and shadow evidence remain offline

Cross-adapter vectors MUST compare canonical semantic family, compatible stage,
body facts, facets, linkage, and truthful capability absence without requiring
equal adapter IDs or native coordinates. Offline shadow/equivalence remains
measurement evidence and MUST NOT become a live dual-execution path.

#### Scenario: Equivalent vectors compare meaning, not adapter identity

- **WHEN** OpenClaw and Qwen produce equivalent synthetic message/tool vectors
- **THEN** conformance compares their semantic meaning while allowing source
  provenance and native coordinates to differ

#### Scenario: Offline shadow does not alter authority

- **WHEN** an OpenClaw or Qwen canonical vector is included in offline shadow
- **THEN** the existing deterministic legacy result remains authoritative and no
  live or production shadow path is enabled

### Requirement: Event 3.0 and adjacent source compatibility

Production scanning MUST consume OpenClaw and Qwen Canonical Observation v2
through the shared runtime. Exact parser ownership, Event3 schema/wire/privacy,
already-persisted events, Event4 inactivity, and the absence of a generic adapter
framework MUST remain unchanged.

#### Scenario: Existing compatibility behavior remains intact

- **WHEN** P15 adapter tests run beside existing Event3 and source regressions
- **THEN** Event3 bytes/behavior and unrelated adapter output remain unchanged,
  and no production v2 observations are required

### Requirement: Acquisition reuses source-owned canonical mapping

The authoritative public acquisition API MUST accept exactly
`(OpenClaw, openclaw.agents)` and `(Qwen, qwen.projects)` with `Jsonl` source
kind. It MUST validate identity and kind before source I/O. Each invocation
reaching extraction MUST invoke its existing native extractor exactly once and
map those records through the same source-owned canonical semantics as the
reference projector, without a
`ParsedRecord` or `NormalizedRecord` conversion.

Shared acquisition input MUST remain caller-owned `observed_at`, without SQLite
read controls. Both sources MUST return `AcquisitionProgress::None`. Acquisition
MUST preserve the identity, time, capability, and evidence-strength requirements
above, MUST NOT persist scanner state, and MUST NOT return a partial successful
batch or successful progress on mapping/validation failure. Source-read, mapping,
and validation errors MUST remain bounded and privacy-safe in Display and Debug.

#### Scenario: Acquisition matches the reference projection

- **WHEN** either source is acquired with a fixed observed time
- **THEN** observations preserve reference projection semantics and capabilities,
  source timestamps, structured tool evidence and source call linkage, with no
  invented execution or direct activity facts, and progress is `None`

#### Scenario: Acquisition preserves replay coordinates

- **WHEN** the same native coordinates are acquired repeatedly or from a renamed
  artifact
- **THEN** observation IDs and session correlation remain stable, native record
  IDs retain precedence over session-scoped sequence, and missing both identity
  forms fails closed rather than using a path or legacy filename fallback

#### Scenario: Invalid acquisition inputs fail before reading

- **WHEN** either identity is supplied with the wrong client or source kind
- **THEN** acquisition rejects it before invoking native extraction or reading
  its path

#### Scenario: All-eight authoritative acquisition feeds production

- **WHEN** authoritative public acquisition covers all eight source identities
- **THEN** scan, watch, and embedding consume those canonical batches through
  the shared runtime without legacy record conversion
