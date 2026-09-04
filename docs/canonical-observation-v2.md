# Canonical Observation v2

> **Status:** **Accepted architecture.** Canonical Observation v2 is the
> reviewed intended future internal evidence contract. **Current
> implementation:** Canonical Observation v2 core domain types/scaffolding are
> implemented in `telltale-schema`. A Claude Code (`claude.projects`) v2
> reference projection and a Codex v2 reference adapter family are implemented
> as non-production projections. An OpenCode (`opencode.sqlite`) v2 reference
> projection is also implemented as a non-production projection. The
> `opencode.legacy_json` source remains supported and its v2 migration has not
> started; `opencode.project_json` remains Candidate and its v2 migration has
> not started. These projections are not the production detector input, and
> production adapter cutover has not started. The P10B identity/conformance
> amendment is implemented: stable identity is coordinate-only and semantic
> comparison is separate. **Existing
> compatibility:** Event 3.0 remains the current frozen external compatibility
> and output contract.

The accepted data path is:

```text
source-native fact -> Canonical Observation v2 -> detection / analytics
                                           \-> policy / future projections
```

Canonical Observation is the unit of evidence. It is local-first and richer
than any export. Detection consumes it, not Event4 or a destination-specific
projection.

The Claude Code, Codex, and OpenCode SQLite v2 reference projections are
deliberately not active normalization paths. They preserve source call IDs,
structured content parts, structured tool values, and truthful lifecycle stages
while the production scanner continues to use `NormalizedRecordV1`.
`opencode.legacy_json` remains supported and `opencode.project_json` remains
Candidate; neither source's v2 migration has started. Detection v2, Event4, and
telemetry/output v2 are not started, and Event 3.0 remains frozen.

## Conceptual contract

```text
CanonicalObservationV2 {
    observation_id: ObservationId,          // required, Telltale-owned
    kind: ObservationFamily,                // required, closed set
    stage: ObservationStage,                // required, family-compatible
    occurred_at?: SourceTimestamp,          // truthful source clock only
    observed_at: TelltaleObservedAt,        // required acceptance clock
    sequence?: non-negative producer-local sequence,
    session_id?: CorrelationId,             // meaningful source/configured ID only
    workflow_id?: CorrelationId,            // explicit workflow correlation only
    correlation?: CorrelationIds,           // one location for remaining IDs
    source: SourceProvenance,                // required
    capability_context?: CapabilityContext,
    body: TypedFamilyBody,                   // closed body matching kind
    facets?: Map<FacetName, SemanticFacet>,
    fact_metadata?: Map<FieldPath, FactMetadata>,
    local?: LocalEvidence,
    identity_basis?: StableIdentityBasis,
    semantic_comparison: SemanticComparison // local comparison state only
}
```

`session_id` and `workflow_id` are the only top-level correlation IDs. Turn,
request, response, call, trace, span, delegation, parent-observation, and
process-instance IDs occur only in `correlation`. Correlation values are opaque
and carry an explicit `source_reported` or `telltale_originated` origin; their
characters do not establish meaning. There are no aliases or duplicate ID
locations.

There is deliberately no `materialized_at` on an observation. Materialization
belongs only to the Event4 terminal representation. A collector's `received_at`
is transport metadata and is never copied into observation time.

## Observation families

The bounded initial family set is:

| Family | Evidence meaning |
| --- | --- |
| `Message` | One conversation message. |
| `Inference` | One model request lifecycle fact; failure is not a Tool stage. |
| `Tool` | One tool intent, execution, or result lifecycle fact. |
| `ToolDefinition` | One tool definition or definition-change fact, separate from a call. |
| `MCP` | MCP inventory, instruction, or change evidence; active connection is not implied. |
| `Process` | Direct agent-relevant process activity/state evidence only. |
| `File` | Direct agent-relevant file activity/state evidence only. |
| `Network` | Direct agent-relevant network activity/state evidence only. |
| `Browser` | Bounded browser surface, origin, page, or navigation metadata. |
| `Runtime` | Bounded execution-mode, isolation, workspace, or privilege context. |
| `Session` | Session lifecycle evidence and safe context references. |
| `Other` | A finite registered escape hatch, not an arbitrary source dump. |

Typed bodies are closed. Their minimums are: Message needs a role; Inference
needs provider or requested/resolved model; Tool needs a name, argument, result,
or reported status; ToolDefinition needs a change and an identity/name/reference
or hash; MCP needs a change; Process, File, and Network need an operation/state
with direct observed provenance for at least one populated fact; Browser needs a
state marker; Runtime needs a state marker; Session needs a meaningful session
ID and lifecycle; and Other needs a registered kind/version/classification plus
a safe summary or local reference. The `Other` registry is finite and versioned.

### Tool lifecycle

Tool lifecycle observations are separate instances, not mutations:

```text
proposed -> requested -> execution_started -> execution_completed -> result_returned
```

A source may expose any subset. Proposal is not request, request is not
execution, execution start is not success, completion is not a returned result,
and a missing later stage is unknown/not-visible rather than failure. A truthful
source-reported status may be `succeeded`, `failed`, `cancelled`, `denied`, or
`unknown`, but it does not change the stage. `is_error` is not inferred from a
missing result.

Parsing a command, path, URL, process name, or tool result produces a parsed or
derived fact. It does **not** produce observed process execution, file activity,
or network activity. Direct OS, file, or socket evidence may produce a separate
Process, File, or Network observation linked by explicit correlation.

## Time, identity, and replay

`occurred_at` is optional source-reported time. Invalid, untrusted, or absent
source time is omitted, never replaced by a collector or fallback clock.
`observed_at` is required Telltale acceptance time. An observation `sequence`
and source sequence/offset are optional producer-local coordinates; they are not
global ordering claims. A later detector must name the ordering dimension it
consumes and treat missing data as ineligible.

`observation_id` is Telltale-owned and distinct from Event4 `event_id`, source
IDs, session IDs, collector IDs, and delivery IDs. It identifies a canonical
source fact; it is opaque and is not an authentication proof. When a stable
source coordinate exists, Telltale derives the ID from exactly this
domain-separated canonical tuple:

```text
["telltale:canonical-observation-coordinate-id-v1", adapter_type, adapter_id,
 coordinate_kind, coordinate_value, family, stage, child_ordinal]
```

Semantic values, semantic fingerprints, adapter versions, key epochs, paths,
filenames, session titles, collection locations, privacy keys, and HMAC
material are not in this tuple. Adapter version remains provenance only. The
textual form is:

```text
obs:v2:sha256:<64 lowercase hexadecimal digits>
```

Coordinate selection is deterministic and ordered: `source.native_id`, then an
identity-eligible scoped source sequence, then an identity-eligible scoped
offset. A producer-local sequence or offset is provenance only unless its
uniqueness namespace is explicit and stable. A scoped source sequence is
encoded in the coordinate value as `["session", namespace, ordinal]`. Empty,
newline-containing, slash-containing, backslash-containing, and `..` namespaces
are rejected. If none exists, a protected persisted assignment is required.
Telltale must not invent an ID from a path, filename, batch, collector value, or
inferred parent name.
`source.native_id` is optional and must be a truthful source-native identifier,
never one derived from a prompt, tool, path, or other semantic content.

Canonical identity encoding uses UTF-8 JSON, NFC strings and sorted object keys,
compact separators, unescaped non-ASCII UTF-8, rejection of non-finite numbers
and unpaired surrogates, and SHA-256 with lower-case hexadecimal output. A
semantic fingerprint excludes timestamps, source/admin metadata, capability and
profile references, and raw references. Sensitive semantic values enter only as
structural location, sensitivity class, and a producer-local keyed digest.

Semantic comparison is separate from source-fact identity. All-Normal values
use the existing unkeyed semantic fingerprint at epoch `none`. Sensitive,
secret, and reference-only values use keyed fingerprints when available; if a
stable coordinate exists but a sensitive value has no keyed fingerprint,
construction still succeeds with `SemanticComparison::Unavailable` and the
sensitive value is never hashed unkeyed. Keyed fingerprints and epochs remain
local comparison material and do not enter `observation_id`.

`SemanticComparison::compare` returns `Equivalent` only for equal comparable
fingerprints in the same epoch, `Mutated` for different comparable fingerprints
in the same epoch, and `Incomparable` when either side is unavailable or epochs
differ. Unavailable versus unavailable is not equivalent, and an epoch mismatch
is not mutation. Comparison material has no generic serde/export path and is
redacted from Debug/Display.

Keys and commitments never enter the observation or an export. Key
unavailability on the persisted-assignment path remains fail-closed and must
not be presented as a deterministic source-coordinate ID.

Persisted assignment state is durable replay state, not source identity. It must
contain protected comparison state. Matching assignment and commitment is an
idempotent replay; changed content is a replay collision. Missing assignment
state or comparison key is `replay_unverifiable`. Without a stable coordinate or
protected assignment, normalization fails closed rather than creating an
ephemeral identity.

## Provenance, fidelity, and capability

Source provenance describes the adapter and source coordinate. It is separate
from fact provenance, which applies to each populated body field or facet:

| Fact provenance | Meaning |
| --- | --- |
| `reported` | The source explicitly asserted the value. |
| `parsed` | Telltale extracted the value from source structure or text. |
| `derived` | A deterministic transformation of known facts produced it. |
| `inferred` | A heuristic or model interpretation produced it. |
| `observed` | Adapter semantics establish direct activity or state evidence independent of a request or description. |

`observed` is not a stronger spelling of `reported`. A log saying “completed”
is reported unless direct activity evidence exists. In particular, parsed
command/path/URL/process facts are not observed process, file, or network
activity.

Fidelity is independent of provenance and capability:

| Internal fidelity | Meaning | Event4 mapping |
| --- | --- | --- |
| `full_native` | Relevant native structure is retained. | `exact` |
| `partial_structured` | Structured data exists but relevant fields/parts are missing. | `partial` |
| `flattened_lossy` | Flattening removed distinctions needed for semantics. | `lossy` |
| `derived_only` | Only a deterministic derivative is available. | `lossy` |
| `unknown` | Representation quality cannot be established. | `unknown` or omit |

Capability availability is exactly `supported`, `unsupported`, or `unknown`.
Supported means a source can provide a fact if it occurs; it does not assert
occurrence. Unsupported means the source cannot provide it. Unknown means the
adapter cannot establish whether it can. Unresolved capability queries resolve
to `unknown`. Unsupported and unknown are never clean, false, or empty values.

## Facets and local evidence

The model is a bounded hybrid: typed family bodies carry stable semantics, while
governed facets avoid a new family variant for every provider field. Canonical
facet namespaces are:

```text
session.*   message.*   tool.*       command.*   resource.*
network.*   process.*   inference.* mcp.*       runtime.*   browser.*
```

Facet names are canonical paths, not source-native keys. Each facet carries its
value; the matching `FactMetadata` entry carries provenance, optional fidelity,
sensitivity, and keyed fingerprint. Every populated semantic body field and
facet has exactly one metadata entry, with core administration explicitly
excluded from that requirement.

Tool arguments/results and ordered message content parts remain structured when
available. A searchable text form may coexist, but it is a derivative and never
the semantic source. Large or binary data is bounded or represented by an
opaque local reference. `local.structured_values` is a finite governed registry,
not a native-key map; values are bounded, marked, and policy-controlled.

`local.raw_ref` and value-level raw references are local-only. They are opaque
handles, never copied payloads, never silently serialized to Event4, and never
marked exportable merely because a detector can see them.

## Absence and cross-source equivalence

Consumers use value presence, capability, fact metadata, and analytic status:

| Situation | Meaning |
| --- | --- |
| Present `false` with metadata | Known false. |
| Present negative status/value with `reported` provenance | Source explicitly reported a negative. |
| No value on a present record | No claim about the fact. |
| `unsupported` capability | Not visible; never clean. |
| `unknown` capability | Visibility unresolved; never clean. |
| Not applicable family | Ignore that field for the family. |
| Not evaluated analytic | No detection conclusion. |

Empty strings, fabricated false values, fallback timestamps, path-derived
sessions, and placeholder IDs are not absence representations.

Two adapters are semantically equivalent when they produce the same family,
compatible stage, normalized semantic facts, causal linkage, and truthful
absence/capability behavior. Adapter identity, native IDs, coordinates,
provenance, fidelity, and local references may differ. Lower-fidelity adapters
must omit unavailable fields rather than fabricate them to match a richer source.

## Event4 and compatibility

Canonical Observation v2 is local truth and Event4 is a later privacy/export
projection:

```text
Canonical Observation v2 -> privacy/export policy -> selected Event4 projection
```

Not every observation exports. Event4 `event_id` remains distinct from
`observation_id`; Event4 alone gains `materialized_at`. A Session observation may
map to the Event4 `session` body when eligible; it does not become an Event4
observation by conversion. Detection targets canonical body fields and facets,
not Event4 or destination JSON.

> **Event 3.0: FROZEN / CURRENT COMPATIBILITY CONTRACT**

Event3 remains supported. Existing persisted/replayed Event3 bytes, IDs,
parser ownership, deterministic scoring, privacy behavior, and durable JSONL
semantics are unchanged. Event4 is independently versioned, does not replace
Event3 until explicit migration gates pass, and future semantics are not
backported. Event3 and Event4 are independent projections from common accepted
internal semantics, not canonical conversions of each other.

See the [Event4 architecture](event4.md) and the [current normalization
schema](normalization-schema.md). The [Event4 draft schema](../schemas/event4-draft.schema.json)
is an **architecture draft / not runtime-supported** and is not the internal
observation schema.
