# Canonical Observation v2

> **Status:** **Accepted architecture.** Canonical Observation v2 is the
> reviewed intended future internal evidence contract. **Current
> implementation:** Canonical Observation v2 core domain types/scaffolding are
> implemented in `telltale-schema`. Claude Code (`claude.projects`), Codex,
> OpenCode (`opencode.sqlite`), OpenClaw (`openclaw.agents`), Qwen
> (`qwen.projects`), and Copilot (`copilot.process_log`) v2 reference
> projections are implemented as non-production projections. The offline
> shadow/equivalence harness includes Copilot across 15 cases, 17 reviewed
> sessions, and 306 detector evaluations. It reports one reviewed match-set
> difference plus 28 reviewed capability-driven indeterminate outcomes, with
> zero unexplained differences. These
> projections are not production detector input: production remains on
> `telltale_schema::record::NormalizedRecord` and Rule v1, with no live shadow
> or production parity. `NormalizedRecordV1` is separate timeline/export-oriented
> compatibility material.
> Copilot native-v2 capabilities are ToolCall **Supported**, UserContext
> **Unsupported**, and ToolExecution **Unknown**.
> `opencode.legacy_json` is retired, and production adapter runtime cutover has
> not started. The public `telltale_sources::acquisition` contract now covers
> `claude.projects`, `codex.sessions`, `codex.archived_sessions`,
> `codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
> `qwen.projects`, and `copilot.process_log`—all eight target identities. The P10B
> identity/conformance amendment is implemented: stable identity is
> coordinate-only and semantic comparison is separate. **Existing
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

The Claude Code, Codex, OpenCode SQLite, OpenClaw, Qwen, and Copilot v2 reference
projections are deliberately not active normalization paths. They preserve
source call IDs, structured content parts, structured tool values, and truthful
lifecycle stages while the production scanner continues to use
`telltale_schema::record::NormalizedRecord`. The experimental Detection v2 foundation exists, but
production activation and telemetry/output v2 have not started. The Event4
contract foundation is implemented without a Canonical Observation v2
projection or production output path, and Event 3.0 remains frozen.

## Acquisition convergence status

The public `telltale_sources::acquisition` module, including its public batch,
options, progress, error, and router functions, owns authoritative cross-source
acquisition for all eight identities:
`claude.projects`, `codex.sessions`, `codex.archived_sessions`,
`codex.headless_sessions`, `opencode.sqlite`, `openclaw.agents`,
`qwen.projects`, and `copilot.process_log`. The single router performs
source-native extraction, calls the source-owned crate-private canonical mapper,
and returns an acquisition batch. All eight use explicit caller-owned
`observed_at`.

The OpenCode-specific `acquire_opencode_sqlite` entry point accepts a part
minimum-update coordinate and part limit, and returns separate progress as the
selected part-row `time_updated` high-water value. These read controls and
progress are source-specific operational metadata, not canonical evidence,
provenance, occurrence time, or durable state; the acquisition call does not
persist a cursor. The other seven identities return
`AcquisitionProgress::None`, and do not share the OpenCode controls.

Copilot reuses source-local stateful native interpretation, but has no durable
progress coordinate or durable local acquisition state. Its active session and
ordinal state is rebuilt on each acquisition.

The all-eight adapter coverage gate and ROADMAP step 4 convergence are complete.
The experimental parallel top-level canonical facade has been deleted; the
acquisition module is the single public cross-source router. This does not
activate production: the legacy detection and embedding paths remain unchanged.
Scanner-owned processing success now gates OpenCode cursor commit eligibility;
acquisition progress reporting is unchanged and still does not persist a cursor.
Step 5 Tranche A adds inactive canonical session evaluation and Event3
compatibility; coordinated scan/watch/embedding activation remains later work
under Issue #51. Event 3.0 remains frozen and Event4 remains inactive.

Acquisition directly maps source-native facts to Canonical Observation v2. It is
not a conversion bridge to or from `NormalizedRecordV1`; the later coordinated
runtime cutover remains a separate step.

### Shared inactive source runtime

`telltale-core::canonical_runtime` owns the single source-semantic composition:
acquisition → COv2 → Detection v2 → Event3 compatibility → canonical activity.
It is a hidden, deliberately unstable cross-crate seam, not a supported public
embedding API. The inactive CLI adapter and private `Pipeline` canonical adapter
both call it. The existing core crate already depends on sources, rules, and
detection; it does not depend on CLI code.

The operation takes caller-owned observation time, optional acquisition read
bounds, effective Rule v1 compatibility content, optional canonical process-chain
configuration, and explicit prior baseline context. It returns source-atomic
semantic output or typed failure; no partial successful event set escapes a late
activity failure. Completion and acquisition accounting coverage remain separate.
The resolved-file canonical correlation identity is unchanged and is not a durable
baseline replacement key.

The inactive embedding adapter uses one observation time for a whole root scan,
shared discovery, no process-chain configuration, an empty prior snapshot store,
and disabled baseline deviation. It creates activity from accounting without
inventing history or persisting replacement candidates. OpenCode remains partial
and cannot produce whole-source replacement. Scanner cursor policy, mode policy,
error-event adaptation, state installation, and output transactions stay in the
CLI; event allowlisting stays outside the semantic operation.

The supported `Pipeline::scan_root` remains legacy-selected, with unchanged
outputs/errors. Canonical activation would add activity output and requires an
explicit decision on typed failures versus the current scanner-error stream.
Canonical metadata/visibility corrections also require compatibility review.
Event3 constructors retain fresh envelope IDs/times; semantic ordering, not
byte-identical envelopes, is deterministic. Record-level `detect_records` and
`evaluate_session` remain intentional legacy compatibility APIs rather than a
second source-runtime design. Coordinated activation still requires scanner
transaction integration and reset prerequisites, followed by deletion of the
temporary legacy source branch. Step 5 remains incomplete; Event3 is frozen and
Event4 inactive.

### Inactive session attestation and accounting

Issue [#51](https://github.com/Dark-Roast-Cyber/telltale/issues/51) Tranche B3A adds
`AcquisitionBatch.accounting`, owned by acquisition from the same native read.
`SourceAccounting` contains source-reported canonical session IDs **with origin**,
per-field agent/model/provider attestation, and native accounting. `Missing`,
`Known`, and `Ambiguous` are distinct: absent values do not erase known evidence;
distinct values discard the retained candidate and become ambiguous. No client,
filename, tool, or content-derived metadata defaults are used. Existing COv2
capabilities remain separate from per-session value absence.
Each adapter selects metadata only from source-defined semantic envelopes. If
recognized native session coordinates for one unit disagree, acquisition fails
closed rather than selecting an alias or importing joined metadata across sessions.

Each session and the explicitly unscoped bucket retain native-unit counts and
native-derived legacy record-kind counts. JSONL units are extracted JSON objects;
SQLite units are message rows and selected text/tool part rows, including parents
suppressed by canonical mapping; Copilot units are workspace-initialization events
and accumulated output items, not arbitrary log lines or completion controls.
These are batch counts, not whole-store, deduplicated, or lifetime totals.
Legacy activity `record_counts` is a kind histogram, not a COv2 observation count:
one Claude tool-use record can emit both message and tool observations, while one
Copilot call can count as two legacy kinds. Unscoped counts have no invented session.
For native tool-call units, the same sidecar also retains normalized tool-name,
path-class, and network-host contribution counts, including semantic indicators
from source fields that COv2 intentionally omits. It does not retain flattened
legacy content, raw envelopes, commands, arguments, or source paths. This is the
single contribution input for later baseline convergence; B3B must not recount
overlapping COv2 arguments.

Retained strings use the COv2 local string limit (4,096 bytes); acquisition caps
session cardinality at 4,096 because metadata-only sessions need not emit any
observations. Potential contribution tokens and retained labels use the same local string limit,
and each batch permits 4,096 distinct contribution keys across scoped and
unscoped buckets. One acquisition-owned budget is checked before each new map
entry, including during derivation, not only after aggregation. Native records
retain no per-unit contribution maps. Legacy parsers do not compute these inactive
contributions; canonical acquisition borrows existing native projection fields
without another source read, reconstructed records, or a new raw-input sidecar.
Internal SQL transport aliases are not source JSON ownership evidence, and ignored
Copilot items cannot attest metadata. Counts use checked `u64` arithmetic. Invalid/oversized metadata
or contribution input, capacity exhaustion, and overflow fail with code-only errors. Missing and
ambiguous metadata remain successful acquisition. Debug rendering hides labels
and session IDs. The inactive composition borrows only known fields for exact
evaluated session keys into Event3 projection and retains the single accounting
sidecar on successful Complete or VisibilityLimited processing. Cursor policy
and projection's fail-closed origin/collision validation are unchanged.

B3B's inactive activity/baseline integration and pre-1.0 compatibility decision
are described below. Client is available from the source; agent/model/provider
can each be missing or ambiguous. Current baseline keys cannot express ambiguity,
and legacy sticky/default metadata and fallback session grouping differ. Old
snapshots therefore cannot be assumed reusable. Event3's existing kind histogram
is not repurposed; B3B preserves its vocabulary with sparse checked conversion,
native contribution consumption, and prior-snapshot timing.
Acquisition itself produces no activity events or baseline state. Validation covers
all eight native identities, conflicts, bounds/privacy, counts, and projection.
Activation requires reviewed B3B, embedding convergence, scanner transaction
integration, and coordinated runtime cutover; then remove
legacy metadata/count derivation and temporary legacy activity carriers. Scan,
watch, and embedding remain legacy; Event3 is frozen, Event4 inactive, Step 5 incomplete.

### Inactive canonical activity and baseline staging

Current production baseline state aggregates the latest retained contribution for
each source instance; it is not a lifetime counter or a defined rolling window.
Legacy scanning replaces a source contribution and evaluates activity against a
snapshot taken before that update. OpenCode reads all messages but only a capped,
cursor-filtered selection of parts, with ten minutes of overlap. Consequently,
replacement can discard older parts outside the selection; addition would instead
count overlap again. An unchanged-source fingerprint does not solve changed,
partially overlapping batches.

B3A.1, committed at
`2c7bc2878ff28224b154d0151260a8430814c1f0`, adds explicit source-instance
coverage. Exhaustive file reads are `CompleteSource`; current bounded OpenCode
reads are `PartialSource`. This resolves the prerequisite for file support, but
does not make an OpenCode partial batch a replacement or an additive population.
The prior overlap analysis remains authoritative: a previous A+B read followed
by a B+C read would either lose A under replacement or train B twice under
addition. Partial coverage is therefore disallowed for baseline storage, not a
blocker to producing truthful file activity or to supporting a successful partial
operation.

The unchanged frozen Event3 constructor permits truthful batch session activity for
`PartialSource`: Known metadata is retained and Missing or Ambiguous fields are
omitted. A successful partial operation can progress, but it produces no baseline
storage or deviation and returns `NoReplacement`.

`CompleteSource` returns an explicit `BaselineReplacement::Replace(Vec<BaselineSummary>)`,
including `Replace(empty)` to clear stale sessions excluded by the current
eligibility policy. An Ambiguous agent, model, or provider excludes that session
from baseline storage and deviation, but is not a processing failure. Missing
fields use the existing optional baseline keys; missing model/provider suppresses
deviation while missing agent does not. Unscoped accounting never creates a
session, activity, or baseline; a complete unscoped-only source therefore returns
`Replace(empty)`.

The inactive evaluator consumes authoritative `SourceAccounting` counts and
contributions once: it does not recount COv2, reread the source, or reconstruct
legacy records. Sparse six-kind histograms use checked `u64` to `u32` conversion.
Normalized plaintext hosts are hashed with the existing `sha256:` host identity
before a candidate is retained, and aggregation is checked. Evaluation uses the
immutable canonical evaluation, accounting, source path hash, prior snapshots,
and configuration; the prior snapshot includes the old same-source contribution
and the current sample never trains its own comparison snapshot.

The inactive scanner result retains the accounting sidecar transiently alongside
the baseline replacement and emits one terminal Event3 collection. Source errors
discard events and replacements, and `Failed` gates progress. Scanner-owned
`CanonicalProcessingOptions` owns `dry_run` and `backfill`: the pure evaluator may
build a candidate, but composition suppresses staging to `NoReplacement` for
both modes. No canonical state mutation, install, or apply occurs in production. A
future state owner applies a replacement using the authoritative `Source` key,
not the canonical correlation hash.

No persisted schema or reset is active now. Coordinated activation must reset both
legacy source contributions and derived snapshots once, durably: reserve the
baseline schema increment from current 2 to 3, clear both and write a new stamp
transactionally in an explicit migration, and never silently reset on load or at
process start. The strict current state envelope 1.0 remains unchanged for now.
Future aggregate application must be checked and source-atomic before install;
the existing legacy apply is unchecked and is not activated by B3B. Production
scan/watch/embedding remain legacy; Event3 is frozen, Event4 inactive, and Step 5
incomplete. Independent review and activation remain separate gates.

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

Keys and commitments never enter an export. Key unavailability on the
persisted-assignment path remains fail-closed and must not be presented as a
deterministic source-coordinate ID.

Persisted assignment state is durable replay state, not source identity. The
optional local store in `telltale_core::assignment` requires a caller-proven,
versioned replay association that remains attached to exactly one source fact
across every supported mutation. It HMAC-protects raw association material
before lookup or persistence and atomically binds the protected replay key,
adapter domain, child ordinal, random opaque assignment reference, protected
commitment, comparison-key reference, and assigned observation ID. The random
seed used for first allocation is not a source coordinate; the committed
assignment is the identity authority. Initialization and reopen are separate:
reopen never recreates missing state. An authenticated append-only local receipt
chain outside SQLite detects assignment-row/database deletion or rollback before
absence can be interpreted as a first claim.

Matching bound assignment and commitment is an idempotent replay; changed
complete content is `replay_collision`. Missing, ambiguous, corrupt, or
unverifiable assignment/key state is `replay_unverifiable` or a bounded local
store error. Without both a safe replay association and durable assignment,
normalization fails closed rather than creating an ephemeral identity. Paths,
timestamps, mutable ordinals, bare producer coordinates, semantic values, and
unkeyed content hashes remain invalid reassociation substitutes even though the
store is local.

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
schema](normalization-schema.md). The authoritative packaged Event4 4.0
structural schema at `crates/telltale-schema/data/event-4.0.schema.json` is an
external contract boundary, not the internal observation schema.
