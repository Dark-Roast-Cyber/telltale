# Inference and runtime acquisition

**Status: accepted bounded first implementation for
[Issue #49](https://github.com/Dark-Roast-Cyber/telltale/issues/49), not shipped
behavior.** The accepted bounded extension implements explicit frozen OpenAI
Chat JSON/SSE, Anthropic Messages JSON/SSE, OpenAI Responses HTTP JSON/SSE and
Ollama `/api/chat` JSON/NDJSON profiles, with shared atomicity, bounds,
identity-isolation and secret-safe diagnostic gates. These are Linux synthetic
subsets, not live interoperability evidence. Runtime acquisition, WebSockets,
Bedrock/Vertex dialects and production/gateway integration remain deferred.
The crate README (`crates/telltale-inference/README.md`) defines the actual
supported subsets, versions and conservative unsupported statuses.
Investigation baseline:
`dcb36a81bb93eec2654b84107e3deb835f1b9818`; primary sources consulted 2026-10-01.

COv2 acquisition and Detection v2 production convergence are complete. Event
3.0 is the sole production output. Event4 production activation and generalized
`CanonicalPayload` remain deferred in
[#55](https://github.com/Dark-Roast-Cyber/telltale/issues/55). Nothing here adds
a proxy, sensor, policy/enforcement runtime, output contract, or supported source.

## Decision and ownership

```text
existing session/store adapters --\
caller transport -> inference -----> COv2 -> one Detection v2 core
caller collection -> runtime -----/       -> existing eligible Event3 projection
```

Normalize source-native evidence directly into COv2, never through
`NormalizedRecord` or Event3. Keep session adapters for retrospective scanning,
offline/unmanaged deployments, compatibility, and source-specific enrichment.
The eight exact production `(ClientId, source_id)` identities and their parser
ownership remain unchanged. NemoClaw/OpenShell deployment does not establish a
new agent identity: reuse the actual agent's native adapter where applicable.

Experimental `telltale-inference` owns protocol interpretation, bounded incremental
framing/reconstruction, lifecycle mapping, and COv2 construction. Dependencies
point inward to `telltale-schema` and existing JSON parsing facilities; it must
not depend on CLI, session parsers, detection, sinks, HTTP clients/servers,
provider SDKs, async runtimes, or OpenShell. A concrete optional runtime adapter
owns OpenShell OCSF interpretation separately from agent parsers. Decide its
crate packaging when its pinned mapping is accepted; do not introduce a generic
runtime/plugin framework. Gateway or middleware transport, TLS, authentication,
credential substitution, connection limits, persistence, and actions are callers'
responsibilities, not normalizer responsibilities.

The implemented local API (not a published stable Rust API) is:

```text
Normalizer::with_profile(profile, identity, capture_policy, limits)
accept_request(bytes, observed_at) -> bounded COv2 batch or code-only failure
begin_response(format) -> code-only status
push_response(bytes, elapsed_ms) -> code-only status, never response facts
finish(end_reason, observed_at, elapsed) -> bounded batch/status
```

Initial tranches accept stable source coordinates only; `identity_context` is
verified coordinate scope, not a protected-assignment integration. Coordinate-less
facts fail closed and their support is deferred as described below.
One normalizer handles one attempt; the caller bounds concurrent instances and
drains output. Bytes are already HTTP transfer-decoded/decompressed under caller
limits. The normalizer owns SSE/NDJSON framing, not HTTP framing. Caller supplies
acceptance time for each accepted fact and monotonic elapsed time for deadline
checks; no internal clock, network, filesystem, logging, persistence, sleeps, or
retries. Explicit end reasons distinguish protocol terminal, EOF, upstream
error, cancellation, transport failure, and timeout. A closed acquisition status
reports unsupported profile, visibility limits, truncation, malformed input,
capacity, or identity failure without inventing canonical evidence.

## Protocol evidence and proposed mapping

“Compatible” is a selected, versioned wire profile, not a promise that every
provider implements the vendor API. Do not auto-detect another dialect after
a known-profile parse failure. Provider attribution comes from verified caller
configuration or explicit source fields, not the API dialect, hostname guess,
model spelling, or agent name. Preserve requested and source-reported resolved
model separately; neither authenticates the provider.

| Profile / primary source | Observed protocol contract | Proposed COv2 mapping and limits |
| --- | --- | --- |
| [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create), REST `v1` | Request messages and function definitions; response choices; streaming deltas, indexed tool calls, finish reasons, `[DONE]`; optional final usage chunk | Request -> InferenceRequested; complete messages -> MessageObserved; definitions -> DefinitionChanged with change `present`, not an inferred inventory diff. Completed response calls -> ToolProposed. Tool-role request messages -> ToolResultReturned using explicit `tool_call_id`. Reconstruct independently by choice/tool index. Missing final usage is unknown, not zero. |
| [OpenAI Responses streaming](https://developers.openai.com/api/docs/guides/streaming-responses) and [function calling](https://developers.openai.com/api/docs/guides/function-calling#streaming), REST `v1` | Typed lifecycle/item/argument events; response and item IDs distinct from `call_id`; `function_call_output` feeds results back | Implemented separate HTTP profile, not a Chat alias. Explicit request/response/call IDs remain distinct; item IDs are selected sensitive local evidence, not call IDs. Only completed lifecycle plus matching closed item snapshots commits. Failed/incomplete states reject. Built-in tools and previous-response/conversation references are unsupported; no history reconstruction. |
| [Anthropic Messages streaming](https://platform.claude.com/docs/en/build-with-claude/streaming), `anthropic-version: 2023-06-01` | `message_start`, indexed block start/delta/stop, message deltas and `message_stop`; pings and in-stream errors; tool input JSON fragments; cumulative usage | Reconstruct by block index, parse tool arguments only after block closure; commit response facts only on valid message termination. `tool_use` -> ToolProposed; incoming `tool_result` -> ToolResultReturned with `tool_use_id` and reported `is_error` only. Cumulative usage replaces earlier values, never sums snapshots. Unknown semantic event types make relevant coverage unknown. |
| [Ollama streaming](https://docs.ollama.com/api/streaming) and [chat schema](https://docs.ollama.com/api/chat), documentation OpenAPI `0.1.0` | `/api/chat` uses NDJSON by default, JSON with `stream:false`; `done:true` terminates; structured function arguments; optional `thinking`; token counts/durations. Documented ToolCall schema does not require a call ID | Separate native profile, not SSE. Map reported model/time and terminal usage; validate units before nanosecond-to-millisecond conversion. Never join a result by tool name or array position across requests when call identity is absent. `/api/generate` can later reuse lifecycle/text reconstruction but is not chat/tool parity. OpenAPI version is not an Ollama binary version. |

OpenAI [API versioning/request-ID guidance](https://developers.openai.com/api/reference/overview)
permits additive events/fields; current web references are not immutable wire
snapshots. First implementation must freeze synthetic profile fixtures and
document the supported subset/version headers. These observations are from
documentation, not interoperability tests against live providers.

InferenceStarted requires visible response lifecycle evidence, not merely
opening a socket. Tool proposals, harness requests, authorization, execution
start/completion, side effects, and returned results remain separate facts.
A request containing historical assistant calls or tool results proves their
presence in model input, not a new execution or that the provider received them.
Scope such evidence to that request; do not count re-sent history as new actions.
Tool execution is **Unsupported** at an inference-only boundary; a returned
result is reported content, not directly observed process/file/network activity.
ToolCall/UserContext capabilities are **Supported** only for accepted profiles
and visible content; opaque/unknown content makes the relevant coverage unknown.
Missing values remain absent. Unsupported endpoints/content kinds return explicit
status, not a clean result, invented Message, or arbitrary `Other` dump.

Reasoning capture is limited to legitimately exposed, explicitly classified
summary fields. Never request hidden chain-of-thought, decode opaque signatures
or encrypted reasoning, or relabel Ollama `thinking` as a summary. First tranche
does not retain thinking/signatures; summary support requires a later bounded
mapping and explicit local capture policy. Images/audio/binary content are not
decoded or copied into text. Mark the unsupported content boundary explicitly.

## Actual COv2 support and gaps

Pointers below refer to the investigation baseline, not speculative interfaces.

| Existing implementation | Reuse / limitation |
| --- | --- |
| [`observation/body.rs`](../crates/telltale-schema/src/observation/body.rs): `InferenceObservation`, `InferenceMetrics` | Provider, requested/resolved model, streaming, stop reason; input/output/reasoning tokens, duration and TTFT in milliseconds. No typed HTTP status, failure cause, cache-token accounting, per-choice lifecycle, or reasoning-summary field. Do not stuff these into stop reason. |
| Same file: `MessageObservation`, `ToolObservation`, `ToolDefinitionObservation`; [`mod.rs`](../crates/telltale-schema/src/observation/mod.rs): `ObservationStage` | Ordered content, structured arguments/results and local references; separate tool lifecycle and inference requested/started/completed/failed stages. No inference-truncated/cancelled stage or separate authorization body. Report acquisition interruption separately; InferenceFailed only for a known failure, not absence of completion. Tool definitions support name/change/references/hashes, not arbitrary native payloads. |
| Same file: `ProcessObservation`, `NetworkObservation`, `FileObservation`, `RuntimeObservation` | Process operation/state/name/PID/instance/parent/privilege; network operation/state/domain/protocol/port/destination class; file operation/state/path class/reference; runtime state marker/mode/isolation/workspace/privilege/versioned reference. No dedicated HTTP body, sandbox-ID slot, policy decision/action body, full endpoint pair, or process exit-code body. Families exist; this is not full OCSF support. |
| [`mod.rs`](../crates/telltale-schema/src/observation/mod.rs): `CorrelationIds`, `SourceProvenance`, `FactMetadata`, `CapabilityId`, constructor validation | Request/response/call/trace/span/process and optional session/workflow correlation; explicit origins and per-field provenance. Only ToolCall, ToolExecution, UserContext are registered capabilities today. Runtime coverage must use a bounded adapter status until separately accepted capabilities exist. Direct Process/File/Network minimums require observed provenance on operation/state. |
| [`value.rs`](../crates/telltale-schema/src/observation/value.rs): `validate_local_key`, `LOCAL_MAX_*` | Registered inference request/response and tool/message/definition keys; 4,096-byte strings, 16,384-byte values, depth 6, arrays 64, objects 32, 16 entries and 65,536-byte aggregate local evidence. No registered runtime raw-payload key. Raw wire buffers must not be smuggled into even registered raw keys. |
| [`identity.rs`](../crates/telltale-schema/src/observation/identity.rs), [`assignment.rs`](../crates/telltale/src/assignment.rs): `AssignmentAdapterDomain::registered`, `claim_or_replay` | Reuse coordinate identity and separate privacy-safe semantic comparison. Production assignment domains permit only the eight current agent identities; `claim_or_replay` consumes a completed `ObservationBuilder`, not a preallocated identity token. New inference/runtime domains and a caller-owned fact-level assignment seam require separately accepted work. Current assignment storage cannot simply be supplied to these new adapters. |
| [`v2/selector.rs`](../crates/telltale-detect/src/v2/selector.rs), [`v2/observation_match.rs`](../crates/telltale-detect/src/v2/observation_match.rs) | Existing direct canonical matcher and governed inference/runtime/process/network selectors. A body field's existence does not mean every selector or rule exists; metrics/new HTTP or policy fields need explicit selector decisions. No second detector required. |
| [`v2/session.rs`](../crates/telltale-detect/src/v2/session.rs): `CanonicalSourceInput`, `evaluate_source`; [`canonical_runtime.rs`](../crates/telltale/src/canonical_runtime.rs): `process_source`, private `finish_batch`; [`acquisition.rs`](../crates/telltale-sources/src/acquisition.rs) | Production composition is file/source-atomic and tied to exact supported agent identities, source accounting/path hashes and Event3 compatibility. It is not an arbitrary inference/runtime batch ingestion API. Do not fake ClientId, path, session accounting, baseline population, or source registration to invoke it. Pure normalization plus direct matcher tests can finish before production integration. |

First implementation uses existing bodies and bounded acquisition statuses.
If a required fact cannot be represented, record a specific schema/selector gap
and defer it rather than introducing generalized payloads/facets by stealth.
Governed facet namespaces are not permission to add unreviewed semantic keys.
Production composition/attribution and richer authorization semantics need
separate accepted work; Event3 is not expanded to export every new observation.

## Identity, correlation and replay

Source provenance identifies the selected adapter/profile/version and verified
installation scope; native IDs and source occurrence timestamps remain reported.
Parsed JSON structure is parsed provenance; directly observed transport/runtime
activity is observed only where the concrete source semantics prove it. Attach
exact metadata to every populated semantic field. `observed_at` is caller-owned
acceptance time, never a provider timestamp or collector receipt substituted for
occurrence time. Producer-local order does not establish global causality.

Use explicit request/response/call IDs only in their correct correlation slots
with source-reported or Telltale-originated origins. Session/workflow require
source assertion or explicit configured association; do not infer them from
model, tool, sandbox name, PID, URL, time proximity, or prompt similarity.
Sandbox correlation is not agent/session correlation. Same IDs from independent
installations/providers must not join; retained associations include verified
source-instance scope. An absent call ID leaves a result unjoined.

For observation identity reuse the coordinate-only tuple in
[COv2](canonical-observation-v2.md#time-identity-and-replay): adapter type/ID,
native coordinate or explicitly stable scoped sequence/offset, family, stage,
child ordinal. Native response IDs alone do not identify pre-response request
facts. **First tranches are stable-coordinate-only**: absent native or verified
stable scoped source coordinates fail `replay_unverifiable`. A caller-assigned
attempt token is not a source-native ID. Coordinate-less support is deferred
pending separately accepted assignment-domain registration and a caller-owned
fact-level seam for completed builders and proven durable replay associations;
the current agent-only assignment API is not an available fallback. No ephemeral
UUID, body hash, path, receipt timestamp, or mutable stream-chunk ordinal fallback.
Child ordinals use native message/choice/block/tool positions with a fixed
projection ordering, never arbitrary transport chunk boundaries.

Installation provenance or correlation does not participate in `derive_stable_id`.
Use the existing `adapter_id` slot to encode verified installation scope:
`inference.boundary:installation:<32-lowercase-hex>` or
`openshell.ocsf:installation:<32-lowercase-hex>`. The hex component is a durable,
explicitly provisioned, caller-verified installation namespace, unique among
installations collected together; never generate it per attempt or derive it
from gateway/sandbox names, paths, content, timestamps or protocol. Missing or
unverified scope fails closed. This encoding passes `SourceProvenance::new`'s
non-empty/NFC/no-newline validation without changing source registration. Keep
the truthful native ID unchanged and subject to `with_native_id`'s opaque-text
validation (no slash, backslash, `..`, or newline). `selected_coordinate` prefers
native ID over scoped sequence/offset: a sequence namespace alone cannot protect
a populated native ID from cross-installation collisions. Putting installation
scope in `adapter_id` protects either coordinate branch. Protocol/profile/version
and runtime/session/call correlation remain separate from this installation
namespace; changing them must not silently change installation scope. This
proposed adapter ID encoding is not accepted by the current agent-only production
composition or assignment registration and must not be used to impersonate them.

Replay of the same captured attempt preserves observation IDs despite different
chunking or observation times. Changed content at a stable coordinate uses
semantic comparison, not a replacement identity. A new upstream retry is a new
attempt with distinct verified coordinates, even if request content is
identical; attach a retry relationship only when the caller explicitly provides
it. The normalizer never retries inference or resumes by concatenating a second
response. Observation replay/duplicate handling is distinct from sink delivery
retry. Do not coalesce evidence across adapters merely because call IDs match.

## Streaming, bounds and privacy

Validate a complete bounded request before emitting its request facts. Response
start may emit a truthful lifecycle fact; keep response messages, tool arguments
and proposals private until the caller explicitly calls `finish`. At that
chunk-independent commit boundary, validate the protocol terminal and reject
trailing conflicting data before atomically releasing the response batch. Seeing
a terminal marker in `push_response` does not release response facts. Identical
invalid streams split before or after terminal markers must fail equivalently.
A block stop or finish reason alone is not a successful whole-stream terminal.
EOF, malformed JSON, conflicting IDs/indices, in-stream
error, deadline, cancellation or capacity failure discards uncommitted response
content. Previously accepted request/start facts remain facts, but are not
returned again as a fabricated completed response. No repaired partial JSON,
missing braces, guessed usage, empty placeholder results or inferred success.
`length`/`max_tokens` can terminate a generation without transport failure;
retain the reported stop reason and reject incomplete structured tool values.
Unknown additive fields may be ignored under the frozen profile; unknown semantic
events/content reduce coverage, and unknown terminal semantics cannot complete.

Proposed first-tranche limits: 1 MiB request, 4 MiB cumulative response bytes,
64 KiB incomplete SSE frame/NDJSON line, 256 content/tool items, 4,096 frames,
30 seconds without progress and 300 seconds total. Enforce before allocation,
including checked arithmetic, UTF-8 splits, JSON depth/cardinality and output
batch counts. A profile's limits cannot weaken COv2 local-value bounds. Oversized
semantic values fail explicitly rather than being silently shortened. Caller
enforces aggregate concurrency/memory and HTTP decompression limits, supplies
deadline notifications even during silence, and decides whether observation
failure interrupts transport; this plan introduces no enforcement behavior.

Private raw request/stream buffers are transient implementation state: no serde,
Debug payloads, error Display, logs, callbacks, sink, raw-reference store, or
durable spool receives them. Selected structured detector inputs remain local,
sensitivity-marked and bounded; do not redact them before deterministic matching.
Top-level `CanonicalObservationV2` Debug is deliberately payload-hiding, but
nested `ObservationBody`, Message/Tool bodies and `JsonValue` Debug are
payload-bearing. Forbid logging/debug-formatting these nested types or their
accessor results at normalizer/caller boundaries; existing schema types are not
a universal safe-Debug contract. Normalizer-owned public Debug/Display and
diagnostics must hide their private buffers and selected content.
Existing top-level observation Debug still prints source provenance, including
caller-provisioned capture coordinates. Those verified identifiers must be
non-secret, never raw payload or credentials; normalizer Debug hides them too.
Do not accept arbitrary headers: credentials, cookies, authorization, query
secrets and provider placeholders are excluded. Local capture of prompt/response,
definitions and tool values requires explicit caller policy and access control;
default export contains none of them automatically. Diagnostics are code-only.
Existing [terminal Event3 privacy](privacy-model.md) remains the export authority
for any later eligible projection, before JSONL/remote sinks. No new raw-evidence
export, retention service, enforcement feedback or output contract is proposed.

## OpenShell: first runtime candidate

Evidence is pinned to NVIDIA/OpenShell commit
[`82e889374fa26246ca6efe7da8b9bc3ec0a07f4d`](https://github.com/NVIDIA/OpenShell/tree/82e889374fa26246ca6efe7da8b9bc3ec0a07f4d),
not an assertion about an installed release. Its
[OCSF export documentation](https://github.com/NVIDIA/OpenShell/blob/82e889374fa26246ca6efe7da8b9bc3ec0a07f4d/docs/observability/ocsf-json-export.mdx)
documents opt-in JSONL, OCSF 1.8.0, stable `metadata.uid` on reserialization,
`container.uid` sandbox association, distinct gateway/supervisor product
identities, best-effort collection and lossy 1.1/1.3 downgrade. Downgrade strips
container/model/profile information; absence is then visibility loss, not proof
of no sandbox/model. Gateway name can be reused or renamed, so it is not an
authenticated globally unique installation identity.

| OCSF class | Proposed bounded mapping / evidence restriction |
| --- | --- |
| 1007 Process Activity | Process only for a verified event producer and operation that directly observes activity/state. Policy permission or a command string alone is not execution. PID alone is not a durable process instance or tool-call link. |
| 4001 Network Activity; 4002 HTTP Activity | Observed connection/request attempt can map to Network operation/state and known destination. Allow/deny is authorization; `allowed` alone does not prove connection completion or successful HTTP response. HTTP method/status/path exceed current typed Network fields: defer detailed mapping, do not flatten into invented tool execution. |
| 5019 Device Config State Change; 6002 Application Lifecycle | Runtime configuration/lifecycle marker where semantically justified, with reported versus observed provenance kept distinct. Configured isolation or filesystem policy does not prove effective enforcement or file access. |
| 6003 API Activity | The pinned [API builder](https://github.com/NVIDIA/OpenShell/blob/82e889374fa26246ca6efe7da8b9bc3ec0a07f4d/crates/openshell-ocsf/src/builders/api_activity.rs) supports model/provider and optional HTTP/unmapped metrics, although the export page's class table omits 6003. This proves a builder exists, not current production emission or complete inference capture. Map Inference only after the emission site and lifecycle semantics are qualified; never treat the builder's supervisor actor as the agent process. |
| 0 Base; 4007 SSH; 2004 Detection Finding | Unsupported initially, with explicit status. Do not import foreign findings as Telltale detections or arbitrary `Other`. |
| Filesystem | No file-activity class is documented in the cited export class table. Filesystem policy/landlock configuration is not observed read/write evidence. File coverage remains Unknown pending a qualified direct emitter, not Supported based on enforcement claims. |

Start with a dedicated pure OCSF mapper fed by caller-owned Linux JSONL
collection, not a new agent parser. Validate producer/schema/class/operation and
source scope before claiming direct facts. `metadata.uid` can identify a runtime
source fact only with the installation-scoped `adapter_id` above and a valid
native UID; a provenance-only namespace is insufficient. `container.uid` can
associate sandbox facts, never automatically populate session ID. Actor PID,
model and destination do not establish a request/call/trace bridge. Missing UID,
downgrade, rotation gaps, best-effort losses and duplicate collection must be
explicit. Caller retains collection checkpoints separately and advances them
only after its required durable processing; normalizer owns no cursor.

[Supervisor Middleware](https://github.com/NVIDIA/OpenShell/blob/82e889374fa26246ca6efe7da8b9bc3ec0a07f4d/docs/extensibility/supervisor-middleware/index.mdx)
is relevant as a later transport host for the same inference normalizer, not a
second detection product. The pinned
[operations contract](https://github.com/NVIDIA/OpenShell/blob/82e889374fa26246ca6efe7da8b9bc3ec0a07f4d/docs/extensibility/supervisor-middleware/operations.mdx)
documents sandbox context, pre-credential HTTP requests, response byte streams
and outgoing WebSocket text. Policy-denied traffic never reaches middleware;
TLS-skip traffic and compressed/partial/no-transform response bodies are outside
body inspection. Incoming WebSocket messages/binary frames are not inspected.
Response blocking cannot undo upstream effects. The API is evolving and default
middleware failure can block traffic: no service, allow/deny wrapper or action
integration belongs in the first observation tranche.

The issue's managed `inference.local` assumption is version-sensitive. At this
pin, [inference documentation](https://github.com/NVIDIA/OpenShell/blob/82e889374fa26246ca6efe7da8b9bc3ec0a07f4d/docs/how-it-works/inference.mdx)
says managed routes were removed and clients call native provider endpoints via
profile attachments. For older managed-route deployments, direct-provider
traffic bypasses a gateway that only watches the route. For this pin, native
traffic is expected; coverage depends on the configured interception boundary,
not the host name. OCSF may show a destination/attempt without revealing model
content. Missing gateway traffic never means no inference, and a configured
profile never proves complete traffic coverage. Report unobserved/unknown
coverage; do not attempt active bypass prevention.

## Authorized first tranche and deferred tranches

None is required to reopen or delay completed 0.7 convergence. Begin on the
singular foundation, with separately accepted scopes. Local completion is
Linux-only and synthetic; no external/live provider, OpenShell service, real
transcript/session database, credential, or other OS is needed.

1. **Authorized: pure Chat profile, API and mandatory safety gates.** Add only `telltale-inference` and synthetic
   request/JSON/SSE fixtures, using existing COv2, stable source coordinates only,
   installation-scoped adapter IDs and explicit caller time. Coordinate-less
   request/start facts reject rather than falling back to assignment storage.
   Test text, definitions, parallel indexed calls, results/history, missing IDs,
   requested/resolved model, absent/final usage and unknown content. Acceptance:
   every emitted observation passes existing COv2 validation; chunk each fixture
   at every single byte boundary and compare identities/semantics to unchunked
   input; no ToolExecution/Process/File/Network or fabricated session appears.
   The Chat-relevant failure, replay and privacy gates below are part of this
   first implementation, not a later optional hardening tranche.
2. **Mandatory first-tranche failure, replay and privacy gates.** Test CRLF/multiline SSE, split UTF-8,
   duplicate/conflicting terminals/indices/IDs, EOF before terminal, malformed
   argument JSON, upstream errors, cancellation, silent timeout, exact-limit and
   limit+1 bytes/items/depth, arithmetic overflow and replay/retry separation.
   Acceptance: zero completed response/proposals escape a failed response batch;
   same captured attempt retains IDs under rechunking/time changes; new retry
   does not; missing stable coordinates or verified installation scope fail closed.
   Mandatory collision regression: identical native IDs, family/stage/child and
   semantic content in two provisioned installations yield different observation
   IDs, even with native ID preferred over a populated scoped sequence; replay in
   one installation yields the same ID. Repeat for the sequence-only branch.
   Assert synthetic secret markers absent from normalizer-owned public
   Debug/Display/diagnostics, top-level COv2 Debug and eligible sanitized exports;
   forbid nested schema-type logging rather than claiming its Debug is safe.
   Measured buffer counters never exceed limits. No raw-buffer export path.
3. **Accepted bounded extension: Anthropic, Ollama and Responses profiles.** Implemented
   native state machines reuse the framing/COv2 boundary, not a provider framework. Test
   cumulative usage, block closure, in-stream errors/pings/unknown types; NDJSON
   `done`, JSON non-streaming, duration units and absent Ollama call IDs; Responses
   item/call IDs and failed/incomplete terminals. Acceptance: equivalent supported
   synthetic tool intent/result facts match the same existing canonical matcher
   as session-adapter fixtures; unsupported facts remain visibly unsupported.
   No pre-redacted detector inputs or provider-dependent rule forks.
   Current evidence covers canonical body equivalence and synthetic JSON/stream
   parity; live-provider and production/session-matcher interoperability are not
   established. COv2 has no typed Responses item-ID correlation slot: selected
   native item IDs remain in sensitivity-marked `inference.response` local
   evidence; typed joins/selectors are deferred. Nonempty annotations, reasoning,
   built-in tools and unknown semantic content fail `unsupported`. Ollama total
   duration maps unsigned nanoseconds to integer milliseconds (precision loss
   below one millisecond); other duration components are validated but not
   conflated with total time or TTFT. Cache-token breakdowns and provider
   timestamps are unselected envelope metadata, not inferred canonical facts.
4. **Deferred: pinned Linux OpenShell mapper.** First qualify emission sites against the pin
   and freeze a synthetic operation allowlist; implement only qualified Process,
   Network and Runtime mappings. Test allow versus actual activity, denied
   attempts, config versus file reads, unknown classes, downgraded/missing
   container/UID, duplicate IDs, renamed installations and PID reuse. Acceptance:
   100% of retained fields have truthful metadata; no permission becomes success,
   no policy path becomes File, no sandbox becomes session and replay is stable.
   Unqualified 6003/HTTP detail remains explicit unsupported/unknown output status.

Production caller integration is a later separately scoped decision, not a fifth
automatic implementation tranche: resolve truthful attribution outside the
current agent-only `evaluate_source` gate, eligible Event3 projection, durable
identity/checkpoint ownership and resource/failure policy without fake sources or
paths. Add focused tests for those exact boundaries before activation. Preserve
existing adapters, denominator, privacy and durable-JSONL-first output contracts.
macOS/Windows qualification and deployed OpenShell/provider interoperability
are separate later evidence gates, not blockers or implied coverage of the
Linux synthetic normalizer/mapping acceptance above.

## Detection v2 equivalence tests

The non-publishable `telltale-inference` crate owns the ordinary integration test
`tests/inference_session_equivalence.rs`, covered by default workspace tests and
Clippy. The three existing hidden Detection v2 wrappers are retained to access
Rule v1 session aggregation and independent atomic/process-session kernels without
source registration or a new public API. The test uses local synthetic JSON/streams and
temporary native stores, not live inference or production integration. It compares
message role/text, tool name/object arguments,
explicit call IDs, string results, captured error state, and definition name/change.
Observation IDs, adapter/native coordinates, time and provenance are not semantic
equality keys. Absent usage remains absent; reported usage is tested separately.

Pinned capability differences include proposal versus harness-request stages,
inference's unsupported execution, Copilot's unsupported user context and missing
error state, and unknown execution visibility in OpenClaw/Qwen/Copilot. An
OpenCode execution-state fixture is distinct from a returned result. Command-text
detector hits never establish observed execution. Comparisons classify equivalent
facts, expected capability differences, or defects; defects fail the tests.

Claude object tool-request arguments now derive the parsed `command.text` facet
from a string `command`, falling back to a string `cmd`, like other native adapters.
Results do not derive this facet, and command text does not establish execution.
The inference command-facet omission is also corrected within its supported mapping.
An additional synthetic Rule v1 `command` positive gate exercises the command
member of the shared object payload through the existing `command.text` selector,
alongside a tool-name positive and explicit non-matches. This does not require
generic structured-argument matching or detector-eligibility changes. Direct
cross-profile projections compare shared messages, tool fields, definitions and
call-ID values; unsupported error-state fields and inference lifecycle/origin are
excluded from that projection.

Additional synthetic coverage exercises `cmd`-only objects across all four
inference profiles (JSON and streams) and all six native adapters, including
Rule v1 command matches and bundled process-chain outcomes. Inference proposals
now use string `command`, then string `cmd`, with parsed provenance and unchanged
sensitivity; returned results never derive command text. Precedence, non-string
fallback, and result isolation are pinned separately. Synthetic `file_path` and
`path` objects preserve arguments but pin an expected path-selector difference;
the benign fixture does not change bundled detector outcomes, so no inference
`resource.path` derivation is added.

Read-only, bounded characterization of discovered local Linux stores was reduced
to minimal synthetic fixtures. No raw store content was retained in the repository.
SQLite inspection was structure-only, and absent or unsampled stores establish no
coverage. This characterization is not live interoperability evidence.

## Remaining evidence-dependent decisions

- Which supported OpenShell release/emission sites provide direct Process/Network
  and API facts matching this pin? Export docs and builders alone do not prove
  operation coverage, loss accounting, or a stable cross-stream request/call link.
- Can a deployment explicitly propagate a shared request/trace and agent/session
  association across transport, runtime and native stores? Until demonstrated,
  keep those streams unjoined; sandbox association alone is insufficient.
- Which minimal typed fields/selectors/capabilities are required for HTTP,
  authorization, interruption and reasoning summaries, and how will production
  attribution work without widening the agent denominator? Resolve only with a
  concrete accepted consumer, not Event4/generalized payload activation.

The resolved direction is OCSF plus an independent inference boundary first;
middleware may host it later if its versioned visibility/failure contract fits.
No new enforcement or universal traffic-coverage claim follows from this plan.
