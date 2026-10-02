# telltale-inference

Pure, experimental inference acquisition into existing Canonical Observation
v2. No transport, clock, logging, storage, execution, detector, Event projection,
production source registration or provider attribution is supplied.

## Frozen profiles

Select `Profile::{OpenAiChat, AnthropicMessages, OpenAiResponses, OllamaChat}`
with `Normalizer::with_profile(profile, identity, capture, limits)`.
`Normalizer::new` remains the OpenAI Chat default. `Profile::version()` reports
the frozen subset; there is no auto-detection or fallback after parse failure.
These are implemented local subsets, not deployed-provider compatibility claims.

### OpenAI Chat (unchanged default)

`openai-chat-v1-subset-2026-10-01` targets the REST `/v1/chat/completions`
JSON request and JSON or SSE response shape. Synthetic fixtures in
`tests/fixtures/` are the compatibility boundary, not live interoperability
evidence. No HTTP headers are accepted or required by the normalizer; the caller
selects this profile and validates endpoint/content type itself. Other endpoints,
extensions and version negotiation are not implemented by this profile.

- Required request model and nonempty messages. Text system/developer/user/
  assistant messages; assistant function-call history; tool-role string results
  with optional explicit call ID. History belongs to the captured request, not
  a newly observed execution or proof of provider receipt.
- Function definitions retain selected name/description/parameters/strict fields
  as sensitive local evidence, with `DefinitionChanged(present)`. No inventory
  diff or unkeyed content hash. Function proposals require complete object JSON
  arguments and a name; missing call IDs stay absent.
- JSON choices and SSE deltas reconstruct by explicit choice index and tool index
  (JSON tool array position). Indices are 0–255. Names/IDs are complete values,
  not name/ID fragments. Repeated identical names/IDs are allowed; conflicts,
  duplicate indices within a chunk, duplicate call IDs within a response and
  deltas after choice closure fail. Arguments and content concatenate, bounded.
- SSE accepts LF/CRLF, comments and multiline `data:`. Other SSE fields/events,
  bare CR, incomplete frames, repeated `[DONE]`, or data after `[DONE]` fail.
  Every choice needs an explicit assistant role and recognized finish reason;
  `[DONE]` alone cannot complete. JSON needs complete choices and finish reasons.
- Recognized finish reasons: `stop`, `length`, `tool_calls`, `content_filter`.
  Completion means protocol generation termination, **not success or execution**.
  Different per-choice finish reasons fail `unsupported`: COv2 has only one
  inference stop-reason slot. No fabricated per-choice inference lifecycle.
- Optional final usage maps only explicitly reported input/output/reasoning token
  counts. Missing usage stays unknown. SSE usage is a single final empty-choice
  chunk, after all choices close. No duration, TTFT or success is inferred.
- Envelope additive fields are ignored, not retained. Unknown semantic message/
  delta fields, non-text content, legacy function calls, refusal content, audio,
  exposed thinking and reasoning are unsupported. There is no hidden reasoning
  capture or opaque-payload decoding. Unsupported input fails the whole batch,
  never producing a falsely clean coverage result.

### Anthropic Messages

`anthropic-messages-2023-06-01-subset-2026-10-01`: native Messages JSON/SSE,
with caller-validated `anthropic-version: 2023-06-01`. Text system/user/assistant
content, explicit-ID `tool_use` object arguments, string `tool_result` content
with optional explicit `tool_use_id` and reported `is_error`, and native tool
definitions are implemented. Missing result IDs stay unjoined; proposals require
the native explicit ID. Structured/multimodal results, thinking/signatures,
cache-control blocks, server tools and unknown semantic blocks/events fail
`unsupported` rather than silently reducing coverage.

SSE requires `message_start`, contiguous indexed block starts, matching typed
deltas and exactly one closure per block, a recognized message stop reason and
`message_stop`. Interleaved open blocks are tracked independently. Tool argument
fragments are parsed only on block closure. Pings are accepted before the terminal;
in-stream errors fail the whole response. Cumulative usage replaces reported
counts, never adds snapshots; omitted counts retain previously reported values.
Recognized stops: `end_turn`, `max_tokens`, `stop_sequence`, `tool_use`.

### OpenAI Responses HTTP

`openai-responses-v1-subset-2026-10-01`: separate native request/JSON/SSE state
machine, **not** a Chat alias. Text input/instructions, message items with text
parts, function definitions, `function_call` proposals and string
`function_call_output` results are implemented. `previous_response_id` and
conversation references fail `unsupported`; history is never fetched or invented.
Built-in/server tools, reasoning, encrypted payloads, nonempty annotations or
logprobs and unknown semantic events/content fail explicitly. WebSockets are absent.

SSE requires `response.created`, indexed item/part starts, typed text/argument
deltas, matching text/argument/part/item done snapshots and `response.completed`.
The final full output must equal the reconstructed closed items; IDs, indices,
optional increasing sequence numbers, model and terminal state are checked.
Failed/incomplete terminals never commit. Response IDs populate response correlation;
only `call_id` populates call correlation. Native item `id` is retained separately
as selected sensitive local `inference.response` evidence (`{"id":...}`), including
historical input items. It is never substituted for call, capture or response ID.
There is no typed item-ID correlation slot in COv2; typed item-ID selectors/joins
remain a schema gap. Completion is lifecycle, not an invented stop reason.

### Ollama native chat

`ollama-chat-subset-2026-10-01`: `/api/chat` JSON with `stream:false`, bounded
NDJSON otherwise (native default). Text messages, native definitions, complete
object-argument function calls and string results are supported. Each streamed
call must be complete; tool-name/position/index-based fragment joining is absent.
Optional explicit call IDs are retained, never generated. `tool_name` on results
does not establish a call association. Thinking, images and unknown message
content fail explicitly. `/api/generate` is not supported.

`done:true` is mandatory, at most once, with no later JSON record. Recognized
optional `done_reason`: `stop`, `length`. Terminal token counts map only when
reported. Native durations must be unsigned integer nanoseconds; alternate-unit
markers, floats, strings, negative values and overflow fail. `total_duration`
is converted by integer division to milliseconds; sub-millisecond precision is
not representable in COv2. Other native duration fields are validated but not
projected as total time or TTFT. Final NDJSON newline is optional, but the last
line still counts against byte/frame limits. Source `created_at` is not mapped
to caller-owned acceptance time.

All profiles use one shared COv2 construction boundary for equivalent supported
text/tool/result facts. Cache-token breakdowns, provider timestamps and other
unselected envelope metadata are not retained. No absent metric is filled with
zero. Full interoperability, Bedrock/Vertex dialects, runtime adapters, gateways,
live services, production attribution/routing and Event export remain deferred.

## API and commit boundary

`Normalizer::new(Identity, CapturePolicy, Limits)` requires an explicit local
sensitive-capture policy, caller-verified provisioned installation namespace and
durable source coordinate. `accept_request(bytes, observed_at)` validates the
whole request before returning a batch. `begin_response(Json|Sse|Ndjson)` selects the
format, agreeing with request `stream`. `push_response(bytes, elapsed_ms)` admits
bounded bytes and returns **no observations**, including at terminal markers.
Empty pushes check silent deadlines. `finish(reason, observed_at, elapsed_ms)`
consumes the attempt. Only `Complete` validates and atomically releases the
response; EOF, cancellation, transport/upstream error and timeout return codes.

The implementation deliberately retains one bounded wire buffer and reconstructs
at finish rather than publishing provisional state. SSE frame admission counters
run incrementally across arbitrary byte/UTF-8 boundaries. All trailing input is
validated before release. Started/requested/completed facts are distinct; response
`InferenceStarted` is conservatively returned with the committed response, not
on socket opening. Supplied observation times are acceptance times, not source
occurrence timestamps. Any mutating-method failure closes and discards the attempt.

## Identity and privacy

Installation namespaces are exactly 32 lowercase hex characters, attested by
the caller, encoded as `inference.boundary:installation:<namespace>` in
`adapter_id`. The native coordinate remains unchanged. Schema identity prefers
native coordinates over verified scoped sequence, so installation isolation
works for both branches. Missing scope/coordinates fail `replay_unverifiable`.
No generated identity, body hash, timestamp or chunk ordinal fallback exists.

The fixed Chat/Ollama child projection is request message position × 257, plus
tool position + 1; responses set the high bit (Chat uses choice index × 257 plus
tool index + 1). Anthropic uses message position × 257 plus native block position;
Responses uses item position × 257 plus content-part position. Native response
positions set the high bit; separate system/instructions use `0x40000000`.
Definition positions and lifecycle zero ordinals occupy their own family/stage.
Replays retain IDs; retries need distinct verified coordinates. The API does not
accept or invent retry/session/workflow relationships. Consumers must scope call
associations by source installation **and captured request coordinate**, never
join historical calls across requests or installations using bare call IDs.

All selected semantic fields and local definition values are sensitivity-marked.
Without keyed fingerprints, semantic comparison is `Unavailable`, even on replay.
Public normalizer/identity Debug and failure Debug/Display are code-only or
payload-hiding. No serializer, raw accessor, callback or export surface exists.
Returned observations contain sensitive local detector input: callers must not
log nested schema bodies, local values, correlation objects or accessor results.
Top-level observation Debug hides semantic payloads, but the existing schema
prints `SourceProvenance`, including capture coordinates. Caller-provisioned
coordinates/namespaces must therefore be non-secret identifiers, never raw
payload, credentials or paths; they are not a raw-evidence channel. The normalizer's
own Debug hides these too. There is no eligible Event3
export integration here; later integration must use existing terminal sanitization.

## Bounds and caller responsibilities

Default ceilings: 1 MiB request, 4 MiB cumulative response, 64 KiB SSE frame/NDJSON line
(including delimiters/comments), 4,096 frames, 256 message/tool/definition items
per batch, 1,024 observations, JSON depth 16 (root counts as one), 32 object
members, 256 wire array entries, 4,096 string bytes, 30 seconds idle and 300 seconds
total. Configuration can only tighten these limits. Blank SSE frame separators
also count toward the frame ceiling. String limits count **raw escaped bytes**
as well as decoded UTF-8, intentionally conservative. Selected local values also
must satisfy stricter schema depth/cardinality/aggregate limits; oversize values
fail rather than truncate. Duplicate JSON keys are rejected. Lexical string
admission precedes JSON allocation; recursive JSON collection/depth bounds precede
growth. Response/frame limits are checked before appending incoming bytes.

The caller owns transport/decompression/concurrency limits, elapsed time from
attempt start (including silence notifications), trusted identity provisioning,
access control, draining batches and any transport interruption policy. Bytes
count as progress, bounded by the absolute deadline. Buffers are dropped on
failure, not cryptographically zeroized. No live secrets should be supplied to
tests. Local qualification is Linux synthetic only.

Run `cargo test -p telltale-inference` and
`cargo clippy -p telltale-inference --all-targets -- -D warnings`.
