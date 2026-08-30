# durable-delivery Specification

## Purpose
Defines opt-in durable downstream delivery over the canonical local JSONL first
write, while preserving existing best-effort behavior and keeping transport,
delivery policy, and persistence role distinct.

The public boundary is normative: `telltale-core::Pipeline` yields an `Event`
and the host owns I/O. The durable sequence is `terminal Event 3.0 -> durable
canonical JSONL -> future vendor-neutral collector transport`; Issue #26
implements only terminal serialization, the JSONL first write, and current
SQLite downstream replay state.
## Requirements
### Requirement: Delivery semantics are transport-neutral

The system SHALL represent transport, delivery policy, and persistence role as
distinct semantics. A local transport MUST be able to use BestEffort policy and
a non-local transport MUST be able to use Durable policy without locality alone
changing reliability behavior.

The former `SinkEntry.durable` flag MUST NOT be the semantic authority, and
the former `add_remote` construction meaning MUST resolve to an explicit
BestEffort policy plus no downstream delivery-state persistence. Sink identity,
transport, delivery policy, and persistence role MUST remain independently
represented with minimal compatibility mapping for existing callers. Durable
MUST NOT mean HTTP, and a future local IPC transport MAY be BestEffort.

#### Scenario: Best-effort remote compatibility

- **WHEN** an existing remote sink is configured without the new durable policy
- **THEN** it retains bounded in-memory retry and its current failure/reporting
  behavior, with no persistent replay implied

#### Scenario: Future local best-effort transport boundary

- **WHEN** a future vendor-neutral out-of-process local collector transport is
  added independently
- **THEN** it can use BestEffort policy without changing sink-layer policy
  semantics, adding an in-process plugin ABI, or changing Event 3.0

#### Scenario: Former remote helper has explicit semantics

- **WHEN** an existing construction path equivalent to `add_remote` is used
- **THEN** it creates a sink with an explicit identity and transport,
  BestEffort delivery policy, and no downstream delivery-state persistence;
  locality and reliability are not inferred from the helper name

### Requirement: Durable downstream policy is opt-in and requires JSONL

Durable downstream delivery SHALL be additive and opt-in. Configuration
validation MUST reject Durable policy unless canonical local JSONL is enabled,
the outbox location is private and writable, and each durable sink has a stable
configured identity. Remote-only output SHALL remain BestEffort in this change.

#### Scenario: Durable configuration is valid

- **WHEN** an operator enables Durable policy with canonical JSONL, a private
  writable outbox, and stable sink identities
- **THEN** the configuration is accepted and durable delivery state is enabled

#### Scenario: Durable configuration lacks JSONL

- **WHEN** an operator enables Durable policy without canonical local JSONL
- **THEN** configuration fails before a scan accepts telemetry and explains that
  durable downstream delivery requires JSONL

#### Scenario: Remote-only configuration remains best effort

- **WHEN** an operator configures only a remote sink and does not enable Durable
  policy
- **THEN** the scan retains the existing best-effort/no-persistent-replay
  posture

#### Scenario: Durable policy is not remote-only

- **WHEN** Durable policy is requested for any downstream transport
- **THEN** canonical JSONL is required as the first write, and no remote-only
  durable spool is enabled

### Requirement: Durable private storage has an explicit platform and threat boundary

Persistent Durable delivery SHALL use the private local-storage profile
implemented by Issue #26. On Windows, every persistent durable-delivery/storage
entry point MUST fail closed deterministically before creating, opening,
inspecting, or mutating an outbox or its sidecars, before a prospective
canonical JSONL append, and before scanner-state progress. The diagnostic MUST
be structured as `DurableStorage` and contain the bounded message
`persistent durable-delivery private storage is not supported on Windows yet`.
The failure MUST NOT silently change the requested policy to BestEffort or
otherwise claim that the batch was accepted.

This platform boundary applies only to persistent durable delivery/storage.
Telltale itself and existing Windows BestEffort operation remain supported.
Cross-platform API/cfg compilation and deterministic policy tests are not
native Windows durable-runtime evidence. Network filesystems are unsupported.

Durable storage guarantees assume private local storage controlled by a
cooperating Telltale process/user boundary. Hostile actors with the same OS
principal and privileged/root/admin actors are outside this threat model.
Path, advisory-lock, and stable-identity checks remain integrity defenses for
cooperating writers, but MUST NOT be described as an atomic pathname-to-opened
SQLite-object binding against excluded actors. A stronger opened-object-aware
SQLite/VFS design is required for that defense and is outside Issue #26.

#### Scenario: Windows durable configuration is rejected before initialization

- **WHEN** a valid durable configuration is initialized on Windows
- **THEN** initialization returns the structured bounded unsupported-storage
  diagnostic before creating or opening the outbox, its parent, or sidecars

#### Scenario: Windows durable admission is rejected before side effects

- **WHEN** a persistent durable batch is admitted on Windows
- **THEN** rejection occurs before prospective JSONL append, outbox inspection or
  mutation, and scanner-state advancement, with no BestEffort fallback

#### Scenario: Windows durable health is rejected before storage inspection

- **WHEN** durable queue health is requested on Windows
- **THEN** it reports the same structured unsupported-storage condition without
  creating, opening, or inspecting durable storage

#### Scenario: Windows BestEffort remains valid

- **WHEN** an existing BestEffort configuration is initialized on Windows
- **THEN** it remains valid and is not rejected by the persistent durable-storage
  platform guard

### Requirement: Canonical JSONL is the durable first write

Canonical terminal Event 3.0 JSONL SHALL be durably first-written before a batch
is accepted in Durable mode. It is the canonical durable ingress and recovery
source until reconciliation commits it into SQLite; SQLite is then the durable
downstream replay state. Scanner-state progress MUST NOT wait for downstream
acknowledgement, and a failed local durable write MUST NOT be reported as a
successful accepted batch. JSONL is not required to be retained forever or
until downstream acknowledgement.

#### Scenario: Local commit precedes downstream acknowledgement

- **WHEN** an event batch is serialized and synchronized to canonical JSONL but
  its downstream sink is unavailable
- **THEN** the local durable commit remains available for replay and scanner
  state does not depend on remote acknowledgement

#### Scenario: Local write fails

- **WHEN** canonical JSONL cannot be written or synchronized
- **THEN** the batch is not accepted as durably committed and no downstream
  acknowledgement is fabricated

### Requirement: Durable delivery uses persistent SQLite state

The Durable policy SHALL persist outbox state in SQLite using the existing
bundled engine rather than a second database engine. The state MUST include a
schema version, canonical event identity and payload hash/bytes, creation
metadata, per-sink delivery state, and a durable JSONL ingest cursor.

#### Scenario: Outbox restarts normally

- **WHEN** the process exits after outbox state is committed and later restarts
- **THEN** pending delivery rows, retry times, sink identities, and the ingest
  cursor are recovered without requiring the original process memory

#### Scenario: Outbox schema is newer or unsupported

- **WHEN** the outbox declares a schema version this build cannot safely read
- **THEN** durable operation fails closed with a bounded operator-visible
  storage diagnostic and does not prune JSONL generations

### Requirement: Durable ingest closes the JSONL crash gap

The system SHALL reconcile complete canonical JSONL records from a persistent
cursor. A cursor position MUST identify the journal namespace, a generation
stable across coordinated rotation rename, a complete-line byte offset, and
bounded integrity information sufficient to detect replacement or truncation.
Event/payload rows, missing durable-sink rows, and cursor advancement MUST be
committed transactionally.

#### Scenario: Crash after JSONL synchronization before ingest

- **WHEN** the process crashes after JSONL synchronization but before outbox
  insertion
- **THEN** restart reads from the last committed cursor, inserts the event and
  sink rows, and does not lose the event

#### Scenario: Crash after ingest before send

- **WHEN** the process crashes after the outbox transaction commits but before
  a transport attempt
- **THEN** restart finds the pending row and schedules it for delivery

#### Scenario: Incomplete tail record

- **WHEN** reconciliation reaches a partial final JSONL line
- **THEN** it does not advance past that line or treat incomplete bytes as a
  canonical event; a later complete write can make it ingestible

#### Scenario: Cursor integrity is ambiguous

- **WHEN** a cursor generation is missing, replaced, truncated, corrupt, or
  cannot be identified safely
- **THEN** reconciliation fails closed or rebuilds only through a bounded
  duplicate-safe path, and rotation does not prune the uncertain generation

#### Scenario: Cursor identity and offset are exact

- **WHEN** a cursor is persisted for a JSONL generation
- **THEN** it names the journal namespace and stable generation identity and
  records an exact byte offset at the beginning of a complete line; a filename
  alone or an offset past an unverified byte boundary is insufficient

#### Scenario: Ingest transaction is restart-safe

- **WHEN** a crash occurs during cursor, generation, event, or per-sink state
  updates
- **THEN** restart observes either the prior committed transaction or the
  complete next transaction, never an unverified cursor advance, and retains
  any generation whose safety cannot be proven

### Requirement: Payloads use the canonical privacy-safe Event 3.0 form

Every payload-bearing outbox, retry, and permanent/dead record SHALL contain
only canonical terminal/emittable Event 3.0 bytes. The system MUST NOT persist
raw source/transcript records or manually reconstruct Event JSON. Event 3.0
shape, `NATIVE_SCHEMA_VERSION`, parser identity, detector inputs, and scoring
semantics SHALL remain unchanged.

#### Scenario: Persisted payload is checked

- **WHEN** a durable payload is stored or moved to a retry/permanent state
- **THEN** serialized-event marker validation can inspect the bytes and finds no
  controlled synthetic marker

#### Scenario: Event contract is serialized

- **WHEN** the same event is emitted to JSONL and durable downstream delivery
- **THEN** both paths use the same canonical terminal Event 3.0 representation,
  with sink metadata outside the event body

### Requirement: Delivery is at least once and collision-safe

Durable delivery SHALL provide at-least-once replay semantics, not exactly-once
semantics. A receiver MUST be able to deduplicate by `event_id` within its
deployment context. If the same `event_id` is observed with different canonical
payload bytes, Telltale MUST fail closed and report a collision rather than
choose or overwrite an authoritative payload.

#### Scenario: Receiver succeeds before local acknowledgement

- **WHEN** the receiver accepts an event but the process crashes before local
  acknowledgement is committed
- **THEN** the event may be sent again after restart, and no local event is
  discarded solely because the result was uncertain

#### Scenario: Duplicate identical ingest

- **WHEN** the same event ID and identical canonical bytes are encountered again
- **THEN** ingest remains idempotent for queue state and does not create an
  unbounded duplicate row

#### Scenario: Same ID has different bytes

- **WHEN** the same event ID is encountered with different canonical payload
  bytes
- **THEN** the conflict becomes a bounded collision/permanent failure and the
  system does not guess which payload to deliver

### Requirement: Delivery state is independent per sink

The system SHALL track delivery state, retry schedule, terminal state, and
health metadata independently for each configured durable sink. A failure or
blocked state for one sink MUST NOT mark another sink as failed or prevent the
other sink from progressing.

#### Scenario: One sink recovers while another is blocked

- **WHEN** one durable sink acknowledges an event while another returns a
  blocked or retryable result
- **THEN** the first sink is recorded as acknowledged and the second retains
  its own pending/blocked state

### Requirement: Retry and failure classes are structured

Delivery results SHALL expose a structured class rather than requiring callers
to parse diagnostic strings. The model MUST distinguish transport/no-response,
independently observable timeout, received HTTP/status failure,
sink/application rejection, authentication/authorization blocked, payload or
collision, durable-storage failure, and unknown/internal failure, while
remaining extensible for later protocols.

#### Scenario: Network failure is retryable

- **WHEN** no response is obtained from an otherwise configured endpoint
- **THEN** the row receives a bounded retry schedule and a transport/no-response
  class without relying on message wording

#### Scenario: HTTP retry statuses are scheduled

- **WHEN** a durable sink receives HTTP 408, 429, or a 5xx response
- **THEN** the row is scheduled for bounded retry and records the HTTP/status
  class

#### Scenario: Authentication failure is blocked

- **WHEN** a durable sink receives HTTP 401 or 403
- **THEN** the row enters blocked/operator-action state without hot-loop retry

#### Scenario: Operator releases blocked sink deliveries

- **WHEN** an operator explicitly runs `telltale delivery retry-blocked` for a
  validated sink identity
- **THEN** every blocked row for that exact sink becomes pending with an
  immediate next-attempt time, its attempt and error history is preserved, and
  rows for other sinks or states are unchanged; the command reports the number
  of released rows

### Requirement: Poison events do not wedge delivery

Payload or application failures that are permanent for the event SHALL be
recorded as dead/permanent with a structured class and bounded diagnostic.
Such a row MUST NOT prevent later valid rows for the same sink from being
attempted.

#### Scenario: Rejected payload is quarantined

- **WHEN** a sink permanently rejects one event as invalid or unprocessable
- **THEN** that event becomes dead/permanent and a later valid event remains
  eligible for delivery

### Requirement: Capacity exhaustion is visible and fail-safe

Durable queue limits SHALL bound pending event count and payload bytes. Capacity
accounting MUST include committed JSONL bytes that have not yet been ingested.
When projected headroom or required persistent state cannot be established, the
system MUST reject the new batch before appending it and before advancing new
scanner dedup/cursor state. It MUST NOT silently delete accepted telemetry.

Admission for one canonical JSONL/outbox pair MUST be serialized by its private
admission sidecar lock. The lock MUST remain held across recovery reconciliation,
eligible ready-work dispatch, capacity inspection, canonical JSONL append, and
follow-up reconciliation. Before a prospective batch is checked, eligible ready
rows SHALL be attempted without sleeping or hot-looping: successfully
acknowledged rows release pending capacity, while blocked and retry-delayed rows
continue to consume it. Cooperating durable writers MUST therefore not both
admit against the same observed headroom.

#### Scenario: Pending queue reaches its limit

- **WHEN** a new batch would exceed configured pending count or byte capacity
- **THEN** the batch is rejected before acceptance, a privacy-safe capacity
  status/error is visible, and earlier JSONL bytes remain available

#### Scenario: Outbox availability is unknown

- **WHEN** the outbox is locked, busy beyond its bounded wait, unavailable, or
  too corrupt to calculate safe headroom
- **THEN** the new batch fails safely without silent discard or unbounded retry

#### Scenario: Ready pending work releases capacity before admission

- **WHEN** the pending queue is full but an eligible pending row can be
  acknowledged during the admission drain
- **THEN** the acknowledged row is terminal, its capacity is released, and the
  new batch can be admitted without restarting the process

#### Scenario: Blocked work remains capacity-consuming until release

- **WHEN** the full queue contains an authentication-blocked row
- **THEN** admission remains rejected and the row is not hot-looped until an
  explicit sink-specific release makes it eligible; a later admission can then
  drain it before accepting new work

#### Scenario: Concurrent writers share one admission decision

- **WHEN** two cooperating durable writers target the same JSONL/outbox pair
  with only one pending slot available
- **THEN** the sidecar serialization permits at most one new batch to pass the
  capacity gate, and JSONL, outbox rows, and the ingest cursor remain mutually
  consistent

### Requirement: Durable alert follow-up is non-recursive

An operational `operational_alert` with `check_name=sink_delivery` SHALL remain
canonical Event 3.0 data and may be first-written to JSONL and represented in
the outbox event table, but it MUST NOT create per-sink durable replay rows.
The durable dispatcher MUST not send such an alert as ordinary replay work or
create another alert when an older outbox contains one. The follow-up path SHALL
skip the sink named by the failure, deliver an admitted alert directly to other
eligible sinks, and report follow-up errors through bounded diagnostics without
emitting another alert. This is an alert-loop guard, not an exactly-once claim
for repeated caller invocations or receiver delivery.

#### Scenario: Durable delivery failure does not recurse

- **WHEN** a durable sink failure produces an admitted sink-delivery alert and
  later durable dispatch cycles run
- **THEN** the failed sink is skipped, healthy eligible sinks receive the
  operational signal through the follow-up path, and the alert does not become
  new replay work or produce an alert-of-alert

#### Scenario: Full capacity does not enqueue an alert loop

- **WHEN** the alert itself cannot pass the durable capacity gate
- **THEN** its canonical append and outbox event are rejected before acceptance,
  durable sinks do not receive an unadmitted follow-up, and no recursive alert
  is created

### Requirement: Storage failures are bounded and fail closed

Locked, busy, corrupt, permission-denied, and synchronization-failed outbox
conditions MUST produce deterministic bounded operational outcomes. The system
MUST NOT treat an unverified cursor commit or unverified deletion as successful.

#### Scenario: Outbox is locked

- **WHEN** another process holds the outbox lock beyond the configured bounded
  wait
- **THEN** durable processing reports storage unavailability and does not
  advance the cursor or prune JSONL

#### Scenario: Outbox is corrupt

- **WHEN** SQLite integrity or schema loading fails
- **THEN** durable processing stops with a privacy-safe bounded diagnostic,
  preserves canonical JSONL, and does not attempt unsafe replay-state repair

### Requirement: Rotation cannot prune unread durable generations

The active JSONL generation MUST NOT be pruned. A rotated generation SHALL
remain pinned while its durable ingest cursor has unread bytes, or while its
identity/integrity is uncertain. Pruning eligibility MUST be independent of
downstream Pending, Blocked, retrying, or terminal/ACK state: once durable state
proves that the cursor fully consumed the generation, downstream rows remain in
SQLite as replay state and do not pin the JSONL generation. Non-durable mode
MUST retain the existing rotation behavior.

Pruning MUST be fail-safe and metadata-driven: active, unread, unknown,
identity-mismatched, corrupt, or not-provably-consumed generations MUST remain
pinned. Missing, corrupt, locked, or ambiguous cursor/generation/outbox state
MUST disable pruning, and failed prepare, rename, metadata commit, deletion, or
finalization MUST retain the generation for later recovery. Prepare/delete/
finalize and restart recovery MUST be idempotent. The implementation MUST
actually invoke this eligibility check from the rotation lifecycle; a dead-code
eligibility helper is insufficient.

#### Scenario: Rotation finds unread bytes

- **WHEN** keep-count cleanup would remove a rotated generation containing
  bytes beyond the durable cursor
- **THEN** cleanup leaves that generation in place and records safe rotation
  health rather than deleting replayable bytes

#### Scenario: Rotation follows complete terminal ingest

- **WHEN** a rotated generation is completely consumed by the durable ingest
  cursor and its identity/integrity are verified
- **THEN** the generation becomes eligible for the normal keep policy

#### Scenario: Crash occurs during rename coordination

- **WHEN** the process exits before or after a generation rename but before all
  cursor/generation metadata is committed
- **THEN** restart resolves only verifiable generation identities and keeps
  ambiguous generations; uncertain cleanup never prunes them

#### Scenario: Eligible generation is pruned safely

- **WHEN** a non-active generation is fully consumed by the durable cursor and
  its identity/integrity are verified, regardless of downstream row state
- **THEN** the normal keep policy may prune it, but only after the persisted
  eligibility decision and coordinated deletion succeed; any failure retains
  the bytes

### Requirement: Durable storage resource and writer boundaries are explicit

Capacity inspection has a bounded unread-byte scan, but reconciliation currently
loads complete discovered JSONL generations and their complete payload plan in
memory. Issue #26 SHALL NOT claim an arbitrary-size or streaming reconciliation
guarantee; deployments must keep generation sizes within available process
resources, and an oversized generation remains a local operational failure
boundary rather than permission to advance an unverified cursor.

The SQLite event table SHALL retain canonical payload bytes for `Acked` and
`Dead` delivery history. Those terminal rows are excluded from pending capacity,
have no automatic retention or compaction guarantee in this change, and may
grow the private outbox beyond the configured pending queue limits.

Verified rotation deletion SHALL claim coordination only for writers that honor
the corresponding private JSONL sidecar lock. A non-cooperating local writer can
still change a path between final verification and unlink (with an additional
close/recheck window on Windows), so external writers, external rotation in the
managed generation namespace, and network filesystems are unsupported durable
storage configurations.

#### Scenario: Reconciliation size is an explicit operational boundary

- **WHEN** a complete JSONL generation is larger than the process can safely
  reconcile in memory
- **THEN** Issue #26 provides no arbitrary-size or streaming guarantee, and an
  incomplete reconciliation does not authorize advancing an unverified cursor

#### Scenario: Terminal payloads remain outside pending capacity

- **WHEN** delivery rows become `Acked` or `Dead`
- **THEN** their canonical payload bytes remain available in the private SQLite
  event table, are excluded from pending limits, and are not automatically
  purged or compacted by this change

#### Scenario: Non-cooperating deletion writers are unsupported

- **WHEN** an external writer changes a managed JSONL generation without taking
  Telltale's sidecar lock during verified deletion
- **THEN** Telltale makes no atomic deletion guarantee against that race; only
  cooperating local writers and the fail-safe verification path are supported

### Requirement: Queue health does not inspect payloads

Durable health status SHALL expose pending depth, oldest pending age, pending
payload bytes, dead/permanent count, and last success/error class independently
per sink. These fields MUST be derivable from metadata without reading event
payload content.

#### Scenario: Operator reads durable status during outage

- **WHEN** a durable sink has pending and dead rows during an outage
- **THEN** status reports depth, oldest age, bytes, dead count, and last
  structured error class without exposing event payloads or source text

### Requirement: Privacy-safe diagnostics remain bounded

Outbox, retry, collision, capacity, storage, and rotation diagnostics SHALL pass
through the established privacy boundary and SHALL not include raw credentials,
source content, or unnecessary host paths. Diagnostic failures MUST NOT recurse
into unlimited alert queuing.

#### Scenario: Endpoint returns sensitive error content

- **WHEN** a sink response or local error contains a controlled marker, URL
  credential, or sensitive host path
- **THEN** persisted and displayed operational diagnostics contain neither the
  controlled value nor the unsafe path content

### Requirement: Public boundary remains generic and stable

The change MUST keep `telltale-core::Pipeline` I/O-free, keep collector
metadata outside Event 3.0, and avoid in-process plugins, DLL/shared-library
ABIs, adopter-specific implementations, and Emusary branding. A future
collector's received time MUST remain distinct from Event `ingested_at`, and
Event `session_id` MUST NOT be treated as a Windows session identity.

Issue #26 MUST NOT add `emusary_local`, named pipes, adopter-specific
protocol/concepts, collector framing or ACK behavior, collector
configuration/identity/security, protocol versioning, or protocol-only error
classes. Those future generic local-collector concerns are deferred to a
separately versioned effort. Issue #28 is deferred; JSONL-only is not its final
client-adoption architecture and its acceptance criteria remain unfrozen.
Any future transport extension SHALL reuse the generic structured delivery
classification and outbox dispatch seam without requiring a foundational sink
refactor.

#### Scenario: Unrelated EDR adopts the public boundary

- **WHEN** an unrelated security product consumes canonical Event 3.0 JSONL or
  later uses an independently versioned local collector transport
- **THEN** it can supply its own deployment/tenant/receipt metadata outside the
  event without requiring Telltale to become a multi-tenant identity boundary

### Requirement: Fault-injection and platform evidence is required

The implementation test suite SHALL cover endpoint recovery without restart,
restart replay, both JSONL/outbox crash gaps, uncertain-success duplication,
429/5xx scheduling, 401/403 blocking, poison ordering, queue full, locked/busy
and corrupt outbox, unread rotation, independent sinks, and deterministic
Linux/macOS/Windows behavior where applicable.

The following fourteen scenarios are individually normative acceptance cases:

#### Scenario: F1 outage recovery without restart

- **WHEN** an endpoint is unavailable and later recovers while the process is
  running
- **THEN** bounded scheduling retries and delivers the pending event without a
  restart

#### Scenario: F2 outage restart replay

- **WHEN** an endpoint is unavailable, the process exits, and it restarts
- **THEN** persisted pending state replays the event without loss

#### Scenario: F3 fsync before ingest crash

- **WHEN** the process crashes after JSONL fsync but before SQLite ingest
- **THEN** restart ingests the complete line from the prior cursor and replays
  it

#### Scenario: F4 ingest before send crash

- **WHEN** the process crashes after SQLite ingest commits but before a send
- **THEN** restart finds the pending per-sink row and attempts delivery

#### Scenario: F5 remote success before local ACK

- **WHEN** the receiver succeeds before local acknowledgement commits
- **THEN** a restart may duplicate the event but cannot silently lose it

#### Scenario: F6 retry status scheduling

- **WHEN** a durable HTTP attempt receives 429 or 5xx
- **THEN** structured retry scheduling persists the next eligible time

#### Scenario: F7 authentication blocked

- **WHEN** a durable HTTP attempt receives 401 or 403
- **THEN** the row becomes blocked/operator-action state and does not hot-loop

#### Scenario: F8 poison ordering

- **WHEN** one event is permanently rejected before a later valid event
- **THEN** the poison row becomes dead/permanent and the later event is still
  attempted

#### Scenario: F9 queue capacity full

- **WHEN** projected pending count or bytes exceed capacity, or capacity is
  unknowable
- **THEN** the new batch is rejected visibly before acceptance and no accepted
  telemetry is silently discarded

#### Scenario: F10 locked or busy storage

- **WHEN** outbox storage remains locked/busy beyond its bounded wait
- **THEN** processing fails safely without cursor advancement or pruning

#### Scenario: F11 corrupt storage

- **WHEN** outbox integrity or schema loading is corrupt
- **THEN** processing fails with a bounded privacy-safe diagnostic and retains
  canonical JSONL without unsafe repair

#### Scenario: F12 rotation safety

- **WHEN** rotation sees unread durable bytes and later sees a fully eligible
  generation
- **THEN** unread bytes are retained and only the verified eligible generation
  can be pruned

#### Scenario: F13 independent sinks

- **WHEN** one durable sink succeeds while another retries or blocks
- **THEN** each sink's state and health progress independently

#### Scenario: F14 deterministic platform behavior

- **WHEN** lock, rename, sidecar, permission, and restart cases are exercised
  on Linux, macOS, or Windows where available
- **THEN** outcomes are deterministic; unsupported native execution is not
  represented as passed and platform-independent deterministic tests cover the
  shared safety rules

#### Scenario: Fault matrix is incomplete

- **WHEN** a durable-delivery change lacks evidence for one required crash,
  retry, storage, capacity, rotation, sink-isolation, or applicable platform
  case
- **THEN** the Issue #26 acceptance gate remains incomplete and the durable
  capability is not represented as fully validated
