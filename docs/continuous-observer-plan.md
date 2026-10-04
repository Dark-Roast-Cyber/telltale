# Resource-bounded continuous observer

**Status: proposed architecture and implementation plan; not shipped behavior.**
Requested by the operator on 2026-09-27. Implementation requires bounded Issues,
OpenSpec deltas, and the acceptance gates below. This document is the public
planning reference; local execution packages must remain consistent with it.
It does not authorize deployment, service changes, or removal of existing APIs.

### Accepted bounded production JSONL tranche (not shipped)

Separately accepted in [Issue #81](https://github.com/Dark-Roast-Cyber/telltale/issues/81)
is a narrow hard-cap contract
for the shared production JSONL reader only: 8 MiB per physical record, 128 MiB
total acquired source bytes, and 100,000 nonblank units across the six JSONL
identities (Claude projects, the three Codex JSONL variants, OpenClaw agents,
and Qwen projects). All boundaries are inclusive: 8 MiB is 8,388,608 bytes and
128 MiB is 134,217,728 bytes. Physical record bytes include LF/CRLF terminators;
aggregate bytes include all whitespace, blank records, and terminators. Nonblank
units retain Unicode `str.trim()` semantics. These are fixed internal limits,
not configuration knobs, enforced on actual reads before UTF-8/JSON decoding.
Over-limit acquisition must fail atomically through the existing source-read
category; it is not shipped behavior, selection/truncation, or a heap/RSS
promise. Copilot and OpenCode are outside this tranche. This accepted implementation
does not establish shipped behavior until release and does not activate
the broader proposed resource policy, SQLite bounds, deadlines, observer/service
work, or other runtime changes below.

## Outcome

Telltale should be a dependable, resource-bounded security observer that can run
continuously without scheduling repeated full-content scans. It must also remain
useful as a one-shot scanner and a component controlled by another application,
including Emusary. All modes use the same authoritative acquisition, detection,
privacy, and durable-output contracts.

Continuous operation means event-driven work with explicit recovery, not blind
trust in filesystem notifications. A running process is not proof of coverage.
This is observation and detection, not a tamper-proof endpoint agent or an active
blocking control. A same-user administrator can stop or modify a user service.

## Current capability and gaps

- `scan --once` processes a batch and exits. Periodic scan options also exist;
  they remain available for explicit caller-controlled use.
- `watch` is a foreground process that reacts to session-store changes. It can
  target changed sources, but it does not currently process existing content at
  startup or provide periodic notification-loss recovery.
- `status` reports the latest scanner health event, not service lifecycle state.
  `start` and `stop` are proposed new commands.
- Managed Linux deployment currently uses a user-level one-shot service and an
  opt-in timer. There is no shipped cross-platform lifecycle command contract.
- Some readers materialize whole inputs. OpenCode bounds selected parts but
  rereads all messages. Making the process persistent alone does not make those
  reads incremental or memory-bounded.
- Durable replay reconciliation has a separate whole-generation buffering path;
  an acquisition budget alone cannot establish end-to-end bounded delivery.

See [installation](install.md), [embedding](embedding.md),
[architecture](architecture.md), and [delivery limitations](telemetry-output.md).

## 1. Three supported ownership modes

| Mode | Entry point | Lifecycle owner |
| --- | --- | --- |
| One-shot | `telltale scan --once` | Operator, scheduler, or invoking application |
| Foreground continuous | `telltale watch` | Terminal, external supervisor, container, or management application |
| Managed continuous | `telltale start`, `stop`, service status | Supported OS service manager through the Telltale CLI |

Reuse the foreground watcher as the managed service process. Do not add a second
daemon, self-backgrounding implementation, persistent control server, or generic
plugin framework. Core embedding remains available; embedded hosts own I/O and
must satisfy documented serialization/state-ownership obligations.

An external controller such as Emusary can invoke one-shot scans, supervise
foreground watch, use the supported embedding API, or explicitly manage the
canonical Telltale service through lifecycle commands. It must choose an owner
rather than unknowingly run both. No Emusary-specific type or dependency belongs
in the detection core, and no existing integration is implied by this plan.

### Proposed command contract

| Command | Proposed behavior |
| --- | --- |
| `telltale start` | Start the installed, validated current-user observer service; do not enable reboot persistence implicitly |
| `telltale start --enable-on-boot` | Explicitly enable and start that service after prerequisites and ownership checks |
| `telltale stop` | Stop only the canonical managed observer and wait for bounded shutdown; retain configured boot enablement |
| `telltale stop --disable-on-boot` | Disable future automatic starts and stop the canonical managed observer |
| `telltale status` | Preserve the existing scan-health interface; do not silently reinterpret old output |
| `telltale status --service` | Report service lifecycle, enablement, runtime liveness, and coverage health separately |
| `telltale status --service --json` | Versioned machine-readable service/coverage result for external controllers |

`start` is idempotent only for an already running compatible canonical service.
It must reject uninstalled, ambiguous, incompatible, or unmanaged definitions
instead of silently creating arbitrary units or running an unverified binary.
Repeated `stop` on an already stopped managed service succeeds. Neither command
kills unrelated foreground processes, adopts arbitrary PIDs, clears checkpoints,
or edits an upstream session database. Partial lifecycle operations report the
actual resulting state rather than claiming transactional success.

Before implementation, specify exact exit codes for success, invalid/unsupported
configuration, ownership conflict, authorization failure, and lifecycle timeout.
For status, separate failure to retrieve status from a successfully retrieved
stopped/degraded state; automation must not infer healthy coverage from exit zero.

## 2. Current-user service first; explicit reboot persistence

Implement and validate Linux/systemd user-service management first. Other
platforms keep one-shot and foreground operation. Unsupported lifecycle commands
must return an actionable unsupported result, not silently become a scheduler or
an ad-hoc background process. macOS launchd and Windows service ownership require
their own reviewed platform work before claiming equivalent support.

Fresh installation remains disabled unless opted in. Provide a documented path:
install a verified package and its canonical observer unit, validate effective
configuration, then run `start --enable-on-boot` and verify `status --service`.
Enablement must identify whether the service starts at login or actually at boot.
On Linux, user-manager lingering may be required for operation before login or
after logout. Report that prerequisite and the explicit administrator action;
do not silently enable lingering, invoke privilege elevation, or promise reboot
persistence when the user manager will not be started.

Extend the existing installer transaction and canonical-resource validation.
`installer-service-archive` currently forbids unit-specific drop-ins. Therefore,
resource customization must use reviewed installer-generated canonical policy
or a narrowly specified installer-contract change with equivalent validation.
Do not instruct operators to bypass the existing proof with arbitrary drop-ins.
Keep canonical unit generation and effective-unit validation in agreement.

Migration from the canonical scan timer requires explicit operator selection:
validate the new observer and policy first, quiesce the canonical timer and any
active scan, transfer ownership, then start the observer. Failure leaves a known,
reported state; do not silently reactivate a schedule. Never alter unrelated
timers/services. Rollback stops/disables the observer and restores the previously
chosen canonical schedule only with operator authorization. Existing state must
remain readable; no state reset is an acceptable migration shortcut.

## 3. Correct startup, incremental work, and reconciliation

1. Acquire exclusive writer ownership for the selected state/output profile.
2. Register relevant watch roots before bootstrap discovery/processing; collect
   changes during bootstrap. Handle missing roots and roots created later.
3. Discover sources and reconcile against committed source progress.
4. Perform bounded bootstrap work. First-run sources may require historical
   processing; report its scope, remaining work, or explicit budget failure.
5. Drain/coalesce changes received during bootstrap and enter steady operation.

Registering watchers is not readiness. Distinguish `starting`, `reconciling`,
`observing`, `degraded`, `stopping`, and `stopped` from OS process state. An observer
can be operational while some sources have incomplete coverage; expose both.

### No regularly scheduled full-content scan

Notifications trigger affected-source work. Add a lightweight inventory/progress
reconciliation every **15 minutes by default**, configurable with a finite
positive interval. It is a safety check, not permission to reread every transcript.
Measure file/source identity and adapter-specific progress, then schedule only
changed or uncertain sources. Work stays subject to cycle budgets and rate limits.

Mtime/size alone is not authoritative for every adapter. SQLite WAL changes,
replacement, rotation, truncation, and unavailable roots need explicit handling.
An adapter unable to prove unchanged state must report uncertainty and schedule
bounded recovery; it cannot declare complete coverage from a metadata shortcut.
Backend overflow or lost watch roots triggers immediate recovery subject to
rate limits, not a 15-minute silent gap. Inventory discovery itself must have
bounded pending work and deadline behavior.

Keep existing 500 ms fixed collection-window and 10-second minimum processing
interval as initial defaults. Document that this is not a quiet-period debounce.
Do not postpone processing indefinitely during a continuous write stream.
Bound both the notification handoff channel and the coalesced path set; pending
detail overflow becomes a full-reconciliation-required flag. Changes during
reconciliation require a subsequent pass. Notification errors/disconnection
produce degraded health or a supervised failure, never silent successful exit.

Configuration is validated and fixed for a running instance in the first release.
Changing roots or project configuration requires a controlled restart and startup
reconciliation; hot reload is not implied. Document this rather than leaving
operators to assume all configuration edits take effect immediately.

## 4. Incremental acquisition is a distinct correctness gate

Resource bounds and a persistent process do not solve repeated historical reads.
Deliver service lifecycle and acquisition work as separate reviewable tranches,
but do not call the result fully incremental until adapters establish that claim.

For OpenCode, explicitly design message selection/progress as well as part
progress. Before replacing the uncursored message query, establish:

- independent message observations versus context joined to selected parts;
- updates, equal timestamps, late writes, replay overlap, and stable ordering;
- database replacement/restore, bootstrap selection, and honest history coverage;
- consistent read snapshots and correct cursor eligibility;
- preserved metadata ambiguity, parser-failure, accounting, and detection behavior;
- required cross-record/session context across processing windows;
- compatible state migration or explicit bounded fallback for old checkpoints.

Do not simply add a message `LIMIT`, process only joined messages, or advance a
high-water mark beyond work not durably covered. A design unable to prove those
semantics must retain explicit bounded failure rather than invent successful
partial coverage. Other file adapters likewise need contracts before append-only
offset reads can replace full-source interpretation.

A notification-driven release may initially use bounded source rereads; its
documentation must say so. Message incrementality and bounded durable replay
remain release gates for broader claims about continuous, bounded history
processing—not invisible future optimizations.

## 5. Resource policy

Initial defaults are engineering targets requiring synthetic validation, not
capacity guarantees for arbitrary history. Existing stricter adapter/evaluator
caps remain in force. MiB denotes 1,048,576 bytes.

| Application control | Default |
| --- | ---: |
| Encoded record / SQLite payload field | 8 MiB |
| Aggregate admitted source payload | 128 MiB |
| Native units per source operation | 100,000 |
| Pending encoded Event3 output | 32 MiB |
| Source / processing-cycle cooperative deadline | 30 / 120 seconds |
| Pending notification handoff / unique pending paths | 4,096 entries each |
| Recovery inventory interval | 15 minutes |

Counters reset per operation/cycle, not just process startup. Limit configuration
uses the existing resolution/provenance path and an equivalent typed embedding
policy. Reject zero/unlimited values, overflow, and invalid combinations. Expose
effective policy. Operators may choose larger finite budgets deliberately.

Encoded-byte caps are not heap bounds. Check lengths before allocating complete
payloads; use bounded JSONL record accumulation and consistent SQLite snapshots
for preflight/read. Avoid whole-input raw-row vectors and duplicate serialized/
decoded payload retention. Bound retained evaluation context as well as input.
Release intermediate results promptly without changing source-atomic detection.

Proposed Linux backstop: `MemoryAccounting=yes`, `MemoryHigh=1G`,
`MemoryMax=2G`, `MemorySwapMax=0`, and CPU/IO weights of 25 where supported.
These are process/cgroup safeguards, not application-budget substitutes. Report
unsupported controllers honestly; embedding hosts own their OS isolation.
Measure process RSS and cgroup anonymous/file memory separately. Do not impose a
finite `RuntimeMaxSec` on a healthy continuous observer.

An oversized source must be visibly unprocessed. These defaults intentionally do
not make arbitrarily large historical messages fit. Automatic budget escalation,
silent truncation, or disabling detection to meet a benchmark is unacceptable.

## 6. Ownership, durability, shutdown, and backpressure

Use an OS-released exclusive ownership lock for a continuous writer over its
selected state/output profile, composed with existing transactional state locks.
Define lock ordering and avoid recursive acquisition/deadlock. A PID file alone
is not authority; PID reuse and stale files must not cause adoption or killing.
Do not release ownership while asynchronous writes still belong to the instance.

A competing state-mutating scan/observer must fail with an actionable conflict,
not interleave checkpoint ownership. For an operator-requested one-shot on the
same profile, stop the managed writer first or use an explicitly separate
profile. Existing dry-run/snapshot reads remain read-only and must not mutate
writer state. A global lock must not prevent independent profiles/embedded hosts.

Preserve source-atomic failure and required durable output before cursor/baseline
installation. Source budget failure discards that source's provisional success;
scan-wide staging/deadline exhaustion abandons uncommitted cycle state. Reserve
bounded diagnostic capacity. No incorrect cursor advancement is acceptable after
OOM, disk full, cancellation, or remote outage; do not claim exactly-once output.

On SIGTERM/Ctrl-C, stop admitting new work, retain ownership, and finish or safely
abandon the current uncommitted operation. Use a **30-second cooperative shutdown
target** and a **60-second supervisor stop ceiling** as initial settings, validated
against existing delivery cancellation/retry behavior. If forced termination is
needed, restart uses last committed progress and reconciles queued/missed changes.
Do not acknowledge successful graceful drain when the deadline forced a kill.

Remote delivery retries and observer acquisition must not create unbounded queues
or hide prolonged coverage loss. When existing durable capacity is exhausted,
report backpressure/coverage degradation and preserve progress guarantees; do not
drop payloads silently. Bounded replay, retention, disk-capacity behavior, and
restart reconciliation require a separate delivery tranche. Do not introduce an
unreviewed ingestion/delivery concurrency pipeline just to hide slow sinks.

## 7. Health that describes the security control

Use existing compatible Event3 diagnostics and a separately versioned service
status result; do not modify Event3 simply to add lifecycle management. Expose:

- installation/support, boot enablement prerequisites, and service-manager state;
- current owner/mode and running binary/configuration identity using safe fields;
- fresh runtime heartbeat, lifecycle phase, and last successful processing;
- last successful reconciliation, watcher/backend errors and overflow count;
- pending work count, oldest pending age, and last progress time;
- discovered/admitted/completed/failed/unattempted source counts;
- budget exhaustion, delivery backlog/failure, and incomplete coverage reasons.

Use a bounded atomically replaced local status snapshot with a proposed
10-second heartbeat and 30-second stale threshold. Do not emit a durable event
or fsync log on every heartbeat. Treat snapshots as diagnostic, not checkpoint
authority; do not trust a stale snapshot over the service manager/ownership state.
Combine instance identity and freshness, avoid trusting a PID alone, and handle
clock jumps conservatively. A process blocked in a scan may become stale and
must be reported as such; a timer thread's heartbeat alone is not processing
progress. Stopped observers cannot announce their own absence: external
controllers/SIEM monitoring must detect stale health or missing telemetry.

No raw session content, credentials, arbitrary exception text, or unnecessary
paths appear in status, logs, diagnostics, state, or configuration provenance.
Test synthetic sensitive markers on every output surface. Bound and rate-limit
repeated diagnostics while preserving visible persistent coverage loss.

## 8. Future named-pipe and process inputs

Keep acquisition/evaluation policy independent of systemd and file notifications.
Do not implement future transports in this change. Each needs an accepted contract
for producer identity, framing/max frame size, session attribution, authentication
where applicable, backpressure, loss, disconnect/reconnect, cancellation, and
durable acknowledgement/restart position. Files can be rescanned; pipes usually
cannot. No transport acknowledgement may imply durable coverage before the
required commit boundary. Process observation also needs explicit privilege and
supported-platform boundaries.

## 9. Implementation sequence and acceptance gates

### A. Contracts and characterization

- Create bounded implementation Issues linked to this public plan; reconcile
  active adapter/state changes rather than overwrite them.
- Add OpenSpec deltas for lifecycle commands/status compatibility, ownership,
  watch recovery, resource budgets, and installer service migration. Keep shipped
  specs unchanged until the corresponding work is accepted and implemented.
- Define exit codes, status schema, lock scope/order, readiness, failure states,
  and exact supported Linux service-manager behavior before production edits.
- Characterize existing under-budget observations, scoring, ordering, state,
  baseline, parser failure, and output-before-state behavior with synthetic tests.

### B. Bounded runtime and watcher recovery

- Add policy validation, allocation-aware readers, deadlines, bounded result
  staging, and privacy-safe incomplete-coverage diagnostics.
- Add watcher-before-bootstrap sequencing, bounded handoff, overflow recovery,
  missing-root recovery, WAL handling, and lightweight periodic reconciliation.
- Test notification loss, removal/recreation, replacement/rotation/truncation,
  changes during bootstrap/recovery, disconnected backends, repeated failures,
  and shutdown during every durability boundary.

### C. Supervised service and external control

- Reuse foreground watch; implement idempotent lifecycle commands, compatible
  status extension, ownership conflicts, bounded shutdown, and restart backoff.
- Extend canonical installer generation/validation and explicit timer migration;
  test partial enable/start failures, ambiguity, unsupported managers, reboot
  prerequisites, rollback, and preservation of unrelated services.
- Test external supervision and one-shot use without Emusary-specific core code;
  verify managed/external instances cannot silently share writer ownership.

### D. Incrementality and durable capacity

- Approve and implement adapter-specific progress semantics with restart, cursor,
  malformed-input, and historical coverage tests before claiming incremental
  ingestion. Independent read-only correctness review is required.
- Bound durable replay/capacity behavior separately, preserving first-write and
  retry contracts. Test offline sinks, disk exhaustion, corrupt replay input,
  rotation, restart, and bounded backlog behavior.

### E. Release evidence and rollout

- Benchmark a documented synthetic ordinary workload (300 small sources,
  <=16 MiB ordinary source payloads, within existing semantic limits). Initial
  target: successful ordinary processing with RSS <=768 MiB and cgroup peak
  <1 GiB on a recorded Linux reference environment. Amend targets/defaults only
  with evidence, not by silently raising limits or reducing coverage.
- Separately test near-limit and oversized inputs in constrained disposable
  processes: graceful resource failure before catastrophic allocation, no
  incorrect checkpoint, and correctly reported hard-ceiling termination.
- Run at least a 24-hour synthetic continuous soak with steady traffic, bursts,
  idle time, backend loss, and sink failures. Report processing lag, coverage,
  restart recovery, memory plateau/growth, and CPU/I/O. Do not extrapolate this
  finite Linux evidence to untested platforms or production efficacy.
- Prove simulated reboot/login/no-login behavior in an isolated platform test,
  not by rebooting or mutating an operator's live host. Test upgrade and rollback
  with compatible state and one unambiguous owner.
- Run focused checks first, then formatting, strict Clippy, full tests, applicable
  fixture/package/installer gates and strict OpenSpec validation. Require
  independent read-only security/correctness review for lifecycle, ownership,
  persistence, and release-integrity changes.
- Publish tested revision/platform/policy and residual limitations. Update
  install/current-behavior docs only when shipped. Deployment and any live timer
  migration require separate explicit operator authorization.

## Scope and design boundaries

This proposal does not introduce privileged system-wide operation, tamper
protection, active response, IPC management APIs, remote rule feeds, arbitrary
service management, or a new event schema. Preserve deterministic detection,
exact `(ClientId, source_id)` ownership, and fail-closed parser behavior.

Relevant formal contracts:
[installer/service safety](../openspec/specs/installer-service-archive/spec.md),
[OpenCode acquisition](../openspec/specs/opencode-sqlite-canonical-observation-v2-adapter/spec.md),
[coverage and state](../openspec/specs/canonical-accounting-coverage/spec.md),
and [durable delivery](../openspec/specs/durable-delivery/spec.md).
Follow the [Telltale/Emusary boundary](development-principles.md) and keep detailed
implementation task state in Issues/local OpenSpec packages, not in this page.
