# telltale-core


The supported Telltale embedding facade. `Pipeline` combines discovery,
native acquisition, and detection while returning events to the host application. It does
not write JSONL, connect to a SIEM, or exit the process. The source directory
remains `crates/telltale` for repository compatibility.

## LocalEventFeed

`LocalEventFeed` is an opt-in, synchronous, read-only consumer for the local
canonical Event 3.0 JSONL journal. The host owns the cadence; the feed does not
start a thread, watcher, runtime, database, cursor file, lock, or outbox
operation.

```rust,no_run
use std::path::PathBuf;
use telltale_core::{LocalEventFeed, LocalEventFeedConfig, StartupMode};

let config = LocalEventFeedConfig::new(
    PathBuf::from("logs/telltale-events.jsonl"),
    StartupMode::Recent { max_events: 100, max_bytes: 256 * 1024 },
);
let mut feed = LocalEventFeed::new(config)?;
// A host timer or event loop calls this at its chosen cadence.
let batch = feed.poll()?;
for record in batch.records {
    println!("{}", record.common().event_id);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Beginning`, `End`, and `Recent` use physical built-in rotation order, not
event timestamps. Polling, framing, directory discovery, and deduplication are
bounded. Recent is a bounded suffix view; in-memory deduplication uses a FIFO
window of exact-line SHA-256 values, so restart and eviction can replay an
identical event. The feed recognizes only Telltale's built-in rotation names;
external rotators and uncertain replacement races produce safe notices rather
than a universal recovery claim. It reads complete LF-terminated lines and
returns typed `Event3Record` values without re-redaction. Durable outbox state
is private and is not exposed by this API.

`FeedBatch.bytes_read` is the actual journal payload bytes physically
read/processed during that poll. It is not a cursor substitute; a poll that
only emits pending records while draining may report zero. `FeedBatch.caught_up`
means the currently discoverable eligible bytes and records were drained
consistently with the startup floor and a stable observation. It is false when
a budget, bound, partial frame, unresolved race, or generation gap remains. It
does not mean that no future events will arrive, that sessions are complete,
that event time is current, or that excluded Recent history does not exist.

## Local session investigation (opt-in)

`investigation::SessionInvestigator` accepts a consumed `Event3Record` and returns
typed `Found`, `SourceUnavailable`, `SessionUnavailable`, or
`NotLocallyResolvable`. Configure a discovery root and optionally a caller-owned
snapshot of known sources; there is no persistent index or automatic discovery
of additional roots. Correlation requires exact client and existing `path_hash`,
then confirmation of the source-reported terminal session identity. Missing or
ambiguous correlation never triggers a session-ID-only search.

The three unavailable outcomes carry closed reason enums; `reason_code()` returns
an optional static code (`None` for `Found`). Reasons contain no paths, source
content, native messages, or raw diagnostic strings, including through `Debug`.
Embedding callers must update unit-variant matches to payload matches, for example
`InvestigationResult::SourceUnavailable(reason)` (or `SourceUnavailable(_)`).
The four outcome names and `Found` payload are unchanged; Event3 is unchanged.

`Found.timeline` uses `ExportedSessionTimeline` but contains **no record content**:
every entry's evidence is empty; agent/model/provider metadata is omitted. Safe
tool labels, opaque call IDs, timestamps, ordering, and unambiguous call/result
links remain. Existing transcript timeline exports are unchanged. Anchors expose
only the recorded index and whether a current entry exists at that index, not an
immutable-history or fuzzy-match guarantee. Event3 remains authoritative.

The direct reader supports the existing Claude, Codex, OpenClaw, and Qwen JSONL
identities, including a single JSON object in such a source. No new JSON source
layouts are enabled. Retired JSON layouts and Copilot process logs are not
session investigation providers.

**OpenCode investigation is unavailable and deferred.** Source-correlatable
OpenCode requests return `SourceUnavailable(ReadOnlyProviderUnavailable)` before discovery, source I/O, or
process spawning. This denotes an unavailable provider, not confirmation that
the source exists. There is no executable/export configuration or public native
export acquisition API, and no SQLite/WAL/SHM fallback. The native OpenCode CLI
initializes, checkpoints, and migrates its store even for export, violating the
no-mutation boundary. [Issue #42](https://github.com/Dark-Roast-Cyber/telltale/issues/42)
remains incomplete pending a genuinely read-only OpenCode capability. Production
scan/watch OpenCode acquisition is unchanged.

Defaults cap discovery at 16,384 visited entries and depth 32, known sources at
1,024, direct input at 8 MiB, input/observation counts at 8,192, and JSON
depth at 64. Limits can only be lowered. Incomplete
discovery fails closed; read/parse/limit/provider failures expose no raw errors.
Direct reads validate a regular opened file and bound bytes including growth;
they are not filesystem snapshots or hard wall-clock bounds on OS file I/O.

### Availability reasons and operator actions

These codes describe the current attempt, not historical source state. The host
owns any later invocation; the backend keeps no retry state and never retries.
Do not weaken access controls, raise the documented maxima, or use native export
as a fallback to make an unavailable result succeed.

| Outcome | Reason code | Operator action |
| --- | --- | --- |
| `SourceUnavailable` | `read_only_provider_unavailable` | OpenCode is deferred. Keep Event3 as the evidence; wait for a separately accepted read-only provider. This is not a missing-store, permission, or busy diagnosis. |
| `SourceUnavailable` | `source_missing` | The exact correlated path was absent at the read attempt (often a known source that moved/disappeared). Check local retention/location; no alternate-path lookup occurs. |
| `SourceUnavailable` | `source_permission_denied` | The OS reported permission denial. Check the caller's intended access locally without broadening permissions automatically. |
| `SourceUnavailable` | `source_unreadable` | Other read/open failure, including an unclassified rejected symlink. Check source type and local filesystem availability; no busy/access diagnosis is inferred. |
| `SourceUnavailable` | `non_regular_source` | The opened object was not an accepted regular file. Check the configured source; pipes/devices/reparse points are not investigation inputs. |
| `SourceUnavailable` | `source_limit_exceeded` | Bytes, input/observation records, JSON depth, or acquisition/accounting capacity exceeded a bound. Use Event3; smaller caller limits may be restored only up to the documented maxima. |
| `SourceUnavailable` | `malformed_source` | JSON, native envelope, attestation, or canonical mapping/validation failed. Check local source integrity and supported layout; there is no parser fallback or partial timeline. |
| `SessionUnavailable` | `exact_session_absent` | The acquired source did not attest the exact terminal session identity. Check retention; never substitute a similarly named session. |
| `SessionUnavailable` | `session_has_no_timeline` | The exact identity was attested but has no projectable observations (for example, metadata only). Use Event3; this does not assert that the session never existed. |
| `NotLocallyResolvable` | `unknown_source` | No exact client/path-hash source was discovered or supplied. Check the caller-owned root/known-source snapshot; the backend cannot diagnose a missing file without that correlation. |
| `NotLocallyResolvable` | `missing_correlation`, `unsupported_client`, `unsupported_source` | The event family lacks source correlation or the client/source is not a direct investigation provider. Use Event3; no session-ID-only lookup occurs. |
| `NotLocallyResolvable` | `ambiguous_source`, `ambiguous_session`, `conflicting_session_ownership` | Exact ownership is not unique/consistent. Check the caller snapshot or source integrity locally; no candidate is selected. |
| `NotLocallyResolvable` | `invalid_limits`, `event_limit_exceeded`, `invalid_event_timestamp` | Correct caller limits or inspect the consumed event locally. Do not bypass the consumed Event3 contract. |
| `NotLocallyResolvable` | `discovery_limit_exceeded` | Entry/depth budget exhausted. Use a narrower valid root or restore a lowered entry limit within the maximum; no partial discovery is used. |
| `NotLocallyResolvable` | `discovery_permission_denied`, `discovery_unavailable`, `discovery_symlink_root` | Discovery was incomplete due to an observed denial, other traversal error, or rejected symlink search root. Check the root/access locally. A known-source snapshot does not bypass incomplete discovery. |

Support remains the registered direct JSONL layouts, not a new client-version
compatibility matrix. Linux synthetic tests exercise direct reads and OpenCode
no-launch/no-open/no-read probes. Platform-specific regular-object rejection is
implemented for Unix and Windows; this change does not independently qualify
macOS/Windows native client versions. OpenCode investigation is unavailable for
all versions/platforms in this tranche, regardless of production scanner support.

Focused gate: `make session-investigation-check` (synthetic sources and fake
executable no-launch sentinel only; no host session access).

## Protected assignment (optional)

The `assignment` module is available only with the default-off
`protected-assignment` Cargo feature. Git-pinned adopters using this module
must enable the feature when updating their revision:

```toml
[dependencies]
telltale-core = { git = "https://github.com/Dark-Roast-Cyber/telltale", rev = "<commit>", features = ["protected-assignment"] }
```

Default builds retain `Pipeline` and `LocalEventFeed` but do not compile or
expose `telltale_core::assignment`. Enabling the feature retains that module
path and the existing store format and behavior; no state migration is needed.

The opt-in `assignment` module owns a local protected-assignment SQLite store
for Canonical Observation v2 facts that lack a stable source coordinate. It is
not wired into production scanning or adapter projection. Callers must provide
a separately proven, mutation-stable replay association; the store does not
derive one from paths, timestamps, ordinals, or content. Each association also
requires a closed, code-reviewed `AssignmentAdapterDomain` registered from
non-sensitive adapter identifiers; unknown and dynamic source, tenant, or
credential values are rejected. Durable assignment is currently Linux-only; other
platforms fail closed until equivalent descriptor/ACL profiles are validated. New
state must be created explicitly with `ProtectedAssignmentStore::initialize`;
`open` never recreates missing authority, database, key, or receipt state.
Domain registration does not establish replay-association readiness or enable a
projector.

Operational limits: the store targets a single local filesystem under the owning
user's private directory; network filesystems are unsupported. Assignment and
receipt state grows without bound and operators own capacity. Interrupted
initialization can leave a partial store root that must be removed manually
before reinitializing; `open` never repairs or recreates state. Replacement of
the entire trusted store boundary by a same-UID attacker is out of scope.

## Pipeline

Returned native events use the Event 3.0 contract, deterministic `response`
metadata, and optional top-level `timeline_anchors`; the embedding host owns
transport and any historical-event handling.

```rust
use telltale_core::Pipeline;

let pipeline = Pipeline::builder().build()?;
println!("{} rules", pipeline.rule_count());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `Pipeline::producer_provenance_manifest` to materialize the deterministic
`ProducerProvenanceManifestV1` for the same already compiled rules and resolved
producer values. The Rust assembler does not resolve filesystem paths, managed
tiers, policy files, or allowlist paths; the CLI performs that resolution with
the scan resolver before assembly. The manifest is separate from Event 3.0
telemetry and is not an attestation or per-event claim.

This package follows Telltale's pre-1.0 release and compatibility policy.

> **Crates.io name warning:** The package named `telltale` is an unrelated
> session-types crate. Use `telltale-core` and `telltale_core` for this project.

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
