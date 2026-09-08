# telltale-sources

[![crates.io](https://img.shields.io/crates/v/telltale-sources.svg)](https://crates.io/crates/telltale-sources)

Cross-platform session-store discovery and parsing for supported AI coding
agents, including source definitions and install inventory. This crate parses
and normalizes source data but does not apply detection rules or emit telemetry.

```rust
let sources = telltale_sources::discovery::discover_sources(std::path::Path::new("/tmp"))?;
println!("{} sources", sources.len());
```

This package follows Telltale's pre-1.0 release and compatibility policy.

## Native OpenCode investigation export

`opencode_export::export_session(event, discovered_source, config)` is an
opt-in source primitive, not a scanner/parser route or investigation UI. It
accepts a validated `Event3Record` and a `Source` obtained from local discovery.
Before spawning it requires client `opencode`, exact `opencode.sqlite` ownership,
SQLite source kind, an existing source file, and the exact existing path hash.
The caller must use discovery for the same local store context as the trusted
OpenCode executable; matching the path hash does not attest to external CLI
store selection. Telltale does not open SQLite, WAL or SHM files.

The native schema was audited against OpenCode **1.18.25**. An optional explicit
executable path is supported; otherwise exactly `opencode` is resolved by PATH.
Explicit Windows paths must end in `.exe`; batch scripts are rejected to avoid
Rust's implicit `cmd.exe` handling.
There is no executable scanning, installation, version subprocess or fallback
without `--pure`. The only commands are direct argv, never a shell:

```text
opencode --pure export <session-id> --sanitize
opencode --pure session list --format json --max-count <N>
```

Safe preserved `ses_` IDs export directly. Current mixed-case IDs become opaque
under the existing terminal-session policy; bounded listing compares each raw
candidate's `terminal_session_id` exactly. Only listing IDs are extracted. Zero
matches (including native empty stdout) are unavailable; multiple matches are
ambiguous. Listing is native roots-only/recent bounded context, not exhaustive
history. Candidate IDs must be 5–128 ASCII alphanumeric/underscore bytes with a
`ses_` prefix, so none can be parsed as an option. Exported session/message/part
ownership is checked, and missing or duplicate tool call identity fails closed.
Message/part IDs and explicit call IDs are bounded to 256 bytes.

### Bounds and process ownership

Defaults are also maximum configurable values; callers can lower them:

| Limit | Default / maximum |
| --- | ---: |
| Listing candidates | 256 |
| Listing stdout | 1 MiB |
| Export stdout | 8 MiB |
| Stderr, per command | 64 KiB |
| Monotonic wall deadline, per command | 10 seconds |
| JSON object/array nesting | 64 |
| Returned canonical records | 8,192 |

The fallback uses at most two commands, each with its own deadline. Serialized
JSON is byte/depth bounded before typed parsing; these are not process RSS or
external-harness storage budgets. Zero or above-maximum limits are rejected.
Input is never accepted partially after truncation or a limit failure.

Telltale owns **only the direct child**: stdin is null; stdout and stderr drain
concurrently with independent byte caps and no drain threads. Unix uses
nonblocking pipe reads; Windows peeks available anonymous-pipe bytes before
reading. On timeout/overflow it kills and waits for the direct child before
returning; there is no permanent runtime. A successful child is also reaped.
This is not process-tree containment or a sandbox. OpenCode under mandatory
`--pure` (which disables external plugins in 1.18.25) is trusted harness behavior
outside Telltale's lifecycle/storage boundary, including its internal services
and any descendants. Telltale adds no network client, listener or server.

### Canonical and privacy boundary

The returned `Vec<NormalizedRecordV1>` is **internal data**, not a public
transcript. Consumers must pass it through
`telltale_detect::timeline::build_exported_session_timeline` before exposure.
An export without supported records returns `SessionUnavailable`.

The native enclosing tool part's explicit `callID` populates both canonical call
and completed/error result IDs. Pending/running parts create only calls. Text
parts create user/assistant messages; unknown part types and unknown fields
are ignored, not forwarded. Source ordering is preserved; no detection/scoring
or producer provenance changes occur.

Provenance carries the Event3-correlated `source_path_hash`, the native part ID
as `source_event_id`, no fabricated offset, and the extension
`source_adapter=opencode.native-export.v1`. Source timestamps are normalized to
RFC3339. Native `--sanitize` is defense in depth, not Telltale's boundary: it
leaves some error text and unknown fields intact. Telltale applies
`redact_sensitive_text` and hashes text/arguments/results into owned redacted
summaries, rather than exposing another transcript surface. Arguments are a
typed redacted-summary object; results are typed summary strings. Tool names
use terminal identifier policy; explicit call IDs remain internal and the
existing public timeline hashes them while retaining linkage.

`ExportError` contains only static categories: invalid limits, source mismatch/
unavailability, session unavailability/ambiguity, unsafe session ID/executable, spawn/
capture/nonzero exit, timeout, stdout/stderr limit, JSON depth, malformed
listing/export, candidate/record limit and identity mismatch. Neither stderr,
OS/serde diagnostics, executable paths nor input payloads appear in errors.

Synthetic tests and the portable fake executable run with
`make opencode-export-check`; the existing Linux/macOS/Windows test jobs include
them. No real session content is used in the fixtures or tests.

- [API documentation](https://docs.rs/telltale-sources)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
