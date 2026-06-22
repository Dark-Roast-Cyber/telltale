# Telemetry Output

> **Website:** For an approachable overview of telemetry output and SIEM integration, see [AgentArchaeology.ai/telltale/telemetry-output](https://agentarchaeology.ai/telltale/telemetry-output/).

Telltale emits compact JSONL events for local review, forwarding, dashboards,
and alerting. The default scan path writes one canonical JSON object per line
to a local file; optional delivery paths can wrap the same event body for a
specific sink without changing the event schema.

## Default JSONL Sink

By default, `adr scan` uses the `user` path profile and appends telemetry to
an operating-system-standard per-user JSONL path:

| OS | Default user telemetry path |
| --- | --- |
| Linux | `$XDG_STATE_HOME/telltale/logs/adr-events.jsonl` or `~/.local/state/telltale/logs/adr-events.jsonl` |
| macOS | `~/Library/Logs/Telltale/adr-events.jsonl` |
| Windows | `%LOCALAPPDATA%\Telltale\Logs\adr-events.jsonl` |

```sh
cargo run -- scan --once --emit-activity
```

Use `--path-profile system` for managed service deployments, or
`--path-profile project` when you intentionally want repo-relative development
paths such as `logs/adr-events.jsonl` and `state/adr-state.json`. Explicit
`--log-path` and `--state-path` flags still override profile defaults. Service
managers can set `ADR_LOG_PATH` and `ADR_STATE_PATH` instead of repeating flags.

Use `--dry-run` when validating fixtures or command behavior without writing
events:

```sh
cargo run -- scan --once --dry-run --root tests/fixtures/session_stores
```

The JSONL sink is the stable interchange point. Each line is a complete event
that follows [schemas/event.schema.json](../schemas/event.schema.json).

## Event Families

Common event types include:

- `activity`: redacted per-session activity summaries.
- `activity` with `check_name=install_inventory`: metadata-only installed-agent
  inventory collected on a cadence. Evidence records agent names, confidence,
  signal types, and path hashes rather than raw transcript or session contents.
- `detection`: rule matches, risk scores, categories, and response guidance.
- `session_risk_summary`: optional per-session rollups from already-redacted
  activity and detection events.
- `scanner_health`: source-discovery and scanner health status.
- `scanner_error`: parser or scan errors that should be visible to operators.
- `correlation`: cross-session patterns built from emitted telemetry.

Enable optional activity and session summary events when dashboards need more
than detection-only output:

```sh
cargo run -- scan --once --emit-activity --emit-session-risk-summary
```

Installed-agent inventory is separate from session-store discovery. It checks
metadata such as executable names, package roots, VS Code-style extension IDs,
and globalStorage presence to identify installed tooling even when no sessions
exist. By default, scans collect and emit this inventory at most once every 24
hours according to the state file. Tune the cadence with
`--install-inventory-interval-seconds` or
`ADR_INSTALL_INVENTORY_INTERVAL_SECONDS`; use `0` to collect every scan, or
`--install-inventory-disabled` to suppress inventory for a run.

## Privacy Boundary

Telemetry should be useful without becoming a transcript dump. Telltale emits
redacted excerpts, evidence hashes, rule IDs, risk scores, source metadata, and
bounded context by default. It should not emit raw secrets, full auth files, raw
private keys, complete `.env` values, or full session bodies.

See [privacy-model.md](privacy-model.md) for the evidence classes and redaction
rules that govern emitted event content.

## Public Examples And Release Evidence

Public documentation, release notes, and support evidence should follow the same
privacy boundary as emitted telemetry: use synthetic fixtures or already-redacted
event output, not live session stores, raw transcripts, local telemetry logs,
scanner state, workstation paths, SIEM endpoint details, or credential-like
values. Keep host-specific validation observations in local-only notes and
recreate public examples with fixture-backed commands when evidence is needed.

See [trust-boundaries.md](trust-boundaries.md) and
[release-readiness.md](release-readiness.md) for the publication and artifact
boundary checks.

## Forwarding To SIEMs

Forward the active JSONL file for the path profile your deployment actually
uses. A safe starter pattern is:

1. Write events locally with the default path profile, `ADR_LOG_PATH`, or an
   explicit `--log-path`.
2. Validate the event shape against the schema.
3. Configure the shipper to read only that active JSONL event path.
4. Keep human-readable diagnostics, scanner state, credentials, and raw agent
   session stores outside the forwarded telemetry path.

For default workstation installs, that active file is the `user` profile path,
such as `~/.local/state/telltale/logs/adr-events.jsonl` on Linux. For managed
service deployments, run scans with `--path-profile system` or explicit
`ADR_LOG_PATH`/`ADR_STATE_PATH` values and point shippers at the system path,
such as `/var/log/telltale/adr-events.jsonl` on Linux. Do not keep monitoring
legacy repo-local `logs/adr-events.jsonl` unless the scanner is intentionally
running with `--path-profile project` or an explicit `ADR_LOG_PATH` that writes
there.

Use explicit file paths instead of broad log directory monitors so diagnostic
logs or source logs do not get indexed as Telltale events. For Splunk Universal
Forwarder deployments, install timestamp and JSON parsing props on the tier that
performs parsing (the indexer or a heavy forwarder; a UF with indexed JSON
extractions may also apply them before forwarding). The `adr:json` timestamp
parser expects Telltale's canonical `timestamp` field to remain the first JSON
field.

For managed deployments, prefer OS-native rotation first. Keep the active file
name stable, such as `/var/log/telltale/adr-events.jsonl` on Linux, and configure
`logrotate`, `newsyslog`, a Windows scheduled task, or your endpoint collector to
rotate completed files without changing the active shipper target. The Linux
starter example is `config/examples/telltale-logrotate`.

## Built-In Rotation

For user-profile installs and cross-platform consistency, Telltale includes
built-in size-based rotation. No OS-specific tooling (`logrotate`, `newsyslog`,
Scheduled Tasks) is required.

When the active JSONL file exceeds the configured max size, Telltale renames it
to a date-stamped rotated file and starts a fresh active file. The active file
name is always stable (`adr-events.jsonl`) so shippers can monitor a single
path. Rotated files are named `adr-events-YYYY-MM-DD.jsonl`, with a counter
suffix (`.1`, `.2`) for same-day rotations. Files beyond the keep count are
deleted oldest-first.

Defaults:

| Setting | Default | Env var |
| --- | --- | --- |
| Max size | 100 MB (104_857_600 bytes) | `ADR_LOG_ROTATE_MAX_SIZE` |
| Keep count | 5 | `ADR_LOG_ROTATE_KEEP` |

CLI flags override env vars:

```sh
adr scan --once --emit-activity --log-rotate-max-size 52428800 --log-rotate-keep 10
```

To disable built-in rotation (for system-profile deployments that use OS-native
`logrotate` instead):

```sh
adr scan --once --emit-activity --log-rotate-disabled
```

The local JSONL file is a **transient spool**, not the canonical store. Once
events are shipped to a SIEM or central log platform, that platform is
canonical. Rotation keeps the local spool bounded without external tooling.

## Optional Export And Sink Paths

The canonical event payload remains the same across delivery paths:

- `adr export --format jsonl` reads existing JSONL telemetry.
- `adr export --format elastic-bulk` writes Elasticsearch Bulk API pairs.
- `adr scan --splunk-hec-endpoint ... --splunk-hec-token ...` can post the same
  events through a Splunk HEC envelope when a deployment explicitly opts in.

Sink-specific metadata belongs at the sink or export layer. Do not add
deployment-specific SIEM fields to the canonical event body.
