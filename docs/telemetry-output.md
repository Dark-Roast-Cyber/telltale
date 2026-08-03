# Telemetry Output

> **Website:** For an approachable overview of telemetry output and SIEM integration, see [AgentArchaeology.ai/telltale/telemetry-output](https://agentarchaeology.ai/telltale/telemetry-output/).

Telltale emits compact JSONL events for local review, forwarding, dashboards,
and alerting. The default scan path writes one canonical JSON object per line
to a local file; optional delivery paths can wrap the same event body for a
specific sink without changing the event schema.

## Default JSONL Sink

By default, `telltale scan` uses the `user` path profile and appends telemetry to
an operating-system-standard per-user JSONL path:

| OS | Default user telemetry path |
| --- | --- |
| Linux | `$XDG_STATE_HOME/telltale/logs/adr-events.jsonl` or `~/.local/state/telltale/logs/adr-events.jsonl` |
| macOS | `~/Library/Logs/Telltale/adr-events.jsonl` |
| Windows | `%LOCALAPPDATA%\Telltale\Logs\adr-events.jsonl` |

```sh
cargo run --bin telltale -- scan --once --emit-activity
```

Use `--path-profile system` for managed service deployments, or
`--path-profile project` when you intentionally want repo-relative development
paths such as `logs/adr-events.jsonl` and `state/adr-state.json`. Explicit
`--log-path` and `--state-path` flags still override profile defaults. Service
managers can set `ADR_LOG_PATH` and `ADR_STATE_PATH` instead of repeating flags.

Use `--dry-run` when validating fixtures or command behavior without writing
events:

```sh
cargo run --bin telltale -- scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
```

The JSONL sink is the stable interchange point. Each line is a complete event
that follows [schemas/event.schema.json](../schemas/event.schema.json).

## Scan Diagnostics

Every scan also prints one JSON summary to stdout. This local diagnostic is not
an Event 2.0 payload and is not appended to JSONL or wrapped for HEC. In
addition to the existing delivery and event totals, diagnostic sections explain an
otherwise ambiguous zero-detection result without exposing session content:

- `source_processing` reports selected sources, successful parses, empty and
  failed parses, the number of normalized records, and fixed counts for user,
  assistant, tool-call, tool-result, session-metadata, and other records.
- `detection_flow` reports effective detection candidates before state
  deduplication, matched rule-ID references, allowlist-marked candidates,
  state-deduplicated candidates, and emitted detections. Effective candidates
  equal emitted plus state-deduplicated detections.
- `runtime` reports the package version, embedded build hash, and best-effort
  executable observation. The executable path is represented by a path hash and
  its bytes by a streaming SHA-256 digest; unavailable executable observations
  degrade to a bounded status without aborting the scan.
- `effective_configuration` reports hashed path provenance for local config,
  log/state resolution, rules and overrides, policy/allowlist selection,
  project config, and startup output selection. Rule sources and replacement
  winners are identity-hashed. Output projections expose only sink name/type,
  selection/origin, JSONL destination hashes, secret/TLS posture, and delivery
  posture; endpoints, credentials, credential references, hosts, indices,
  sourcetypes, and CA paths are excluded.
- `source_discovery` reports privacy-safe discovery accounting. A full scan uses
  `basis=current_full_scan` and performs checked discovery for that scan. A
  targeted watch scan uses the retained
  `basis=watch_source_index_snapshot` and sets
  `performed_for_current_scan=false`; a full watch reconciliation refreshes the
  current discovery result. `returned_source_count` is before selection, while
  `operational_source_count` is after client filtering, OpenCode SQLite-over-
  legacy preference, and `max_sources` for a full scan (or is the canonical
  path-keyed watch index size). Selection order is unchanged.
- Checked discovery reports only the first error category (`invalid_root`,
  `traversal`, or `other`). On that error, the CLI uses the best-effort partial
  result and marks `best_effort_fallback_used`; this is first-error status, not
  a total failure count. Project configuration reports the mode
  (`default_roots`, `configured_documents`, or `none`) and attempted,
  successful, failed-document, and loaded-project counts. A failed configured
  document contributes no projects.
- `diagnostic_warnings` contains constant-only `{code, classification, basis}`
  observations. Failure codes are `project_config_load_failed`,
  `source_discovery_degraded`, and `source_parse_error_observed`. Suspicious
  zero codes are `no_sources_selected`,
  `selected_sources_produced_no_records`,
  `all_selected_sources_parse_failed_or_empty`, `no_tool_records_observed`,
  and `no_effective_detection_candidates`. `Ok([])` is a parse success;
  empty sources do not imply parse failure when another source is productive,
  and repeated state-deduplicated positives do not imply zero candidates.
  These are observations only: they are not health verdicts, security alerts,
  Event 2.0 fields, sink payloads, persisted state, or exit-status changes.
  Discovery and project-load diagnostics never include roots, paths, source IDs,
  loader errors, or operating-system error text.

The existing top-level `log_path` field remains raw for compatibility and is a
local diagnostic caveat. Newly added path fields use hashes. These diagnostic
sections are stdout-only: they are not Event 2.0 fields and are not written to
JSONL or HEC.

Allowlisting marks a detection informational and does not necessarily prevent
emission. Scanner-error events remain visible through the existing scan totals
but do not inflate the detection-only flow. When a rule policy is active, the
summary explicitly reports pre-policy match accounting as unavailable; policy
filtering occurs before effective rule evaluation and is not inferred.

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
- `operational_alert`: operator-facing threshold and delivery alerts, including
  `alert_type=sink_delivery_failure` when a configured remote sink (Splunk HEC,
  Elastic bulk) could not be delivered to after retries.
- `correlation`: cross-session patterns built from emitted telemetry.

## Sinks and Delivery Failures

Beyond the default local JSONL sink, scans can deliver the same events to
Splunk HEC and the Elasticsearch Bulk API, configured centrally through
`outputs.d` YAML files under the standard config roots (`/etc/telltale`, the
user config dir, or `--config-dir`); an annotated example ships in
[config/examples/telltale-outputs.yaml](../config/examples/telltale-outputs.yaml).
Remote delivery uses bounded in-memory retries where applicable; on failure the scan continues
and emits an `operational_alert` event with `alert_type=sink_delivery_failure`
(check name `sink_delivery`) to the remaining healthy sinks. The failed sink
never receives its own failure alert, so delivery problems cannot cascade.
These alerts bypass duplicate suppression and are not counted in the health
event's `emitted_count`; the scan's stdout summary also lists failures under
`sink_failures`. A failure writing the local JSONL sink itself still aborts
the scan, because that file is the durable record.

## Delivery Guarantees

Local JSONL is the durable first-write and bounded local handoff record. It is
not an indefinite system of record or a built-in replay queue; rotation or
deletion can remove events before an external shipper ingests them. Direct
Splunk HEC and Elastic HTTP delivery are best-effort sinks with bounded
in-memory retries, not queues. A process exit or restart discards pending direct
delivery attempts, while the JSONL record remains available to an external
shipper when JSONL is enabled. Uncertain responses and retries can produce
duplicate delivery.

Remote-only output is valid but has no built-in persistent replay. After retry
exhaustion, or process exit/restart while the endpoint is unavailable, events
may be lost. Elastic uses `_id = event_id`, so a redelivery overwrites the same
document rather than duplicating it, but this is not an exactly-once guarantee.
Elastic item-level Bulk API errors are observable failures and are not retried by
the current sink.

`telltale config validate` reports the `outputs.d` delivery posture, while each
scan summary reports its effective posture and delivery status, including
whether Telltale itself has `built_in_persistent_replay` (currently false).
Scan CLI HEC overlays can change the runtime posture; they are not part of the
`config validate` report. These reports do not create remote history or imply
external-shipper replay capability.

Enable optional activity and session summary events when dashboards need more
than detection-only output:

```sh
cargo run --bin telltale -- scan --once --emit-activity --emit-session-risk-summary
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
telltale scan --once --emit-activity --log-rotate-max-size 52428800 --log-rotate-keep 10
```

To disable built-in rotation (for system-profile deployments that use OS-native
`logrotate` instead):

```sh
telltale scan --once --emit-activity --log-rotate-disabled
```

The local JSONL file is a **bounded handoff record**, not the canonical store.
Once events are shipped to a SIEM or central log platform, that platform is
canonical. Rotation keeps local retention bounded without external tooling.

## Optional Export And Sink Paths

The canonical event payload remains the same across delivery paths:

- `telltale export --format jsonl` reads existing JSONL telemetry.
- `telltale export --format elastic-bulk` writes Elasticsearch Bulk API pairs.
- `telltale scan --splunk-hec-endpoint ... --splunk-hec-token ...` can post the same
  events through a Splunk HEC envelope when a deployment explicitly opts in.

Sink-specific metadata belongs at the sink or export layer. Do not add
deployment-specific SIEM fields to the canonical event body.
