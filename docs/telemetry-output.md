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

Forward the JSONL file with the shipper or collector your environment already
uses. A safe starter pattern is:

1. Write events locally with the default path profile, `ADR_LOG_PATH`, or an
   explicit `--log-path`.
2. Validate the event shape against the schema.
3. Configure the shipper to read only the JSONL event path.
4. Keep human-readable diagnostics, scanner state, credentials, and raw agent
   session stores outside the forwarded telemetry path.

Use explicit file paths instead of broad log directory monitors so diagnostic
logs or source logs do not get indexed as Telltale events.

## Optional Export And Sink Paths

The canonical event payload remains the same across delivery paths:

- `adr export --format jsonl` reads existing JSONL telemetry.
- `adr export --format elastic-bulk` writes Elasticsearch Bulk API pairs.
- `adr scan --splunk-hec-endpoint ... --splunk-hec-token ...` can post the same
  events through a Splunk HEC envelope when a deployment explicitly opts in.

Sink-specific metadata belongs at the sink or export layer. Do not add
deployment-specific SIEM fields to the canonical event body.
