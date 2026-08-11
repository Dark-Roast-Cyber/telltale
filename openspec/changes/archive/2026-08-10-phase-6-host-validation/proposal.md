## Why

The 0.5.0 implementation and PR #9 CI are green, but CI does not prove that the
integrated scanner, canonical Event 3.0 JSONL, durable state, source ingestion,
service/timer, rotation, or Splunk HEC path work together on the validation host.
Phase 6 supplies bounded, privacy-safe evidence for those already-approved
contracts before release decisions are made.

## What Changes

- Define a repeatable evidence ledger that separates fixture-backed proof, live
  current-host proof, service-manager proof, live Splunk proof, supplied PR CI
  proof, and release gates that remain unexercised.
- Run synthetic or controlled fixture checks for canonical Event 3.0 JSONL,
  schema-valid output, detection identity and fields, bounded health and
  diagnostics, removal of native triage artifacts, state persistence, duplicate
  suppression, source-failure versus no-detection accounting, backfill, cursor or
  fingerprint continuity, rotation, and restart durability.
- Run only bounded live source checks that use explicit client filters, source
  caps, and dry-run exploration before any intentional telemetry write.
- Exercise only the service manager actually available on the validation host,
  using an isolated or narrowly backed-up current mechanism and reversible
  temporary paths. Prove canonical `telltale` invocation, configured log/state
  locations, repeated execution, and required reload/restart behavior.
- Route live Splunk interaction through `splunk-analyst` and use read-only
  metadata/search operations. Validate HEC delivery and extraction under
  `index=telltale`, `sourcetype=telltale:json`, and `source=telltale` without
  changing Splunk configuration or knowledge objects.
- Retain only counts, statuses, event IDs or hashes, redacted excerpts, and
  bounded metadata. Record every planned gate as PASS or BLOCKED/FAIL and route
  concrete implementation defects to a separate bounded OpenSpec change.
- Update release/readiness or durable working-state documentation only when it
  records measured truth; do not add product behavior or public claims from
  unredacted host evidence.

## Capabilities

### New Capabilities

None. This batch validates capabilities that are already implemented and
specified; it does not introduce a runtime capability.

### Modified Capabilities

None. No behavioral requirement is being changed. The change sets
`skip_specs: true` in `.openspec.yaml` deliberately because a delta spec would
invent product behavior merely to describe validation evidence.

## Impact

- **Product/runtime:** no Rust, schema, rule, parser, state, sink, installer, or
  service implementation changes are authorized by this change.
- **Validation environment:** later application may create temporary synthetic
  roots, state files, JSONL logs, staged binaries, units, and secret references;
  any live-host mutation must be isolated, reversible, and cleaned up.
- **Splunk:** later application may send synthetic events through the existing
  canonical HEC configuration and query the resulting events through
  `splunk-analyst`; it must not mutate indexes, alerts, saved searches,
  dashboards, roles, or server configuration.
- **Tracked artifacts:** only redacted evidence summaries, durable state, and
  readiness/status documentation justified by measured results may be changed
  during the later apply session.

## Validation Contract and Acceptance

Phase 6 is complete only when every validation item in `tasks.md` is either
**PASS** with bounded evidence or explicitly **BLOCKED/FAIL** with its release
gate recorded. A green PR #9 CI result is retained as CI evidence only and is
not substituted for native host, service-manager, source-store, or Splunk
proof. No claim is made for an operating system, service manager, source kind,
or transport that was not actually exercised.

An inconclusive result may receive one bounded investigation/retry (A). An
unavailable or failed release condition is recorded as an unpassed release gate
(B). A reproducible implementation defect is captured with redacted evidence
and deferred to a separate bounded defect OpenSpec change (C). Phase 6 does not
silently repair product code after a failed check.

## Non-goals

- Touching, reading, hashing, moving, deleting, or committing
  `tokscale-export-20260809-013857.json`.
- Applying, dropping, inspecting the contents of, or modifying the preserved
  README/docs stash.
- Dumping private source transcripts, session contents, raw local telemetry,
  credentials, HEC tokens, authorization headers, `.env` values, or sensitive
  local paths.
- Broad historical ingestion merely to increase coverage; arbitrary private
  source stores are not a Phase 6 fixture.
- Opportunistic refactoring, new rules, parser changes, schema changes, sink or
  state semantics changes, new service managers, or cross-platform claims based
  only on CI.
- Modifying model/OpenCode configuration, force-pushing, merging PR #9,
  marking PR #9 ready, tagging, releasing, publishing, or hosted-site cutover.
- Mutating Splunk alerts, saved searches, indexes, dashboards, roles, or server
  configuration as part of normal validation.
