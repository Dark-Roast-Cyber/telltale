## 1. Boundary and evidence setup

## Apply results (2026-08-10)

The redacted ledger is `evidence.md`. Completed validation tasks are recorded
with their measured disposition here; BLOCKED rows are completed evidence work,
not implied PASS results:

- 1.1–5.1: **PASS** (`E6-1.1` through `E6-5.1`).
- 6.1: **BLOCKED**, `G-HOST-SOURCE` / B (`E6-6.1`).
- 7.1–7.2: **BLOCKED**, `G-SERVICE` / B (`E6-7.1` and `E6-7.2`).
- 8.1: **BLOCKED**, `G-HEC` / B (`E6-8.1`).
- 8.2: **BLOCKED**, `G-SPLUNK` / B (`E6-8.2`).
- 9.1–9.2: **PASS** (`E6-9.1` and `E6-9.2`).
- 9.3: **PASS after correction** (`E6-9.3`; independent `coder-quality`
  review completed and all concrete evidence/bookkeeping findings resolved).
- 9.4: **PASS** (`E6-9.4`; final checks, archive move, status review, and
  completion boundary recorded below).

No product defect was fixed or handed off in this batch. Native Windows/macOS
host proof, live service execution, controlled HEC delivery, and controlled
canonical Splunk extraction remain unpassed release gates.

- [x] 1.1 Establish the apply-session boundary and record the supplied CI context.
  
  **Preconditions:** Begin from the planned `phase-6-host-validation` change on
  `release/0.5.0-maturation`; do not begin until the operator confirms that
  PR #9 is still Draft and that its supplied Linux, Windows, and macOS CI
  results are green. The planning artifacts and the two durable `.ai` updates
  are expected; no other tracked product change is expected.
  
  **Command/check:** Run `git status --short --branch`, `git log -1
  --oneline --decorate`, `git diff --name-only -- .`, `git status --short --
  tokscale-export-20260809-013857.json`, and `git stash list --date=iso`.
  Do not run `git stash show`, inspect the stash contents, or read the Tokscale
  export. Through the read-only GitHub lane, if a refresh is needed, run both
  `gh pr view 9 --repo Dark-Roast-Cyber/telltale --json isDraft,headRefName,headRefOid`
  and `gh pr checks 9 --repo Dark-Roast-Cyber/telltale`; bind the reported
  checks to the local HEAD and do not alter PR state.
  
  **Expected result:** HEAD remains `774020f` or the explicitly supplied
  reviewed successor; the only unrelated untracked path is the Tokscale export;
  the preserved README/docs stash remains present; no unexpected tracked
  product files are changed. CI is recorded as `evidence_class=ci`, never as
  host or Splunk proof.
  
  **Minimum evidence:** branch, HEAD, PR number/state, CI job-state summary,
  expected planning-path list, stash-present boolean, and the untracked-export
  path-present boolean. Retain no diff or content from the stash/export.
  
  **Privacy/safety:** Do not print environment variables, credentials, session
  content, stash patches, or the export. Do not stage, hash, open, move, or
  modify the export. Do not apply or drop the stash. Do not force-push, merge,
  or mark PR #9 ready.
  
  **Pass/fail:** PASS only when the precondition boundary is exact. Any
  unexpected product change, missing preserved stash, changed export status, or
  PR mutation is `G-COMPLETION`/B and stops the batch.
  
  **Cleanup:** None; leave the boundary unchanged. **Failure meaning:** This is
  an environment-integrity failure, not permission to repair unrelated files.

- [x] 1.2 Create a private temporary validation workspace and evidence ledger.
  
  **Preconditions:** Task 1.1 passes. The operator has a writable temporary
  directory outside the repository and confirms that synthetic fixture copies,
  temporary state, logs, service staging, and HEC secret references may be
  removed at the end of the session.
  
  **Command/check:** With shell tracing disabled and `umask 077`, create a
  temporary directory with separate `positive`, `benign`, `failure`, `state`,
  `logs`, `service`, `splunk`, and `evidence` children. Copy exactly the
  synthetic positive fixture
  `tests/fixtures/session_stores/codex/sessions/2026/04/tool-injection-shape.jsonl`
  and benign fixture
  `tests/fixtures/session_stores/codex/sessions/2026/04/uc001-negative-normal-mcp.jsonl`
  into their corresponding temporary Codex session layouts, and create only
  the named truncated `malformed-controlled.jsonl` failure input. Initialize
  one ledger row per check using the fields in `design.md`; do not capture raw
  stdout.
  
  **Expected result:** All test roots and output paths are temporary and
  distinct; state is outside the JSONL rotation namespace; no real home
  session-store path is used as a fixture root; the ledger can record PASS,
  BLOCKED, or FAIL without storing raw payloads.
  
  **Minimum evidence:** Temporary workspace class (not its exact path), child
  purpose names, permissions, fixture identities, and ledger schema.
  
  **Privacy/safety:** Never use the real `$HOME` store as a fixture, never copy
  real transcripts, and never put a token or `.env` value in the ledger. Keep
  the workspace outside the tracked tree.
  
  **Pass/fail:** PASS when the workspace is private, bounded, and isolated.
  Failure to create a safe workspace is `G-PRIVACY`/B; do not fall back to
  repository logs, real state, or private source data.
  
  **Cleanup:** Register a trap or equivalent cleanup procedure immediately and
  verify that the workspace is absent after all tasks. **Failure meaning:** A
  cleanup blocker is a release-gate failure and prevents archival.

## 2. Fixture-backed Event 3.0 and diagnostics

- [x] 2.1 Prove integrated canonical JSONL emission, schema coverage, and a known detection.
  
  **Preconditions:** Task 1.2 passes; the build is available; the positive root
  contains exactly
  `tests/fixtures/session_stores/codex/sessions/2026/04/tool-injection-shape.jsonl`
  copied into the temporary Codex sessions layout. The expected synthetic
  session is `tool-injection-shape-session` and the expected rule ID is
  `tool.injection.shape`; no local configuration is needed.
  
  **Command/check:** Run a write-enabled synthetic scan with explicit temporary
  paths, for example:
  
  `cargo run --bin telltale -- scan --once --allow-fixtures --no-local-config --root <positive-root> --client codex --max-sources 1 --emit-activity --emit-session-risk-summary --install-inventory-disabled --log-path <temp-log> --state-path <temp-state>`
  
  Then parse every JSONL line with `jq -e .` without printing the full line,
  validate the same file against `schemas/event.schema.json` with an ephemeral
  validator such as
  `uv run --with jsonschema python -c 'import json,sys; from jsonschema import Draft202012Validator; s=json.load(open(sys.argv[1])); v=Draft202012Validator(s); lines=[line for line in open(sys.argv[2]) if line.strip()]; [v.validate(json.loads(line)) for line in lines]; print(len(lines))' schemas/event.schema.json <temp-log>`,
  run `cargo test --test cli every_native_event_constructor_emits_schema_valid_json`,
  and run the existing sink parity test
  `cargo test --test cli scan_once_emits_identical_events_to_jsonl_hec_and_elastic`.
  If the ephemeral validator cannot run, record the schema gate as BLOCKED
  rather than substituting `jq`; `jq` proves syntax/line completeness only.
  Project actual output to event-family counts and selected field-presence
  booleans. Do not claim that the mock HEC test is live Splunk proof.
  
  **Expected result:** The scan succeeds and emits at least one `detection`.
  Every emitted line is a complete JSON object with `schema_version: "3.0"`;
  the detection has a non-empty canonical `event_id`, `event_type`, client,
  session identity, `source_path_hash`, `rule_ids`, categories, severity,
  `risk_score`, and `response`, with `timeline_anchors` when the controlled
  fixture supplies them. The constructor test validates native event shapes
  against `schemas/event.schema.json`; actual output is valid JSONL and is
  checked against the same constructor/event-family contract.
  
  **Minimum evidence:** Scan exit status; counts by `event_type`; count of
  parseable and schema-valid lines; the expected synthetic rule ID; a
  redacted/hash-based detection identity; schema-test and actual-output
  validator status; and local JSONL/HEC parity-test status.
  
  **Privacy/safety:** Do not copy raw JSONL or stdout into retained evidence;
  temporary raw files may remain only in the private workspace until dependent
  checks finish. Do not expose source paths, session text, credentials, or full
  evidence arrays. Keep only field names, counts, stable synthetic IDs, and
  hashes. The temporary output path is not evidence.
  
  **Pass/fail:** PASS when all expected canonical fields and schema/parsing
  checks pass and a detection is present. Malformed output or a reproducible
  constructor/schema mismatch is C: capture bounded facts and open a separate
  defect change. A transient build/test/environment failure is A once; if the
  required validator or build remains unavailable, record `G-EVENT` as B.
  
  **Cleanup:** Keep only the projected ledger row; retain raw files until the
  dependent deduplication and rotation checks finish, then delete them.
  **Failure meaning:** Do not change event code or schema in this batch.

- [x] 2.2 Prove bounded health/diagnostic output and the native no-triage boundary.
  
  **Preconditions:** Task 2.1 produced a successful synthetic scan and a
  captured stdout projection can be examined without retaining raw output.
  
  **Command/check:** Project stdout with `jq` to the documented diagnostic
  sections `source_processing`, `detection_flow`, `runtime`,
  `effective_configuration`, `source_discovery`, and `diagnostic_warnings`.
  Project JSONL/HEC events to `event_type`, `event_id`, `schema_version`,
  severity, score, rule IDs, and health fields. Assert that native Event 3.0
  events do not have `triage`, `llm_triage`, `adr_version`, model/guard verdict
  fields, or a native triage transport artifact. Count `health`,
  `scanner_error`, and `operational_alert` separately from detections. Confirm
  that diagnostic-only sections are absent from Event 3.0 JSONL and HEC event
  bodies.
  
  **Expected result:** Diagnostics explain source and detection accounting with
  bounded counts; health/diagnostic events are distinguishable from detections;
  no native triage artifact or raw session body is emitted; path provenance is
  hashed or omitted except for the documented compatibility caveat, which is
  not copied to retained evidence.
  
  **Minimum evidence:** Diagnostic section presence, warning codes and counts,
  event-family counts, no-triage boolean, no-raw-content boolean, and the
  health/detection separation result.
  
  **Privacy/safety:** Never use `env`, shell tracing, raw `systemctl show`
  environment output, or a full `jq .` dump. Treat `log_path`, endpoints,
  credential references, and source identity strings as sensitive when
  projecting evidence.
  
  **Pass/fail:** PASS when diagnostics are bounded and all native no-triage and
  separation assertions hold. A reproducible emitted secret, transcript, or
  forbidden triage artifact is C for a separate security/behavior defect and
  `G-EVENT`/`G-PRIVACY` is B for the unpassed release gate; stop before any
  publication. An inconclusive projection is A once, then B.
  
  **Cleanup:** Delete only the projected stdout copy at this point. Keep the
  raw event/log files under task 1.2's private temporary workspace until tasks
  3–5 finish their dependent assertions, then delete them. **Failure meaning:**
  Do not broaden or redact product output in this change.

## 3. Detection deduplication and failure accounting

- [x] 3.1 Prove state persistence and repeated-scan detection deduplication.
  
  **Preconditions:** Task 2.1 passes; the positive synthetic root is isolated;
  one state path is reserved for all three scans and one or more temporary log
  paths are available for comparison.
  
  **Command/check:** Run the same bounded positive scan twice as separate
  `scan --once` processes with the same `--state-path`, `--root`, client cap,
  and no local configuration. Read only summary counters and projected event
  IDs. Inspect the state JSON for native `state_schema_version: "1.0"` and the
  relevant detection/source state without printing its values.
  
  **Expected result:** The first scan emits the expected detection. The state
  file persists after process exit. The second unchanged scan reports a positive
  `state_deduplicated_detection_count` (or the equivalent documented counter),
  emits zero new detections, and does not replay the first detection event.
  Health or other explicitly non-deduplicated operational events are counted
  separately and do not invalidate detection deduplication.
  
  **Minimum evidence:** First/second exit statuses; first/second emitted and
  deduplicated detection counts; native state-schema boolean; count of unique
  detection IDs; and a state-file hash, not its contents.
  
  **Privacy/safety:** Use only synthetic source content. Do not compare or
  retain raw state values, session bodies, source paths, or private fingerprints.
  
  **Pass/fail:** PASS only when the first positive and second deduplicated
  outcomes are both observed. A stable environment/timing problem is A once;
  a reproducible state or replay defect is C plus `G-DEDUP` as an unpassed B
  release gate.
  
  **Cleanup:** Keep only counts and hashes; delete duplicate-run logs after the
  rotation checks no longer need them. **Failure meaning:** Do not reset state,
  alter fingerprints, or relax deduplication in Phase 6.

- [x] 3.2 Distinguish a successful no-detection result from a source/scanner failure.
  
  **Preconditions:** Task 1.2 has separate roots containing exactly
  `uc001-negative-normal-mcp.jsonl` for the benign case and one temporary
  `malformed-controlled.jsonl` with a deliberately truncated JSON object for
  the failure case. Both are synthetic and contain no credentials.
  
  **Command/check:** Scan the benign root with the same bounded, explicit
  temporary paths and scan the malformed root separately. Compare exit status,
  `source_processing` parsed/empty/failed counts, `detection_flow` candidate
  and emitted counts, `diagnostic_warnings`, `scanner_error` events, and the
  presence of a state commit. Do not treat an empty source tree as the benign
  parse case.
  
  **Expected result:** The benign case has a successful parse, zero effective
  detection candidates, no scanner failure, and an explicitly explainable
  no-detection result. The malformed case reports the documented parse/scanner
  failure accounting and is not misreported as a clean no-detection result.
  
  **Minimum evidence:** One redacted row for each case containing exit status,
  parsed/failed/empty counts, candidate/emitted counts, warning/error code
  categories, and state-commit status.
  
  **Privacy/safety:** The malformed input and retained error evidence must not
  contain raw source text or OS error paths. Store only the error category.
  
  **Pass/fail:** PASS when the two outcomes are observably distinct. If the
  environment prevents the controlled parser run, A once then `G-EVENT` as B.
  If the scanner conflates the outcomes reproducibly, C plus `G-EVENT` as an
  unpassed B gate and a separate defect change; do not adjust diagnostics here.
  
  **Cleanup:** Delete malformed and benign temporary roots and logs after the
  projected rows are recorded. **Failure meaning:** A no-detection result is
  not evidence of a healthy source unless parse accounting proves it.

## 4. Backfill, incremental ingestion, and source-change continuity

- [x] 4.1 Prove bounded initial ingestion and controlled file-source change discovery.
  
  **Preconditions:** Tasks 2 and 3 pass; a temporary source root contains only
  a small, explicitly counted set of synthetic files; the state path is empty
  before the initial scan.
  
  **Command/check:** Create exactly
  `codex/sessions/2026/04/controlled-incremental.jsonl` in the temporary root
  with only the first `session_meta` line from the named
  `tool-injection-shape.jsonl` fixture. Run an initial scan with
  `--client codex`, `--max-sources 1`, explicit temporary state/log paths, and
  `--allow-fixtures`; record source and record counts. Run the unchanged scan
  once. Then append exactly the second assistant-event line from that same
  fixture to `controlled-incremental.jsonl`, and run a third scan with the same
  cap and state path.
  
  **Expected result:** Initial ingestion is limited to one source and has no
  detection; the unchanged scan does not replay already-consumed data; the
  third scan discovers the one appended event and emits the expected
  `tool.injection.shape` detection for the controlled session, subject to
  documented parser overlap and state deduplication. State/cursor/fingerprint
  information remains durable across process exits.
  
  **Minimum evidence:** Initial/unchanged/changed source and parsed-record
  counts, cap, cursor/fingerprint-present boolean, changed-source count, and
  unique emitted event IDs. No source content is retained.
  
  **Privacy/safety:** Use synthetic data only; do not use the old local JSONL or
  arbitrary home history as backfill. Do not widen the source cap after a
  failure just to obtain more events.
  
  **Pass/fail:** PASS when bounded initial ingestion, no-replay behavior, and a
  single controlled source change are all observed. An unavailable source
  adapter is `G-BACKFILL` as B for that source-specific gate. A reproducible
  replay, missed change, or state corruption is C plus `G-BACKFILL` as an
  unpassed B gate and a separate defect change.
  
  **Cleanup:** Remove the changed synthetic source and temporary state/logs
  after recording counts and hashes. **Failure meaning:** A failure does not
  authorize changing cursor/fingerprint semantics.

- [x] 4.2 Prove the approved SQLite cursor/backfill contract where the host supports it.
  
  **Preconditions:** The actual host is Linux or another host where the
  repository's controlled OpenCode SQLite tests are applicable; no real
  OpenCode database is opened. If the host cannot exercise this source, retain
  a BLOCKED row rather than substituting private history.
  
  **Command/check:** Run the existing synthetic cursor coverage:
  `cargo test --test cli migrated_state_preserves_sqlite_cursor_continuity` and
  `cargo test --test cli migrated_sqlite_cursor_emits_only_newly_appended_sessions`.
  If the later apply session has a separately approved controlled SQLite root,
  repeat the same initial-row, unchanged-scan, and one-new-row sequence from
  task 4.1 and inspect only cursor timestamps/counts.
  
  **Expected result:** The cursor survives state migration/serialization; a new
  controlled row advances the cursor and is emitted; the parser's bounded
  overlap may reread old rows, but state deduplication emits only the newly
  appended session/record.
  
  **Minimum evidence:** Test statuses, source kind, initial/new row counts,
  cursor-present and cursor-advanced booleans, emitted count, and unique event
  IDs. No database rows or paths are retained.
  
  **Privacy/safety:** Never open or query a real user database. Do not print
  SQLite data, session IDs, or exact source paths. Use the test fixture and
  temporary database only.
  
  **Pass/fail:** PASS when applicable tests and controlled sequence pass. If the
  source is not applicable on the actual host, BLOCKED with `G-BACKFILL`/B
  rather than a false cross-platform claim. A reproducible cursor/replay defect
  is C plus `G-BACKFILL` as an unpassed B gate and a separate defect change.
  
  **Cleanup:** Delete the temporary database, state, and logs; verify no
  repository or user database was touched. **Failure meaning:** Do not add a
  new cursor implementation or broaden source support in Phase 6.

## 5. Rotation and restart durability

- [x] 5.1 Prove bounded JSONL rotation, parseability, and post-rotation deduplication.
  
  **Preconditions:** Tasks 2–4 pass; create exactly 500 temporary Codex session
  files named `session-000.jsonl` through `session-499.jsonl`, each copied from
  the synthetic `uc001-positive.jsonl` fixture; state is in a separate temporary
  path; no OS-native rotation tool is configured for the test.
  
  **Command/check:** Run this exact first scan against that temporary root:
  `cargo run --bin telltale -- scan --once --allow-fixtures --no-local-config --root <rotation-root> --client codex --max-sources 500 --emit-activity --install-inventory-disabled --log-path <rotation-log> --state-path <rotation-state> --log-rotate-max-size 1000 --log-rotate-keep 3`.
  Run the same exact command a second time after the first process exits.
  Also run `cargo test --test cli concurrent_scans_produce_parseable_jsonl_with_rotation`
  and the documented Linux-only soak
  `cargo test --test cli scan_watch::watch_synthetic_multi_cycle_soak -- --ignored --nocapture`
  when the actual host is Linux. Enumerate only the temporary JSONL filenames;
  parse every retained line with `jq -e .`; project event IDs and event-family
  counts.
  
  **Expected result:** The active file remains `telltale-events.jsonl`; rotated
  files use the documented date/counter names and at least one rotated file is
  present; `keep=3` retains at most three
  rotated files in addition to the active file; every line is complete and
  parseable; the state file is not in the rotation namespace; and the restart
  scan does not replay detections.
  The bounded union of retained/active files contains the expected first-run
  event IDs without unexpected gaps attributable to local rotation.
  
  **Minimum evidence:** Threshold and keep count, active/rotated file counts,
  parseable-line count, duplicate event-ID count, first/second detection counts,
  state-location separation boolean, and soak/test statuses.
  
  **Privacy/safety:** Store only filenames by class, counts, and hashes; do not
  retain event bodies or source content. Do not alter real logrotate, newsyslog,
  Windows, or collector configuration.
  
  **Pass/fail:** PASS when rotation, parseability, restart state continuity,
  and bounded no-replay checks hold. A filesystem timing issue is A once. A
  reproducible truncation, data loss, replay, or namespace collision is C plus
  `G-ROTATION` as an unpassed B gate; do not change rotation code here.
  
  **Cleanup:** Delete all temporary active/rotated files and state after
  projection; verify the real telemetry path is unchanged. **Failure meaning:**
  This check does not establish external shipper replay or exactly-once HEC.

## 6. Live current-host source validation

- [x] 6.1 Run bounded, read-only source discovery only for safe clients on the actual host.
  
  **Preconditions:** Tasks 1–5 pass; the operator explicitly names the clients
  and maximum source count to check; the host's OS and usable source roots are
  known without dumping environment values. Use only a real host root for this
  task, never a fixture root and never `--allow-fixtures`.
  
  **Command/check:** For each approved client, run the documented bounded shape
  with a timeout, for example:
  `timeout 120s cargo run --bin telltale -- scan --once --client <id> --max-sources 5 --dry-run --root <host-root>`.
  Prefer `opencode`, `codex`, `claude`, or `copilot` only when the operator
  confirms that the source is present and safe to sample. Keep `--dry-run` for
  exploratory checks and do not write local telemetry.
  
  **Expected result:** Each exercised client reports bounded discovery and parse
  accounting, with successful/empty/failed sources distinguishable. The command
  completes within the timeout or is explicitly recorded as blocked; no claim
  is made for clients not exercised. A zero-source result is a bounded host
  observation, not a parser success.
  
  **Minimum evidence:** Redacted OS and client/source-kind, source cap, timeout
  result, selected/returned/operational counts, parsed/failed/empty counts,
  warning categories, and PASS/BLOCKED/FAIL. Never retain exact host roots.
  
  **Privacy/safety:** Do not scan broad history, omit `--client`/`--max-sources`,
  or save raw stdout. Use path hashes or path classes if provenance is needed.
  Do not expose transcripts, source IDs, session IDs, credentials, or `.env`.
  
  **Pass/fail:** PASS only for the bounded clients actually parsed without an
  unexpected scanner failure. Missing/unsupported source, timeout, or access
  denial is `G-HOST-SOURCE`/B after one A retry if evidence is inconclusive. A
  reproducible parser defect is C plus `G-HOST-SOURCE` as an unpassed gate and
  requires a separate change. **Cleanup:** Dry-run creates no log/state target;
  remove any temporary
  diagnostic capture. **Failure meaning:** No native platform or broad source
  support claim follows from this one host.

## 7. Service/timer validation on the actual host

- [x] 7.1 Detect and stage only the service manager that is actually available.
  
  **Preconditions:** Task 6.1 establishes the actual OS and the operator has
  approved a reversible user-scope test. No system/root service installation is
  authorized. The temporary validation workspace is private.
  
  **Command/check:** Detect manager availability with non-mutating command
  checks such as `command -v systemctl`, `command -v launchctl`, or the native
  task-manager availability check on Windows. For Linux user-systemd, inspect
  only bounded properties of `telltale-scan.service` and
  `telltale-scan.timer` with `systemctl --user show` (for example
  `FragmentPath`, `ExecStart`, `UnitFileState`, and `ActiveState`), never raw
  environment output. Stage the approved current installer with an isolated
  temporary HOME/config root and temporary install directory using the
  documented `scripts/install-telltale --from-source --install-dir <temp-bin>
  --no-timer` mechanism; do not use `--with-timer` during staging. Inspect
  staged unit bytes for canonical `telltale`, `TELLTALE_LOG_PATH`,
  `TELLTALE_STATE_PATH`, and the scan-root setting before activation. Because
  `%h` in a user unit resolves through the already-running user manager, prove
  a temporary manager or install a temporary drop-in/override that sets
  `TELLTALE_SCAN_ROOT`, `TELLTALE_LOG_PATH`, and `TELLTALE_STATE_PATH` to the
  private workspace before any service execution; hash that override before
  and after the test.
  
  **Expected result:** The actual manager is identified; staged artifacts use
  canonical service/timer names and the canonical executable; the execution
  override, not an unmodified `%h` expansion, points the test to temporary
  log/state/root paths; no active ADR identity or system scope is introduced.
  If isolated units or a reversible override cannot be loaded by the user
  manager, do not silently write or run the real profile.
  
  **Minimum evidence:** OS/manager class, staged artifact identity booleans,
  unit enablement/status class, temporary path-class override boolean,
  pre-state and override hashes, and restore plan. Do not retain unit files with
  private paths.
  
  **Privacy/safety:** Never print `systemctl show-environment`, `.env`, token
  values, or raw unit output. Do not install to `/usr/local`, `/etc`,
  `/var/log`, `/var/lib`, or any system-managed location. If isolation cannot
  work, require an explicit byte-for-byte backup/restore plan before touching
  current-user units; otherwise mark the gate blocked.
  
  **Pass/fail:** PASS when staging is canonical and isolated. Missing manager,
  unsupported native migration, or inability to load isolated units is
  `G-SERVICE`/B. A reproducible wrong executable, wrong path, duplicate
  schedule, or unsafe installer mutation is C plus `G-SERVICE` as an unpassed
  gate; do not repair installer code here.
  
  **Cleanup:** Do not activate until the restore plan is recorded. If the
  isolated attempt falls back to a current-user backup and any mutation occurs,
  restore the saved unit bytes/enablement immediately on every failure path,
  reload the manager, and compare pre/post hashes before recording the B row.
  Remove staging on a failed preflight. **Failure meaning:** CI or a checked-in
  unit template alone is not service-manager proof; an unproven failed-path
  restore is `G-SERVICE`/B and stops the batch.

- [x] 7.2 Prove repeated service/timer execution, reload/restart, and restoration.
  
  **Preconditions:** Task 7.1 passes and the actual manager supports the
  required operation. The temporary override has been installed and hashed;
  staged service runs with the exact synthetic positive/benign root and
  temporary `TELLTALE_LOG_PATH`/`TELLTALE_STATE_PATH`. Prove HEC is disabled by
  using a temporary config root with no `outputs.d` HEC sink and an allowlisted
  environment-key check that records names/status only, never values; do not
  inherit live output configuration for this task.
  
  **Command/check:** After a bounded `daemon-reload` or equivalent, start the
  canonical service twice as separate invocations and inspect bounded status
  and result properties. Start/enable the timer only in the isolated or
  explicitly backed-up user scope, inspect its schedule and linkage to the
  service, and exercise restart/reload where the Phase 6 contract requires it.
  Use only status/log projections containing exit state, event counts, and
  canonical identity; never dump full journal/source output.
  
  **Expected result:** Both service runs invoke canonical `telltale`, write to
  the configured temporary log/state locations, and preserve deduplication
  across the second run. The timer is canonical, linked to the service, and
  does not create a duplicate schedule. Required reload/restart returns the
  expected manager status. If the timer cannot be accelerated safely, prove
  linkage/schedule loading and record timer-fire execution as BLOCKED rather
  than claiming it.
  
  **Minimum evidence:** Service/timer names, invocation count, exit/result
  statuses, emitted/deduplicated counts, log/state location classes, reload or
  restart status, timer linkage, pre/post unit and override hashes, and
  cleanup/restore status.
  
  **Privacy/safety:** Do not expose command lines containing secrets, journal
  transcript content, user environment values, or exact private paths. Do not
  leave a timer enabled after the check.
  
  **Pass/fail:** PASS only for operations actually exercised. Unsupported or
  unavailable timer/restart behavior is `G-SERVICE`/B; a wrong invocation,
  duplicate schedule, state loss, or failed restoration is C plus
  `G-SERVICE` as an unpassed gate. An ambiguous status is A once before
  classification.
  
  **Cleanup:** Stop/disable temporary units, remove the test-only override,
  restore exact pre-existing unit bytes and enablement, reload the manager,
  compare pre/post unit and override hashes/states, remove staged
  binary/config/log/state files, and verify no temporary unit remains.
  **Failure meaning:** If exact restoration cannot be proven, stop and leave the
  gate unpassed.

## 8. Live Splunk HEC and read-only search validation

- [x] 8.1 Deliver the controlled detection and health events through canonical HEC configuration.
  
  **Preconditions:** Tasks 2–5 pass; an operator-approved HEC endpoint and
  token are available through an environment variable or private file
  reference; the operator authorizes a synthetic event window. No Splunk
  server mutation is permitted.
  
  **Command/check:** Create a temporary `outputs.d` configuration with a local
  JSONL sink and a `splunk_hec` sink using `index: telltale`,
  `sourcetype: telltale:json`, `source: telltale`, and a `{env: ...}` or
  `{file: ...}` token reference. Run
  `timeout 30s cargo run --bin telltale -- config validate --config-dir <temp-config>`
  before scanning, but retain only its redacted sink posture. Then run the
  exact controlled command
  `timeout 120s cargo run --bin telltale -- scan --once --allow-fixtures --no-local-config --root <positive-root> --client codex --max-sources 1 --emit-activity --emit-session-risk-summary --install-inventory-disabled --config-dir <temp-config> --log-path <temp-log> --state-path <temp-state>`
  twice with the same state path. Capture only summary fields `sink_failures`,
  delivery status, and local event counts without printing the endpoint or
  token.
  
  **Expected result:** Secret resolution succeeds without the secret appearing
  in argv, stdout, stderr, process listings, or evidence. HEC delivery succeeds
  after the bounded retry policy; local JSONL remains the durable first-write
  record; the second scan suppresses the known detection locally. HEC envelopes
  use the canonical target tuple and carry the same canonical event body as
  local JSONL; sink metadata does not appear in the event body.
  
  **Minimum evidence:** Secret-reference type (not value), endpoint host hash
  or redacted class, target tuple, scan delivery status, failure count, local
  event count, first/second detection counts, and event-ID hashes.
  
  **Privacy/safety:** Never use CLI token flags for live secrets, print the
  config, read `.env`, or retain HEC request/response bodies. Use a private
  `0600` secret file or inherited environment and delete it during cleanup.
  
  **Pass/fail:** PASS when secret resolution and HEC delivery succeed and the
  local canonical/dedup assertions hold. Missing credentials, network
  reachability, TLS, or permission denial is `G-HEC`/B unless the response is
  genuinely inconclusive; only timing/propagation ambiguity receives one A
  retry before `G-HEC`/B. A reproducible local/HEC payload mismatch or
  credential leak is C plus `G-HEC` as an unpassed gate; do not change the sink
  here.
  
  **Cleanup:** Delete temporary outputs config, secret reference, state/logs,
  and synthetic roots; do not alter server-side data or configuration. **Failure
  meaning:** A local success does not prove Splunk indexing until task 8.2.

- [x] 8.2 Use `splunk-analyst` for bounded, read-only extraction and deduplication checks.
  
  **Preconditions:** Task 8.1 has a UTC window no longer than 10 minutes and
  projected synthetic detection/health event IDs and rule IDs. The live Splunk
  handoff contains no endpoint, token, authorization header, raw path,
  transcript, or secret. Each analyst call uses a result limit of at most 100
  rows.
  
  **Command/query/check:** Delegate all Splunk MCP interaction to
  `splunk-analyst`. Request read-only metadata plus searches shaped like:
  
  `index=telltale sourcetype="telltale:json" source=telltale earliest=<window> latest=<window> | fields - _raw | stats count by event_type`
  
  and the explicit field-extraction search
  `index=telltale sourcetype="telltale:json" source=telltale event_type=detection event_id="<synthetic-detection-event-id>" earliest=<window> latest=<window> | fields - _raw | head 1 | table event_id schema_version event_type severity risk_score client session_id source_path_hash rule_ids response timeline_anchors`.
  Run the bounded family search
  `index=telltale sourcetype="telltale:json" source=telltale (event_type=health OR event_type=operational_alert) earliest=<window> latest=<window> | fields - _raw | head 50 | stats count by event_type component check_name status`
  and, only when the controlled fixture emitted one, the process-chain search
  `index=telltale sourcetype="telltale:json" source=telltale event_type=process_chain earliest=<window> latest=<window> | fields - _raw | head 20 | table event_id schema_version event_type rule_ids process risk_entity_type risk_entity_value`.
  Repeat the known-detection search after the unchanged scan and
  compare detection IDs/counts. The analyst must not create or mutate any
  Splunk knowledge object or configuration.
  
  **Expected result:** Events are searchable under exactly
  `index=telltale`, `sourcetype=telltale:json`, and `source=telltale`; canonical
  Event 3.0 fields are extractable; the controlled detection is located; the
  repeated scan does not add a duplicate detection where local deduplication
  suppresses it; health/diagnostic events remain distinguishable; and a
  process-chain event is identifiable if exercised.
  
  **Minimum evidence:** Analyst task ID, bounded time window class, target
  tuple, counts by family, extracted field-name list, synthetic rule/event-ID
  hashes, duplicate count, and read-only/no-mutation confirmation.
  
  **Privacy/safety:** Splunk results must be projected to counts and approved
  fields. Do not request raw `_raw`, raw source paths, token/config fields,
  transcript bodies, or authorization data. Do not query unrelated indexes.
  
  **Pass/fail:** PASS when live extraction and the expected detection/dedup
  searches succeed. HEC-delivered-but-not-indexed, field-extraction failure,
  or unavailable analyst access is `G-SPLUNK`/B unless the result is genuinely
  inconclusive during propagation; only that ambiguity receives one A retry. A
  reproducible payload/privacy mismatch is C plus `G-SPLUNK` as an unpassed
  gate. No Splunk mutation is authorized as remediation.
  
  **Cleanup:** No server cleanup is permitted or needed because the task is
  read-only; do not request deletion or mutation of indexed events. Delete
  only local handoff material after the retention policy is confirmed.
  **Failure meaning:** Do not alter alerts, saved searches, indexes, dashboards,
  roles, or server configuration.

## 9. Privacy review, release-gate accounting, and completion

- [x] 9.1 Review and sanitize the complete evidence bundle before any tracked update.
  
  **Preconditions:** Tasks 1–8 have ledger rows and all temporary raw outputs
  are still available only where needed for assertion. The operator has not
  staged any product file or sensitive artifact.
  
  **Command/check:** Project the ledger to counts, statuses, hashes, redacted
  identifiers, event-family names, and field-presence booleans. Review with
  `git diff --check`, `git status --short`, and an explicit allowed-path list.
  Search only the projected evidence for forbidden material using a bounded
  redaction check; do not run the check against the Tokscale export, the stash,
  real session stores, or raw temporary logs. Verify no evidence file contains
  raw source transcripts, prompt/session bodies, credentials, HEC tokens,
  authorization headers, `.env` values, or unredacted private paths.
  
  **Expected result:** The retained evidence is local-only or explicitly
  redacted; no unrelated file is changed; the export and stash are untouched;
  and every row has an `evidence_ref`, `attempt_id`, cleanup result, and
  `failure_class=none` for PASS or A/B/C plus retry/gate metadata for a
  non-PASS outcome.
  
  **Minimum evidence:** Redaction-check status, allowed tracked-path list,
  cleanup status, and counts of PASS/BLOCKED/FAIL rows. Do not retain the
  forbidden material as evidence of its absence.
  
  **Privacy/safety:** Treat any suspected leak as a security stop. Do not copy
  or quote the leaked value while investigating. Do not stage or commit the
  export, stash, raw logs, state, source stores, HEC config, or secret file.
  
  **Pass/fail:** PASS when the bundle is safe and path-bounded. A suspected
  leak is immediately `G-PRIVACY`/B and may be C if emitted by the product; stop
  before documentation or commit. An inconclusive scanner/redaction check is A
  once, then B.
  
  **Cleanup:** Delete raw outputs and secrets, verify temporary workspace
  removal, and leave only the approved redacted summary. **Failure meaning:**
  Phase 6 cannot be declared complete from unsafe evidence.

- [x] 9.2 Record every Phase 6 result and the release gates that remain outside it.
  
  **Preconditions:** Task 9.1 passes. The evidence ledger distinguishes fixture,
  current-host, service-manager, live Splunk, supplied CI, and release-gate rows.
  
  **Command/check:** Mark each planned check PASS or BLOCKED/FAIL with its
  evidence reference. Record the supplied PR #9 CI as CI-only evidence. Record
  unexercised native Windows/macOS host validation, unsupported service
  managers, unavailable source families, publication/tagging, hosted-site
  cutover, and any unrun `make release-preflight` or packaging/publication gate
  explicitly as outside Phase 6 rather than implying success.
  
  **Expected result:** No validation item is silently omitted; every blocked or
  failed result names the gate and failure class. Any reproducible product defect
  has a bounded handoff describing the likely affected current contract and is
  not fixed in this batch.
  
  **Minimum evidence:** Final gate matrix, unpassed-gate list, defect-handoff
  references where applicable, and statement that PR #9 remains Draft.
  
  **Privacy/safety:** Do not add raw host/Splunk evidence to public docs or
  release notes. Use local-only notes, counts, hashes, and redacted summaries.
  
  **Pass/fail:** PASS when each row has an explicit outcome. A missing result is
  B; a defect is C plus B until separately resolved. This task never authorizes
  merge, ready-state change, tag, release, or hosted-site work.
  
  **Cleanup:** None beyond task 9.1. **Failure meaning:** An incomplete matrix
  means the Phase 6 batch is not complete.

- [x] 9.3 Obtain independent Luna Max review of the evidence and claims before finalization.
  
  **Preconditions:** Task 9.2 has a complete redacted matrix, all temporary
  cleanup is verified, and no product implementation change is present. The
  reviewer receives the proposal, design, tasks, changed tracked paths, gate
  matrix, validation commands, actual statuses, and known uncertainty, but not
  secrets or raw source/Splunk content.
  
  **Command/check:** Delegate an independent `coder-quality` review of the
  evidence and claims. Ask it to check unsupported platform/transport claims,
  privacy leakage, unrecorded gates, cleanup/restoration evidence, defect
  classification, public-boundary scope, and accidental product changes.
  Resolve only concrete planning/evidence findings; do not commit, archive, or
  begin a defect implementation while review findings remain unresolved.
  
  **Expected result:** Luna Max finds no unsupported claim, privacy leak,
  unrecorded gate, unsafe cleanup, or accidental product change, or each finding
  is corrected in the bounded evidence/status material. A reproducible product
  repair request is converted to a separate OpenSpec handoff and does not enter
  this batch.
  
  **Minimum evidence:** Reviewer task/result, reviewed scope, finding status,
  any separate defect-handoff reference, and a statement that raw secrets and
  source/Splunk content were not shared.
  
  **Privacy/safety:** Do not send secrets, raw telemetry, raw source records,
  private paths, or the Tokscale export/stash to the reviewer. Do not change
  model/OpenCode configuration, force-push, or perform release actions.
  
  **Pass/fail:** PASS when review is independent and all consequential findings
  are resolved or explicitly recorded as `G-COMPLETION`/B. Only genuinely
  inconclusive evidence receives one A reconciliation; a substantive reviewer
  disagreement or unsupported claim is `G-COMPLETION`/B, or C when it
  reproduces a product/privacy defect. **Cleanup:** Keep the evidence bundle
  unchanged and ready for final verification. **Failure meaning:** Review
  approval is not a license to broaden Phase 6.

- [x] 9.4 Run final repository/public-boundary verification, update durable status, and finalize only at the batch boundary.
  
  **Preconditions:** Tasks 9.1–9.3 pass; all planned rows are PASS or explicitly
  BLOCKED/FAIL with gate IDs; no defect repair is mixed into the diff; and the
  temporary workspace and any service override have been removed/restored.
  
  **Command/check:** First run `openspec validate --changes
  phase-6-host-validation`. Run the narrowest checks implied by tracked changes
  (for example `make release-public-docs-check` or
  `cargo test --quiet public_docs_` for readiness/public Markdown changes).
  Review `git diff --check`, `git diff --stat`, and an exact allowed-path list.
  Update only measured truth in `PLAN.md`'s Phase 6 status,
  `.ai/working-state.md`, `.ai/task-queue.md`, and explicitly justified
  readiness/source documentation; never add live operational notes, raw
  telemetry, private paths, or Splunk deployment details to public files.
  Reconfirm `gh pr view 9 --repo Dark-Roast-Cyber/telltale --json isDraft,headRefName,headRefOid`
  is still Draft and bound to the reviewed commit. After all tracked updates,
  run a final content/public-boundary review on the exact allowed-path diff
  (including the final `git diff --check`, `git diff --stat`, and a bounded
  forbidden-material scan); do not run that scan against the Tokscale export,
  stash, raw logs, state, or source stores. If the batch is complete with every
  row PASS or explicitly BLOCKED/FAIL, run
  `openspec archive --change phase-6-host-validation`, then run
  `openspec list --json`, update `.ai/working-state.md` and
  `.ai/task-queue.md` if the archive path/status requires it, inspect the
  archive move and final allowed-path diff, and only then stage/commit the
  legitimate tracked archive/status/readiness files. Push normally only if the
  repository git/public-boundary workflow
  explicitly permits those exact final paths; never push live evidence. If
  archival cannot be justified, leave the gate/change state explicit and stop.
  Do not merge or mark PR #9 ready, tag, release, publish, or begin another
  PLAN batch.
  
  **Expected result:** OpenSpec validation passes before archival; the final
  post-archive evidence/status diff contains no product implementation or
  sensitive material; PLAN and both
  `.ai` status files agree on the active/completed batch; CI, host, service,
  Splunk, and remaining release-gate evidence are still separately labeled; PR
  #9 remains Draft; and archive/push status is truthful.
  
  **Minimum evidence:** Validation output, focused/full test statuses, final
  allowed-path content/redaction review, diff check, status alignment, PR
  draft/head evidence, commit/push/archive status, final gate matrix, and
  next-batch handoff.
  
  **Privacy/safety:** Perform a final public-boundary review after tracked
  updates and before any push. Do not expose credentials, HEC tokens,
  authorization headers, source transcripts, `.env`, arbitrary private paths,
  or the unrelated Tokscale export. No force-push or destructive cleanup.
  
  **Pass/fail:** PASS when the final tracked state, validation, review, cleanup,
  and gate matrix are complete. A missing status alignment, unsafe path, failed
  validation, or ambiguous archive/push decision is `G-COMPLETION`/B; a
  reproducible product failure remains its specific C defect plus an unpassed
  gate. **Cleanup:** Leave the repository clean except for the intentionally
  preserved unrelated Tokscale export, preserve the stash, leave PR #9 Draft,
  and stop.
  
  **Failure meaning:** This is the Phase 6 completion boundary; no later PLAN
  batch starts in the same root session. run narrowest verification, then cargo
  fmt --check, cargo clippy --all-targets -- -D warnings, cargo test.
