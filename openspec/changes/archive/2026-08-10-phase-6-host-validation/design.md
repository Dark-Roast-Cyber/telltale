## Context

See `proposal.md` for the motivation and scope. The current implementation
already defines the contracts that Phase 6 must exercise: native Event 3.0
events use the canonical JSONL payload; local JSONL is the durable first-write
record; HEC is a best-effort sink; scanner state owns cursors and duplicate
suppression; source discovery is bounded with client filters and source caps;
the Linux user installer owns canonical `telltale-scan.service` and
`telltale-scan.timer`; and built-in rotation keeps the active JSONL filename
stable. The current host, service manager, available sources, and Splunk access
must be discovered by the later apply session, not assumed from CI.

The repository is security-sensitive. The compatible top-level `log_path`
diagnostic field may be raw, while newly added diagnostic path fields are
hashed. Consequently, raw command output is not a suitable retained evidence
artifact even when the scanner itself is operating as documented.

## Goals / Non-Goals

**Goals:**

- Execute validation from deterministic to live: synthetic fixtures first,
  then bounded current-host checks, then the actual service manager, then live
  HEC/Splunk checks.
- Make each check produce a small evidence row with its evidence class,
  preconditions, command or query shape, expected result, observed counts and
  statuses, privacy disposition, cleanup result, and PASS/BLOCKED/FAIL outcome.
- Prove local detection deduplication and source cursor/fingerprint continuity
  without claiming exactly-once remote transport.
- Keep service and Splunk work reversible and separate from product
  implementation, public-release preparation, and unrelated local artifacts.
- Make a later reviewer able to distinguish fixture proof, native host proof,
  service proof, live Splunk proof, supplied CI proof, and gates that remain
  unpassed.

**Non-Goals:**

- Changing Rust code, rules, schemas, state semantics, installer behavior,
  service templates, or sink behavior to make a check pass.
- Scanning arbitrary private historical stores or using the old local JSONL as a
  convenient bulk backfill source.
- Treating a mock HEC test, green CI, or one host as proof for another host,
  operating system, service manager, or Splunk deployment.
- Mutating Splunk knowledge objects or deployment configuration, or exposing
  live secrets and source content in evidence.

## Decisions

### 1. Use a typed evidence ledger rather than a transcript

Each validation row will use these fields, with values bounded to statuses and
counts wherever possible:

| Field | Meaning |
| --- | --- |
| `check_id` | Stable task/check identifier from `tasks.md`. |
| `evidence_ref` | Unique local ledger-row or redacted evidence reference. |
| `attempt_id` | Unique attempt identifier; a retry points to its `retry_of` attempt. |
| `evidence_class` | `fixture`, `host`, `service`, `splunk`, `ci`, or `release_gate`. |
| `scope` | Redacted OS/manager/client/source-kind or synthetic scope. |
| `command_shape` | Command or query family without secrets, raw paths, or transcript text. |
| `preconditions` | Preconditions checked before the command/query runs. |
| `expected` | The bounded observable result required by the task. |
| `result` | `PASS`, `BLOCKED`, or `FAIL`; a failed gate also records its release-gate ID. |
| `observations` | Counts, event IDs, rule IDs, hashes, statuses, and field-presence booleans. |
| `privacy_disposition` | Redaction/projection performed and forbidden-content check result. |
| `pass_basis` | Exact assertion or query result that supports the outcome. |
| `cleanup` | `complete`, `restored`, or a bounded cleanup blocker. |
| `failure_class` | `none` for PASS, otherwise A, B, or C as defined in the proposal. |
| `retry_count` | Number of bounded investigation retries, at most one for A. |
| `retry_of` | Prior `attempt_id` when this row is the one allowed retry. |
| `release_gate_id` | The unpassed gate identifier when the result is BLOCKED/FAIL. |
| `defect_handoff` | Separate OpenSpec/issue reference and affected contract for C. |

Raw stdout, HEC requests, Splunk responses, source records, tokens, and exact
private paths are never retained as the evidence ledger. Temporary raw data may
exist only long enough for a local assertion and is deleted afterward.

### 2. Validate the existing event path in layers

The local proof combines the repository's schema-constructor test with a
schema-validator pass over every actual emitted JSONL line and explicit
assertions over the actual output. The existing
`cargo test --test cli every_native_event_constructor_emits_schema_valid_json`
test proves that native constructors validate against
`schemas/event.schema.json`; an ephemeral `uv run --with jsonschema` validator
then validates the generated lines against that checked-in schema without
adding a project dependency or changing product code. `jq -e .` remains a
syntax/line-completeness check, not the schema proof. The sink parity test is
also run because it verifies that HEC receives the same canonical event body as
JSONL while keeping `index`, `sourcetype`, and `source` outside that body. This
keeps the validation direct without adding a runtime validator.

The event assertions require at least one deterministic detection and inspect
canonical identity fields (`schema_version`, `event_id`, `event_type`, client,
session, source hash, rule IDs, categories, severity, score, response, and
timeline anchors when present). They also assert that native Event 3.0 output
does not contain `triage`, `llm_triage`, `adr_version`, or a native triage
transport artifact. Health and operational events are counted separately.
Stdout diagnostics are checked for bounded accounting sections and then
discarded or projected to counts; they are not treated as Event 3.0 payloads.

### 3. Use separate synthetic roots for positive, benign, and failure cases

The later apply session copies only checked-in synthetic fixtures into a
temporary root outside the repository. A positive root proves a detection, a
benign root proves a successful parse with no effective detection, and a
malformed synthetic source proves a scanner/source failure. The three outcomes
are compared through `source_processing`, `detection_flow`, exit status, and
event counts so an empty result is not mislabeled as a scanner failure.

Each scan uses explicit temporary `--log-path` and `--state-path`,
`--no-local-config`, and bounded client/source selection. Fixture writes use
`--allow-fixtures` only because the output is an explicit temporary development
sink; real-host scans never use that flag.

### 4. Prove state, backfill, and rotation with process boundaries

A sequence of separate `scan --once` processes is the restart test: process one
ingests the initial controlled source, process two repeats it unchanged, and a
later process sees one controlled source append or one newly inserted SQLite
row. The state file must persist the native schema and cursor/fingerprint, the
unchanged pass must emit no duplicate detection, and the changed pass must emit
only the new bounded source contribution. On Linux, the existing SQLite cursor
tests are run in addition to the controlled CLI sequence; on a host without a
usable SQLite source, that source-specific gate is recorded as unpassed rather
than replaced with a broad private scan.

Rotation is forced with a small explicit size threshold and a bounded keep
count. The active filename must remain `telltale-events.jsonl`; rotated files
must match the documented date/counter naming and remain parseable. The union of
active and retained files is checked for complete records and duplicate event
IDs, while the state file remains outside the rotation namespace. Because HEC
and external shippers are at-least-once-oriented, these checks assert Telltale's
local deduplication, not a general exactly-once delivery guarantee.

### 5. Treat live source discovery as an operational confidence check

The host session first identifies which supported clients are safe and useful
to check. For each selected client it uses the documented bounded shape,
`timeout 120s ... scan --once --client <id> --max-sources <n> --dry-run`, and
retains only source counts, parse counts, diagnostic categories, and a
pass/fail status. No real output is written during exploratory discovery. A
zero-source, empty, or unsupported client is recorded distinctly from a parse
failure and is not converted into a public support claim.

### 6. Isolate service-manager validation and restore exact pre-state

The later apply session identifies the actual manager before changing anything.
On a Linux host with the approved user-systemd path, the preferred staging
attempt is the current installer in a temporary HOME/configuration root with
`--from-source`, a temporary install directory, and `--no-timer`; staging must
not enable or start a schedule. The staged service and timer are inspected for
canonical `telltale` identity and `TELLTALE_*` settings before activation. The
installer's `%h` expansion is not assumed to be the temporary HOME of an
already-running user manager.

Before an execution test, the apply session must prove that the user manager
will supply a temporary `TELLTALE_SCAN_ROOT`, `TELLTALE_LOG_PATH`, and
`TELLTALE_STATE_PATH`—for example through an isolated manager or a temporary
drop-in/override. The override is test-only and is hashed before and after. If
that proof cannot be made without running the unmodified unit against the real
home or leaving a live mutation, the service execution gate is BLOCKED.

If the user manager cannot load the isolated unit directory, the apply session
must not silently write the real profile. It may proceed only with an explicit,
byte-for-byte backup and restoration plan for current-user units; otherwise the
service gate is BLOCKED. System-managed paths, root-owned services, Windows
task migration, and macOS launch-agent migration are not inferred from the
Linux user installer. A service run is started twice as separate invocations;
reload/restart is exercised only where the manager supports it and the contract
requires it. Cleanup disables/stops temporary units, restores prior bytes and
enablement, reloads the manager, compares pre/post hashes and states, and
removes temporary files.

### 7. Keep live Splunk work read-only and secret-reference based

The later apply session creates a temporary `outputs.d` configuration that uses
the current canonical HEC target and a `{env: ...}` or `{file: ...}` token
reference. A token is never passed as a command argument, printed, or copied to
tracked evidence. The scan includes a local JSONL sink, so local durability can
be compared with HEC delivery; the scan summary and a bounded local projection
are the only local delivery evidence.

All live Splunk MCP work is delegated to `splunk-analyst` with a sanitized
handoff containing only the bounded time window, synthetic event IDs/rule IDs,
expected event families, and canonical target tuple. The analyst performs
read-only metadata and search checks for the target tuple, Event 3.0 fields,
the known controlled detection, duplicate suppression, health/diagnostic
separation, and a process-chain event only if the fixture emitted one. No
alert, saved-search, dashboard, index, role, or server mutation is allowed.

### 8. Use one failure decision table and separate measured truth from release decisions

Every task uses the same decision table:

| Class | Condition | Required action |
| --- | --- | --- |
| A | Evidence is inconclusive because of timing, propagation, or a transient environment condition. | Retry once with the same bounded inputs; preserve the first status; do not change product code. |
| B | A required environment/transport/platform gate is unavailable, or a check fails without a proven product reproduction. | Record the gate ID, bounded failure evidence, and an unpassed release gate; do not claim PASS. |
| C | The same controlled check reproducibly demonstrates an implementation/privacy/contract defect. | Capture a minimal redacted reproduction, affected current contract, and separate OpenSpec defect handoff; leave the Phase 6 gate unpassed until resolved. |

No wording such as “B because product edits would be needed” may replace the
reproduction decision: a reproducible product defect is C, while an unavailable
host capability is B.

Use these stable release-gate IDs in the ledger: `G-EVENT` (canonical Event 3.0
and diagnostics), `G-DEDUP` (state/deduplication), `G-BACKFILL` (bounded source
continuity), `G-ROTATION` (rotation/restart), `G-HOST-SOURCE` (live source
discovery), `G-SERVICE` (service/timer), `G-HEC` (HEC delivery), `G-SPLUNK`
(Splunk extraction), `G-PRIVACY` (evidence safety), and `G-COMPLETION`
(bookkeeping/review/cleanup). A BLOCKED/FAIL row names one of these IDs or an
explicit external release gate.

The later apply session also keeps public-boundary decisions separate from
measured truth:

The later apply session records PR #9's supplied green CI as a `ci` row and
records unexercised native-platform, publication, packaging, hosted-site, and
other release gates separately. It may update `PLAN.md`, `.ai/working-state.md`,
`.ai/task-queue.md`, and readiness/source documentation only with measured,
redacted facts and only after a public-boundary review confirms that each
tracked path is legitimate for the release branch. Live operational evidence
is never pushed. A Luna Max review checks the evidence and claims, not just code
style. A reproducible implementation defect becomes a separate bounded
OpenSpec handoff; Phase 6 does not absorb its repair.

## Risks / Trade-offs

- **[Risk]** A bounded live scan can still encounter sensitive or unexpectedly
  large stores. → Use `--client`, `--max-sources`, `--dry-run`, a timeout, and
  discard raw stdout; use synthetic roots for all behavior claims.
- **[Risk]** HEC retries or uncertain responses can duplicate transport. → Keep
  local JSONL enabled, compare event IDs, and state explicitly that proof is
  not exactly-once remote delivery.
- **[Risk]** Service-manager discovery or isolated unit loading can differ from
  the documented Linux user path. → Detect the manager first, preserve exact
  pre-state, use temporary paths, and block rather than mutate an unapproved
  profile.
- **[Risk]** A raw diagnostic field or shell tracing could expose a path or
  secret. → Disable tracing, avoid `env`/environment dumps, use secret
  references, project output to counts/hashes, and review the evidence bundle
  before writing tracked files.
- **[Risk]** A current-host failure may be a product defect rather than an
  environmental block. → Preserve bounded facts, classify A/B/C, and open a
  separate defect change for reproducible implementation failures.
- **[Risk]** Existing local historical telemetry appears useful for backfill.
  → Do not use it by default; a controlled synthetic backfill is sufficient for
  the Phase 6 contract, and any unavailable historical gate remains explicit.

## Migration Plan

There is no product migration. Later application creates a temporary validation
workspace, runs the ordered checks, cleans it, restores any pre-existing
current-user service state, and retains only redacted evidence summaries. If a
tracked readiness or working-state update is justified, it is reviewed and
committed separately from any future product defect. If cleanup or restoration
cannot be proven, the batch stops with a blocked gate and does not archive or
publish as though validation passed.

## Open Questions

- Which service manager is available on the actual validation host?
- Which supported source kinds can be checked safely without reading arbitrary
  private history?
- Is the approved HEC secret available through an environment or file reference
  for this validation window?

These questions affect only which planned evidence rows become PASS or
BLOCKED; they do not authorize a different implementation or a new behavior
contract.
