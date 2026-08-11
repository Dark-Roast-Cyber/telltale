# Apply-time evidence

## Boundary and preflight

- Batch: `resolve-linux-host-validation-gates`; tasks `1.1`–`4.2` are covered;
  `5.x` remains open.
- Branch: `release/0.5.0-maturation`; upstream configured; HEAD short hash:
  `015dfe1`.
- Tracked worktree: clean. Pre-edit untracked items: 5; the active change
  artifacts and the unrelated Tokscale export were not read or operated on.
- Active OpenSpec changes before this change: none. Current active change count:
  1. Archived Phase 6 was not inspected or modified; no tracked archive change
  was present.
- PR #9: open, Draft, status-check count 0, failed-check count 0. No completed
  post-Phase-6 product check was observed as failed.
- Immutable boundaries: README/docs stash untouched; Tokscale export untouched;
  product code/configuration untouched; `G-HEC` and `G-SPLUNK` remain BLOCKED.

## G-HOST-SOURCE

### Metadata-only source checks

All checks were read-only. Ownership is relative to the current user; modes are
classes only. Project-local candidates were checked only for the current project.

| Source identity | Presence/type | Readable | Owner/mode | Size/time | Bounded matching files | Class |
| --- | --- | --- | --- | --- | ---: | --- |
| `codex.sessions` | present/directory | yes | current/world-shared | directory/stale | 167 JSONL | usable |
| `codex.archived_sessions` | absent | no | unknown | none | 0 | A: absent |
| `codex.headless_sessions` | absent | no | unknown | none | 0 | A: absent |
| `codex.project_sessions` | absent | no | unknown | none | 0 | A: not applicable |
| `opencode.sqlite` | present/regular file | yes | current/world-shared | medium-or-large/recent | n/a | usable |
| global `opencode.legacy_json` | present/directory | yes | current/world-shared | directory/stale | capped at 2,000 entries | present but intentionally suppressed by SQLite precedence |
| `opencode.project_json` | present/directory | yes | current/world-shared | directory/established | capped at 2,000 entries | present but not selected/exercised under the bounded project configuration/cap |

The SQLite metadata-only query completed with `status=ok`, message and session
tables present, normal locking, WAL journal mode, and bounded query-step class
6. No database row values were retained.

### Bounded Telltale reads

Commands used one client at a time, `--client`, `--max-sources`, `--dry-run`, an
explicit private project configuration, private log/state destinations, and a
strict timeout. Raw stdout/stderr was projected to these counts/categories and
deleted.

| Client / exercised source | Selected | Parse success | Empty | Parse errors | Records | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Codex / `codex.sessions` | 5 | 5 | 0 | 0 | 1,352 | usable |
| OpenCode / `opencode.sqlite` | 1 | 1 | 0 | 0 | 1 | usable |

Codex activity count was 12 with 3 detections and 0 scanner errors. OpenCode
activity count was 8 with 0 detections and 0 scanner errors. No source record,
session identifier, prompt, message, transcript, or raw log was retained.

The prior 120-second OpenCode result is consistent with broad discovery and/or
SQLite parse size. `src/cli/scan.rs` applies client filtering and
`max-sources` after full discovery, and suppresses global `opencode.legacy_json`
only when SQLite exists; it does not suppress project JSON. Stage-specific timing
was not retained. The narrowed `--max-sources 1` representative run selected
SQLite and completed successfully, so the operational procedure was narrowed,
but the causal stage is not proven. Global legacy JSON was present but
intentionally suppressed by SQLite precedence. Project JSON was present but not
selected or exercised under the bounded project configuration/cap; neither JSON
source is claimed as parsed. No lock, malformed-database, permission, or
reproducible Telltale parser defect was established, and no parser defect was
found. No retry beyond this narrower representative run was made.

**Final gate: `G-HOST-SOURCE` PASS.** A real supported Codex source and a real
supported OpenCode source produced bounded usable records. Absent Codex
identities and unselected OpenCode candidates were not fabricated or promoted.

## G-SERVICE

### Preflight and prior-failure diagnosis

- Approved installer and canonical user-service contract were inspected.
- User manager status: `running`.
- Canonical pre-state: service and timer `not-found`, no enablement, inactive,
  result `success`, no fragment, zero drop-ins, destination file absent.
- A bounded private HOME/XDG staging attempt used the approved
  `--from-source --install-dir <private-install> --no-timer` path. It exited
  with error class `manager-unit-visibility` before private binary or unit
  staging (`install_stage=false`, `unit_stage=false`).
- Root cause: the running user manager retained a manager-visible legacy service
  from the real user unit namespace, while the private XDG configuration made
  the installer expect a different private unit directory. The installer’s
  ownership/path check therefore failed closed before mutation. This is a
  B-class environment/procedure limitation, not a C-class product defect.

The exact safe prerequisite for activation is either a separately managed user
session whose unit search path is the private workspace, or an explicitly
manager-visible temporary unit/override in the real user scope with complete
byte/state backup and restoration. Neither was safe to introduce without
touching the existing manager namespace, so no bypass or real canonical install
was attempted.

### Cleanup and restoration

- No canonical service/timer was enabled or started; no timer linkage was added.
- The cleanup scope covered the canonical identities
  `telltale-scan.service` and `telltale-scan.timer`, and the legacy identities
  `adr-scan.service` and `adr-scan.timer`, including their associated drop-in
  state classes. Canonical service/timer state was `not-found`, inactive, with
  no fragment and zero drop-ins; legacy service state was loaded/static,
  inactive/dead, with one drop-in, and legacy timer state was loaded/disabled,
  inactive/dead, with no drop-ins.
- A bounded post-failure user-manager `daemon-reload` completed with exit class
  0. For systemd, only bounded metadata queries and this `daemon-reload` ran: no
  `start`/`enable`/`disable`/`stop` or other mutating systemd calls were made.
- The prior execution retained only set-scoped redacted equality results, not
  independent per-unit values. The covered identities and associated drop-in
  state classes were:

  | Identity | Pre/post state class | Drop-in state pre/post | State equality | Unit-hash equality | Drop-in-hash equality |
  | --- | --- | --- | --- | --- | --- |
  | `telltale-scan.service` | `not-found/inactive/no-fragment` | `zero/zero` | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) |
  | `telltale-scan.timer` | `not-found/inactive/no-fragment` | `zero/zero` | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) |
  | `adr-scan.service` | `loaded/static/inactive/dead` | `one/one` | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) |
  | `adr-scan.timer` | `loaded/disabled/inactive/dead` | `zero/zero` | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) | `true` (covered-set result; redacted) |

  These booleans report the retained covered-identity-set result and do not
  claim unretained per-unit hash values.
- Canonical post-state remained service/timer `not-found`, inactive, no
  fragment, zero drop-ins, and absent destination files. Existing legacy
  manager state remained unchanged within the covered identity set.
- Private validation-root residual count: 0. Raw installer output and all
  private staging material were deleted.
- No service execution or synthetic fixture activation was attempted because
  isolated staging was not loadable and the manager prerequisite was not safe
  to bypass.

**Final gate: `G-SERVICE` BLOCKED.** Classification is B environment/procedure;
no product defect was established and no unrelated service was changed.

## Scope confirmation

- HEC/Splunk: untouched; no HEC request, credential, or Splunk operation.
- Product code/configuration: unchanged.
- Archived Phase 6, README/docs stash, and Tokscale export: untouched.

## Review record

- Fresh coder-quality/Luna Max review: **PASS** after these corrections; the
  OpenCode causal-stage claim, source-selection classifications, systemd cleanup
  scope/restoration wording, and durable status reconciliation findings were
  resolved. Tasks `4.1`, `4.2`, and `5.1` are complete; task `5.2` is now
  complete and task `5.3` remains open.

## Final repository validation

- `openspec validate --changes resolve-linux-host-validation-gates`: **PASS**.
- `git diff --check`: **PASS**.
- Archived Phase 6 path working-tree diff: **CLEAN**.
- `cargo fmt --check`: **PASS**.
- `cargo clippy --all-targets -- -D warnings`: **PASS**.
- `cargo test`: **PASS**; 1 ignored test, no failures.
- No Rust source, product configuration, fixture, stash, export, HEC, or
  Splunk path was changed or exercised by this follow-up.

## Commit and PR status

- Evidence/status/OpenSpec commits `c54cf80` (`Record Linux host gate resolution
  evidence`) and `fc39c35` (`Record pushed host gate status`) were pushed
  normally to `origin/release/0.5.0-maturation`.
- PR #9 remains open and Draft at the pushed head. After approximately 50
  seconds after the first push and 90 seconds after the final push, no newly
  visible workflow run or check conclusion was available; this remains
  pending/absent, not a product failure.

## Archive completion

- OpenSpec archive: **PASS** — archived as
  `openspec/changes/archive/2026-08-11-resolve-linux-host-validation-gates/`;
  no delta specs were created or synchronized.
- Active OpenSpec changes after archive: **0**.
- Task `5.3` is complete. No HEC/Splunk validation or subsequent batch was
  started.
