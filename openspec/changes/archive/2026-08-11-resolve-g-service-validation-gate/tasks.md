## 1. Fresh `/opsx-apply` preflight and contract boundary

- [x] 1.1 At the start of the fresh `/opsx-apply` session, reconfirm
  `release/0.5.0-maturation`, its upstream, tracked cleanliness, Draft PR #9
  status, and exactly one active OpenSpec change; stop if any completed
  post-Phase-6 product check is actually failed. This task list is deferred
  apply work; the current planning session performs none of these live checks.
- [x] 1.2 Re-read the synced installer/service specification, current
  `scripts/install-telltale`, user installer tests, user/system unit examples,
  `docs/install.md`, `docs/release-readiness.md`, and the two archived service
  evidence ledgers; record the authoritative contract without editing archives.
- [x] 1.3 Create a private redacted evidence ledger before host mutation. Record
  only check IDs, manager/unit state classes, counts, booleans, hashes, error
  categories, cleanup status, and PASS/BLOCKED/FAIL metadata. Do not retain raw
  unit bytes, journal output, environment values, `.env` contents, exact
  private paths, source/session content, or secrets.
- [x] 1.4 Reconfirm the immutable boundaries: do not inspect, apply, drop, or
  modify the preserved README/docs stash or
  `tokscale-export-20260809-013857.json`; do not touch product code,
  OpenCode configuration, HEC, Splunk, native Windows/macOS validation, or
  release/publication state.

## 2. Read-only host preflight and manager resolution

- [x] 2.1 Confirm Linux, non-root current-user scope, an available real
  `systemd --user` manager, and the manager endpoint using bounded metadata
  checks only. Before invoking the installer, obtain the approved 0.5.0
  candidate tag and expected artifact/binary digest from the release candidate,
  verify the public metadata/checksum, and retain only version/hash classes.
  After staging, recheck the actual temporary binary against that fixed
  expectation before any service start. If the current unpublished branch has
  no matching approved tag/archive, or the installer refetches a different tag
  or digest, record `G-SERVICE=BLOCKED/B`, clean up, and stop. Never use
  `--skip-checksum`, system scope, `loginctl` lingering changes, or a fake
  `systemctl` implementation.
- [x] 2.2 Before any mutation, inspect only
  `telltale-scan.service`, `telltale-scan.timer`, `adr-scan.service`, and
  `adr-scan.timer`. Record bounded `LoadState`, fragment-location class,
  `UnitFileState`, `ActiveState`, `SubState`, `Result`, drop-in count, file
  ownership/type/mode class, and SHA-256 hashes for owned regular unit files.
  The backed-up real-manager path is eligible only when all four report
  `ActiveState=inactive` with expected inactive/dead substates,
  `Result=success` or the documented not-found/empty equivalent, and a
  disabled/static unit-file state; an enabled, active, failed, or ambiguous
  unit is a block condition, not a state to recreate after installer rollback.
  Also metadata-check `/etc/telltale` without reading values: each of
  `organization-rules.d`, `rules.d`, `ui-rules.d`, `overrides.d`, `policies.d`,
  `allowlists.d`, and `outputs.d` must be absent or an owned, non-symlink,
  readable empty directory. For this check, owner must be root or the current
  user, the parent/subdirectories must not be group/world writable, and the
  parent may contain only those seven optional directory names. Any YAML,
  symlink, inaccessible directory, unexpected owner/type, unrecognized entry,
  or non-empty relevant directory blocks the unmodified service proof.
- [x] 2.3 Stop with `G-SERVICE=BLOCKED/B` if a relevant unit is symlinked,
  ambiguously owned, manager-visible outside the approved user-unit directory,
  has an unexpected existing drop-in, or cannot be restored byte-for-byte.
  Record the pre-existing legacy condition; never delete it to make staging
  pass.
- [x] 2.4 Create a `0700` temporary validation workspace with synthetic source,
  install, configuration, state, log, runtime, `TMPDIR`, `CARGO_HOME`, and
  `CARGO_TARGET_DIR` purposes. Use a sanitized configuration with no HEC sink,
  no inherited secret values, and no real transcript/session input; register
  cleanup before creating validation files. Stop if installer or Cargo writes
  outside the allowlisted workspace/paths.
- [x] 2.5 Use an isolated real user-manager path only if the host already
  provides a documented manager endpoint with a private runtime bus, unit
  search path, `%h` expansion, and `Persistent=true` timer state root; do not
  launch an ad-hoc manager or invent a socket. Prove those bindings, private
  root ownership/mode, and pre/post timer-entry counts before starting
  anything. If the prerequisite or timer-state cleanup is unavailable, record
  the bounded reason and consider the backed-up real-manager path exactly once;
  do not repeat broad private-XDG retries.
- [x] 2.6 For the backed-up real-manager path only, save exact bytes and hashes
  for the four approved unit files and absent/present state for their drop-in
  directories. Record the installer lock, fresh install directory, temporary
  state subtree, `TMPDIR`/Cargo cache subtrees, marker-owned unit staging
  directory, the timer target-wants link, and empty config-directory existence
  classes that the installer may create. Require legacy state/event files and
  `adr.env` to be absent so no real migration occurs. Permit no other backup or
  mutation, and stop if any allowed path cannot be removed safely. In the real
  manager fallback, never enable the timer because manager-owned persistent
  timer state is outside the allowlist; use the isolated manager or leave the
  timer check blocked.

## 3. Canonical user installer staging

- [x] 3.1 Use the approved source staging path with a temporary user-owned
  install directory and `--no-timer`, only after the exact approved 0.5.0
  binary provenance check passes; do not use `--with-timer` until a
  manager-visible isolated or explicitly backed-up scope and restoration plan
  are proven. If staging again fails with manager visibility, or the installer
  selects a different public tag, classify B only when the bounded evidence
  shows an unavailable manager/release prerequisite. A reproducible wrong
  fragment, executable, path, or unsafe installer mutation is repository
  `failure_class=C` / user-facing D; do not bypass the installer or mutate the
  real namespace to force a result. Account for the installer's fixed
  `--dry-run --no-local-config` smoke possibly collecting metadata-only install
  inventory: run with the sanitized allowlist, discard its output, and retain
  no inventory event or path data.
- [x] 3.2 Verify, using projections and hashes only, that the staged executable
  is canonical `telltale`, matches the fixed approved 0.5.0 version/digest,
  and the generated units are exactly
  `telltale-scan.service` and `telltale-scan.timer`, and no active ADR runtime
  identity was introduced. Confirm service `ExecStart`, `TELLTALE_*` paths,
  user scan root, optional environment-file handling, timer interval/linkage,
  and disabled initial schedule.
- [x] 3.3 Prove manager visibility after staging with bounded unit properties
  and fragment-location checks. Run `daemon-reload` only in the selected
  user-manager scope and stop if the manager resolves a real-home path,
  unexpected fragment, or duplicate schedule.
- [x] 3.4 In the real-manager fallback, add only the hashed test override
  allowed by `design.md` after disabled staging. Set temporary scan/root,
  log/state, and XDG paths; clear or replace the generated environment file
  with an empty validation-owned file; clear `TELLTALE_PROJECT_CONFIG`; and
  replace `ExecStart` only to append the existing
  `--install-inventory-disabled` flag. Never expose or inherit live HEC/output
  configuration; if `/etc/telltale` contains relevant local configuration,
  stop rather than trying to override it with an unapproved product change.

## 4. Live service and timer proof

- [x] 4.1 After a successful bounded `daemon-reload`, use the checked-in
  synthetic positive fixture
  `tests/fixtures/session_stores/codex/sessions/2026/04/install-persistence-chain.jsonl`
  under a temporary root. Run `systemctl --user start
  telltale-scan.service` twice as separate invocations and collect only
  `LoadState`, `ActiveState`, `SubState`, `Result`, `ExecMainCode`,
  `ExecMainStatus`, invocation-count, output-count, and deduplication
  projections. The first run must exit successfully with two parsed fixture
  records and one emitted detection; the unchanged second run must exit
  successfully with zero new emitted detections and one state-deduplicated
  detection. Prove both runs use the canonical executable and temporary paths.
- [x] 4.2 Exercise `systemctl --user restart telltale-scan.service` once after
  the two starts, then inspect the same bounded status properties. Validate
  every retained JSONL line against the checked-in Event 3.0 schema, confirm
  the expected activity/detection accounting and state schema/commit class,
  and verify that the unchanged restart emits zero new detections and counts
  one state-deduplicated detection, with no new detection event ID. Keep only
  counts, booleans, and hash prefixes; discard raw logs and state contents after
  assertions.
- [x] 4.3 Load and inspect the canonical timer's schedule and linkage to
  `telltale-scan.service` using bounded `show` properties, including
  `UnitFileState`, `ActiveState`, `OnActiveUSec`, `OnUnitActiveUSec`,
  `Persistent`, `Triggers`, and next-elapse class. In the isolated manager
  only, run `start`; use `enable --now` only there, where the target-wants link
  and Persistent timer state are private. In the real-manager fallback inspect
  linkage only; do not start the timer unless a host-specific persistent-state
  location is independently proven inside the allowlist. Wait at most 75
  seconds for the documented one-minute first fire when the isolated timer is
  started, observe one bounded timer-triggered service result with zero new
  emitted detections and one state-deduplicated detection, stop/disable it
  immediately, and remove the isolated target-wants link. If timer fire or
  required restart behavior cannot be safely exercised, leave `G-SERVICE`
  BLOCKED/B rather than claiming a full PASS.
- [x] 4.4 Do not leave a timer enabled because of validation. Before cleanup,
  stop and disable every validation-owned service/timer activation; preserve a
  pre-existing enabled/active state only for exact restoration.

## 5. Restoration, classification, and evidence review

- [x] 5.1 On every success and failure path, remove the test override and any
  marker-owned staged units, stop/disable validation-owned units, run a bounded
  user-manager `daemon-reload`, and restore exact pre-existing unit bytes,
  legacy identities, drop-in absence/presence, and the recorded disabled/
  inactive classes. Remove any validation-created
  `timers.target.wants/telltale-scan.timer` link in the isolated unit root.
  The fallback must have blocked before mutation if a relevant unit was
  initially enabled, active, failed, or ambiguous. Do not invoke an invented
  uninstall or remove unrelated files.
- [x] 5.2 Verify post-state hashes/classes against pre-state, confirm the
  manager sees no validation residue, and remove the temporary binary,
  configuration, synthetic source, log, state, staging, installer lock, Cargo
  caches, `TMPDIR`, target-wants link, and runtime roots that the validation
  created. If any restoration or cleanup assertion is unknown, keep
  `G-SERVICE` unpassed.
- [x] 5.3 Reconcile the evidence ledger with the contract: `PASS` only for a
  real manager-visible canonical service/timer proof with output/state,
  restart/status, and restoration evidence; `BLOCKED/B` for an unavailable or
  unsafe manager/session or unexercised required operation; `FAIL` only for a
  reproducible contract violation (`failure_class=C` in the repository ledger,
  user-facing D). Do not encode the procedural A observation or legacy-host C
  condition as the primary gate class. A FAIL receives a separate defect
  handoff; no product repair is allowed in this change.
- [x] 5.4 Update only measured local status in `PLAN.md`,
  `.ai/working-state.md`, and a redacted evidence artifact if needed. Keep
  `G-HEC` and `G-SPLUNK` BLOCKED and untouched, and do not make native,
  publication, hosted-site, or release-preflight claims.
- [x] 5.5 Obtain one fresh `coder-quality` review of the contract adherence,
  manager visibility, mutation allowlist, privacy projection, gate
  classification, and restoration proof. Apply only concrete evidence or
  documentation corrections; do not expand the scope.

## 6. Apply-session verification and handoff

- [x] 6.1 After the live work has either passed or been blocked and all allowed
  systemd changes are restored, run the narrowest OpenSpec status and
  validation checks plus `git diff --check`; confirm exactly one active change,
  `specs` intentionally skipped, no product-code diff, no archived-change
  modification, and untouched stash/Tokscale boundaries.
- [x] 6.2 Reconcile task status, evidence, durable working state, and archive
  readiness within the same fresh `/opsx-apply` session. Do not begin
  `G-HEC`, `G-SPLUNK`, native Windows/macOS validation, release preflight,
  publication, or another OpenSpec batch in the same root session.
- [x] 6.3 Run the narrowest verification, then `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Apply-session dispositions (2026-08-11)

- Tasks 1.1–1.4: completed. Branch/upstream, Draft PR #9, active-change count,
  contract files, immutable boundaries, and the redacted evidence ledger were
  confirmed.
- Tasks 2.1–2.3: completed with `G-SERVICE=BLOCKED/B`. The read-only Linux
  preflight found a real user manager, no approved 0.5.0 candidate provenance,
  and one unexpected manager-visible drop-in on `adr-scan.service`.
- Tasks 2.4–2.6: closed `BLOCKED/B` without entering the mutation path. No
  validation workspace or restoration backup was created because the candidate
  prerequisite was unavailable and the fallback pre-state was unsafe.
- Tasks 3.1–3.4: closed `BLOCKED/B`; installer staging, binary verification,
  manager reload, and the test override were not attempted.
- Tasks 4.1–4.4: closed `BLOCKED/B`; service, restart, timer, and live
  Event 3.0/state proof were not attempted.
- Tasks 5.1–5.3: completed on the no-mutation path. The independent post-state
  query matched all bounded pre-state classes and hashes, no validation residue
  existed, and the conservative gate classification was recorded.
- Task 5.4: completed. Measured status was reconciled in `PLAN.md`,
  `.ai/working-state.md`, `.ai/task-queue.md`, and `evidence.md` without
  changing the other release gates.
- Task 5.5: completed. The final Luna Max review found one stale local task
  queue count; it was corrected, with no substantive contract, privacy,
  classification, or restoration finding remaining.
- Task 6.1: completed. OpenSpec validation, `git diff --check`, one active
  change, intentionally skipped specs, no product/archive diff, and protected
  stash/Tokscale boundaries were confirmed.
- Task 6.2: completed. Task status, evidence, durable state, and archive
  readiness were reconciled without starting another gate or batch.
- Task 6.3: completed. OpenSpec validation, formatting, strict Clippy, and the
  full test suite passed; no product edit was manufactured.
