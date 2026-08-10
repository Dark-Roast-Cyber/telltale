# Tasks

## 1. Inventory and contract freeze

- [x] 1.1 Inventory exact installer/service/archive/release-workflow rename
  surfaces: `scripts/install-telltale`, systemd user unit templates,
  `Makefile` release targets, archive manifest checks, public boundary
  checks, helper scripts, and active CI assertions.
- [x] 1.2 Confirm the frozen canonical mappings against `.ai/working-state.md`:
  `telltale` only; `TELLTALE_*`; `telltale-events.jsonl`; `telltale-state.json`;
  `telltale-scan.service`/`.timer`; `/etc/telltale/telltale.env`;
  `telltale-*` release assets.
- [x] 1.3 Define the versioned migration matrix: fresh install, 0.3 upgrade,
  current unpublished state, interrupted migration, old/new schedule
  conflicts, permissions/symlinks, duplicate binaries, state/log dedup
  continuity.

## 2. Installer transaction

- [x] 2.1 Acquire installer lock with cross-process advisory lock; fail fast
  on contention with a bounded busy error.
- [x] 2.2 Detect and quiesce old `adr-scan` and new `telltale-scan` schedules;
  resolve to one known schedule or all-disabled; fail closed on unresolvable
  duplicate-schedule conflict.
- [x] 2.3 Stage and verify the sole canonical archive and binary with
  fail-closed checksums; pin source builds to the validated release tag;
  only explicit `--skip-checksum` may bypass.
- [x] 2.4 Run explicit `migrate state`, `migrate events`, and `migrate env`
  before activation; preserve legacy files until commit; no historical event
  rewrites.
- [x] 2.5 Install `telltale-scan.service` and `telltale-scan.timer` disabled;
  remove only an identified obsolete compatibility binary; never destructively
  delete an unidentified file.
- [x] 2.6 Reload the user service manager and run a bounded smoke test
  (version output, bundled rule validation, fixture dry-run scan).
- [x] 2.7 Enable only `telltale-scan.timer`; rollback to one known schedule
  or all-disabled on any failure.

## 3. Scope and ownership safety

- [x] 3.1 Refuse unmanaged/system scope and ambiguous ownership with a
  static error; the installer owns only the current Linux user install and
  its user-unit directory.

## 4. Release archive and manifest identity

- [x] 4.1 Ensure release archives and manifests contain no active ADR
  technical executable, archive, service, task, or installer identity.
- [x] 4.2 Update `make release-preflight`, archive manifest checks, and
  public boundary checks to agree with canonical `telltale-*` identity and
  reject active ADR technical identity.

## 5. CI, helpers, and public docs

- [x] 5.1 Update active CI assertions, helper scripts, and public
  docs/examples that reference installer/service/archive identity to agree
  with the canonical identity.

## 6. Validation

- [x] 6.1 Run the versioned migration matrix (task 1.3) and prove fresh
  install, 0.3 upgrade, current-unpublished-state upgrade, interrupted
  migration recovery, schedule conflicts, permissions/symlinks, duplicate
  binaries, and state/log dedup continuity.
- [x] 6.2 Prove canonical binary/archive/install behavior and negative
  assertions for active ADR assets without changing native Event 3.0/SIEM
  behavior.
- [x] 6.3 Run focused installer/service/archive transaction tests first.
- [x] 6.4 Run `cargo fmt --check`, `cargo clippy --all-targets -- -D
  warnings`, and `cargo test`.
- [x] 6.5 Run fixture smoke, public-doc checks, shell syntax, and
  `git diff --check`.
- [x] 6.6 Confirm native Windows/macOS execution remains an unpassed release
  gate; do not publish or tag.

## 7. Review and commit

- [x] 7.1 Independent review approves the batch before commit.
- [x] 7.2 Update `.ai/working-state.md` with completed work, changed files,
  validation, decisions, risks, and the next recommended batch.
- [x] 7.3 Update `docs/CHANGELOG.md` for the shipped behavior change.
- [x] 7.4 Commit the batch; do not start the next major batch.
