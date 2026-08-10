# Design: Installer/service/archive transaction

## Technical approach

The installer/service/archive cut is a deferred-surface migration, not new
detection or schema work. The design follows the transaction contract
already frozen in `.ai/working-state.md` and `docs/migration-contract.md`.

### Transaction sequencing

The installer runs as one journaled, staged, idempotent transaction:

1. **Acquire installer lock.** A cross-process advisory lock prevents
   concurrent installer runs. Reuse the existing sidecar lock discipline from
   `docs/migration-contract.md`; do not introduce a new lock primitive.
2. **Detect and quiesce old/new schedules.** Inspect loaded systemd user
   units for both `adr-scan.*` and `telltale-scan.*`. Disable conflicting
   schedules before staging. A duplicate-schedule conflict that cannot be
   resolved to one known schedule or all-disabled fails closed.
3. **Stage and verify the sole canonical archive and binary.** Verify
   checksums against `SHA256SUMS`; fail closed on missing checksum, missing
   archive, or no supported hash tool. Only explicit `--skip-checksum` may
   bypass. Source builds must pin the validated release tag.
4. **Run explicit state/log/env migration before activation.** Invoke the
   already-committed `migrate state`, `migrate events`, and `migrate env`
   primitives. No migration rewrites historical events. Existing legacy files
   remain recoverable until the transaction commits.
5. **Install new units disabled.** Install `telltale-scan.service` and
   `telltale-scan.timer` disabled. Remove only an identified obsolete
   compatibility binary; never destructively delete an unidentified file.
6. **Reload and smoke-test.** Reload the user service manager and run a
   bounded smoke test (version output, bundled rule validation, fixture
   dry-run scan).
7. **Enable only the canonical schedule.** Enable only `telltale-scan.timer`.
8. **Rollback.** On any failure, rollback to one known schedule or leave all
   schedules disabled. Never leave both old and new schedules enabled.

### Scope boundary

The user installer owns only the current Linux user install and its
user-unit directory. It must refuse unmanaged/system scope and ambiguous
ownership. Native Windows/macOS task migration, managed system paths/units,
automatic reindexing, and hosted-site cutover are separate boundaries and
remain out of scope.

### Release archive identity

Release archives and manifests contain no active ADR technical executable,
archive, service, task, or installer identity. Archive file-member lists
remain a stable contract; this batch changes identity, not structure
semantics. `make release-preflight`, archive manifest checks, and public
boundary checks must agree with the canonical identity.

### CI, helpers, and public docs

Active CI assertions, helper scripts, and public docs/examples that
reference installer/service/archive identity must agree with the canonical
identity. Deferred UF, service, installer, archive, release, and hosted
artifacts are migrated from isolated/deferred to canonical in this batch.

## Decisions

- **Reuse existing migration primitives.** `migrate state`, `migrate
  events`, and `migrate env` are committed (`4f20fac`) and independently
  approved. This batch wires them into the installer transaction; it does not
  alter their semantics or budgets.
- **No new schema or detection work.** Event 3.0/SIEM, detection/scoring,
  and historical schemas/fixtures/hashes are immutable in this batch.
- **Short-lived PR.** Per the architecture review outcome, this is a
  bounded, short-lived PR, not an undifferentiated rename/installer
  implementation. Conditional GO only with the transaction sequencing and
  fail-closed requirements above.
- **Journaled, not globally atomic.** The transaction is journaled, staged,
  idempotent, and recoverable. A crash between destination installs leaves an
  incomplete subset; a later identical run repairs it without clobbering
  existing bytes.

## Cross-platform implications

- Linux: the user installer and systemd user units are the primary target.
- Windows/macOS: native task migration and managed system paths/units remain
  out of scope and unpassed release gates. Do not publish or tag until native
  Windows/macOS execution passes with `make release-preflight`.

## Release-workflow and public-boundary impact

- `make release-preflight` must validate canonical archive identity.
- Archive manifest checks must reject active ADR technical identity.
- Public boundary checks must agree with canonical `telltale-*` identity.
- `docs/CHANGELOG.md` records the shipped behavior change; detailed
  execution context is archived in `.ai/working-state.md`.