# Proposal: Installer/service/archive transaction

## Intent

Cut the canonical Telltale installer, systemd service/timer units, release
archive identity, and release-workflow surface from their deferred ADR-era
state to the canonical `telltale` identity as one reviewed, journaled,
idempotent transaction. This is the next bounded Phase 2 batch selected by
`PLAN.md`, following the committed runtime-identity cut `d3ef8e6` (`Cut
canonical Telltale-only runtime identity`).

The runtime identity cut already made `telltale` the sole executable, switched
runtime defaults to `TELLTALE_*` / `telltale-*` paths, tombstoned retired ADR
variables, and aligned active CI/helpers/docs. Installer, service, archive,
and release-workflow behavior were **explicitly deferred** during that cut and
remain on their ADR-era surfaces today. This batch closes that deferred gap.

## Source

- `PLAN.md` "Active next batch — installer/service/archive transaction".
- `.ai/working-state.md` "Active batch" change contract and stop conditions
  (lines 39-106): the installer transaction sequencing, frozen canonical
  mappings, ownership boundaries, and fail-closed requirements.
- `docs/migration-contract.md`: explicit, source-preserving, lock-held,
  no-clobber, atomic installation guarantees this batch must honor.
- Architecture review outcome recorded in working-state: **conditional GO only
  for a bounded, short-lived PR**; the user installer owns only the current
  Linux user install and its user-unit directory.

## Scope

In scope (the deferred installer/service/archive/release-workflow surface):

- The user installer (`scripts/install-telltale`): canonical `telltale`
  identity, fail-closed checksums, pinned source builds, transactional
  rollback. Quiesce old/new schedules, migrate explicit state/log/env inputs
  before activation, install one canonical identity.
- Systemd user service/timer units (`telltale-scan.service` / `.timer` and
  templates): canonical identity, `TELLTALE_*` environment, canonical JSONL
  path, timer de-duplication.
- Release archives and manifests: no active ADR technical executable, archive,
  service, task, or installer identity. Canonical `telltale-*` release assets.
- Release workflow (`make release-preflight`, archive manifest checks, public
  boundary checks): agreement with canonical identity.
- Active CI assertions, helper scripts, and public docs/examples that
  reference installer/service/archive identity.

## Behavioral contract

- **One transaction.** Installer sequencing is one transaction: acquire
  installer lock; detect and quiesce old/new schedules; stage/verify the sole
  canonical archive and binary; run explicit state/log/env migration before
  activation; install new units disabled; remove only an identified obsolete
  compatibility binary; reload and smoke-test; enable only the canonical
  schedule; rollback to one known schedule or leave all schedules disabled.
- **User scope only.** The user installer owns only the current Linux user
  install and its user-unit directory. It must refuse unmanaged/system scope
  and ambiguous ownership.
- **Journaled and recoverable.** The transaction is journaled, staged,
  idempotent, and recoverable rather than globally filesystem-atomic. Existing
  legacy files remain recoverable until the installer transaction commits.
- **Fail closed.** Fail closed on ownership ambiguity, duplicate-schedule
  risk, destructive deletion of an unidentified file, or silent aliasing.
- **Migration before activation.** State/log/env migration runs before
  activation using the already-committed explicit migration primitives
  (`migrate state`, `migrate events`, `migrate env`). No migration rewrites
  historical events.
- **Canonical identity.** Release archives and manifests contain no active
  ADR technical executable, archive, service, task, or installer identity.
  Public docs/examples and CI assertions agree; historical migration artifacts
  are exempt.

## Compatibility requirements

- Preserve detection/scoring/state fingerprint semantics, Event 3.0/SIEM
  fields, historical schemas/fixtures/hashes, and private host architecture.
- Preserve the already-committed runtime identity cut (`d3ef8e6`): `telltale`
  executable, `TELLTALE_*` / `telltale-*` paths, tombstoned retired variables.
- Preserve immutable historical records/schemas/fixtures and explicit
  migration documentation; ADR remains only as Agent Detection and Response
  category prose and in explicit historical/migration artifacts.
- Existing release archive file-member lists remain a stable contract; this
  batch changes identity, not archive structure semantics.
- Native Windows/macOS task migration, managed system paths/units, automatic
  reindexing, and hosted-site cutover remain **out of scope** (non-goals).

## Acceptance criteria

- Fresh install, 0.3 upgrade, and current-unpublished-state upgrade paths are
  covered by a versioned migration matrix including interrupted migration,
  old/new schedule conflicts, permissions/symlinks, duplicate binaries, and
  state/log dedup continuity.
- Canonical binary/archive/install behavior is proven; negative assertions
  hold for active ADR assets without changing native Event 3.0/SIEM behavior.
- The installer transaction is journaled, staged, idempotent, and recoverable;
  rollback to one known schedule or all-schedules-disabled is demonstrable.
- The user installer refuses unmanaged/system scope and ambiguous ownership.
- Release archives and manifests contain no active ADR technical identity;
  active CI/helper/public-doc assertions agree.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test` pass; narrowest relevant verification runs first.
- Independent review approves the batch before commit.

## Validation

- Versioned migration matrix: fresh install, 0.3 upgrade, current
  unpublished state, interrupted migration, old/new schedule conflicts,
  permissions/symlinks, duplicate binaries, state/log dedup continuity.
- Canonical binary/archive/install behavior and negative assertions for
  active ADR assets without changing native Event 3.0/SIEM behavior.
- Focused installer/service/archive transaction tests; then
  `cargo fmt --check`, strict Clippy, full `cargo test`, fixture smoke,
  public-doc checks, shell syntax, and `git diff --check`.
- Native Windows/macOS execution remains an unpassed release gate; do not
  publish or tag until it passes with `make release-preflight`.

## Non-goals

The following deferred surfaces are explicitly out of scope and must not be
started in this batch:

- Native Windows/macOS task migration and managed system paths/units.
- Automatic reindexing of historical events.
- Hosted-site (AgentArchaeology installer) cutover.
- New detection rules, scoring changes, or Event 3.0 schema changes.
- Changes to detection/scoring/state fingerprint semantics or historical
  schemas/fixtures/hashes.
- New agent sources, response/blocking, remote rule feeds, plugin APIs, or
  GUI.
- The labeled test-dataset and visibility-requirements workstream.
- Crates.io publication (blocked until the complete 0.5.0 release candidate
  passes native Linux/macOS/Windows gates).

## Stop boundary

Stop and return control if implementation requires any of:

- Silent aliasing of old ADR paths/variables/services.
- Destructive deletion of an unidentified file.
- Duplicate schedule risk that cannot be resolved to one known schedule or
  all-disabled.
- An unreviewed public schema change or Event 3.0/SIEM field change.
- Changes to detection/scoring/state fingerprint semantics or historical
  schemas/fixtures/hashes.
- Crossing into any non-goal surface listed above.

After the batch is implemented, reviewed, validated, committed, and recorded
in `.ai/working-state.md`: stop. Do not start the next major batch. A fresh
root OpenCode session owns the next one.