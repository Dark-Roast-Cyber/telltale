# Linux installer migration matrix

This matrix is the versioned execution contract for the current-user Linux
installer. It describes explicit migration inputs; the installer never probes
or aliases historical paths during normal scanning.

## Canonical active identity

| Surface | Canonical value |
| --- | --- |
| executable | `telltale` |
| environment names | `TELLTALE_*` |
| event log | `telltale-events.jsonl` |
| state | `telltale-state.json` |
| user units | `telltale-scan.service`, `telltale-scan.timer` |
| release assets | `telltale-*` archives with the exact nine canonical regular members |
| managed system environment example | `/etc/telltale/telltale.env` |

The user installer may write only the current user's install, state/config
migration destinations, and `~/.config/systemd/user`. It never writes the
managed system environment path or system unit directories.

## Versioned migration cases

| Case | Recognized legacy input | Required transaction result |
| --- | --- | --- |
| Fresh | No legacy executable, schedule, state, log, or environment file | Stage and verify one `telltale` binary; install units disabled; enable only the canonical timer when requested. |
| 0.3 user upgrade | Owned `adr` compatibility binary, `adr-scan` user schedule, and legacy `adr-*` state/log/environment files | Quiesce the old schedule, run explicit `migrate state`, `migrate events`, and `migrate env`, install canonical units disabled, remove only the identified owned compatibility binary, then activate one canonical timer. |
| Current unpublished | Owned `telltale` binary with legacy unit or legacy data still present | Preserve canonical bytes until the staged replacement and migrations validate; remove only identified obsolete unit/binary artifacts. |
| Interrupted transaction | Installer journal and/or owned transaction staging directory | Recover staged backups without clobbering existing bytes, leave one known schedule or all schedules disabled, then rerun idempotently. |
| Old/new schedule conflict | Both `adr-scan.timer` and `telltale-scan.timer` enabled or active | Disable both before failure; do not guess ownership. The installer fails closed unless it can establish one known schedule. |
| Permissions/symlinks | A managed path, unit, binary, journal, source, or destination is a symlink, non-regular file, or not owned by the current user | Fail with a static diagnostic before destructive changes. System scope and unmanaged paths are refused. |
| Duplicate binaries | More than the canonical binary, or an `adr` path that is not an owned verified compatibility binary | Install no alias; remove only an identified owned compatibility binary, otherwise fail closed. |
| State/log dedup continuity | Legacy fingerprints and historical JSONL records | Explicit migration preserves source bytes and state fingerprints; the canonical runtime continues duplicate suppression without reindexing or rewriting history. |

## Transaction evidence

The installer journal records bounded phase names (`staging`, `schedules`,
`migration`, `units`, `smoke`, `activation`, `committed`, `failed`, or
`recovered`) without transcript, environment-value, or credential content.
`activation` records the optional timer enablement step, while `recovered`
records completed stale-stage recovery before a new transaction begins.
Checksums are required unless the operator passes the explicit `--skip-checksum`
option. Source builds use the validated release tag and Cargo's locked
dependency resolution. Downloaded Linux archives are checked before extraction
for the exact canonical member set, one regular `telltale` binary, no duplicate
or traversal names, and no links or other non-regular members.

Before migration and every unit or binary mutation, the installer re-queries all
known old and new schedules and proves them disabled. It also rejects any
systemd-reported `DropInPaths` or local canonical-unit `.d` directory for
`telltale-scan.service` or `telltale-scan.timer`, so unmanaged overrides cannot
change execution, environment, or timer targets. A `--no-timer` transaction
performs the same all-schedules-disabled proof immediately before commit; timer
activation has an explicit canonical-only postcondition. If repository fixtures
are unavailable to a piped installer, its smoke test uses a deterministic
synthetic Codex fixture rather than an empty directory.

Native Windows/macOS task migration, managed system installation, automatic
reindexing, and hosted-site changes are not covered by this matrix. Native
platform execution remains an unpassed release gate.

## Surface inventory

The implementation surfaces covered by this batch are:

- `scripts/install-telltale`;
- `config/examples/telltale-scan.service[.in]` and
  `config/examples/telltale-scan.timer[.in]`;
- `Makefile` release/install targets and archive manifest validation;
- `.github/workflows/release.yml` and `scripts/package-verify`;
- `scripts/slunk_uf_set_up` and `config/examples/telltale-logrotate`;
- `tests/install_telltale.rs` and `tests/cli/release_public_boundary.rs`;
- `docs/install.md`, `docs/license-and-packaging.md`,
  `docs/release-readiness.md`, and `release/README.md`.

Historical changelog entries, migration documentation, historical schemas,
fixtures, and hashes retain their original values and are not active release
identities.
