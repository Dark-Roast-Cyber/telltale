# G-SERVICE Apply Evidence

Private, redacted evidence ledger for the bounded
`resolve-g-service-validation-gate` apply session. This file records metadata,
state classes, counts, booleans, hashes, and error categories only. It does not
contain unit bytes, journal output, environment values, `.env` contents,
transcript/session content, credentials, or exact private paths.

## Gate result

- **G-SERVICE:** `BLOCKED/B`
- **Primary blocker:** no approved, matching 0.5.0 release candidate/tag,
  downloadable artifact, and expected SHA-256 digest were available from the
  authorized release state before installer or systemd mutation.
- **Secondary safety blocker:** the real user manager reported one existing
  drop-in for the legacy `adr-scan.service`; the backed-up fallback therefore
  was not eligible under the exact-restoration contract.
- **Product defect:** none established. No product repair was attempted.

## Repository and OpenSpec preflight

- Branch: `release/0.5.0-maturation`.
- Upstream: `origin/release/0.5.0-maturation`.
- HEAD: `57dcb77` (bounded commit identifier).
- Tracked worktree: no unrelated tracked modifications at session start.
- Expected untracked boundaries: the active change directory and
  `tokscale-export-20260809-013857.json`; the latter was not read or modified.
- Preserved README/docs work: existing stash remained present and was not
  applied, dropped, inspected, or modified.
- PR #9: open and Draft; head is the current release branch; no check runs were
  reported by the read-only status check.
- Active OpenSpec changes: exactly one,
  `resolve-g-service-validation-gate`.
- Archived OpenSpec changes: not modified.
- Schema: `spec-driven`; `specs` intentionally skipped; 26 apply tasks pending
  at session start.

## Candidate provenance

- Workspace package metadata reports all six Telltale packages at `0.5.0`.
- Local `v0.5.0` tag: absent.
- `origin` `v0.5.0` tag: absent.
- Approved 0.5.0 public release/archive: absent; the read-only release check
  found only the existing stable 0.3.0 release and no 0.5.0 assets.
- Checked-out release artifact/checksum locations: no matching archive or
  `SHA256SUMS` artifact found.
- Expected candidate binary digest: unavailable because the approved matching
  candidate artifact is unavailable.
- `--skip-checksum`: not used.
- Installer invocation: not attempted.
- Required follow-up prerequisite: publish or otherwise authorize the reviewed
  0.5.0 candidate tag and archive, expose its checksum metadata, and verify the
  expected binary digest before any future installer or manager mutation. A
  locally built checkout or public 0.3.x binary is not a substitute.

## Read-only host preflight

No installer, unit-file, drop-in, manager lifecycle, enablement, activation, or
system-scope operation was performed.

- Platform: Linux.
- Current-user scope: non-root.
- Running real `systemd --user` manager: bounded `show` succeeded and reported
  a version.
- Manager unit search path: included the approved current-user user-unit
  directory.
- Separate isolated manager: not provided or established; no ad-hoc manager or
  socket was launched.
- `/etc/telltale`: parent absent; no system configuration values were read.
- System-level `systemctl`, `sudo`, `loginctl`, and manager restart/lifecycle
  operations: none used.

### Approved unit pre-state

The following is limited to the four approved identities. `fragment-location`
is a location class, not a private path.

| Unit | LoadState | fragment-location | UnitFileState | Active/SubState | Result | manager drop-ins | file class | SHA-256 |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| `telltale-scan.service` | `not-found` | absent | empty/not-found | inactive/dead | success | 0 | absent | n/a |
| `telltale-scan.timer` | `not-found` | absent | empty/not-found | inactive/dead | success | 0 | absent | n/a |
| `adr-scan.service` | loaded | approved user-unit directory | static | inactive/dead | success | **1** | current-user regular, mode 0644 | `caa6311bfe3d7642b7513d792f9683448da7c8b3d2b575de8c4996f8757f9b43` |
| `adr-scan.timer` | loaded | approved user-unit directory | disabled | inactive/dead | success | 0 | current-user regular, mode 0644 | `a01954299d6c9c01a574c2746bcbb3459895c18e02f1449981a89ca27b2aec38` |

The existing manager-visible `adr-scan.service` drop-in is an unexpected
pre-existing condition. Its bytes and path were not inspected because the
candidate prerequisite was already missing and the contract requires fail
closed for an unexpected drop-in. No legacy unit was removed or migrated.

## Live validation disposition

- Validation workspace/source/install/config/state/log/runtime roots: not
  created; candidate provenance failed before staging.
- Restoration backups/overrides/staged units: not created.
- Canonical staging with `--no-timer`: not attempted.
- Manager `daemon-reload`: not run for validation.
- Service start #1: not attempted.
- Service start #2/deduplication: not attempted.
- Service restart: not attempted.
- Timer load/activation/fire: not attempted.
- Canonical Event 3.0 JSONL/state evidence: not produced by this blocked
  validation. The approved fixture and expected counts remain contract
  requirements, not live evidence.

## Cleanup and restoration

- Validation-created service/timer activity: none.
- Validation-created units/drop-ins/target-wants links: none.
- Validation-created binary, source, state, log, cache, runtime, or installer
  artifacts: none.
- Host restoration: no mutation occurred; the bounded pre-state above remains
  the host state to preserve. The unexpected legacy drop-in was left untouched.
- Independent post-state query: all four unit state classes and both pre-existing
  unit hashes matched the pre-state; manager-visible drop-in counts remained
  `1 -> 1` for `adr-scan.service` and `0 -> 0` for the other three units;
  canonical validation overrides remained absent.
- Product code, installer code, system-level systemd, HEC, Splunk, native
  platform validation, release/publication state, preserved stash, and Tokscale
  export: untouched.

## Review and finalization

- Initial independent Luna Max (`coder-quality`) review: completed; it found
  four evidence/status issues, all corrected without product or host changes:
  explicit blocked dispositions for unexercised live tasks, aligned task queue
  and plan wording, explicit `1 -> 1` drop-in preservation, and finalization
  status sequencing.
- Final independent Luna Max review after those corrections: completed. It
  found one stale `22/26` versus `21/26` local task-queue count; that count was
  corrected. No substantive contract, privacy, classification, or restoration
  finding remained.
- OpenSpec positional validation: passed (`Change ... is valid`).
- `git diff --check`: passed.
- `cargo fmt --check`: passed.
- `cargo clippy --all-targets -- -D warnings`: passed.
- `cargo test`: passed; 211 + 34 + 6 + 157 + 25 + 59 + 112 tests passed,
  1 ignored.
- Archive: ready; all 26 task dispositions are complete and no delta specs
  require synchronization.
