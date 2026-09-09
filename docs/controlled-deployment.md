# Controlled development deployment

Status: operator procedure for validating an exact development build. It does
not make that build a release or authorize deployment to a live host.

The supported production release remains `v0.5.0` until a newer stable GitHub
Release exists. Use this procedure only in a lab or on an explicitly approved
canary target.

## Identity

An official release is identified by its immutable Git tag, GitHub Release,
archive attestation, published `SHA256SUMS`, and extracted binary checksum. A
development canary is identified by both:

```text
full clean Git commit SHA
SHA-256 of the exact candidate archive and extracted binary
```

The embedded short Git hash from `telltale --version`, package verification,
producer manifest, and rules fingerprint are corroborating evidence. They do
not replace the full SHA and checksums. The published candidate source on
development `main` reports package `0.6.0-rc.2`; that is a candidate line, not
proof of an official stable release. The exact
version output alone cannot distinguish an untagged build from an eventual
official release on that same line. The
historical Issue #37 artifact from `dd3ef2dc2fa0c7ab256f43a62ce3e0b183957248`
still reports `0.5.0` and retains its original archive/binary checksums. Never
substitute a newer build into that evidence. See the [versioning contract](versioning.md).

Use `telltale-dev-<40-character-sha>-<target>.tar.gz` for the archive name.
Never name it `telltale-v0.5.0-*`, attach it to the `v0.5.0` Release, or call it
stable.

## Compatibility record

This matrix compares official tag `v0.5.0` at
`2d37bd52bd004ddad4956f2fa4f6f3c791e7ee9e` with development `main` after
Issue #29, as recorded for the Issue #37 lab. This is historical compatibility
evidence, not a claim that every later build was exercised. Re-run the gates below
only for an explicitly approved exact candidate.

| Surface | v0.5.0 release | Historical #37 development candidate | Classification and rollback effect |
| --- | --- | --- | --- |
| Binary identity | Tag, release archive/checksum, `0.5.0 (2d37bd52bd00)` | Full source SHA, archive/binary SHA-256, `0.5.0 (<short-sha>)` | Same reported version is ambiguous. Retain or recover the release archive and checksum. |
| Event schema | Event 3.0 | Event 3.0, byte-identical schema | Backward and forward compatible. Event4 draft is irrelevant and not runtime-supported. |
| Rules fingerprint | No public producer-manifest surface | Rule v1 fingerprint and producer manifest; bundled rule content has advanced | Detection output may differ. Do not copy development bundled rules over release rules. |
| Configuration format | Outputs version 1 | Outputs version 1 with additive delivery settings | Existing v0.5.0 config is backward-compatible. Development-only keys are not downgrade-compatible. |
| Output configuration | JSONL, HEC, and Elastic sink entries | Same entries plus durable delivery policy/outbox | Existing files validate on both. `delivery:` is rejected by v0.5.0 and must be restored or removed on rollback. |
| Event3 JSONL | Append-only durable first write | Same contract and rotation naming | May be left in place, but snapshot it with the state set before canary. `event_id` permits downstream deduplication but does not make HEC or UF exactly-once. |
| Scanner state and cursors | State schema 1.0 | State schema 1.0; source file is byte-identical | Tested v0.5.0 → development → v0.5.0. May be reused, but backup is mandatory before canary. |
| Durable outbox | Absent | Optional private SQLite state | v0.5.0 does not read it. Restore the pre-upgrade state/config set; quarantine development outbox state rather than merging it. |
| Protected assignments | Absent | Optional foundation; no active Roo/Kilo projector | Irrelevant to the canonical scan. If explicitly used by a lab, back it up and do not present it to v0.5.0 as compatible state. |
| Environment file | Optional canonical file | Same path and semantics; additive variables only | Existing file is compatible. Restore the backup if changed for the canary. |
| Systemd service | Canonical service contract | Repository example unchanged; generated user unit remains canonical | Compatible. Preserve exact prior unit bytes and restore them if locally customized. |
| Systemd timer | One-minute initial/five-minute recurring timer | Unchanged | Compatible. Record enabled/active state and restore it exactly. |
| Installer | Release provenance and recoverable transaction | Adds explicit exact local development-archive mode; release mode unchanged | Candidate archive/version/SHA/checksum validation occurs before lock, unit, schedule, or binary mutation. Failed installer smoke restores the prior binary and units. |
| Release package | Canonical nine-member archive | Same nine-member archive shape | Compatible shape. Development archive is local evidence, not a Release asset or attested release. |

The scanner-state round trip was exercised with a synthetic fixture. The
development-only durable output document was accepted by development and
rejected by v0.5.0 at the unknown `delivery` field. That is why rollback backs
up and restores configuration and state together even though scanner state 1.0
itself is bidirectionally readable.

## Output routing

Local durable Event3 JSONL remains enabled in every supported topology. Select
exactly one canonical remote ingestion path for that JSONL:

| Route | Direct HEC sink | Universal Forwarder monitor for canonical JSONL |
| --- | --- | --- |
| UF-primary (repository operational default) | Disabled | Enabled |
| HEC-primary | Enabled | Disabled |

`config/examples/telltale-outputs.yaml` ships direct HEC disabled. The
deployment-managed UF-primary stanza must monitor
`monitor:///var/log/telltale/telltale-events.jsonl` for the system profile (or
the exact selected user-profile path). No UF configuration is part of the
release archive. Enabling direct HEC without removing that UF monitor sends the
same canonical events twice. It is allowed only when duplicate ingestion is an
explicit, separately named test.

HEC uses rustls certificate verification and public roots by default. `ca_file`
replaces the default roots with the configured corporate certificates.
`insecure_skip_verify: true` is an explicit lab-only exception that emits a
warning; do not enable it to make a canary pass. Use an environment or private
file token reference. Record only whether endpoint, TLS, token, HTTP 2xx, and
indexed count were observed, never the token or endpoint credentials.

## Build and package an exact candidate

Use a clean detached worktree for the selected SHA. These commands mirror the
Unix release bundle rather than creating a second package format.

```sh
candidate='<full-40-character-sha>'
target="$(rustc -vV | awk '/^host:/ {print $2}')"
worktree="/tmp/opencode/telltale-canary-$candidate"
artifact_dir="/tmp/opencode/telltale-canary-artifacts-$candidate"

git fetch origin main
git cat-file -e "$candidate^{commit}"
git worktree add --detach "$worktree" "$candidate"
test -z "$(git -C "$worktree" status --short)"
test "$(git -C "$worktree" rev-parse HEAD)" = "$candidate"
cargo build --manifest-path "$worktree/Cargo.toml" --locked --release --target "$target"

mkdir -m 0700 -p "$artifact_dir/bundle/config/examples"
install -m 0755 "$worktree/target/$target/release/telltale" "$artifact_dir/bundle/telltale"
install -m 0644 "$worktree/LICENSE" "$artifact_dir/bundle/LICENSE"
install -m 0644 "$worktree/release/README.md" "$artifact_dir/bundle/README.md"
printf '\nDevelopment-Source-SHA: %s\n' "$candidate" >>"$artifact_dir/bundle/README.md"
for file in telltale-outputs.yaml telltale-scan.service telltale-scan.timer \
  telltale-scan-task.xml elastic-telltale-index-template.json elastic-telltale-role.json; do
  install -m 0644 "$worktree/config/examples/$file" "$artifact_dir/bundle/config/examples/$file"
done
archive="$artifact_dir/telltale-dev-$candidate-$target.tar.gz"
tar czf "$archive" -C "$artifact_dir/bundle" \
  telltale LICENSE README.md config/examples/telltale-outputs.yaml \
  config/examples/telltale-scan.service config/examples/telltale-scan.timer \
  config/examples/telltale-scan-task.xml \
  config/examples/elastic-telltale-index-template.json \
  config/examples/elastic-telltale-role.json
archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
binary_sha256="$(sha256sum "$artifact_dir/bundle/telltale" | awk '{print $1}')"
"$artifact_dir/bundle/telltale" --version
printf 'source_sha=%s\narchive_sha256=%s\nbinary_sha256=%s\ntarget=%s\n' \
  "$candidate" "$archive_sha256" "$binary_sha256" "$target"
```

Before replacement, run the repository gates in [Validation](#validation).
Keep `rustc -vV`, package verification, and clean-tree output with the checksum
record.

## Back up and quiesce

Set paths for the approved target; do not infer them. This example is for the
current-user installer. Managed system installations need equivalent approved
paths and are not handled by this installer. First inspect the effective unit,
`telltale.env`, explicit config roots, `/etc/telltale`, output documents, and
CLI arguments. If any of `TELLTALE_STATE_PATH`, `TELLTALE_LOG_PATH`, JSONL
`path`, or durable `outbox_path` points outside the roots below, add that exact
path and its coordination sidecars to a target-specific source-to-backup
inventory. The inventory MUST cover every effective configuration root
(including `/etc/telltale` when present), environment file, scanner state,
canonical JSONL and rotations/lock, durable outbox and sidecars, and unit file.
For each path, record its absolute source, backup destination, checksum (for an
existing file), and whether it was absent. A path recorded absent must be
removed during rollback if the canary created it. Stop before quiescing if any
effective path is unknown, outside the inventory, or cannot be copied and
verified.

```sh
set -euo pipefail
state_root="${XDG_STATE_HOME:-$HOME/.local/state}/telltale"
config_root="${XDG_CONFIG_HOME:-$HOME/.config}/telltale"
unit_root="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
backup="/tmp/opencode/telltale-canary-backup-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup"

for unit in telltale-scan.service telltale-scan.timer; do
  systemctl --user is-enabled "$unit" >"$backup/$unit.enabled" || printf 'disabled\n' >"$backup/$unit.enabled"
  systemctl --user is-active "$unit" >"$backup/$unit.active" || printf 'inactive\n' >"$backup/$unit.active"
  systemctl --user disable "$unit" || test "$(systemctl --user is-enabled "$unit")" = disabled
  systemctl --user stop "$unit" || test "$(systemctl --user is-active "$unit")" = inactive
done
test "$(systemctl --user is-active telltale-scan.service)" = inactive
test "$(systemctl --user is-active telltale-scan.timer)" = inactive
cp -a "$HOME/.local/bin/telltale" "$backup/telltale"
sha256sum "$backup/telltale" >"$backup/telltale.sha256"
paths=(
  "$state_root"
  "$config_root"
  /etc/telltale
  "$unit_root/telltale-scan.service"
  "$unit_root/telltale-scan.timer"
)
# Append every effective external JSONL, outbox, state, config root, and sidecar
# found during inspection. The reviewed target inventory must not omit one.
: >"$backup/path-inventory.tsv"
for source in "${paths[@]}"; do
  test "${source#/}" != "$source" && test "$source" != / && test "${source#*$'\n'}" = "$source"
  destination="$backup/paths/${source#/}"
  if test -e "$source" || test -L "$source"; then
    install -d -m 0700 "$(dirname "$destination")"
    cp -a -- "$source" "$destination"
    printf 'present\t%s\t%s\n' "$source" "$destination" >>"$backup/path-inventory.tsv"
  else
    printf 'absent\t%s\t%s\n' "$source" "$destination" >>"$backup/path-inventory.tsv"
  fi
done
find "$backup" -type f ! -name backup.manifest -print0 | sort -z | \
  xargs -0 sha256sum >"$backup/backup.manifest"
sha256sum -c "$backup/backup.manifest"
```

Confirm the retained binary checksum against the published v0.5.0 archive
record. A backup failure stops the canary.

## Install and canary

All five development identity arguments are mandatory and cannot be combined with
release-tag, from-source, or checksum-bypass modes.

```sh
package_version='0.6.0' # obtain from exact candidate metadata; the historical #37 artifact uses 0.5.0
./scripts/install-telltale \
  --development-archive "$archive" \
  --development-sha "$candidate" \
  --development-sha256 "$archive_sha256" \
  --development-binary-sha256 "$binary_sha256" \
  --development-version "$package_version" \
  --no-timer
test "$(sha256sum "$HOME/.local/bin/telltale" | awk '{print $1}')" = "$binary_sha256"
```

The installer verifies archive safety and exact members, archive checksum,
the full source SHA bound in the bundled README, extracted binary checksum,
reported package version plus embedded candidate SHA, bundled rules, synthetic
fixture scan, generated unit policy, and disabled schedules before replacement.
It atomically stages replacement and restores the previous binary and units if
its post-replacement smoke fails.

Run one approved synthetic source through the actual service configuration.
Validate every emitted line with the existing Event3 gate/consumer. Record:

- exact binary checksum and version output;
- scan exit success and expected synthetic result;
- Event3 schema SHA
  `9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754`;
- local JSONL append and state health;
- selected remote route only;
- for HEC, endpoint configured/TLS enabled/token configured/HTTP status/indexed
  event count, without values or credentials;
- `systemctl --user start` and `status` for the service;
- `systemctl --user enable --now` and `list-timers` for the timer only after the
  one-shot service canary passes.

An HTTP success proves request acceptance, not indexing. If indexing cannot be
checked without exposing sensitive data, record it as unverified. Confirm that
the unselected remote path is disabled before claiming no duplicate ingestion.

## Rollback

Rollback after a completed install is configuration-aware:

1. Disable and stop the timer; stop the service.
2. Quarantine the complete post-canary state/config directory for diagnosis.
3. Run `./scripts/install-telltale --release-tag v0.5.0 --no-timer` to recover
   and verify that exact official release. If the network is unavailable, use the separately
   verified retained official archive through an approved offline process; do
   not substitute an unverified copied binary.
4. Restore the pre-canary state and configuration directories atomically while
   all schedules remain stopped. Apply every source-to-backup inventory row:
   restore and checksum existing paths, and remove canary-created paths recorded
   absent. This is mandatory if development-only durable configuration/outbox
   was used. Validate every source is the same reviewed absolute non-root path
   before removing or replacing it; never apply an edited or untrusted inventory.
5. Restore prior unit bytes if they differed, run `systemd-analyze verify`, and
   `systemctl --user daemon-reload`.
6. Confirm the restored binary SHA-256 equals the pre-canary/published value.
7. Run the same synthetic one-shot canary and validate Event3.
8. Restore each service/timer enabled and active state from its record only
   after the scan passes. A normally configured one-shot service is disabled
   and inactive; treat a different prior state as an explicit local policy.

Do not merge a development outbox into v0.5.0 state. Event3 JSONL is compatible,
but keep the quarantined canary log as separate evidence until rollback health
is proven.

## Failure handling

| Failure | Deterministic action |
| --- | --- |
| Source, package, checksum, version/SHA, schema, provenance, or evaluation gate | Stop before installation. Nothing is replaced. |
| Installer policy or candidate preflight | Stop. Installer leaves the canonical binary unchanged. |
| Replacement or installer smoke | Installer attempts binary/unit rollback and retains its journal/staging if rollback cannot be proven. Do not start services; inspect the journal. |
| Service or scan | Disable schedules, quarantine post-canary state, and perform full rollback. |
| HEC | Keep local durable JSONL; do not enable UF as an ad hoc second path. Roll back or fix only under the approved scope. |
| Timer | Keep it disabled; validate service directly, then roll back if timer health remains failed. |
| Rollback binary replacement | Keep schedules disabled. Do not run either binary until exact identity is restored. |
| State restore | Keep schedules disabled and preserve both state sets. Escalate; do not combine them. |

## Validation

Before selecting a candidate, run:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
make opencode-export-check
make telltale-console-check
make local-event-feed-check
make event3-contract-check
make producer-provenance-check
./scripts/package-verify
make release-public-docs-check
make CARGO_LOCKED=--locked release-fixture-smoke
```

Also run canonical evaluation and require exactly 44 corpus cases, 30 scored,
11 TP, 0 FP, 19 TN, and 0 FN. Verify repository and generated units with
`systemd-analyze verify` where available. Issue #15's absent optional
`EnvironmentFile` case, the present canonical case, noncanonical rejection, and
pre-replacement ordering are covered by the installer regression suite.

## Release recommendation

A successful development canary means only that the selected commit is ready
for release preparation. Production should remain on official `v0.5.0` until a
newer stable release passes its own version, Windows, package, CI, CodeQL, and
publication gates. Issue #23's Windows VC++ runtime dependency remains open and
is a Windows release caveat; it does not block this Linux lab procedure, but its
clean-host policy must be resolved before claiming a self-contained Windows
artifact.
