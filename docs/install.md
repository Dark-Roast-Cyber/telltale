# Install

> **Website:** For an approachable install guide, see [AgentArchaeology.ai/telltale/install](https://agentarchaeology.ai/telltale/install/).

Telltale Core can be installed from a tagged GitHub release archive when one
is available, or built from source with Cargo. In both cases, start with a
fixture-safe scan before pointing the scanner at real agent session stores. See
the [Source Validation Matrix](source-validation-matrix.md) for the canonical
source-support claims and their evidence.

For exact non-production canary identity and output-routing requirements, see
[Controlled development deployment](controlled-deployment.md). Its tested
compatibility record and pinned rollback recipe are historical evidence
against `v0.5.0`, not proof of rollback from the current stable release.
For the next minor line, see the [0.7.0 migration guide](migrations/0.7.0.md).

## Prerequisites

- Rust toolchain with `cargo` when building from source
- Python 3 for strict release metadata validation by the Linux repository installer
- Local access to the agent session stores you want to scan
- Optional: a SIEM or log shipper for the generated JSONL event stream

## Install the CLI with Cargo

The Cargo packages are in current release preparation and are not published to
crates.io yet. After publication, install the CLI with:

```sh
cargo install telltale-cli
```

This installs the sole `telltale` binary. The supported
Rust embedding surface is the separate `telltale-core` package.

## Install From A Release Archive

Tagged GitHub releases publish platform-specific `telltale-*` binary archives
for Linux, macOS, and Windows. Download the canonical archive that matches your
platform, extract the sole `telltale` binary, and use it (`telltale.exe` on
Windows).

The selected policy for official `x86_64-pc-windows-msvc` release builds is to
statically link the applicable MSVC CRT. These binaries do not require a
separately installed Microsoft Visual C++ Redistributable. The exact
`v0.6.0-rc.3` candidate passed five-platform native verification and clean-Windows
static-CRT and functional acceptance. This policy does not apply retroactively to
`v0.6.0-rc.2` or the immutable `v0.5.0` artifact.

Current release archives and CI smoke checks establish binary packaging and
execution support for Linux, macOS, and Windows. They do not establish broad
live validation of agent source stores on those platforms; source-store support
claims remain bounded by the [Source Validation Matrix](source-validation-matrix.md).

Each archive contains exactly these file members (with `.exe` on Windows):

```text
telltale                    # or telltale.exe
LICENSE
README.md                   # concise release quick start
config/examples/
  telltale-outputs.yaml
  telltale-scan.service
  telltale-scan.timer
  telltale-scan-task.xml
  elastic-telltale-index-template.json
  elastic-telltale-role.json
```

`SHA256SUMS` is published as a separate release asset, not inside the binary
archives. Archives do not include local scanner state, telemetry logs, session
stores, credentials, Splunk/Filebeat content, or other deployment-specific
configuration.

### Selecting an RC candidate

Official stable is `v0.7.0`. Published candidates are immutable; each
candidate's identity and qualification results are on its
[GitHub Release](https://github.com/Dark-Roast-Cyber/telltale/releases). The
[versioning contract](versioning.md) requires RC package/tag equality and separate exact
SHA/checksum identity for candidate artifacts.

The no-argument installer selects the latest stable GitHub Release. For
approved candidate validation, select the exact immutable RC tag:

```sh
RC_TAG='v<version>-rc.N' # replace with one exact published candidate; use only with approval
./scripts/install-telltale --release-tag "$RC_TAG" --no-timer
./scripts/install-telltale --release-tag "$RC_TAG" --from-source --no-timer
```

The explicit path requires that tag's published non-draft prerelease metadata,
derives every archive and checksum URL from that tag, and verifies the archive
manifest, checksum, and binary version before any installer lock, file,
schedule, or systemd-manager mutation. It does not fall back to
`releases/latest`. RC artifacts are immutable; a validation-relevant change
needs the next reviewed RC. GitHub binary releases remain separate from the
later dependency-ordered crates.io publication.

### Verify a release archive

The release workflow publishes a GitHub artifact attestation for every `.tar.gz`
and `.zip` archive. Release assets use `telltale-v<version>-...` names. Once the
RC candidate or a later stable release is published, verify the downloaded
archive as a separate post-publication step before extracting it. For a
published candidate, replace `<version>` with its exact version:

```sh
gh attestation verify telltale-v<version>-x86_64-unknown-linux-gnu.tar.gz \
  --repo Dark-Roast-Cyber/telltale
```

Replace the filename with the archive for your platform. The command checks the
archive's digest and its signed GitHub Actions provenance; an online GitHub CLI
environment is required. The Linux installer verifies the published
`SHA256SUMS` checksum, but it does not perform this GitHub attestation check.

### Quick install (Linux)

A repository installer is available for Linux. It downloads the latest release
binary, verifies it against the release's published `SHA256SUMS`, and installs
it to `~/.local/bin/telltale` (no sudo). A missing or mismatched `SHA256SUMS`
entry stops the install, and `--skip-checksum` is rejected on every install path
before any download. It does not enable anything beyond the binary install unless
you opt in:

```sh
./scripts/install-telltale
./scripts/install-telltale --with-timer
```

The hosted one-line installer is not part of this repository's release cutover;
use the checked-in script above for a reviewed install. It uses one locked,
journaled transaction, verifies `SHA256SUMS`, stages the canonical binary, and
smoke-tests before activation. It performs no product migration or cleanup;
explicit Telltale state/event migration is a separate operator command.
`--from-source` first downloads and validates the
selected release's canonical archive provenance, resolves that tag to an
immutable commit, and builds that exact source revision; it does not skip the
prebuilt archive download or bypass release provenance. Add `--with-timer` to
install and enable the canonical user-level systemd timer.

The installer does not create system users, configure SIEM shippers, or require
root. For managed Linux deployments with the `system` path profile, use the
examples in `config/examples/` and the manual systemd setup below.

Built-in size-based log rotation is enabled by default (100 MB max, keep 5
rotated files). No OS-specific rotation tooling is required for user-profile
installs. See [telemetry-output.md](telemetry-output.md#built-in-rotation) for
configuration details.

The release archive does not include the Linux installer script itself. Active
release assets and units use only the canonical identity; historical migration
files are not runtime aliases.

### macOS

Download the release archive for your architecture and extract the binary:

```sh
# Apple Silicon (aarch64)
curl -fsSLO https://github.com/Dark-Roast-Cyber/telltale/releases/latest/download/telltale-$(curl -fsSL https://api.github.com/repos/Dark-Roast-Cyber/telltale/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"//;s/"$//')-aarch64-apple-darwin.tar.gz
tar xzf telltale-*-aarch64-apple-darwin.tar.gz
sudo mv telltale /usr/local/bin/telltale
```

Or build from source:

```sh
git clone https://github.com/Dark-Roast-Cyber/telltale.git
cd telltale
cargo build --release
sudo cp target/release/telltale /usr/local/bin/telltale
```

The default `user` path profile writes telemetry to
`~/Library/Logs/Telltale/telltale-events.jsonl` and state to
`~/Library/Application Support/Telltale/telltale-state.json`. No sudo is needed
for scans — run as your user.

For periodic scans, create a user LaunchAgent at
`~/Library/LaunchAgents/ai.agentarchaeology.telltale.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.agentarchaeology.telltale</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/telltale</string>
        <string>scan</string>
        <string>--once</string>
        <string>--emit-activity</string>
        <string>--root</string>
        <string>/Users/YOUR_USERNAME</string>
    </array>
    <key>StartInterval</key>
    <integer>1800</integer>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

Load it with:

```sh
launchctl load ~/Library/LaunchAgents/ai.agentarchaeology.telltale.plist
```

### Windows

Use the reviewed repository scripts from this checkout with Windows PowerShell
5.1 or PowerShell 7 and a current authenticated GitHub CLI (`gh`). Installation
selects the latest official stable Release (`v0.7.0` currently) and verifies the
exact release/tag/commit, GitHub asset digests, `SHA256SUMS`, source/ref/digest-bound
GitHub attestation, canonical nine-member ZIP and executable version before
changing the installation:

```powershell
# If this shell blocks scripts, allow the reviewed scripts for this process only:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\install-telltale.ps1
# Optional, separately selected changes:
.\scripts\install-telltale.ps1 -AddToPath
.\scripts\install-telltale.ps1 -WithScheduledTask
# Approved published prerelease; no fallback to stable or main:
.\scripts\install-telltale.ps1 -ReleaseTag v0.7.0-rc.2
```

The current-user executable and `install-receipt.json` live under
`%LOCALAPPDATA%\Programs\Telltale`. Runtime defaults remain
`%LOCALAPPDATA%\Telltale\Logs\telltale-events.jsonl` and
`%LOCALAPPDATA%\Telltale\State\telltale-state.json`. No elevation is needed.
Scheduling and PATH changes are disabled by default. Reinstallation retains
installation identity and an existing managed schedule. Open a new terminal
after opting into PATH. The scripts are repository tooling, not additional
release ZIP members; there is no production checksum bypass.

An exclusive current-user lifecycle mutex, file lock, journal, staged executable, digest-bound backup and
journaled executable rename support rollback. A running executable, or a program
holding it open without allowing writes and deletion, blocks replacement and removal
safely: close it and retry. A reader that shares read, write and delete access, such
as a brief scan of a new executable, does not block installation, rollback or
uninstall. Each installed executable receives the permissions inherited at
installation, as on a first install. Reinstallation does not carry permissions or
alternate data streams (such as `Zone.Identifier`) added to the previous executable;
apply custom permissions again after reinstalling. Rerun the installer after interruption;
changed recovery files or task declarations fail closed for operator inspection.

For isolated tests, `-InstallDirectory` and `-DataDirectory` accept separate,
dedicated directories inside the current user's LocalApplicationData folder.
These overrides do not change CLI defaults: use explicit scan paths. Unsafe
aliases (including DOS short paths), PATH separator/expansion characters,
reparse points, hard-linked installed files, unrelated installation
contents and missing ownership receipts are rejected. The boundary trusts the
current user; it does not defend against a malicious process running as that
same user during a transaction.

Or build from source for development-only installation:

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --locked --release --target x86_64-pc-windows-msvc
.\scripts\verify-windows-runtime.ps1 -BinaryPath .\target\x86_64-pc-windows-msvc\release\telltale.exe
.\scripts\install-telltale.ps1 -DevelopmentBinary .\target\x86_64-pc-windows-msvc\release\telltale.exe
```

`-DevelopmentBinary` is a trusted local input, copied and checked for version and
bundled rules. Its receipt says `development-local`; it is never reported as
a verified published artifact. It cannot be combined with `-ReleaseTag`.

For a development build without the manual steps above, run
`.\scripts\build-windows-development.ps1` (add `-Target x86_64-pc-windows-gnu`
only for development-only verification). It builds `telltale` with `--locked`,
checks that `--version` reports the checked-out revision, and prints the binary
path and SHA-256. It never falls back to another target.

To check a live host read-only, run
`.\scripts\verify-live-host.ps1 -BinaryPath <telltale.exe> -Root <source root> -Client codex,claude`.
It performs one dry-run scan per client with temporary log and state paths and
reports `passed`, `passed_with_limits`, `failed`, or `not_available`. It does not
install, schedule, or change any source store.

### Windows Scheduled Task example

`-WithScheduledTask` derives `TelltaleScan` from
`config/examples/telltale-scan-task.xml`: current-user SID, interactive logon,
least privilege, every 30 minutes for 365 days after logon, IgnoreNew instances,
and a one-hour execution limit. It binds absolute executable and working-directory
paths and quotes scan-root/state/log arguments. Registration starts disabled;
enablement follows committed binary replacement. No service, SYSTEM identity,
password, daemon or MSI is created. Existing tasks must match the exact receipt;
conflicting or modified tasks are retained and block changes. Opting in authorizes
scans of supported agent stores under the user's profile at logon.

Executable copying and metadata writes use scratch files outside the installation,
then atomically rename complete files into place. Retry recovers journaled changes.
A killed process may leave a `telltale-install-<GUID>` directory or
`telltale-metadata-<GUID>.tmp` in LocalApplicationData; these scratch leftovers do
not block retry and are retained for separate inspection rather than adopted for purge.

### Windows uninstall and explicit purge

```powershell
.\scripts\uninstall-telltale.ps1 -WhatIf
.\scripts\uninstall-telltale.ps1
# Preview exact generated-data deletions, then confirm:
.\scripts\uninstall-telltale.ps1 -PurgeData -WhatIf
.\scripts\uninstall-telltale.ps1 -PurgeData
# Separate explicit consent for recognized user-authored configuration:
.\scripts\uninstall-telltale.ps1 -PurgeData -PurgeConfiguration -WhatIf
.\scripts\uninstall-telltale.ps1 -PurgeData -PurgeConfiguration
```

Normal uninstall verifies receipts, executable digest and task identity, stops
and removes the managed task, removes managed executable/metadata and undoes only
its own unique user PATH entry (case and trailing slash differences are accepted). It retains logs, state, detection history,
configuration and the data-ownership receipt, so later explicit purge remains
possible. `-WhatIf` performs read-only inspection. Automation may explicitly
supply `-Confirm:$false` after reviewing the plan.

Purge owns only Logs/State directories originally created by the installer and
recognized generated filenames. Existing directories are retained without
adoption. Unexpected files, owners, links or locks block purge; it never
recursively deletes a shared directory. Partial failures return errors and retain
retry metadata where possible. `-PurgeConfiguration` separately selects regular
YAML files under the runtime's user configuration root: `$env:XDG_CONFIG_HOME\telltale`
when set, otherwise `$env:HOME\.config\telltale` when HOME is set. With neither
variable set, no user configuration is selected; USERPROFILE is not a fallback.
Recognized tiers are `organization-rules.d`, `rules.d`, `ui-rules.d`, `overrides.d`,
`policies.d`, `allowlists.d`, and `outputs.d`. Explicit/project configuration roots
remain outside cleanup. Unsafe or relative environment-selected roots fail closed.
All underlying Claude Code, Codex, OpenCode, Gemini and other coding-agent session
stores remain untouched. Downstream embedding consumers' libraries, installation,
and data are outside this standalone lifecycle.

The old `%LOCALAPPDATA%\Telltale\telltale.exe` layout is detected and retained.
Manual executables and tasks have no installer ownership proof. Legacy cleanup
requires separate operator inspection and manual removal of verified artifacts;
these scripts do not adopt it or migrate old state. RC2 remains immutable
published history. Proposed RC3 needs reviewed source preparation and fresh
applicable gates; these scripts do not tag or publish it.

## Build From Source

```sh
git clone https://github.com/Dark-Roast-Cyber/telltale.git
cd telltale
cargo build --release
```

The sole release binary will be available at `target/release/telltale`.

## Verify The Install Safely

Run a fixture-safe dry run before scanning real local session stores:

```sh
cargo run --bin telltale -- scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
cargo run --bin telltale -- config provenance --no-local-config
cargo run --bin telltale -- config validate --no-local-config
cargo run --bin telltale -- rules validate --no-local-config
cargo run --bin telltale -- rules export-default > /tmp/telltale-default-rules.yaml
cargo test
```

The fixture tree under `tests/fixtures/` is synthetic and safe for local
verification.

Use `--dry-run` for this verification step. Do not use `--allow-fixtures`
unless you intentionally want to write synthetic fixture output in CI or local
development.

## Scan Real Session Stores

Once the fixture scan looks healthy, run against your local session stores.
Use the directory that contains the supported session-store roots you want to
scan; for a typical single-user workstation, that is usually your home
directory. Keep `tests/fixtures/` for dry-run verification only:

```sh
cargo run --bin telltale -- scan --once --emit-activity --root "$HOME"
```

For a first real-store check, keep the scan read-only and bounded before
opening it up to every discovered source. `--client` scopes discovery to one or
more supported clients, and `--max-sources` deterministically caps the number of
sources scanned after that filtering:

```sh
cargo run --bin telltale -- scan --once --dry-run --root "$HOME" --client codex --max-sources 5
```

Telltale writes append-only JSONL by default so the output can be reviewed
locally or shipped to a SIEM. The default `user` path profile writes telemetry
under the operating-system-standard per-user location, such as
`$XDG_STATE_HOME/telltale/logs/telltale-events.jsonl` or
`~/.local/state/telltale/logs/telltale-events.jsonl` on Linux,
`~/Library/Logs/Telltale/telltale-events.jsonl` on macOS, and
`%LOCALAPPDATA%\Telltale\Logs\telltale-events.jsonl` on Windows. Use
`--path-profile system` for managed service deployments and
`--path-profile project` when you intentionally want repo-relative development
paths.

Explicit `--log-path` and `--state-path` flags override profile defaults. The
canonical environment overrides are `TELLTALE_LOG_PATH` and
`TELLTALE_STATE_PATH`; precedence is explicit CLI, environment, then profile
default. Unknown inherited variables are ignored.

## Local Rule, Policy, And Allowlist Config

Telltale loads its bundled core rules and the embedded community rule package by
default. Operators can add local YAML and rule packages without repeating every
path by creating a local config root. Existing default
roots are checked in deterministic order:

- `/etc/telltale`
- `$XDG_CONFIG_HOME/telltale`, or `$HOME/.config/telltale` when
  `XDG_CONFIG_HOME` is not set

Supported directories for this phase are:

```text
/etc/telltale/
  rule-packages.d/*.yaml|*.yml
  organization-rules.d/*.yaml|*.yml
  rules.d/*.yaml|*.yml
  ui-rules.d/*.yaml|*.yml
  overrides.d/*.yaml|*.yml
  policies.d/*.yaml|*.yml
  allowlists.d/*.yaml|*.yml
  settings.d/*.yaml|*.yml
```

Rule packs resolve in fixed tier order: bundled core rules, rule packages (the
embedded community package and `rule-packages.d`), `organization-rules.d`,
`rules.d` deployment files, and `ui-rules.d` local/UI files. Files are sorted
within each root and roots are processed in configured root order. A higher tier
fully replaces a same-ID definition in place; unique IDs are additive. Equal-tier
duplicate IDs fail with source diagnostics. Repeated explicit `--rules` paths are
loaded afterward as additive-only documents and cannot replace managed packs.
`overrides.d` files are sorted the same way and applied after packs are merged,
before policy filtering. If no explicit `--policy` is provided, exactly one
discovered `policies.d` file may be used; multiple discovered policies require
passing `--policy` explicitly or removing extras. `scan` and `watch` apply the
same single-file rule for discovered `allowlists.d` files when `--allowlist` is
not provided.

**Trust boundary:** Treat `organization-rules.d`, `rules.d`, and `ui-rules.d` as
trusted operator configuration. Protect them from untrusted or unsigned writes:
higher tiers can fully replace bundled rules, including disabling or changing
detections. Rule-pack integrity or signing is not provided by this configuration
mechanism. `rule-packages.d` files cannot replace or disable core rules, but they
add detections, scores, and analyst-facing text, so install only packages whose
release checksum or attestation you have verified.

### Community rules and rule packages

Detection content comes from three sources that share one rule engine, similar to
running a bundled ruleset beside community and custom rule feeds:

| Source | Delivered as | Default |
| --- | --- | --- |
| Core rules | Compiled into the binary (`telltale rules export-default`) | On; `--no-default-rules` removes them |
| Community rules | Package `telltale.community`, namespace `tdx`, embedded in the binary | On; opt out below |
| Custom packages | Operator-installed `rule-packages.d/*.yaml` files | Off until installed |

Community rules come from the
[community detections repository](https://github.com/Dark-Roast-Cyber/telltale-detections),
which reviews each rule against independently labeled synthetic scenarios before
it reaches a release. Use only the core rules with `--no-community-rules` on
`scan`, `watch`, `rules`, and `config` commands, or set
`TELLTALE_COMMUNITY_RULES=0` in a service environment whose arguments are fixed
(`false`, `off`, and `no` also work, in any case).
`--no-default-rules` omits both the core rules and the embedded community
snapshot, while installed packages still load like other managed content.

A rule package is one YAML file:

```yaml
format: telltale-rule-package/v1
id: acme.agent-rules        # unique package identity
version: "1.4.0"
publisher: Acme security engineering
license: Apache-2.0
rule_namespace: acme        # every rule and modifier ID starts with "acme."
source: https://example.com/acme/agent-rules   # optional, informational
revision: 0123456789abcdef0123456789abcdef01234567  # optional, informational
documents:
  - version: 1
    description: Acme agent rules.
    defaults: {case_insensitive: true, enabled: true}
    rules:
      - id: acme.persistence.example
        # ... ordinary Rule v1 fields ...
    modifiers: []
```

Packages only add definitions. A package cannot reuse a core rule namespace,
replace a core rule, or replace another package's rule; conflicting package IDs,
namespaces, or rule IDs fail validation with both sources. Diagnostics never
show paths, so two installed copies of one package are named by version and the
first 12 hex digits of their content SHA-256; `sha256sum` on the
`rule-packages.d` files finds them. Operators may still
tune a package rule through `overrides.d` or replace it from
`organization-rules.d`, `rules.d`, or `ui-rules.d`. Telltale never downloads
packages and rejects packages that contain control or invisible formatting
characters, including a carriage return outside a CRLF line ending.

To run a newer community release without waiting for a Telltale release, verify
and install its package. An installed package with ID `telltale.community`
replaces the embedded snapshot as a whole:

```sh
gh release download v0.2.0 --repo Dark-Roast-Cyber/telltale-detections \
  --pattern '*.package.yaml' --pattern SHA256SUMS
sha256sum --check SHA256SUMS
gh attestation verify telltale.community-0.2.0.package.yaml \
  --repo Dark-Roast-Cyber/telltale-detections
sudo install -D -m 0644 telltale.community-0.2.0.package.yaml \
  /etc/telltale/rule-packages.d/telltale.community.yaml
telltale config validate
```

Install a custom package the same way under its own file name. `telltale rules
validate` and `telltale config validate` list each effective package with its ID,
version, content SHA-256, origin (`embedded` or `installed`), and any replaced
embedded version; scans record the same list under
`effective_configuration.rules.packages`.

Use overrides for local rule disablement or score tuning without editing bundled
or custom rule files:

```yaml
version: 1
description: Local workstation tuning.
overrides:
  - rule_id: network.download
    enabled: false
    reason: Too noisy on this workstation.
  - rule_id: secret.env.read
    score: 20
    reason: Lab environment tuning.
```

Use `--config-dir <path>` to use explicit config roots instead of the default
roots, and `--no-local-config` when a command should ignore local config.
Explicit config roots must exist so path typos fail closed.
Missing default roots and missing config subdirectories are optional. Present
roots and subdirectories must be directories; metadata or enumeration failures
are errors, not a reason to fall back to defaults. Discovered `.yaml`/`.yml`
entries must resolve to regular files. Valid symlinks are followed, but dangling
configuration symlinks and wrong-type YAML entries fail discovery before scan
outputs or state are activated. Metadata diagnostics report a bounded error
classification without configuration paths or contents. `rules` commands do
not discover `allowlists.d` or `outputs.d`; `--no-local-config` bypasses discovery.

Use `telltale config validate` as the local config preflight before running scans with
custom content. It resolves config the same way as `scan` and `watch`, validates
the effective rule, override, and policy set, validates the selected allowlist
YAML, and prints a JSON status summary without reading session stores.

Use `telltale rules export-default` when you want to inspect or fork the bundled
default rules from an installed binary. Save an edited copy in the intended
managed tier (`organization-rules.d`, `rules.d`, or `ui-rules.d`) when it should
replace matching IDs. Passing an exported copy with `--rules` is additive-only;
use `--no-default-rules` if it is intended to be the complete explicit rule set.
Do not edit bundled defaults in place.

### Operational settings

`settings.d` files hold the operational choices that otherwise need `TELLTALE_*`
variables or flags, so one deployed file gives every workstation, VM, and
container the same behavior. Every key is optional; the values shown are the
defaults:

```yaml
version: 1
rules:
  community: true                    # TELLTALE_COMMUNITY_RULES, --no-community-rules
detections:
  process_chain: true                # TELLTALE_PROCESS_CHAIN_DETECTIONS
risk_thresholds:                     # TELLTALE_RISK_THRESHOLD_LOW, _MEDIUM, _HIGH, _CRITICAL
  low: 20
  medium: 50
  high: 70
  critical: 90
operational_alerts:
  max_scanner_errors: 3              # TELLTALE_OP_ALERT_MAX_SCANNER_ERRORS
  max_scan_duration_ms: 300000       # TELLTALE_OP_ALERT_MAX_SCAN_DURATION_MS
log_rotation:
  max_size_bytes: 104857600          # TELLTALE_LOG_ROTATE_MAX_SIZE, --log-rotate-max-size; 0 disables
  keep: 5                            # TELLTALE_LOG_ROTATE_KEEP, --log-rotate-keep
install_inventory:
  enabled: true                      # --install-inventory-disabled
  interval_seconds: 86400            # TELLTALE_INSTALL_INVENTORY_INTERVAL_SECONDS, --install-inventory-interval-seconds
events:
  emit_activity: false               # --emit-activity
  emit_session_risk_summary: false   # --emit-session-risk-summary
  baseline_deviation_scoring: false  # --baseline-deviation-scoring; needs emit_activity
watch:
  debounce_ms: 500                   # watch --debounce-ms
  min_scan_interval_ms: 10000        # watch --min-scan-interval-ms
```

Precedence, lowest to highest: defaults, settings files (roots in order, files
sorted within a root, so a later file wins per key), environment variables, then
explicit flags. The `events` flags can only turn their setting on. A
vendor-managed `10-vendor.yaml` and a local `90-local.yaml` can share one
directory. Unknown keys, an unsupported `version`, files over 64 KiB,
and environment values that do not parse fail the command before it scans or
writes anything; an empty variable counts as unset. Integer variables are
unsigned decimal numbers with no surrounding whitespace, so a padded value such
as `" 5 "` fails; a leading `+` is accepted, as in YAML. Booleans ignore
surrounding whitespace and accept `0`/`1`, `false`/`true`, `off`/`on`, and
`no`/`yes` in any case. Unrecognized variable names, including misspelled
`TELLTALE_*` names, are ignored, so confirm a value's origin with
`telltale config show`. `--no-local-config` skips every settings file but still
applies `TELLTALE_*` variables and flags.

Risk thresholds must not decrease: `low <= medium <= high <= critical`. Equal
values are allowed and leave a band empty. Telltale checks the merged values
after files, variables and flags apply, because each source can be valid on
its own and still invert the result: for example, `TELLTALE_RISK_THRESHOLD_HIGH=10`
with the default `medium: 50`. An inverted set fails every command that reads
settings before it writes anything. The error names the first inverted pair
with each value's origin.

Path variables, such as `TELLTALE_LOG_PATH`, `TELLTALE_STATE_PATH`,
`TELLTALE_PROJECT_CONFIG`, `CODEX_HOME` and `OPENCODE_DB`, are used literally.
`~` is never expanded, so let your shell or service manager expand it. Only
`path:` entries inside a project config file expand a leading `~/`.
Session-store variables apply only to the default `--root .`; see
[session sources](session-sources.md#host-root-rules).

`telltale config show` prints each setting's effective value, default, origin
(`default`, `settings_file`, `environment`, or `cli`), and `source` without
reading session stores. `source` is the winning file's path hash, the variable,
or the flag, and `files` lists each file read with its path hash. Each scan
records the same view under `effective_configuration.settings`. Settings are
read when a command starts, so restart `watch` or a service to apply a change;
`export --correlate` reads the default roots. Log/state paths and project roots
keep the precedence described above. Telltale libraries do not read these
variables; an embedding host passes values through the [Rust API](embedding.md).

`settings.d` is trusted like `rules.d` and `allowlists.d` in the same root:
anything that can write the user config root, including a coding agent running
as that user, can change these settings. A managed deployment that must not
honor user files runs with `--config-dir /etc/telltale` (root-owned) and sets
variables and flags in its service unit. Scan summaries record each setting's
origin and source, so a SIEM can alert when a value comes from an unexpected
file or variable.

## Project-Local Session Stores

Copilot process logs are discovered inside project directories rather than
under `$HOME`. By default, Telltale scans `~/github` and `~/projects` if they
exist. To customize, declare project roots in a YAML config file:

```yaml
projects:
  - name: my-project
    path: ~/github/my-project
```

Pass the config to scans or watch mode:

```sh
cargo run --bin telltale -- scan --once --root "$HOME" --project-config projects.yaml
```

You can also set `TELLTALE_PROJECT_CONFIG` to a platform-native path list
instead of repeating the flag. On Windows that is not a colon-separated string.
When neither is provided, Telltale uses the
default paths (`~/github` and `~/projects`).

## Optional Watch Mode

Use `telltale watch` when you want repeated scans after local session-store changes.
The watch command accepts the same repeated `--client <id>` filters as
`telltale scan`, which keeps filesystem watches and triggered scans scoped to the
selected supported clients:

```sh
cargo run --bin telltale -- watch --client codex --client opencode --root "$HOME"
```

Watch starts idle: by default it does not scan sessions that already exist, and
it scans a source only after that source changes. Add `--initial-scan` to run
one full scan of every existing session after the filesystem watches are
registered. A write during that scan is still queued and scanned afterward.
`--iterations` counts only change-triggered scans, never the initial scan, and
must be at least 1.
Once later changes will be seen, watch prints one line to stderr that starts
with `telltale watch: ready`. It reports the number of watched roots and
whether the initial scan ran, and it never includes paths. Each scan still
prints its summary on stdout.

Watch reads settings, environment variables and the set of discovered config
files once, when it starts. Restart it to apply an edit to `settings.d`; a new
process picks up the change. Rule and allowlist files that were already
discovered are reread on each scan.

## Check Scanner Status

After a scan writes JSONL telemetry, use `telltale status` to review the latest local
scanner summary:

```sh
cargo run --bin telltale -- status
```

The command keeps its top-level `status` field for the status lookup result. The
latest scanner health check is reported separately as `health_component`,
`health_check_name`, and `health_check_status`, matching the health event fields
that SIEM dashboards can group by as `component`, `check_name`, and `status`.
Neither field is a monitoring verdict. The lookup succeeds whenever native
health exists, and the Event 3.0 health status is always `ok`.

Use `attention_required` and `attention_reasons` instead. Reasons are closed
codes: `scanner_errors` when the latest health event counted scanner errors,
plus one code for each kind of operational alert recorded after it
(`source_parse_outage`, `scanner_error_threshold_exceeded`,
`scan_duration_threshold_exceeded`, `sink_delivery_failure`, or
`operational_alert` for any other type). `attention_required` is `null` when
the journal holds only historical events or is unavailable. It is also `null`
when no alert was recorded and the latest health event's `scanner_error_count`
cannot be read as a number. Any positive count counts as scanner errors,
including counts above the 64-bit range.

These fields describe the scan that wrote the latest health event
(`last_scan_time`). A scan writes a health event only when it sees scanner
errors, raises an alert or detects a source inventory change. After you repair
a source, attention can therefore stay reported until a later health event.
For a current pass or fail result, run
`telltale scan --once --fail-on-source-errors`. The scan first completes as
usual and writes only what it would have written anyway. `--dry-run` writes
nothing, and `--history` writes events but never reads or writes scan state.
It then exits with status 3 if any source failed: a parse error, degraded
discovery such as a missing `--root`, or a failed project config.
Without the flag, exit 0 means only that the scan completed.

## Managed Service Setup (Advanced)

The checked-in systemd templates use the canonical `telltale-scan` unit names
and `TELLTALE_*` environment. Use the explicit state/event commands in the
[migration contract](migration-contract.md) for operator-selected Telltale data.
There is no in-place upgrade path for another product.

The repository and release archives include Linux-oriented systemd examples in
`config/examples/telltale-scan.service` and `config/examples/telltale-scan.timer` for
managed deployments that use the `system` path profile with a dedicated service
account. This is an advanced path for shared scan servers or fleet-managed
hosts where the scanned session stores are explicitly made readable by the scan
account.

The canonical service uses `/usr/local/bin/telltale`,
`/var/log/telltale/telltale-events.jsonl`, and
`/var/lib/telltale/telltale-state.json`.
Create the service account and directories with permissions that let Telltale
append telemetry while granting your shipper read-only access to the log file.
Use `config/examples/telltale-logrotate` as a starter Linux rotation policy so
the active shipper target remains `/var/log/telltale/telltale-events.jsonl`.
The user installer does not create these managed system paths; configure them
only as part of an explicitly managed system deployment.

For the common workstation case, the quick installer above sets up a user-level
timer that runs as your user with no sudo and no service account.

## Optional SIEM Setup

Telltale writes append-only JSONL. Review the generated event schema and your
environment's data-handling requirements before forwarding events to a SIEM or
central log platform. See [telemetry-output.md](telemetry-output.md) for the
vendor-neutral event-output model and forwarding boundary.

Configure file monitors for the active path profile. Workstation installs write
to the `user` profile path by default, such as
`~/.local/state/telltale/logs/telltale-events.jsonl` on Linux. Managed Splunk/Filebeat
deployments should run scans with `--path-profile system` or explicit
`TELLTALE_LOG_PATH`/`TELLTALE_STATE_PATH` values and monitor
`/var/log/telltale/telltale-events.jsonl`. The current project profile uses
`logs/telltale-events.jsonl` unless an explicit path selects otherwise.
