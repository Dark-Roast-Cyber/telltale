# Install

> **Website:** For an approachable install guide, see [AgentArchaeology.ai/telltale/install](https://agentarchaeology.ai/telltale/install/).

Telltale Core can be installed from a tagged GitHub release archive when one
is available, or built from source with Cargo. In both cases, start with a
fixture-safe scan before pointing the scanner at real agent session stores. See
the [Source Validation Matrix](source-validation-matrix.md) for the canonical
source-support claims and their evidence.

## Prerequisites

- Rust toolchain with `cargo` when building from source
- Python 3 for strict release metadata validation by the repository installer
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

The v0.3.0 release archives and CI smoke checks establish binary packaging and
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

The no-argument installer selects the latest stable GitHub Release. For
approved candidate validation, select the exact immutable RC tag:

```sh
./scripts/install-telltale --release-tag v0.5.0-rc.1 --no-timer
./scripts/install-telltale --release-tag v0.5.0-rc.1 --from-source --no-timer
```

The explicit path requires that tag's published non-draft prerelease metadata,
derives every archive and checksum URL from that tag, and verifies the archive
manifest, checksum, and binary version before any installer lock, file,
schedule, or systemd-manager mutation. It does not fall back to
`releases/latest` or permit `--skip-checksum`. RC artifacts are immutable; a
validation-relevant change needs the next reviewed RC. GitHub binary releases
remain separate from the later dependency-ordered crates.io publication.

### Verify a release archive

The release workflow publishes a GitHub artifact attestation for every `.tar.gz`
and `.zip` archive. Release assets use `telltale-v<version>-...` names. Once the
RC candidate or a later stable release is published, verify the downloaded
archive as a separate post-publication step before extracting it. For the
current candidate, the example is:

```sh
gh attestation verify telltale-v0.5.0-rc.1-x86_64-unknown-linux-gnu.tar.gz \
  --repo Dark-Roast-Cyber/telltale
```

Replace the filename with the archive for your platform. The command checks the
archive's digest and its signed GitHub Actions provenance; an online GitHub CLI
environment is required. The Linux installer verifies the published
`SHA256SUMS` checksum, but it does not perform this GitHub attestation check.

### Quick install (Linux)

A repository installer is available for Linux. It downloads the latest release
binary, verifies it against the release's published `SHA256SUMS`, and installs
it to `~/.local/bin/telltale` (no sudo). It does not enable anything beyond the
binary install unless you opt in:

```sh
./scripts/install-telltale
./scripts/install-telltale --with-timer
```

The hosted one-line installer is not part of this repository's release cutover;
use the checked-in script above for a reviewed install. It uses one locked,
journaled transaction, verifies `SHA256SUMS`, stages the canonical binary, runs
explicit state/event/environment migration when legacy inputs exist, and
smoke-tests before activation. `--from-source` first downloads and validates the
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

### Windows Scheduled Task example

The Windows task example is `config/examples/telltale-scan-task.xml`.
Replace both `YOUR_WINDOWS_USERNAME` values with the account that should run the
task, then import it from PowerShell; the canonical runtime executable is
`telltale.exe`:

```powershell
$xml = Get-Content .\config\examples\telltale-scan-task.xml -Raw
Register-ScheduledTask -TaskName TelltaleScan -Xml $xml
```

This phase does not provide a Windows `install.ps1` installer; native task
migration remains a separate release gate.

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
default. Retired ADR path variables fail closed before command parsing.

## Local Rule, Policy, And Allowlist Config

Telltale loads bundled detection rules by default. Operators can add local YAML
without repeating every path by creating a local config root. Existing default
roots are checked in deterministic order:

- `/etc/telltale`
- `$XDG_CONFIG_HOME/telltale`, or `$HOME/.config/telltale` when
  `XDG_CONFIG_HOME` is not set

Supported directories for this phase are:

```text
/etc/telltale/
  organization-rules.d/*.yaml|*.yml
  rules.d/*.yaml|*.yml
  ui-rules.d/*.yaml|*.yml
  overrides.d/*.yaml|*.yml
  policies.d/*.yaml|*.yml
  allowlists.d/*.yaml|*.yml
```

Rule packs resolve in fixed tier order: bundled defaults, `organization-rules.d`,
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
mechanism.

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

## Project-Local Session Stores

Some clients store session data inside project directories rather than under
`$HOME`. By default, Telltale scans `~/github` and `~/projects` if they exist.
Copilot, OpenCode-in-project, and Codex per-project CLI logs are discovered
from these default paths. To customize, declare project roots in a YAML config
file:

```yaml
projects:
  - name: my-project
    path: ~/github/my-project
```

Pass the config to scans or watch mode:

```sh
cargo run --bin telltale -- scan --once --root "$HOME" --project-config projects.yaml
```

You can also set the colon-separated `TELLTALE_PROJECT_CONFIG` environment variable
instead of repeating the flag. When neither is provided, Telltale uses the
default paths (`~/github` and `~/projects`).

## Optional Watch Mode

Use `telltale watch` when you want repeated scans after local session-store changes.
The watch command accepts the same repeated `--client <id>` filters as
`telltale scan`, which keeps filesystem watches and triggered scans scoped to the
selected supported clients:

```sh
cargo run --bin telltale -- watch --client codex --client opencode --root "$HOME"
```

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

## Managed Service Setup (Advanced)

The checked-in systemd templates use the canonical `telltale-scan` unit names
and `TELLTALE_*` environment. Use the explicit migration commands in the
[migration contract](migration-contract.md) for historical environment files;
do not alias retired runtime names.

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
`/var/log/telltale/telltale-events.jsonl`. Do not monitor the legacy repo-local
ADR-named path; the current project profile uses
`logs/telltale-events.jsonl` unless an explicit path selects otherwise.
