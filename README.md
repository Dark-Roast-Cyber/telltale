# Telltale

<p align="center">
  <img src="telltail.png" alt="Telltale logo" width="240" />
</p>

<p align="center">
  <a href="https://agentarchaeology.ai/">
    <img src="https://img.shields.io/badge/AgentArchaeology.ai-Visit_Site-0066cc?style=flat-square" alt="AgentArchaeology.ai" />
  </a>
  <a href="https://darkroastcyber.io/">
    <img src="https://img.shields.io/badge/Dark_Roast_Cyber-Visit_Site-8b4513?style=flat-square" alt="Dark Roast Cyber" />
  </a>
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/Supported_Agents-9-green?style=flat-square" alt="Supported Agents" />
  <img src="https://img.shields.io/badge/Detection_Categories-10-orange?style=flat-square" alt="Detection Categories" />
</p>

Telltale is an open-source detection layer for AI coding agents, built as the foundation for Agent Detection and Response (ADR). It detects telltale signs of risky behavior, preserves redacted evidence, and exports telemetry for review, alerting, and future response workflows.

> **Executable and compatibility contract:** Use `telltale` (`telltale.exe`) and
> `telltale-*` release assets for new integrations. `adr` (`adr.exe`) is the
> compiled deprecated compatibility command and remains part of the current
> release contract. Each `adr-*` release archive is an exact byte-for-byte copy
> of its matching `telltale-*` archive, and both archives contain both binaries.
> This migration does not schedule removal of the compatibility command.
>
> The executable rename does not rename compatibility data or configuration:
> preserve `ADR_*`, `adr-events.jsonl`, `adr-state.json`,
> `/etc/telltale/adr.env`, `adr_version`, `adr-` event IDs, and the Splunk
> `index=adr`, `sourcetype=adr:json`, and existing `telltale:adr` /
> `telltale:adr-events` source identities. Keep uppercase ADR category
> terminology and unrelated architecture decision records and fixtures
> unchanged.

## Why Telltale exists

Agentic coding is not just “the user typed a prompt and the model answered.” By the time an agent decides to run a command, its input tokens may include:

- user prompts and chat history;
- system, developer, and assistant instructions;
- tool schemas, MCP descriptions, and tool results;
- skills, subagents, plugins, and IDE extension context;
- RAG snippets, documentation, search results, and web pages;
- repository files, diagnostics, terminal output, and build logs;
- router or aggregator metadata from services such as model gateways and coding assistants;
- prior session state, retries, summaries, and the assorted incantations and ceremonies required to keep a long-running agent workflow on the rails.

Some of that is intentional. Some of it is scaffolding. Some of it is simply the reality of how modern agentic systems are built.

That creates a real visibility problem for defenders. SOCs and security teams often do not have a good handle on what agentic coders actually did. A compromised router, poisoned skill, prompt-injected web page, malicious tool response, risky extension, or unexpected model behavior can turn into file reads, shell commands, network calls, credential access, or entire sessions that drift away from user intent. When that happens, the evidence is often scattered across local transcripts, tool logs, and application-specific session stores.

Organizations may define policies for what agents should never do, but those policies are not easy to monitor consistently across many platforms, session formats, and tool surfaces. It is difficult to write detections that scale cleanly from obvious policy violations to broader risky behavior and undesired sessions. Telltale takes a risk-analysis approach: scan local session stores, normalize messages and tool activity, apply detections, score behavior across a session, redact sensitive evidence, and emit structured JSONL telemetry that a SOC can inspect, search, forward, and alert on.

Set it up around your agent session stores and point the output at your alerting pipeline. Telltale is detection-first today: it gives builders and SOCs concrete, redacted telemetry to inspect during or after long-running agent tasks, and it exports that telemetry for downstream response workflows.

## What it does

- Discovers supported agent session stores on disk.
- Parses heterogeneous transcript formats into a shared event model.
- Detects suspicious tool activity with YAML-defined rules.
- Scores related behavior across a session window.
- Redacts sensitive evidence before writing events.
- Supports synthetic fixture-based testing across multiple client formats.

## Source support status

The [Source Validation Matrix](docs/source-validation-matrix.md) is canonical
for public source-support claims. Current client-level status is:

- **Fixture-backed plus bounded live validation**: Codex, OpenCode, Claude Code,
  and GitHub Copilot.
- **Fixture-backed only**: Gemini CLI, OpenClaw, Qwen CLI, RooCode, and KiloCode.

These labels describe parser and source-store validation, not broad live coverage.
Release archives and CI smoke checks cover binary packaging and execution on
Linux, macOS, and Windows; they do not establish broad live source-store
validation. Fixture-backed-only clients remain preview/experimental for live use.

## Quick start

```sh
cargo run --bin telltale -- scan --once --dry-run --no-local-config --root tests/fixtures/session_stores
cargo test
```

The fixture tree in `tests/fixtures/` is synthetic and safe for local verification.
Use `--dry-run` for fixture checks. Reserve `--allow-fixtures` for intentional
synthetic writes in CI or local development, not normal scans. See
[Install](docs/install.md) for the full fixture-safe verification sequence and
real-session-store setup.

## Cargo packages

Cargo publication is in current release preparation; these packages should not
be treated as already published. The six official packages are:

- `telltale-schema`
- `telltale-rules`
- `telltale-sources`
- `telltale-detect`
- `telltale-core` — the supported embedding surface (`telltale_core` in Rust)
- `telltale-cli`

See [Versioning and releases](docs/versioning.md) for the dependency-ordered
publication sequence and `0.x` compatibility policy.

Install the CLI from crates.io after publication with:

```sh
cargo install telltale-cli
```

That package installs both the canonical `telltale` binary and the `adr`
compatibility binary.

> **Crates.io name warning:** The package named `telltale` is an unrelated
> active session-types crate, not this project. Telltale uses `telltale-core`
> for its embedding facade. Recheck crates.io availability immediately before
> any future publication.

When you are ready to scan real session stores, point `telltale scan --root` at the
directory that contains your actual supported session-store roots, such as `$HOME`
on a typical single-user workstation, instead of `tests/fixtures/`.

For continuous local monitoring, `telltale watch` accepts the same repeated
`--client <id>` filters as `telltale scan`, so watched runs can stay scoped to one
or more supported client IDs such as `codex` or `opencode`.

### Local rule configuration

Telltale discovers local YAML config files under `/etc/telltale` and
`$XDG_CONFIG_HOME/telltale` (or `$HOME/.config/telltale`) without requiring
every path on the command line. Managed rule packs resolve in fixed tier order
(bundled defaults → `organization-rules.d` → `rules.d` → `ui-rules.d`); a
higher tier fully replaces a same-ID definition in place, while unique IDs are
additive. `overrides.d` tunes rules without editing source YAML, and
`policies.d`/`allowlists.d` provide policy and suppression config.

Use `--config-dir <path>` for explicit config roots, or `--no-local-config` to
disable discovery. Run `telltale config validate` as the local config preflight
before scans with custom content, and `telltale rules export-default` to inspect
or fork the bundled default rules.

See [Install](docs/install.md) for the full directory layout, rule-pack
precedence, trust-boundary guidance, override YAML format, and flag behavior.

### Project-local session stores

Some clients (Copilot, OpenCode-in-project, Codex per-project) store data inside
project directories. By default, Telltale scans `~/github` and `~/projects` if
they exist. To customize, declare project roots in a YAML file and pass it with
`--project-config` (or set `ADR_PROJECT_CONFIG`). Project-local discovery is
additive — home-relative sources are still discovered from `--root`.

See [Install](docs/install.md) for the YAML format and `--project-config` usage.

- Install and setup guide: [docs/install.md](docs/install.md)

Tagged GitHub releases publish platform-specific `telltale-*` binary archives
when available, with matching exact-copy `adr-*` compatibility aliases. Source
builds remain supported; the install guide covers both paths and the
fixture-safe verification step.

### Linux

The v0.2.0 release records establish a synchronized hosted copy of the
repository installer. It downloads the latest release, verifies its published
`SHA256SUMS`, and installs both binaries to `~/.local/bin` without sudo. Use it
with:

```sh
curl -fsSL https://agentarchaeology.ai/telltale_install.sh | bash
```

The repository installer provides the same behavior from this checkout and
installs a user-level systemd timer only when `--with-timer` is provided.

```sh
./scripts/install-telltale
./scripts/install-telltale --with-timer
```

Add `--from-source` to build with cargo instead of downloading a prebuilt
binary. `--no-timer` is accepted only for legacy compatibility and is normally
unnecessary. The installer does not create system accounts or configure SIEM
shippers.

### macOS

Download the release archive for your architecture and extract the binary:

```sh
# Apple Silicon (aarch64)
curl -fsSLO https://github.com/Dark-Roast-Cyber/telltale/releases/latest/download/telltale-$(curl -fsSL https://api.github.com/repos/Dark-Roast-Cyber/telltale/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"//;s/"$//')-aarch64-apple-darwin.tar.gz
tar xzf telltale-*-aarch64-apple-darwin.tar.gz
sudo mv telltale /usr/local/bin/telltale
sudo mv adr /usr/local/bin/adr
```

Or build from source:

```sh
git clone https://github.com/Dark-Roast-Cyber/telltale.git
cd telltale
cargo build --release
sudo cp target/release/telltale /usr/local/bin/telltale
sudo cp target/release/adr /usr/local/bin/adr
```

The default `user` path profile writes telemetry to
`~/Library/Logs/Telltale/adr-events.jsonl` and state to
`~/Library/Application Support/Telltale/adr-state.json`. No sudo is needed
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

Download the canonical release archive and extract `telltale.exe` and `adr.exe`:

```powershell
# PowerShell
$release = Invoke-RestMethod "https://api.github.com/repos/Dark-Roast-Cyber/telltale/releases/latest"
$tag = $release.tag_name
$asset = $release.assets | Where-Object { $_.name -eq "telltale-$tag-x86_64-pc-windows-msvc.zip" }
Invoke-WebRequest $asset.browser_download_url -OutFile "telltale-$tag.zip"
Expand-Archive "telltale-$tag.zip" -DestinationPath "$env:LOCALAPPDATA\Telltale"
```

Or build from source:

```powershell
git clone https://github.com/Dark-Roast-Cyber/telltale.git
cd telltale
cargo build --release
Copy-Item target\release\telltale.exe $env:LOCALAPPDATA\Telltale\telltale.exe
Copy-Item target\release\adr.exe $env:LOCALAPPDATA\Telltale\adr.exe
```

Add `$env:LOCALAPPDATA\Telltale` to your `PATH` to run `telltale` from any
terminal. The default `user` path profile writes telemetry to
`%LOCALAPPDATA%\Telltale\Logs\adr-events.jsonl` and state to
`%LOCALAPPDATA%\Telltale\State\adr-state.json`. No elevation is needed for
scans — run as your user.

For periodic scans, create a Scheduled Task at user logon:

```powershell
$action = New-ScheduledTaskAction -Execute "$env:LOCALAPPDATA\Telltale\telltale.exe" -Argument "scan --once --emit-activity --root $env:USERPROFILE"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RepeatInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 365)
Register-ScheduledTask -TaskName "TelltaleScan" -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited
```

Before pushing public history, run `make public-push-review` to review the
current branch, public remote URLs, working-tree status, and staged path list.
Before tagging a public release, run `make release-preflight` from a clean
working tree. The target runs formatting, linting, tests, fixture-safe scanning,
rule validation, and the branch/remote/staged-content checks covered by the
release readiness checklist.

## Telemetry Output

Telltale is designed to produce structured telemetry that can be searched,
charted, and alerted on in a SIEM. Write append-only JSONL locally, then
connect the output to your preferred shipper or log pipeline after reviewing
your environment's data-handling requirements. See
[Telemetry output](docs/telemetry-output.md) for the public event-output and
forwarding model.

Common use cases include:

- tracking agent activity volume across hosts, clients, and sessions;
- highlighting high and critical detections for analyst review;
- breaking down detection categories and evidence rule IDs for triage;
- emitting optional per-session risk summaries for dashboards that need one
  compact row per agent session;
- spotting spikes, outliers, and session drift over time;
- feeding dashboards, alerts, and investigations in Splunk or another SIEM.

## Early development and community

Telltale is still in early development. The project is usable, but source coverage, detections, and operational ergonomics are still evolving.

PRs, issues, feedback, and active engagement are very welcome. We would especially love testers who can help identify missing features, blind spots, or parsing gaps across different coding-agent platforms and handlers.

## Project layout

- `src/` — scanner, parser, detection, scoring, and event emission code
- `tests/` — CLI coverage plus synthetic fixtures
- `schemas/` — JSON schema for emitted events
- `config/rules/tool-call-regex.yaml` — bundled detection rules
- `config/allowlists.yaml` — suppression examples
- `docs/` — public technical documentation

## Related resources

For approachable guides on agentic forensics, Telltale, and the broader Agent Archaeology practice, see [AgentArchaeology.ai](https://agentarchaeology.ai/).

### Upstream technical docs

These files are the source-of-truth for Telltale's implementation, rules, and schemas:

- [Install](docs/install.md) — build, verify, and deploy
- [Architecture](docs/architecture.md) — pipeline stages and module boundaries
- [Detection model](docs/detection-model.md) — risk scoring, rule categories, thresholds
- [Telemetry output](docs/telemetry-output.md) — JSONL event schema and forwarding
- [Detection content standard](docs/detection-content-standard.md) — quality bar for bundled rules
- [Threat taxonomy](docs/threat-taxonomy.md) — operational threat categories
- [Privacy model](docs/privacy-model.md) — redaction policy and evidence boundaries
- [Release readiness](docs/release-readiness.md) — preflight checklist for public releases
- [Versioning and releases](docs/versioning.md) — package, CLI, schema, and tag version policy

### Additional references

- [Session sources](docs/session-sources.md) — discovery paths and parser notes per client
- [Agent capability profiles](docs/agent-capability-profiles.md) — per-client field availability
- [Client capability matrix](docs/client-capability-matrix.md) — normalization-level field matrix
- [MCP tool inventory](docs/mcp-tool-inventory.md) — MCP configuration inventory emission
- [Policy modes](docs/policy-modes.md) — observe, alert, simulate-block modes
- [Policy authoring](docs/agent-policy-authoring.md) — turning human policy into detection content
- [Adding an agent source](docs/adding-agent-source.md) — contributor checklist for new agent/session-source support
- [Source adapter refactor plan](docs/source-adapter-refactor-plan.md) — planned move toward per-agent source modules
- [Use cases](docs/use-cases.md) — concrete detection use cases with fixture guidance
- [Normalization schema](docs/normalization-schema.md) — canonical `NormalizedRecordV1` schema
- [Source validation matrix](docs/source-validation-matrix.md) — coverage and validation gates
- [Requirements](docs/requirements.md) — functional, security, and operational requirements
- [Trust boundaries](docs/trust-boundaries.md) — trust model for untrusted agent content
- [License and packaging](docs/license-and-packaging.md) — Apache-2.0 core and separate-license boundary

Use the release readiness checklist before tagging or publishing release
artifacts; it includes the public repository boundary review for staged or
tagged content.

## License

Telltale Core is licensed under Apache-2.0. See [LICENSE](LICENSE) and
[License and packaging](docs/license-and-packaging.md) for the open-source core
boundary and the boundary for future separately licensed features.
