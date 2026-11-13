# Telltale Hooks

Pre-execution monitoring and enforcement for AI agent harnesses, built on
Telltale detection and shipped in the Telltale executable as `telltale hooks`.
It is experimental. The scanner (`telltale scan`, `telltale watch`) is
detection-only and unchanged; hooks are a separate, opt-in integration.

A harness hook hands every requested tool call to `telltale hooks`, which
evaluates it with Telltale (together with the session's earlier calls, so
multi-step behavior such as download-then-execute or harvest-then-exfiltrate
is correlated), applies host policy, and answers **no opinion**, **ask**, or
**deny**. Post-execution events settle what actually happened, and every
step is written as JSONL telemetry that forwards Telltale's own
`ActionRecordV1` records.

## Where it lives

- Library: `telltale_core::hooks` (`crates/telltale/src/hooks/`), behind the
  `hooks` Cargo feature of `telltale-core`. The feature is on by default;
  embedders that only read sessions opt out with `default-features = false`.
- CLI: `telltale hooks ...`, behind the `hooks` feature of `telltale-cli`
  (on by default; `cargo build --no-default-features` drops it).
- Configuration and state keep the `telltale-hooks` directory names and the
  `TELLTALE_HOOKS_*` environment variables, so existing setups keep working.
- The runtime reaches Telltale only through the same public facade an external
  embedder has, so it needs no private access to the detection crates.

## Build identity

Hooks run inside the Telltale executable, so the identity of a build is the
identity of that executable. Evaluator compatibility (a hook may use a running
evaluator only if both come from the same build) is a fingerprint over the
package version, the Git hash the CLI registers, the effective configuration
and rule files, and the file identity of the running executable, so a rebuilt
or replaced binary never shares an evaluator with the old one. The telemetry
field `producer.telltale_rev` is a 40-hex digest of the package version and
that Git hash: it names the Telltale release and commit that wrote a record and
is stable across reinstalls. It is not a Git object name. `telltale hooks
version` prints the inputs and the digest.

## Status

| | |
| --- | --- |
| Harnesses | Claude Code (2.1.318), GitHub Copilot CLI (1.0.105), OpenAI Codex CLI (0.166.0; fails open by design, see below) |
| Codex evidence | **Linux only, scripted model; real-model run pending.** Deny (main agent, subagent, `apply_patch`, autostarted evaluator) and ask-as-deny, on the real Codex binary. Also under the documented install: trusted through the real TUI, `codex exec` with no bypass flag. Hook failures fail open: [results](e2e/2026-11-04-codex-cli-0.166.0.md) |
| Real enforcement verified | Claude Code: deny (default and `bypassPermissions` modes, subagents), ask (headless declines), self-protection, download-then-execute chain, fail-open/fail-closed behavior: [results](e2e/2026-11-04-claude-code-2.1.318.md). Copilot CLI (scripted model): deny (default, `--yolo`, autopilot, PascalCase, subagents), ask (prompts interactively, refused in `-p`), fail-closed: [results](e2e/2026-11-04-copilot-cli-1.0.105.md) |
| Latency | PreToolUse p50 16-18 ms with the autostarted long-lived evaluator; ~690 ms in-process fallback ([ADR 0003](adr/0003-process-model.md)) |

The reports in [`e2e/`](e2e/) are historical: they were run against the
standalone `telltale-hooks` binary before the move into Telltale, and no real
harness has been run against `telltale hooks` yet.

## Quick start (Claude Code)

```bash
cargo build --release
```

```bash
./target/release/telltale hooks check
```

Print a settings fragment and merge its `hooks` object into
`~/.claude/settings.json` (user), `.claude/settings.json` (project), or, for
deployments the agent must not be able to change, managed settings with
`allowManagedHooksOnly`. The generated command is `telltale hooks claude-code
hook`; pass an absolute command when `telltale` is not on the harness's `PATH`:

```bash
./target/release/telltale hooks claude-code settings --fail-closed "$PWD/target/release/telltale hooks claude-code hook"
```

`--fail-closed` makes Claude Code block a tool call if the hook crashes,
times out, or is missing. Without it Claude Code fails open. Details:
[harnesses/claude-code.md](harnesses/claude-code.md).

## Quick start (GitHub Copilot CLI)

Print the hook file and install it once, as a root-owned policy file
(`/etc/github-copilot/policy.d/telltale-hooks.json`, which `disableAllHooks`
cannot turn off) or as `~/.copilot/hooks/telltale-hooks.json`:

```bash
./target/release/telltale hooks copilot-cli settings "$PWD/target/release/telltale hooks copilot-cli hook" > telltale-hooks.json
```

On Windows the command runs under PowerShell: quote a path with spaces as
`& "C:\...\telltale.exe" hooks copilot-cli hook`, or every call is blocked.
Copilot blocks a tool call when the hook crashes, exits non-zero or is
missing, but lets it run when the hook times out (the file sets 60 s). A
repository's `.claude/settings.json` Claude Code installation also runs under
Copilot and is handled as Copilot input. Details:
[harnesses/copilot-cli.md](harnesses/copilot-cli.md).

## Quick start (Codex CLI)

```bash
./target/release/telltale hooks codex-cli settings "$PWD/target/release/telltale hooks codex-cli hook" > "${CODEX_HOME:-$HOME/.codex}/hooks.json"
```

Then start `codex` once interactively and choose "Trust all and continue":
Codex never runs an untrusted user hook. Trust is per handler: changing a
handler un-trusts it and the call then runs unchecked, while reformatting the
file does not, and replacing the binary at a trusted path keeps trust. Codex
cannot ask from a hook, so every `ask` is returned as a deny. Codex fails open
on every hook failure and has no fail-closed option (`settings --fail-closed`
refuses). All of this was verified on Linux with a scripted model only.
Optional native backstop against plain relaunches of Codex without hooks (the
agent can delete it while the hook is healthy):

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/rules"
./target/release/telltale hooks codex-cli execpolicy > "${CODEX_HOME:-$HOME/.codex}/rules/telltale-hooks.rules"
```

Details and limits: [harnesses/codex-cli.md](harnesses/codex-cli.md).

## Configuration

Optional TOML at `$TELLTALE_HOOKS_CONFIG`, else at the platform default when
present: `$XDG_CONFIG_HOME/telltale-hooks/config.toml` or
`~/.config/telltale-hooks/config.toml` on Linux and macOS,
`%APPDATA%\telltale-hooks\config.toml` on Windows:

```toml
mode = "enforce"      # or "observe": record verdicts, never return them
on_error = "allow"        # hook infrastructure failure: "allow" (fail open), "ask", "deny"
on_unevaluable = "ask"    # tool call too large, nested or damaged to evaluate: "ask", "deny", "allow"
reason_detail = "full"    # "full": reasons name rules and thresholds; "minimal": verdict and record ID only
                          # (a human approving an `ask` then sees little; use "minimal" for unattended agents)

[thresholds]          # Telltale promotion scores (host policy)
action_ask = 50
action_deny = 90
session_ask = 150     # cumulative session score
session_deny = 300
repeated_denials = 3  # then any scored call is denied

[telltale]
community_rules = true
process_chain = true
rules = []            # extra Rule v1 documents (additive)
rule_packages = []
# policy = "/etc/telltale-hooks/policy.yaml"
self_protection_rules = true

[evaluator]           # long-lived evaluator (telltale hooks serve)
enabled = true
autostart = true      # first hook starts it detached; hooks fall back in-process
idle_timeout_secs = 1800
request_timeout_ms = 10000
# socket = "/run/user/1000/telltale-hooks.sock"  # default: <state dir>/evaluator.sock
```

`TELLTALE_HOOKS_EVALUATOR=0` disables the evaluator for one process. The
evaluator runs on Linux and macOS; on Windows hooks always evaluate
in-process (correct, slower).

State and telemetry default to `$XDG_STATE_HOME/telltale-hooks/` or
`~/.local/state/telltale-hooks/` on Linux and macOS, and to
`%LOCALAPPDATA%\telltale-hooks\` on Windows (`TELLTALE_HOOKS_STATE_DIR`,
`TELLTALE_HOOKS_TELEMETRY`). Telemetry schema:
[schemas/telltale-hooks-record-v1.schema.json](../../schemas/telltale-hooks-record-v1.schema.json).

## Documentation

- [Architecture](architecture.md) and [decisions](adr/)
- [Hooks threat model](../security/hooks-threat-model.md)
- [Harness capability matrix](capability-matrix.md)
- [Real-harness tests](harness-testing.md)

## Development

```bash
cargo test -p telltale-core --test hooks
```

```bash
cargo test -p telltale-cli --test cli hooks_
```

Real harness tests cost model tokens and are run deliberately. Their scripts
are `scripts/hooks/harness/*`; build `target/release/telltale` first:

```bash
scripts/hooks/harness/claude-code-e2e.sh benign deny ask
```

The Copilot CLI tests use a scripted model and cost nothing:

```bash
COPILOT_BIN=/path/to/copilot scripts/hooks/harness/copilot-cli-e2e.py
```
