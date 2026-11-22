# Telltale Hooks

Pre-execution monitoring and enforcement for AI agent harnesses, built on
Telltale detection and shipped in the Telltale executable as `telltale hooks`.
It is experimental. The scanner (`telltale scan`, `telltale watch`) is
detection-only and unchanged; hooks are a separate, opt-in integration.

A harness hook hands every requested tool call to `telltale hooks`, which
evaluates it with Telltale (together with the session's earlier calls, so
multi-step behavior such as download-then-execute or harvest-then-exfiltrate
is correlated) and applies host policy. Post-execution events settle what
actually happened, and every step is written as JSONL telemetry that forwards
Telltale's own `ActionRecordV1` records.

**Hooks are detect-only unless you switch enforcement on.** By default a hook
records the verdict it reached (**no opinion**, **ask** or **deny**) and
gives the harness nothing. With `hooks.mode: enforce` in the configuration it
returns ask and deny verdicts to the harness. See
[Detect-only and enforce](#detect-only-and-enforce).

## Where it lives

- Library: `telltale_core::hooks` (`crates/telltale/src/hooks/`), behind the
  `hooks` Cargo feature of `telltale-core`. The feature is on by default;
  embedders that only read sessions opt out with `default-features = false`.
- CLI: `telltale hooks ...`, behind the `hooks` feature of `telltale-cli`
  (on by default; `cargo build --no-default-features` drops it).
- Configuration is the `hooks:` section of Telltale's `settings.d` YAML, read
  from the same config roots as `telltale scan`; hooks evaluate the same
  `rules.d`, `policies.d` and `overrides.d` content. State lives under
  `<state home>/telltale/hooks`.
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
| Harnesses | Claude Code (2.1.318), GitHub Copilot CLI (1.0.105), OpenAI Codex CLI (0.166.0; fails open by design, see below). OpenCode v2 (2.2.5) is a request-only pilot with a manual plugin install: [contract](harnesses/opencode.md) |
| Codex evidence | **Linux only, scripted model; real-model run pending.** Deny (main agent, subagent, `apply_patch`, autostarted evaluator) and ask-as-deny, on the real Codex binary. Also under the documented install: trusted through the real TUI, `codex exec` with no bypass flag. Hook failures fail open: [results](e2e/2026-11-04-codex-cli-0.166.0.md) |
| Real enforcement verified | Claude Code: deny (default and `bypassPermissions` modes, subagents), ask (headless declines), self-protection, download-then-execute chain, fail-open/fail-closed behavior: [results](e2e/2026-11-04-claude-code-2.1.318.md). Copilot CLI (scripted model): deny (default, `--yolo`, autopilot, PascalCase, subagents), ask (prompts interactively, refused in `-p`), fail-closed: [results](e2e/2026-11-04-copilot-cli-1.0.105.md) |
| Latency | PreToolUse p50 19 ms in a short window and 44 to about 190 ms in a full one, depending on what it holds, with the autostarted long-lived evaluator; ~690 ms in-process fallback ([ADR 0003](adr/0003-process-model.md)) |

The November 4 reports in [`e2e/`](e2e/) are historical: they used the
standalone `telltale-hooks` binary. The
[integrated qualification](e2e/2026-11-17-integrated-pilot.md) records new
scripted-model controls/denials for the integrated executable. The
[OpenCode v2 pilot](harnesses/opencode.md#install-the-pilot) has a separate,
manual plugin install and deliberately leaves outcomes unknown.

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
./target/release/telltale hooks claude-code settings "$PWD/target/release/telltale hooks claude-code hook"
```

The hook is detect-only until the configuration says `hooks.mode: enforce`
([Detect-only and enforce](#detect-only-and-enforce)), and with these settings
Claude Code runs a tool call when the hook fails. `settings --fail-closed`
makes it block instead; that is [tamper prevention](#tamper-prevention), and
an operator's choice. Details:
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
missing, but lets it run when the hook times out (the file sets 60 s). That is
Copilot's own behavior for every hook, in detect-only mode too: keep the
binary at the path the hook file names. A
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
Codex can also refuse plain relaunches of itself without hooks through native
exec-policy rules. They act without the hook, in detect-only mode too, so
they are [tamper prevention](#tamper-prevention) and not part of a default
install (an enforcing hook denies removing them, for as long as it runs):

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/rules"
./target/release/telltale hooks codex-cli execpolicy > "${CODEX_HOME:-$HOME/.codex}/rules/telltale-hooks.rules"
```

Details and limits: [harnesses/codex-cli.md](harnesses/codex-cli.md).

## Detect-only and enforce

One setting decides whether a hook can influence the harness, `hooks.mode` in a
Telltale `settings.d` file:

```yaml
version: 1
hooks:
  mode: observe    # default, also spelled detect: record verdicts, never return them
  # mode: enforce  # return ask and deny verdicts to the harness
```

Changing it needs no rebuild and no change to the harness settings; the next
hook invocation reads it. `telltale hooks check` prints the mode in effect.

**In detect-only mode a hook cannot block a tool call.** A harness hook can
stop a call in three ways, and one gate (`telltale_core::hooks::gate`) closes
all of them before anything else runs:

| Channel | Detect-only |
| --- | --- |
| A decision on stdout | Nothing is written to stdout, whatever was evaluated |
| A non-zero exit status (a block on Copilot CLI; exit 2 on Claude Code) | The exit status is 0 |
| Not returning in time, where the harness blocks on a failed hook (`settings --fail-closed`) | The hook gives up and exits 0 after 20 s |

This holds on every path, not only for rule verdicts: an unreadable or
oversized payload, a failure policy of `deny` (`on_error`, `on_unevaluable`),
a session lock that stays taken, and a panic all end the same way. What the
hook would have returned is in telemetry (`decision.returned: false`), and so
is what it could not read (`error` records).

The gate opens only for a configuration that **was read and says
`hooks.mode: enforce`**. Everything else is detect-only:

| Configuration | Hook |
| --- | --- |
| None | Detect-only |
| Loaded, `hooks.mode` unset, `observe` or `detect` | Detect-only |
| Loaded, `hooks.mode: enforce` | Enforcing |
| Does not load (an unknown key or invalid value in any section, a file that is not YAML, an inverted threshold), and a `settings.d` file says `hooks.mode: enforce` | Enforcing, and tool calls are denied until it is fixed (an operator error should be loud); `config_invalid` in telemetry and on stderr |
| Does not load, and no `settings.d` file says `hooks.mode: enforce`; or a `--config-dir` folder is missing | Detect-only on the defaults; `config_invalid` in telemetry and on stderr |

When the configuration does not load, the hook still reads each `settings.d`
file on its own. A file that is YAML counts when it sets `hooks.mode:
enforce`; a file that is not counts when any line holds a `mode: enforce`
pair, in any quoting or style. One such file is enough, so a broken file
beside the one that enforces cannot switch enforcement off.

Some things are outside the setting, because they are installed into the
harness and act without the hook: `telltale hooks codex-cli execpolicy`
(native Codex rules that refuse nested launches) and a hook command that
cannot start at all under `settings --fail-closed` (a missing binary). No
Telltale command installs either on its own, and `hooks.mode: enforce` does
not either; see [Tamper prevention](#tamper-prevention). Copilot CLI blocks a
tool call whose hook command cannot start whatever Telltale is set to.

Verdicts recorded in detect-only mode are what each call would get on its own
score and the session's score. They are not counted as denials: the
"repeated denials" escalation counts only denials the harness was given, so
detect-only telemetry does not escalate on denials that never happened, and
switching a running session to `enforce` does not start from them.

Moving from detect-only to enforce: run detect-only, read the `decision`
records with `verdict` `ask` or `deny` (rule IDs are in `rule_ids`), tune
thresholds or disable rules with a policy document, then set
`hooks.mode: enforce`. Because enforcement is one line in a file the agent's OS
user can usually write, the same advice applies as for the harness settings:
when the agent is the adversary, keep the configuration where the agent cannot
write it. Put it in a root-owned config root such as `/etc/telltale` and name
that root in the hook command (`telltale hooks claude-code hook --config-dir
/etc/telltale`), so the user's own root, which would otherwise win, is not
read. On Windows the system root is `%ProgramData%\telltale`, and it is read
only when Administrators, SYSTEM and TrustedInstaller alone can change it
([install.md](../install.md#windows-system-config-root)). The self-protection rules detect writes to the config roots in both
modes, including the target of a root, folder or file that is a symlink.

## Configuration

Hooks read Telltale's own configuration: the `hooks:` section of the
`settings.d` YAML files, and the same rule content as `telltale scan`
(`rules.d`, `organization-rules.d`, `ui-rules.d`, `rule-packages.d`,
`overrides.d`, `policies.d`, community rules and `detections.process_chain`),
from the same config roots and with the same precedence. See
[install.md](../install.md#operational-settings) for the roots, precedence and
`telltale config show`. The defaults:

```yaml
version: 1
hooks:
  mode: observe          # also detect: record verdicts, never return them.
                         # enforce: return ask and deny verdicts to the harness
  on_error: allow        # hook infrastructure failure: allow (fail open), ask, deny
  on_unevaluable: ask    # tool call too large, nested or damaged to evaluate: ask, deny, allow
                         # (both are recorded, not returned, unless mode is enforce)
  reason_detail: full    # full: reasons name rules and thresholds; minimal: verdict and record ID only
                         # (a human approving an `ask` then sees little; use minimal for unattended agents)
  # state_dir: <path>    # TELLTALE_HOOKS_STATE_DIR
  # telemetry_path: <path>  # TELLTALE_HOOKS_TELEMETRY
  self_protection_rules: true   # detect tampering with hooks (the tth.tamper.* rules)
  tamper_prevention:
    enabled: false       # true: lock those rules against overrides and policies
  test_signatures:
    enabled: false       # true: load the two harmless enforcement test rules (tth.test.*)
  thresholds:            # Telltale promotion scores (host policy)
    action_ask: 50
    action_deny: 90
    session_ask: 150     # cumulative session score
    session_deny: 300
    repeated_denials: 3  # after this many returned denials, any scored call is denied
  window:                # journal records evaluated with the pending action
    max_records: 256
    max_bytes: 2097152
    max_result_bytes: 16384
  evaluator:             # long-lived evaluator (telltale hooks serve)
    enabled: true        # TELLTALE_HOOKS_EVALUATOR
    autostart: true      # first evaluated hook starts it detached; hooks fall back in-process
    idle_timeout_secs: 1800
    request_timeout_ms: 10000
    # socket: <path>     # default: <state dir>/evaluator.sock
```

The self-protection rules and what locks them are described under
[Tamper prevention](#tamper-prevention); changing what rules do is described
under [Tuning rules and policy](#tuning-rules-and-policy).

The config roots are `/etc/telltale` (Windows: `%ProgramData%\telltale`), then
`$XDG_CONFIG_HOME/telltale` or `~/.config/telltale`; a later root wins per key. `--config-dir DIR` on
`hook`, `check` and `serve` (repeatable) replaces them, and an autostarted
evaluator gets the same folders. A `hooks:` section is accepted and ignored by
a build without the hooks feature.

`TELLTALE_HOOKS_EVALUATOR=0` disables the evaluator for one process. The
evaluator runs on Linux and macOS; on Windows hooks always evaluate
in-process (correct, slower).

State and telemetry default to `$XDG_STATE_HOME/telltale/hooks/` or
`~/.local/state/telltale/hooks/` on Linux and macOS, and to
`%LOCALAPPDATA%\telltale\hooks\` on Windows (`hooks.state_dir` and
`hooks.telemetry_path`, or `TELLTALE_HOOKS_STATE_DIR` and
`TELLTALE_HOOKS_TELEMETRY`). Telemetry schema:
[schemas/telltale-hooks-record-v1.schema.json](../../schemas/telltale-hooks-record-v1.schema.json).

`telltale hooks <harness> settings` pins the user config root
(`--user-config-dir`) and the state directory (`--state-dir`) on the hook
command it prints, so the environment a harness is launched with does not move
them. A hook command with `--state-dir` writes its records to
`hooks.telemetry_path` when a settings file of its config roots sets it, else
to `telemetry.jsonl` in that directory; the environment decides neither. A
relative `hooks.telemetry_path` is resolved against the hook's working
directory, as it is without the pin. When `--state-dir` or
`--user-config-dir` replaces a source that is set to a different value, the
hook names that source in its `session_start` record, in
`lifecycle.pinned_over` (for example `["TELLTALE_HOOKS_STATE_DIR"]`): the name
of the environment variable or settings key, never its value. The names are
those of the hook invocation that received the event, which records it
itself; they do not key the long-lived evaluator. `telltale hooks check` with
the same switches prints one `pinned over:` line per name.

### Updating configuration in place

Every hook invocation reads the configuration again, so a deployment tool
that changes it while harnesses run should never leave a state that does not
load:

- Write a new or changed rule, settings or override file under a name without
  a `.yaml` or `.yml` extension in the same folder, then rename it into place.
  Only YAML names are read, and a rename within one directory on one
  filesystem replaces the file with the new one rather than writing it in
  pieces.
- Replace the policy file by renaming the new one over it. Hooks read at most
  one file in `policies.d` across the config roots they read; two do not
  load.
- Never leave a symlink whose target is missing: a config folder, or a file
  with a YAML name, that is a dangling link does not load.
- Check the staged configuration first with `telltale hooks check` and every
  root the hook reads: the same `--config-dir` or `--user-config-dir`
  arguments as the hook command, with the staged copy in place of the root
  being changed. `check` loads the configuration, builds the rules and exits
  1 on an error; a check of one root alone does not see, for example, a
  second policy file in another root.
- Add rule files before the override files that name their rule IDs: an
  override for a rule ID no rule defines fails the rule build.

While its configuration does not load, an observing hook detects on the
defaults and records `config_invalid`; an enforcing one (the configuration or
`--expect-enforce` asks for `hooks.mode: enforce`) denies tool calls and
records `config_invalid`. The record goes to the records file in a pinned
`--state-dir`, else to the one `TELLTALE_HOOKS_TELEMETRY` names, else to
`telemetry.jsonl` in the state directory `TELLTALE_HOOKS_STATE_DIR` names or
the default one.

## Tuning rules and policy

Hooks evaluate the rules `telltale scan` evaluates, plus the self-protection
rules, so one set of files tunes both. None of this edits a bundled rule, and
the same folders work in a fleet-managed root (`/etc/telltale`) and in a
user's own root ([install.md](../install.md#local-rule-policy-and-allowlist-config)).

| To | Use |
| --- | --- |
| Turn off a noisy rule | `overrides.d`: `enabled: false` for its `rule_id` |
| Make a rule count less, or more | `overrides.d`: `score` |
| Change a deny into an approval request | A `score` for the rule below `hooks.thresholds.action_deny`, or a higher threshold |
| Stop a rule restricting an approved activity | Turn it off, score it below `action_ask`, or replace it with a copy that leaves the activity out |
| Change what a rule matches, or its explanation | A copy of the rule with the same `name` and `id` in `organization-rules.d`, `rules.d` or `ui-rules.d` ([replacement](../rule-format.md#identity-and-replacement)) |
| Turn off a category, a rule or a chain | `policies.d`: `disabled_categories`, `disabled_rules` |
| Say less in the reason the harness shows | `hooks.reason_detail: minimal` |
| Configure a fleet | The same folders in `/etc/telltale`; the user's root is read after it |

How tuning behaves:

- **It removes a restriction and never grants one.** A rule that is off or
  scored low leaves the call to the harness's own permission rules and
  prompts. A hook never returns an `allow`.
- **Rules are independent.** Turning one off leaves every other rule's
  finding for the same call in place.
- **A chain follows its rules.** A chain adds points when the rules it names
  match. Turn a rule off and its chains no longer match through it. A rule
  scored 0 still matches, so its chains still add their points: lowering a
  score removes only the rule's own. Turn a chain off with
  `disabled_rules` in the policy; change its score with a replacement.
  Override entries name rules, not chains.
- **The session score keeps what it counted.** A changed configuration
  applies from the next tool call. Points an earlier call added stay in that
  session's score, so calls that still score can be asked about or denied on
  it until the session ends; calls with no finding are never restricted.
- **One policy file.** Hooks read at most one file in `policies.d` across
  their config roots. Local tuning beside a managed policy belongs in
  `overrides.d`, whose files from every root apply in order.
- **A later root wins.** A user's settings and overrides are read after the
  system root's and decide each key or field both set. Where the user must
  not undo managed configuration, name only the managed root on the hook
  command (`--config-dir /etc/telltale`).

What is in effect:

| Question | Command |
| --- | --- |
| Is the hook observing or enforcing, and on which thresholds? | `telltale hooks check` |
| Which rules are on, with what score, and what changed them? | `telltale hooks check --rules`: one line per rule and chain with `enabled` or what turned it off (its definition, an override, the policy), its score, the tier that defines it, and each override applied to it with the operator's reason |
| The same for one rule of the scanner | `telltale rules show <name>` (`disabled by`, `overrides`) |
| Which file or variable set a setting? | `telltale config show` |
| Why was this call asked about or denied? | Its `decision` record: `verdict`, `basis`, scores, `rule_ids`; `decision.returned` says whether the harness was given it |
| Is tamper prevention on? | `telltale hooks check` and `hooks.tamper_prevention.enabled` in `telltale config show` |

`check --rules` shows the score a session event carries and, where it
differs, the score hooks decide on (`action`). When the rules do not build,
`check` prints the cause on stderr: the file, the rule ID and the parser's
message, which can quote the line it could not read.

## Tamper prevention

**Detecting** an agent that tampers with its hooks is monitoring, and on by
default. The self-protection rules (`tth.tamper.*`, loaded while
`hooks.self_protection_rules` is on) match writes to harness hook settings and
to Telltale's configuration, state and binary, and commands that switch hooks
off. Like every rule they are recorded in detect-only mode and returned as
ask or deny under `hooks.mode: enforce`.

**Preventing** it is a separate choice. Nothing in this table is on until an
operator turns it on, and `hooks.mode: enforce` turns none of it on:

| Protection | Acts in | Turned on by | Turned off by |
| --- | --- | --- | --- |
| Lock on the self-protection rules | The hook | `hooks.tamper_prevention.enabled: true` | The same setting |
| Block a tool call when the hook fails (Claude Code `onFailure: block`) | Claude Code | Merging settings generated with `settings --fail-closed` | Merging settings generated without the flag |
| Refuse nested Codex launches (exec-policy rules) | Codex | Saving the output of `telltale hooks codex-cli execpolicy` in the Codex rules folder | Deleting that file |

The last two are installed into a harness and act there without the hook, so
no Telltale setting switches them on or off, a detect-only hook does not make
them harmless (a missing binary under `--fail-closed` blocks every tool
call), and removing them is a change to the harness's files. Telltale only
prints them: no command writes harness files. `telltale hooks check` lists
them per harness and does not read harness files to see what is installed.
Two harness behaviors are not Telltale's to switch: Copilot CLI blocks a tool
call whose hook command crashes, exits non-zero or cannot start, and the
OpenCode pilot plugin denies when the hook is unavailable only if its own
options say `mode: "enforce"`.

**Without the lock** (the default) the self-protection rules are ordinary
bundled rules. An override can turn one off or change its score, a policy can
leave them out (their category is `approval_bypass`), and a managed tier can
replace one by name, exactly as for any other rule. `check` says how many of
them run, and `check --rules` lists them, with the names of the rules
generated for this installation's own paths. `overrides.d` is shared with the
scanner, which does not carry these rules: an entry for a `tth.tamper.` rule
is applied where the rule is loaded and left out elsewhere (by the scanner,
and by a hook that does not have that rule, where `check` prints
`override left out`). An entry for any other unknown rule stays an error. A
replacement rule file is different: to the scanner it is a rule of its own,
which it then evaluates in scans too. A shared policy with a whitelist
that does not include `approval_bypass` turns all of them off without an
error: that is what the lock refuses.

**With the lock** the `tth.tamper.` names belong to hooks. A rule document,
rule package or override file that names one is invalid configuration, and so
is a policy under which any self-protection rule would not stay enabled: a
shared policy with a whitelist (`enabled_categories` or `enabled_rules`) must
include the `approval_bypass` category or every `tth.tamper.` rule name. A
policy that only turns off other rules or categories is unaffected. The lock
needs the rules, so it is invalid together with
`hooks.self_protection_rules: false`. `telltale hooks check` names the file
(never its content) and exits 1, a hook whose settings ask for
`hooks.mode: enforce` denies tool calls until it is fixed, and any other hook
is detect-only on the defaults with a `config_invalid` record.

### Who may change the rules

Telltale reads configuration files. It cannot tell an administrator's edit
from an edit an agent made as the same OS user, so it does not try: whoever
can write a config root the hook reads is the operator. An override that
names a self-protection rule is therefore tuning, not tampering, unless the
lock says the rules are fixed.

- The agent changing those files is a tool call, and the self-protection
  rules detect it (and deny it under enforcement) whatever the files then
  say.
- The lock guards content, not files. It stops a shared policy, a rule
  package or an override from dropping the self-protection rules unnoticed.
  One who can write a settings file the hook reads can turn the lock off, as
  they can turn enforcement off.
- The boundary against an agent is file ownership: configuration in a root
  the agent's user cannot write, named alone on the hook command
  (`--config-dir /etc/telltale`), with the binary and the harness's managed
  settings out of its reach as well
  ([threat model](../security/hooks-threat-model.md)).

## Testing enforcement

To see what a hook does end to end, without anything that looks like an
attack, turn on the enforcement test signatures. They are Telltale's
equivalent of an antivirus test file: two rules that each match one harmless
command.

```yaml
version: 1
hooks:
  test_signatures:
    enabled: true     # default false
```

| Command | Rule | Score | Under the default thresholds |
| --- | --- | --- | --- |
| `echo TELLTALE_TEST_ASK` | `tth.test.ask` | 60 | ask |
| `echo TELLTALE_TEST_DENY` | `tth.test.deny` | 95 | deny |

Ask the agent to run one of them (the command only prints its marker), or
send the payload to the hook yourself. What comes back follows the
configuration in effect, as for any rule, and `telltale hooks check` prints
it for each test command:

| Configuration | Result |
| --- | --- |
| `test_signatures` off (the default) | No rule matches: an ordinary command |
| `hooks.mode: observe` | The verdict is recorded with `returned: false`; the harness is told nothing |
| `hooks.mode: enforce`, ask test | The harness's own approval prompt (Claude Code, Copilot CLI). Codex CLI and the OpenCode pilot cannot ask: they are given a deny whose reason says that approval was required, and the record keeps `verdict: ask` with `returned_verdict: deny` |
| `hooks.mode: enforce`, deny test | A deny with a reason the user and the model can act on |
| An override, policy, threshold or replacement for a test rule | Applies as to any rule: `enabled: false` makes it an ordinary command again, a lower score or a higher threshold turns the deny into an ask or into no opinion |

What makes them safe to leave in a configuration and to run in a working
session:

- **Only the exact command matches**: the whole command is `echo` and the
  marker. A command, file, prompt or document that mentions a marker is not a
  test, and nothing a tool writes or returns is.
- **They are apart from production rules.** No chain names them or their
  category (`enforcement_test`), production rules detect the same with them
  on, and a call that only test signatures match is decided on its own score
  and stays out of the session's score and denial count: a test is answered
  the same in a quiet and in a busy session and makes no later call stricter.
- **Their records are identifiable**: `decision.rule_ids` holds `tth.test.ask`
  or `tth.test.deny`, `decision.categories` holds `enforcement_test`.
- **Removing them changes nothing else**: set the setting back to `false`.
- Tamper prevention does not lock them.

They test the hook and the harness's answer to it, not a detection. For a
harness with a live model, see [harness testing](harness-testing.md).

### What a denied or asked call says

Under `reason_detail: full` (the default) the reason given to the harness,
which shows it to the user, the model or both, says what happened, what the
matched rules are about, why, and what to do:

```text
Telltale Hooks: this tool call was blocked and has not been executed. It matched a
configured security rule for exfiltration, credential harvesting. Reason: Telltale
action score 145 reached the deny threshold (90). Review the command or request an
authorized configuration exception. Detections: chain.harvest_then_exfil,
credential.cloud_harvest, exfil.outbound_upload. Record tth:<id>.
```

An ask starts `this tool call needs approval before it runs`. The concern is
the categories of the rules that matched (at most three, letters and digits
only). A reason never contains a rule's pattern, its explanation, the matched
text, a file's content or a path from the configuration; those stay in the
decision record, under the record ID the reason ends with.
`reason_detail: minimal` keeps only `denied by policy` or `needs approval`
and the record ID.

## Documentation

- [Architecture](architecture.md) and [decisions](adr/)
- [Hooks threat model](../security/hooks-threat-model.md)
- [Harness capability matrix](capability-matrix.md)
- [Harness tracker](harness-tracker.md): links, configuration paths and adapter
  progress for every harness, implemented or not. `progress.html` beside it is
  the generated milestone view; open it in a browser
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
