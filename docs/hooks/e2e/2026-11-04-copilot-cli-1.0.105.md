# Real-harness results: GitHub Copilot CLI 1.0.105, 2026-11-04

Run: `scripts/hooks/harness/copilot-cli-e2e.py` (all 27 scenarios), telltale-hooks at
commit `b5d55f4` (release build), Telltale `0249eafb`,
`@github/copilot` 1.0.105 (Linux x86-64), `[evaluator] enabled = true`. Each
scenario has its own HOME, `COPILOT_HOME`, XDG directories and a working
directory that is its own git repository; no global configuration is read or
written. Raw per-scenario summaries (paths scrubbed):
[`2026-11-04-copilot-cli-1.0.105.summary.jsonl`](2026-11-04-copilot-cli-1.0.105.summary.jsonl).

**Model: scripted.** Copilot talks to `scripts/hooks/harness/mock-model.py` over
loopback (BYOK, `COPILOT_OFFLINE=true`, no credentials, no tokens), which asks
for `touch <canary> && <command>` once. That makes the run deterministic and
tests what Copilot does with telltale-hooks' answers, not what a real model
would ask for. **Real-model run pending** (it needs the user's Copilot auth;
).

Method: telltale-hooks is registered from its own `copilot-cli settings`
output in `$COPILOT_HOME/hooks/` (the PascalCase scenarios rename the events),
behind a pass-through recorder that logs what each hook invocation printed and
its exit code. The canary is ground truth for execution. It is cross-checked
with telemetry (decision and outcome) and with the tool result the model saw.
"Attribution: hook" requires a returned verdict **and** an outcome showing the
call was settled without running.

| Scenario | Mode, command (after `touch canary &&`) | Verdict (score, rule) | Hook output | Canary | Outcome / enforcement (settled by) | Attribution |
| --- | --- | --- | --- | --- | --- | --- |
| benign | `-p --allow-all-tools`, `ls` | allow (0) | none (6 invocations) | present | completed / not_returned (`postToolUse`) | executed |
| deny | camelCase, `echo TTH_E2E_DENY_MARKER` | **deny** (95, deny marker) | flat deny | absent | not_executed / **honored** (`agentStop`) | hook |
| deny-pascal | PascalCase registration | **deny** (95) | flat deny | absent | not_executed / **honored** (`Stop`) | hook |
| deny-subagent | marker run by a `task` subagent | parent `task`: allow; child: **deny** (95), `agent_id` set, parent's session | flat deny | absent | not_executed / **honored** (child's `agentStop`) | hook |
| deny-yolo | `-p --yolo` | **deny** (95) | flat deny | absent | not_executed / **honored** | hook |
| deny-autopilot | `-p --allow-all-tools --autopilot` | **deny** (95) | flat deny | absent | not_executed / **honored** | hook |
| ask | `-p --allow-all-tools`, `echo TTH_E2E_ASK_MARKER` | **ask** (60, ask marker) | flat ask | absent | not_executed / declined | hook ("unable to ask user for confirmation") |
| ask-yolo | `-p --yolo` | **ask** (60) | flat ask | absent | not_executed / declined | hook (same) |
| ask-autopilot | `-p --allow-all-tools --autopilot` | **ask** (60) | flat ask | absent | not_executed / declined | hook (same) |
| ask-interactive-deny | interactive `-i`, `--allow-all-tools`; user declines (Esc) | **ask** (60) | flat ask | absent | not_executed / declined | hook prompt, user ("Denied by user via preToolUse hook prompt") |
| ask-interactive-approve | interactive, `--allow-all-tools`; user approves | **ask** (60) | flat ask | present | completed / **proceeded_after_ask** | user approved |
| ask-interactive-yolo | interactive, `--yolo`; user declines | **ask** (60) | flat ask | absent | not_executed / declined | hook prompt, user |
| denytool | `--allow-all-tools --deny-tool=shell`, `ls` | allow (0) | none | absent | unknown / not_returned | Copilot's own deny (our silence does not loosen it) |
| claude-settings | repository `.claude/settings.json` with `telltale hooks claude-code hook`, `--trust-folder` | **deny** (95), telemetry `harness = copilot-cli` | Claude `hookSpecificOutput` deny | absent | unknown / unknown (`SessionEnd`) | hook (see 4) |
| claude-settings-ask | same route, `-p --allow-all-tools --trust-folder`, ask marker | **ask** (60, ask marker), telemetry `harness = copilot-cli` | Claude `hookSpecificOutput` ask | absent | unknown / unknown (`SessionEnd`) | hook ("unable to ask user for confirmation") |
| claude-settings-ask-interactive-deny | same route, interactive `-i`, `--allow-all-tools`; user declines (Esc) | **ask** (60) | Claude ask | absent | unknown / unknown (`SessionEnd`) | hook prompt, user ("Denied by user via preToolUse hook prompt") |
| claude-settings-ask-interactive-approve | same route, interactive; user approves | **ask** (60) | Claude ask | present | completed / **proceeded_after_ask** (`PostToolUse`) | user approved |
| claude-settings-unevaluable | same route, `-p`, `ls`, 2 MB `description` (past the projection budget), default `on_unevaluable` | **ask** (`unevaluable_input`) | Claude ask | absent | unknown / unknown (`SessionEnd`) | hook ("unable to ask user for confirmation") |
| claude-settings-unevaluable-control | same call, `on_unevaluable = "allow"` | allow (`unevaluable_input`) | none | present | completed / not_returned | executed: the size alone does not stop the call |
| claude-settings-oversized | same route, `-p`, `ls`, 33 MiB `description` (past the 32 MiB payload limit), default `on_unevaluable` | — (never parsed, so no telemetry record) | Claude ask "could not read this tool call" | absent | — | hook ("unable to ask user for confirmation") |
| claude-settings-oversized-control | same call, `on_unevaluable = "allow"` | — (never parsed) | none on `PreToolUse` | present | — | executed: the size alone does not stop the call |
| result-context | `printf 'TTH_E2E_RESULT_%s' MARKER` (marker only in the result) | allow; result flagged (60, result marker) | `postToolUse` `additionalContext` | present | completed / not_returned | executed; model saw the advisory |
| fail-missing | hook command `/nonexistent/telltale-hooks`, `ls` | — | — | absent | — | Copilot fails closed ("hook errored") |
| fail-exit1 | hook command `sh -c 'exit 1'`, `ls` | — | — | absent | — | Copilot fails closed |
| fail-config | invalid telltale-hooks config, `ls` | — | flat deny "misconfigured and fails closed"; lifecycle events exit 1 | absent | — | telltale-hooks fails closed |
| fail-config-pascal | same, PascalCase | — | flat deny (same) | absent | — | telltale-hooks fails closed |
| timeout | hook sleeps 5 s, `timeoutSec: 2`, deny marker | — | none (killed) | **present** | completed / no_decision | executed: **timeout fails open** (residual) |

Findings:

1. Copilot honors telltale-hooks' flat `deny` in camelCase and PascalCase
   registrations, with `--yolo`, in autopilot and inside a subagent. The
   subagent's call joins the parent session (the subagent is `agent_id`).
2. A hook `ask` is put to the user in interactive mode (a "Hook permission
   request" dialog, also with `--allow-all-tools` and `--yolo`) and refused in
   every `-p` mode. No tested mode runs an asked call without a human, so the
   adapter declares `can_ask = true`. Declined and approved asks are told
   apart by the outcome (`declined` at `agentStop`, `proceeded_after_ask` at
   `postToolUse`).
3. Copilot blocks a call when the hook is missing or exits non-zero, and
   telltale-hooks blocks one on invalid configuration. A hook that times out
   lets the call run whatever it would have answered: this is the residual
   documented in [copilot-cli.md](../harnesses/copilot-cli.md). The
   hook file sets 60 s.
4. A Claude Code installation in a repository's `.claude/settings.json` runs
   under Copilot. `telltale hooks claude-code hook` recognizes Copilot's
   payloads, records them as `copilot-cli`, and its Claude-form deny is
   honored. Its Claude-form `ask` is treated the same as the flat form on this
   PascalCase route: refused in `-p`, put to the user interactively. Default
   `on_unevaluable` therefore blocks there, both for input past the projection
   budget (evaluated, `basis = unevaluable_input`) and for a payload past the
   32 MiB limit (answered without parsing). The `on_unevaluable = "allow"`
   controls ran the same calls, so the absent canaries come from the hook's
   answer and not from a size limit in Copilot. The Claude Code fragment
   registers no `Stop`, so a denied or declined call is settled at `SessionEnd`
   as `unknown` rather than `honored` or `declined`; the canary shows it did
   not run.
5. Silence never loosens Copilot: with `--deny-tool=shell` a call
   telltale-hooks allowed was still refused by Copilot.
6. Evaluator: most decisions were evaluated in process while the hook
   autostarted the evaluator (`evaluator_fallback = evaluator_unreachable`); 2
   of 21 came from the evaluator (`daemon`), the second decision in
   `deny-subagent` and the one in `claude-settings-ask-interactive-approve`.
   Pipeline builds took 320-1227 ms, scans 3-57 ms.

## Earlier rerun on the merged build

Before the commit above, 9 scenarios were rerun at `650c211`, the merge of
`main` with runtime normalization: `benign`, `deny`, `deny-pascal`,
`deny-subagent`, `ask`, `ask-interactive-approve`, `claude-settings`,
`result-context`, `fail-config`. Verdicts, rules, canaries and outcomes all
matched the earlier run. These scenarios call only `bash` and `task`, so they
do not exercise the `view`, `rg` or patch normalization. The full run above
repeats all nine.
