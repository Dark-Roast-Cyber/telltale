# Telltale Hooks threat model

What a pre-execution hook (`telltale hooks`) can and cannot guarantee. This
page is part of the [Telltale threat model](threat-model.md) and covers only
the hooks integration ([overview](../hooks/README.md)). It names residual
risks by category. It does not list the concrete forms that still evade
detection; those are tracked privately under the [security policy](../../SECURITY.md).

Each item has a status: **Mitigated**, **Partial**, **Accepted** (documented
residual risk), **Open** (tracked), **Upstream** (needs a change in the
embedded detection library) or **Out of scope**. Regression tests pin the
mitigated and partial decisions (`crates/telltale/tests/hooks/`,
`tests/cli/hooks_*.rs`). Real-harness results are historical reports in
[`docs/hooks/e2e/`](../hooks/e2e/).

## What the hook sees

The hook sees what the harness reports: the tool name and input it is about
to run, and later the result it reports. It does not see OS-level effects. A
`requested` call is never proof of execution, and a `completed` report is the
harness's claim, not an independent observation.

Hooks run inside the same executable, OS user and file permissions as the
agent's other processes unless an operator deploys them otherwise. Anything
the agent can write as that user, it can try to tamper with. Managed
deployment (settings the agent cannot override, state outside the agent's
reach) is the control that closes this class; the items below are
defense in depth on top of it.

## Agent-controlled bypasses

| Bypass | Status | Notes |
| --- | --- | --- |
| Edit or delete hook configuration (Claude Code, Copilot CLI and Codex CLI hook files, the exec-policy backstop, managed settings, custom harness homes, the installed binary) | Partial | Rules deny native write tools and normalized patches aimed at those files and commands that name a protected path together with a writing program or redirection, across POSIX, cmd.exe and PowerShell spellings, including quote-split and other spellings Telltale's shell reading resolves. A writing program counts at command position (start, after a separator, or behind a recognized wrapper), and a plain writer's target must be in its own command. What cannot write is not denied (reads, read pipelines, dry runs, `git` readers, commit and pull-request text, project-level directories, container flags); any other mention asks. Rules for a custom `CODEX_HOME` or `COPILOT_HOME` and for the running binary are generated from the hook's own environment. |
| Spell the protected path or the writer in a way the deny rules do not list | Partial | Fail-safe rules ask, with no list of wrappers or spellings, when a protected directory appears in any form together with a writer word, or a harness launch appears with a hook-disabling option, anywhere in the command. The cost is false asks on commands that only look like tampering, which are refusals on harnesses that cannot ask. Telltale adds the points of every rule that matches one call, so two different asking rules can reach a deny. |
| Assemble the path or command at run time, or hide it in authored content | Accepted, Upstream | Pattern rules cannot resolve every shell or interpreter semantics, and authored file content is not visible to rule targets. Encoded forms are scored for review by bundled content. A regression test pins the accepted set privately. The real fix is managed settings plus state outside the agent's reach. |
| Stage a hook-free configuration elsewhere, then move it into place; write through an alias created earlier | Partial | The move or link into place is denied; the staging write and a later write through an alias are indistinguishable from ordinary writes. |
| Relaunch the harness without hooks, or point the hook at the agent's own configuration or state | Partial | Rules deny the harness's hook-disabling launch options and any command that sets a `TELLTALE_HOOKS_*` variable and launches a harness. The Codex forms are covered only by the optional exec-policy backstop, which refuses plain launches natively while its file exists and which indirect launches escape. |
| Tamper with journal, state or telemetry (same OS user) | Partial | Rules cover the default and resolved locations, and directories are owner-only on Unix. Deleting state resets cumulative session risk, and deleting the journal blinds cross-call chains; action-level findings are unaffected. Guaranteed: an unparseable ledger is quarantined and the call is still evaluated; files the hook cannot read or write get the stricter of `on_error` and `on_unevaluable` (default `ask`) and an `error` record, so with defaults this is never a silent allow. Runtime files are opened only as regular files (no symlink or FIFO is followed or blocks the hook). Operator inputs may be symlinks but must resolve to regular files. Tampering signals are emitted as `error` records. |
| Pad or nest a tool input so Telltale quarantines it | Mitigated | Inputs are flattened and chunked so every byte is evaluated; only input beyond the projection budget is unevaluable and gets `on_unevaluable`. |
| Craft identity fields (call key, session ID, tool name) so Telltale rejects the journal source | Mitigated | Unsafe values are replaced by a stable digest-based stand-in before journaling, telemetry keeps the raw value, and a call whose tool name had to be encoded is floored at `on_unevaluable` because name-routed rules cannot match the stand-in. Some malformed names remain a residual that is tracked privately. |
| Model-controlled tool input that makes Telltale reject the journal source | Mitigated | Input keys that Telltale would fold together are renamed in the evaluation encoding, so no value is lost. A scan that still fails at source level is retried on a reduced window, and a call that is too large on its own is scanned piece by piece within a time limit. The call keeps its rule verdict, and telemetry records the limit that applied. Exceptions that depend on load or queuing (a lock timeout, a very large call past the piece limit) get the stricter failure policy. Padding can still turn a verdict into an ask; see the failure table. |
| Oversized or malformed PreToolUse payload | Mitigated | Answered on stdout with the stricter of `on_error` and `on_unevaluable`; stdin is drained so the harness never sees a broken pipe. |
| Make the hook miss its timeout | Partial | A timed-out hook is killed and the call runs unless the harness has a block-on-failure option (`settings --fail-closed` enables it where it exists). The agent cannot slow a hook from inside a tool call except by stalling the evaluator (mitigated below). |
| Plugin or extension mechanisms that override hook blocks | Open | Reported by harness documentation, unverified. Managed settings mitigate. |
| Indirection: write a script with a benign call, run it later | Partial | Telltale evaluates each command; written-path rules and download/execute chains catch some forms. Authored content is not visible to rule targets. |
| Split a risky action across many low-scoring calls | Partial | Telltale chains plus the host session ledger. The window is bounded; chains older than the window are not reconstructed. |
| Subagent delegation | Mitigated | Subagent calls hit the same hooks and share the session journal. |
| Tools not covered by hooks | Partial | Some harness paths never fire a pre-execution hook (documented per harness in the capability matrix). MCP and web tools do fire. |
| Prompt injection via tool results | Partial | Results are journaled and evaluated; findings add advisory context and raise session risk. |
| Learn the rules from deny reasons | Mitigated (opt-in) | By default reasons name rule IDs and thresholds. `reason_detail = "minimal"` keeps only the verdict kind and a record ID; use it where the agent is the adversary and runs unattended. |
| Impersonate the evaluator (plant a socket that answers "no opinion") | Mitigated for other users | The socket and its directory must belong to the same UID and not be group- or world-writable, and both ends check peer credentials. The same OS user can still replace the socket, as with any same-user state. |
| Stall the evaluator so other hooks time out | Mitigated | Per-connection reader threads with a total deadline, capped connections, deadlines on requests, and the stricter failure policy for an unanswered pre-execution request. |
| A path value that breaks the generated rule document | Mitigated | Paths from the environment and the configuration reach the generated self-protection rules. A character the YAML reader refuses used to fail the whole document, so no pipeline built and, with no operator rule files, calls were allowed by default; line breaks were folded and the rule never matched. Generated rules now write every such character by its code point, and any pipeline that does not build gets the stricter failure policy. A path that is not UTF-8 still gets no generated rule. |
| Keep a stale evaluator serving old rules after an upgrade | Mitigated | The evaluator fingerprint covers the package version, the executable's build metadata and file identity (unique to the process when the file cannot be read, so nothing matches it), the configuration, referenced rule bytes and every path input; on a mismatch the evaluator retires. |
| Windows: no evaluator transport | Open | Hooks evaluate in-process with the same verdicts, slower, and never fail open. |
| Windows: reparse points, directory ACLs and path normalization | Partial, unverified on Windows | Runtime files are opened without following reparse points. State directories inherit the parent's ACL (the default is per-user). Generated path rules are literal on the native path; static rules carry the common Windows spellings. |

## Failure-induced bypasses

| Condition | Default | Option |
| --- | --- | --- |
| Hook crashes, times out or is missing | Claude Code fails open; Copilot CLI blocks on crash or missing binary and runs the call on timeout; Codex CLI fails open with no option | `settings --fail-closed` where the harness supports it. For Codex, managed hooks are the real fix and the exec-policy backstop only refuses plain nested launches |
| The program at a trusted Codex hook path is replaced | Trust is kept (the hash covers the command text); the replacement runs as the hook | Keep the binary where the agent cannot write |
| Hook infrastructure fails (state directory unresolvable, the scan call itself returns an error). Tool input cannot cause these | `on_error = "allow"`; `error` record | `ask` or `deny` |
| A scan fails at source level (Telltale rejects the window) | The window is reduced and the call keeps its rule verdict, except on a lock timeout; a call with no finding gets its plain verdict; `history_lost` on the record | none needed |
| A pending call fails at source level on its own | Scanned piece by piece for a bounded time: findings count, floor at `on_unevaluable` (default `ask`), `pending_pieces_unscanned` on the record if pieces were left; not evaluated at all: `on_unevaluable` | Raise or lower `on_unevaluable` |
| Referenced rule, package or policy file missing or not a regular file at configuration load | Invalid configuration: tool calls denied | none (deliberately loud) |
| Referenced rule content unreadable after load, or any rule pipeline that does not build (the reason names `telltale hooks check`) | Stricter of `on_error` and `on_unevaluable` (default `ask`); `error` record | Raise either |
| Session files unreadable or unwritable | Stricter of `on_error` and `on_unevaluable`; `error` record | Raise either |
| Session ledger unparseable or from another version | Quarantined and reset; the call is still evaluated | none needed |
| Tool input cannot be evaluated even after projection | `on_unevaluable = "ask"` | `deny`, or `allow` (not recommended) |
| Hook payload unusable, tool call | Stricter of `on_error` and `on_unevaluable`, on stdout | Raise either |
| Hook payload unusable, other named event | Exit 1 whatever `on_error` says: a block on a stop event would prompt the model without limit | none needed |
| Hook payload names no event | Exit 1; under `on_error = "deny"`, each harness's block that needs no event (residual on stop events for Claude Code) | `on_error` |
| A batch settles a call before its result arrives | Settlement is provisional; a later result supersedes it and reports `violated` for a denied call | none |
| Invalid hooks configuration | Tool calls denied | none (deliberately loud) |
| Evaluator unreachable, untrusted, or on another configuration | In-process evaluation (correct, slower) | `[evaluator] enabled = false` |
| Evaluator received the request but did not answer before the deadline | The decision it recorded, if any; otherwise in-process evaluation, which keeps the rule verdict unless that times out on the session's lock | none |
| A session's lock stays taken for the 10 s a call waits (`state_lock_timeout`) | Stricter of `on_error` and `on_unevaluable` (default `ask`); `error` record | Raise either |

## Confounds in testing

Model-side safety classifiers stop some obviously malicious commands before
any tool call reaches the hook. The real-harness suite attributes every
blocked canary to `hook` or `upstream_of_hook` and uses deterministic marker
rules to test enforcement independently of model refusals.

## Out of scope

General EDR, kernel or network enforcement, and sandboxing. Those are
complementary layers.
