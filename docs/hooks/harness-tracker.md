# Harness tracker

A working page: where each harness's hook documentation, source and
configuration files are, and how far its Telltale Hooks adapter has come.
Update it in the same change as the work it describes.

It does not make support claims. The adapters in a build are the registry in
`crates/telltale/src/hooks/harness.rs`; verified behavior is in the
[capability matrix](capability-matrix.md) and the
[harness contract pages](harnesses/README.md).

## How to update

- Change a harness's row in [Progress](#progress) when a stage is finished,
  and add one dated line to the [Log](#log).
- After any change to the Milestones or Progress table, or to the Log,
  regenerate the progress page with `make hooks-progress-update` and commit
  `progress.html` with it. `cargo test --test hooks_progress` fails while the
  page is stale. Never edit `progress.html` by hand.
- Add a row for a harness as soon as it is known, with Survey `todo` and
  Mechanism `Unsurveyed`. A row is not a support claim.
- Record a fact in [Reference](#reference) with its evidence level and the
  date it was checked. Levels are the capability matrix's: **E2E**,
  **Capture**, **Bin**, **Docs/Src**, **3P** (third party only), **?**.
- Link primary sources: the vendor's documentation, repository or changelog.
- When a contract page exists for a harness, the page is the authority and its
  entry here shrinks to links and status.
- Synthetic data only. No real session content, credentials, host names or
  private paths.

## Stages

| Stage | Done when |
| --- | --- |
| Survey | Hook mechanism, configuration paths and links are recorded here from primary sources |
| Contract | `harnesses/<name>.md` describes configuration, the pre-execution payload and the decisions the harness honors |
| Capture | Payloads are captured from the real harness binary at a pinned version, with a scripted model where the harness allows one |
| Adapter | An adapter module is registered, its parse and render tests pass, and its client's tool table declares the harness's built-in tools |
| E2E | A pinned real harness using the integrated `telltale hooks` install runs the permitted control, then returns the marker denial without executing the denied twin. Record build revision, harness version, platform, model mode and tested tool path ([method](harness-testing.md)). |
| Documented | Quick start, capability matrix and contract page describe the shipped behavior |

## Milestones

The bars count checklist cells. Verify the written gate against linked run
reports before declaring a milestone reached. Unassigned harnesses (`—`) are
survey candidates and do not count toward the bars. M3 to M6 are a working
proposal in priority order, not a commitment.

| Milestone | Name | Reached when |
| --- | --- | --- |
| M1 | Integrated command hooks | Linked control/deny reports for Claude Code, Copilot CLI and Codex CLI using the integrated executable |
| M2 | OpenCode v2 pilot | One pinned v2 install passes the ordinary-call, nested-call and failure gates in the OpenCode contract; report settlement limits |
| M3 | Adapter reuse | VS Code Copilot agent mode, Qwen Code and Factory Droid each have a capture and a linked control/deny report, through an existing adapter where the captured contract matches |
| M4 | Own-contract command hooks | Cursor, Gemini CLI, Antigravity and Cline each have a contract page, an adapter and a linked control/deny report |
| M5 | Plugin harnesses | OpenCode v2 passes its gates as a managed install; Kilo and Pi are enforced through a forwarding plugin with linked reports |
| M6 | Vendor agents, second wave | Grok Build, Mistral Vibe, Kimi CLI, Qoder, CodeBuddy and Trae each have an adapter, or reuse one, with a capture and a linked control/deny report |

[progress.html](progress.html) shows these as one bar. It is generated from
the two tables in this section and the next; see [How to update](#how-to-update).

## Progress

Stage cells are `done`, `wip`, `todo` or `n/a`. "Pin" is the version the
latest stage was done against.

"Catalog" names the client IDs from the pinned client catalog
(`crates/telltale-discover/data/tokscale-registry.tsv`) that a row accounts
for; `—` means the catalog does not list the harness.
`cargo test --test hooks_progress` fails while a catalog client has no row, so
a catalog update brings its new clients here as unsurveyed rows. Neither the
catalog nor this page is a complete list of agents: add a harness when one is
found, whatever the source.

| Harness | Catalog | Milestone | Mechanism | Survey | Contract | Capture | Adapter | E2E | Documented | Pin | Next |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Claude Code | `claude` | M1 | Command hook | done | done | done | done | done | done | 2.1.327 E2E; 2.1.318 capture | Broader mode qualification |
| GitHub Copilot CLI | `copilot` | M1 | Command hook | done | done | done | done | done | done | 1.0.105 | Real-model run separately authorized |
| OpenAI Codex CLI | `codex` | M1 | Command hook | done | done | done | done | done | done | 0.166.0 | Real-model run separately authorized |
| OpenCode v2 | `opencode` | M2 | In-process plugin | done | done | done | done | done | done | 2.2.5; queue plugin rerun on 2.3.2 | Request-only pilot; service and hardened install remain unqualified |
| OpenCode v2 managed install | — | M5 | In-process plugin | done | todo | todo | n/a | todo | todo | — | Service mode, packaged install and a startup check from outside the plugin |
| Kilo | `kilo` | M5 | In-process plugin (OpenCode API) | done | todo | todo | todo | todo | todo | — | Capture before considering reuse |
| VS Code Copilot agent mode | — | M3 | Command hook (Copilot harness) | done | todo | todo | todo | todo | todo | — | Capture; compare with Copilot CLI |
| Cursor | `cursor` | M4 | Command hook | done | todo | todo | todo | todo | todo | — | Contract page and capture |
| Gemini CLI | `gemini` | M4 | Command hook | done | todo | todo | todo | todo | todo | 0.66.0 (survey) | Capture; settle exit-code behavior |
| Factory Droid | `droid` | M3 | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| Qwen Code | `qwen` | M3 | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| Cline | `cline` | M4 | Command hook (file hooks) | done | todo | todo | todo | todo | todo | — | Capture extension and CLI payloads |
| Pi | `pi` | M5 | In-process extension | done | todo | todo | todo | todo | todo | — | Capture |
| Goose | `goose` | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| Antigravity | `antigravity`, `antigravity-cli`, `antigravity-extension` | M4 | Command hook | done | todo | todo | todo | todo | todo | — | Capture |
| Crush | `crush` | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Kiro | `kiro` | — | Command hook, Claude-shaped (CLI V3) | done | todo | todo | todo | todo | todo | — | On demand |
| Junie CLI | `junie` | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Auggie CLI | `augment` | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Hermes Agent | `hermes` | — | Command hook; Python plugin | done | todo | todo | todo | todo | todo | 0.19.0 (survey) | On demand |
| OpenHands | — | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Devin Desktop and CLI | `devin-cli`, `devin-desktop` | — | Command hook | done | todo | todo | todo | todo | todo | — | On demand |
| Amp | `amp` | — | In-process plugin | done | todo | todo | todo | todo | todo | — | On demand |
| OpenClaw | `openclaw` | — | In-process plugin | done | todo | todo | todo | todo | todo | 2026.10.10 (survey) | On demand |
| Continue CLI | — | — | None usable | done | n/a | n/a | n/a | n/a | n/a | — | Recheck if the pre-tool event is wired |
| Zed agent | `zed` | — | Tool permissions | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Aider | — | — | Unverified | todo | todo | todo | todo | todo | todo | — | Find primary evidence |
| Warp | `warp` | — | None released | done | n/a | n/a | n/a | n/a | n/a | — | Recheck when hooks ship |
| Roo Code | `roocode` | — | Unverified | todo | todo | todo | todo | todo | todo | — | Verify lifecycle status |
| Aside | `aside` | — | Not a coding harness (browser agent) | done | n/a | n/a | n/a | n/a | n/a | — | None |
| BB | `bb` | — | Not a harness (runs other agents' CLIs) | done | n/a | n/a | n/a | n/a | n/a | — | None; the wrapped agent's hooks apply |
| Cherry Studio | `cherrystudio` | — | Unverified (embeds other agent runtimes) | wip | todo | todo | todo | todo | todo | — | Find whether settings-file hooks load |
| CodeBuddy | `codebuddy` | M6 | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| Codebuff | `codebuff` | — | None documented | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Command Code | `commandcode` | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| DeepSeek Harness | `dsh` | — | In-process plugin; command-hook bridges | done | todo | todo | todo | todo | todo | — | On demand |
| Freebuff | `freebuff` | — | None documented (Codebuff codebase) | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Fx | `fx` | — | None exposed | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Gajae-Code | `gjc` | — | In-process hook module (Pi extension API) | done | todo | todo | todo | todo | todo | — | After Pi |
| Grok Build | `grok` | M6 | Command and HTTP hooks | done | todo | todo | todo | todo | todo | — | Contract page and capture |
| Hindsight | `hindsight` | — | Not a harness (memory server) | done | n/a | n/a | n/a | n/a | n/a | — | None |
| Jcode | `jcode` | — | Command hook | done | todo | todo | todo | todo | todo | — | On demand |
| Kilo Code extension | `kilocode` | — | In-process plugin (OpenCode API) | done | todo | todo | todo | todo | todo | — | After Kilo; confirm the older extension |
| Kimchi | `kimchi` | — | Shell-tool command hook; Pi packages | done | todo | todo | todo | todo | todo | — | On demand |
| Kimi CLI | `kimi` | M6 | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| LM Studio | `lmstudio` | — | Not a coding harness (model runner) | done | n/a | n/a | n/a | n/a | n/a | — | None |
| MiMo Code | `micode` | — | In-process plugin (OpenCode API) | done | todo | todo | todo | todo | todo | — | After Kilo |
| MiniMax Code | `mcode` | — | Command hook in plugins, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Mistral Vibe | `vibe` | M6 | Command hook | done | todo | todo | todo | todo | todo | — | Contract page and capture |
| Muse Code | `muse` | — | Command hook | wip | todo | todo | todo | todo | todo | — | Find the decision contract |
| Mux (Xum) | `mux` | — | Command hook; plugin hooks | done | todo | todo | todo | todo | todo | — | On demand |
| Oh My Pi | `omp` | — | In-process extension (Pi API) | done | todo | todo | todo | todo | todo | — | After Pi |
| OpenCodeReview | `opencodereview` | — | None documented (review tools only) | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Prime Agent | `prime-agent` | — | None documented | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Proma | `proma` | — | None documented | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Qoder | `qoder` | M6 | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| Reasonix | `reasonix` | — | Command hook | done | todo | todo | todo | todo | todo | — | On demand |
| Senpi | `senpi` | — | In-process extension (Pi API) | done | todo | todo | todo | todo | todo | — | After Pi |
| Trae | `trae` | M6 | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | Capture |
| Unsloth | `unsloth` | — | Not a coding harness (model training) | done | n/a | n/a | n/a | n/a | n/a | — | None |
| WorkBuddy | `workbuddy` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey; vendor pages were not readable |
| Xiaomi MiMo AI | `micode-desktop` | — | Unverified (MiMo Code engine) | wip | todo | todo | todo | todo | todo | — | Confirm plugin loading in the desktop build |
| ZCode | `zcode` | — | Command hook, Claude-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Open Interpreter | — | — | Command hook, Codex-shaped | done | todo | todo | todo | todo | todo | — | On demand |
| Firebender | — | — | Command hook | done | todo | todo | todo | todo | todo | — | On demand |
| gptme | — | — | In-process Python hook | done | todo | todo | todo | todo | todo | — | On demand |
| Snowflake Cortex Code | — | — | SDK callback | wip | todo | todo | todo | todo | todo | — | Find whether it runs tools locally and loads hooks from a file |
| Trae Agent | — | — | None documented | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| Plandex | — | — | None for users | done | n/a | n/a | n/a | n/a | n/a | — | Recheck yearly |
| JetBrains AI Assistant | — | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Amazon Q Developer | — | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey; compare with Kiro |
| Replit Agent | — | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Tabnine | — | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| SWE-agent | — | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |

### Shared work

Work that serves several harnesses.

| Item | Status | Notes |
| --- | --- | --- |
| E2E reports against `telltale hooks` | done | [Integrated report](e2e/2026-11-17-integrated-pilot.md); scripted models, narrow tool paths and versions only |
| Strict Hooks record consumer | done | [Strict readback](adr/0005-telemetry-envelope.md#addendum-2026-11-26-strict-readback); shared across harnesses |
| Bounded Hooks telemetry labels | done | [Envelope addendum](adr/0005-telemetry-envelope.md#addendum-2026-11-26-bounded-telemetry-labels); shared across harnesses |
| Bounded Hooks telemetry lines | done | [Strict readback](adr/0005-telemetry-envelope.md#addendum-2026-11-26-strict-readback); writer and reader share the 16 MiB limit |
| Hooks record rotation and feed | done | [Incremental readback](adr/0005-telemetry-envelope.md#addendum-2026-11-26-size-rotation-and-incremental-readback); synthetic Linux coverage includes torn-tail recovery, Recent checkpoints, FIFO and hard-link refusal |
| Hooks operator status | done | [Status commands and schema](README.md#hooks-status); read-only inventory, explicit `not_inspected` for TOML, and bounded telemetry summary |
| Real-model runs for Copilot CLI and Codex CLI | todo | Scripted-model evidence exists |
| OpenCode v2 forwarding plugin | done | [Request-only pilot](harnesses/opencode.md#v2-pilot-design); no settlement, service qualification or Kilo compatibility claim |
| Shared reader for Claude-shaped payloads | wip | `harnesses/payload.rs` holds what adapters share today |
| Capture recipe per harness | wip | `scripts/hooks/harness/` has the scripted model and capture drivers for Codex, Copilot and OpenCode |
| Contract-page template | todo | So each new page records the same fields as this tracker |

For M1, join the attempted call, returned marker denial and harness receipt
to the **same call** before attributing an absent canary to the hook. A model
refusal, failed launch or unrelated denial is inconclusive. For Claude run
`scripts/hooks/harness/claude-code-e2e.sh benign deny` together. The marker
check joins the harness receipt by tool-use ID and the outcome by decision
record ID. Preserve both scenario summaries and the tested revisions.

## Reference

- **Docs/Src, 2026-11-27:** [Hooks journal recovery and admission](adr/0005-telemetry-envelope.md#addendum-2026-11-26-size-rotation-and-incremental-readback) cover torn tails, Recent startup snapshots, nonblocking Unix opens and hard-link refusal. Synthetic Linux filesystem tests only; no new native Windows or macOS evidence.

- **Docs/Src, 2026-11-26:** [Hooks status](README.md#hooks-status) compares local installation files with adapter install output and reports TOML settings without inspecting their contents. [Claude Code's file-based managed locations](https://code.claude.com/docs/en/managed-settings#deploy-a-managed-settings-file) differ by OS. Synthetic tests exercise the local reports, not harness activation.

- **Docs/Src, 2026-11-26:** [Hooks record rotation and incremental readback](adr/0005-telemetry-envelope.md#addendum-2026-11-26-size-rotation-and-incremental-readback) share the journal generation convention. Linux tests exercise the bounded lock wait and append fallback.

- **Docs/Src, 2026-11-26:** the [Hooks envelope contract](adr/0005-telemetry-envelope.md#addendum-2026-11-26-strict-readback)
  defines strict record readback; synthetic runtime tests exercise all registered adapters.
- **Docs/Src, 2026-11-26:** [Hooks telemetry label handling](adr/0005-telemetry-envelope.md#addendum-2026-11-26-bounded-telemetry-labels)
  is shared by the writer and strict reader. Evidence is from synthetic runtime tests.
- **Docs/Src, 2026-11-26:** [Hooks telemetry line limit](adr/0005-telemetry-envelope.md#addendum-2026-11-26-strict-readback)
  is shared by the writer and reader. Synthetic tests cover replacement and outcome linkage.

Each entry was read from the linked primary sources on the date shown and is
**Docs/Src** unless marked otherwise. Nothing below was confirmed by running
the harness unless its contract page says so. "Failure default" is what the
harness does when the hook crashes or times out.

### Implemented and captured

| Harness | Contract page | Evidence |
| --- | --- | --- |
| Claude Code | [claude-code.md](harnesses/claude-code.md) | [E2E reports](e2e/) |
| GitHub Copilot CLI | [copilot-cli.md](harnesses/copilot-cli.md) | [E2E reports](e2e/) |
| OpenAI Codex CLI | [codex-cli.md](harnesses/codex-cli.md) | [E2E reports](e2e/) |
| OpenCode | [opencode.md](harnesses/opencode.md) | Capture (2.2.5); E2E request-only standalone pilot at 2.2.5 and narrow ordinary/nested pairs at installed 2.3.2, checked 2026-11-17 ([report](e2e/2026-11-17-integrated-pilot.md)) |

### Cursor

Checked 2026-11-17.

- Links: [hooks](https://cursor.com/docs/hooks),
  [third-party hooks](https://cursor.com/docs/reference/third-party-hooks),
  [CLI changelog](https://cursor.com/docs/cli/changelog),
  [1.7 release](https://cursor.com/changelog/1-7) (hooks introduced, 2025-09-29).
- Paths: `~/.cursor/hooks.json`; `<project>/.cursor/hooks.json`; managed
  `/etc/cursor/hooks.json`, macOS `/Library/Application Support/Cursor/`,
  Windows `C:\ProgramData\Cursor\`; team dashboard.
- Pre-execution events: `preToolUse`, `beforeShellExecution`,
  `beforeMCPExecution`, `beforeReadFile`, `beforeSubmitPrompt`.
- Decisions: allow, deny, ask on shell and MCP events; `preToolUse` deny only.
  Exit 2 denies.
- Failure default: open; `failClosed: true` per script.
- Payload: `conversation_id`, `generation_id`, `transcript_path`,
  `workspace_roots`. Shell tool is named `Shell`.
- Notes: also loads hooks from Claude Code settings files by default, mapping
  event and tool names. CLI event coverage has no official table (**3P**:
  staff forum replies).

### Gemini CLI

Checked 2026-11-17.

- Links: [hooks](https://geminicli.com/docs/hooks/),
  [reference](https://geminicli.com/docs/hooks/reference/),
  [repository](https://github.com/google-gemini/gemini-cli)
  (`packages/core/src/hooks/hookRunner.ts`).
- Paths: `~/.gemini/settings.json`; `<project>/.gemini/settings.json`;
  managed `/etc/gemini-cli/settings.json`; extensions.
- Pre-execution events: `BeforeTool`, `BeforeAgent`, `BeforeModel`,
  `BeforeToolSelection`.
- Decisions: allow, deny, argument rewrite; no ask. Exit 2 blocks.
- Failure default: open; default timeout 60 s.
- Payload: `session_id`, `transcript_path`, `cwd`, `hook_event_name`,
  `timestamp`.
- Notes: tool hooks since v0.20.0, on by default since v0.27.0. Documentation
  and source disagree on exit codes other than 0, 1 and 2. Consumer tiers
  stopped on 2026-06-18; paid API keys and enterprise continue.

### Antigravity (CLI, IDE, app)

Checked 2026-11-17.

- Links: [hooks](https://antigravity.google/docs/hooks),
  [plugins](https://antigravity.google/docs/build-plugins.md).
- Paths: `.agents/hooks.json`; `~/.gemini/config/hooks.json`; plugin
  `hooks.json`. No managed hook path documented.
- Pre-execution events: `PreToolUse`, `PreInvocation`.
- Decisions: `allow`, `auto_approve`, `deny`, `ask`, `force_ask`,
  `deny_unless_prior_grant`, on stdout only. A non-zero exit is logged and
  ignored.
- Failure default: open; default timeout 30 s.
- Payload: camelCase; `conversationId`, `transcriptPath`, `workspacePaths`,
  `toolCall.name`, `toolCall.args`.
- Notes: does not read other harnesses' settings for hooks.

### Qwen Code

Checked 2026-11-17.

- Links: [hooks](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/),
  [repository](https://github.com/QwenLM/qwen-code).
- Paths: `~/.qwen/settings.json`; `<project>/.qwen/settings.json`; managed
  `/etc/qwen-code/settings.json`.
- Pre-execution events: `PreToolUse`, `PermissionRequest`,
  `UserPromptSubmit`.
- Decisions: deny, ask. Exit 2 blocks.
- Failure default: open; command timeout 60 s.
- Payload: `session_id`, `transcript_path`, `cwd`, `permission_mode`.
- Notes: also offers HTTP, in-session function and prompt hooks. On by default
  since v0.14.0.

### Factory Droid

Checked 2026-11-17.

- Links: [hooks reference](https://docs.factory.com/reference/hooks-reference),
  [release notes](https://docs.factory.com/changelog/release-notes).
- Paths: `~/.factory/` and `<project>/.factory/` (`settings.json`,
  `settings.local.json`, `hooks.json`); `--settings`; organization-managed.
- Pre-execution events: `PreToolUse`, `UserPromptSubmit`, `PreCompact`.
- Decisions: `permissionDecision` allow, deny, ask. Exit 2 blocks.
- Failure default: open; `onFailure: "block"`; default timeout 60 s.
- Payload: `session_id`, `transcript_path`, `cwd`, `permission_mode`. Shell
  tool is named `Execute`.

### Cline

Checked 2026-11-17.

- Links: [repository](https://github.com/cline/cline)
  (`sdk/packages/core/src/hooks/hook-file-hooks.ts`),
  [SDK plugins](https://docs.cline.bot/sdk/plugins.md),
  [hooks announcement](https://cline.bot/blog/cline-v3-36-hooks).
- Paths: extension `.clinerules/hooks/` and `~/Documents/Cline/Hooks/`; CLI
  `.cline/hooks/`, `~/.cline/hooks/`, `--hooks-dir`.
- Pre-execution events: `PreToolUse`, `UserPromptSubmit`, `TaskStart`.
- Decisions: `{"cancel": true, "errorMessage": ...}` on stdout stops the run.
- Failure default: open; tool hook timeout 120 s.
- Payload: `taskId`, `workspaceRoots`, `clineVersion`; no transcript path.
  Extension and CLI payload shapes differ.

### Kilo

Checked 2026-11-17.

- Links: [plugins](https://kilo.ai/docs/automate/extending/plugins),
  [repository](https://github.com/Kilo-Org/kilocode)
  (`packages/plugin/src/index.ts`).
- Paths: `~/.config/kilo/plugin/`; `<project>/.kilo/plugin/`; `plugin` array
  in `kilo.json`.
- Pre-execution events: `tool.execute.before`, `permission.ask`.
- Decisions: throw to block.
- Failure default: a throw aborts the call; no timeout.
- Payload: `tool`, `sessionID`, `callID`.

### Pi

Checked 2026-11-17.

- Links: [repository](https://github.com/earendil-works/pi),
  [extensions](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md).
- Paths: `~/.pi/agent/extensions/`; `<project>/.pi/extensions/` (after
  trust); `settings.json`; `-e`.
- Pre-execution events: `tool_call`, `user_bash`, `input`.
- Decisions: `{block: true, reason}`.
- Failure default: closed (a handler error blocks the tool); no timeout.
- Payload: session id and session file through the extension context,
  `cwd`, `toolCallId`.

### Goose

Checked 2026-11-17.

- Links: [hooks](https://goose-docs.ai/docs/guides/context-engineering/hooks/),
  [repository](https://github.com/aaif-goose/goose).
- Paths: `~/.agents/plugins/<name>/hooks/hooks.json`;
  `<project>/.agents/plugins/<name>/hooks/hooks.json`.
- Pre-execution events: `PreToolUse`, `BeforeShellExecution`,
  `BeforeReadFile`, `UserPromptSubmit`.
- Decisions: only `PreToolUse` and `Stop` block; exit 2 or
  `{"decision": "block"}`; no ask.
- Failure default: open; `on_failure: block`; default timeout 30 s.
- Payload: `session_id`, `working_dir`, `tool_call_id`.
- Notes: blocking since v1.35.0.

### Kiro

Checked 2026-11-17.

- Links: [hooks](https://kiro.dev/docs/hooks/),
  [types](https://kiro.dev/docs/hooks/types/),
  [actions](https://kiro.dev/docs/hooks/actions/),
  [CLI V3 migration](https://kiro.dev/docs/cli/v3/hooks-migration/),
  [changelog](https://kiro.dev/changelog).
- Paths: `<project>/.kiro/hooks/*.json`; `~/.kiro/hooks/` (CLI V3); `hooks`
  array in an agent profile. No managed path documented.
- Pre-execution events: `PreToolUse`, `PermissionRequest` (CLI 3.4.0 and
  later).
- Decisions: exit 2 blocks; allow, ask, deny and input rewrite on CLI 3.4.0
  and later.
- Failure default: other exit codes warn and proceed; timeout behavior not
  documented. Default timeout 60 s.
- Payload (CLI): `hook_event_name`, `cwd`, `session_id`, `tool_name`,
  `tool_input`.

### Crush

Checked 2026-11-17.

- Links: [hooks](https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md).
- Paths: `crushrc`, `.crushrc`, `~/.config/crush/`.
- Pre-execution events: `PreToolUse`, `PermissionRequest`.
- Decisions: allow, deny. Exit 2 blocks; exit 49 halts the turn.
- Failure default: open; default timeout 30 s.
- Payload: `session_id`, `cwd`, `tool_use_id`.

### Junie CLI

Checked 2026-11-17.

- Links: [hooks](https://junie.jetbrains.com/docs/junie-cli-hooks.html).
- Paths: `~/.junie/config.json`; extension `hooks/hooks.json`. Project
  configuration is not read for hooks by default.
- Pre-execution events: `PreToolUse`, `PermissionRequest`,
  `UserPromptSubmit`.
- Decisions: allow, ask, block, deny. Exit 2 blocks.
- Failure default: open; `blockOnError: true`; `PreToolUse` timeout 10 s.
- Payload: `tool_name`, `tool_input`; no session id documented on tool
  events.

### Auggie CLI

Checked 2026-11-17.

- Links: [hooks](https://docs.augmentcode.com/cli/hooks).
- Paths: `~/.augment/settings.json`; `<workspace>/.augment/settings.json`
  and `settings.local.json`; managed `/etc/augment/settings.json`.
- Pre-execution events: `PreToolUse`, `PromptSubmit`, `SessionStart`.
- Decisions: only `PreToolUse` blocks. Exit 2 blocks.
- Failure default: open; default timeout 60 s.
- Payload: `conversation_id`, `workspace_roots`, `cwd`.

### Hermes Agent

Checked 2026-11-17.

- Links: [hooks](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks),
  [repository](https://github.com/NousResearch/hermes-agent).
- Paths: `hooks:` in the profile `config.yaml`; managed
  `/etc/hermes/config.yaml`; consent in
  `~/.hermes/shell-hooks-allowlist.json`.
- Pre-execution events: `pre_tool_call` (shell hook and Python plugin).
- Decisions: block; no ask. Exit 2 or a block decision on stdout.
- Failure default: shell hooks open, `fail_closed: true` per entry, timeout
  60 s; plugin timeout closes.
- Payload: `session_id`, `cwd`, `profile`.

### OpenHands

Checked 2026-11-17.

- Links: [hooks](https://docs.openhands.dev/openhands/usage/customization/hooks.md),
  [CLI repository](https://github.com/OpenHands/OpenHands-CLI).
- Paths: `<cwd>/.openhands/hooks.json`, else a user-level `hooks.json`.
- Pre-execution events: `PreToolUse`, `UserPromptSubmit`.
- Decisions: allow, deny. Exit 2 blocks.
- Failure default: open; default timeout 60 s.
- Payload: `session_id`, `working_dir`, `event_type`. Shell tool is named
  `terminal`.

### Devin Desktop and CLI

Checked 2026-11-17. Devin Desktop was Windsurf until 2026-06-02.

- Links: [hooks overview](https://docs.devin.ai/cli/extensibility/hooks/overview.md),
  [lifecycle hooks](https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks.md),
  [desktop controls](https://docs.devin.ai/desktop/controls).
- Paths: `.devin/hooks.v1.json`; `.devin/config.json` and
  `config.local.json`; `~/.config/devin/config.json`; managed
  `/etc/devin/hooks.json`.
- Pre-execution events: `PreToolUse`, `PermissionRequest`,
  `UserPromptSubmit`.
- Decisions: approve, block, input rewrite; no ask. Exit 2 blocks.
- Failure default: open; `fail_closed: true`.
- Payload: `session_id`, `prompt_id`. Tool names are its own (`exec`,
  `edit`, `read`).
- Notes: also loads hooks from Claude Code settings files by default.

### Amp

Checked 2026-11-17.

- Links: [plugins](https://ampcode.com/docs/customize/plugins),
  [plugin API](https://ampcode.com/manual/plugin-api).
- Paths: `.amp/plugins/`; `~/.config/amp/plugins/`; managed settings
  `/etc/ampcode/managed-settings.json`.
- Pre-execution events: `tool.call`.
- Decisions: `allow`, `reject-and-continue`, `modify`, `synthesize`,
  `error`.
- Failure default: not documented.
- Payload: `thread.id`, `toolUseID`, `tool`, `input`.

### OpenClaw

Checked 2026-11-17.

- Links: [tool policy](https://docs.openclaw.ai/plugins/hooks/tool-policy.md),
  [hook reference](https://docs.openclaw.ai/plugins/hooks/reference),
  [repository](https://github.com/openclaw/openclaw).
- Paths: `~/.openclaw/extensions`; `plugins.load.paths` and
  `plugins.entries` in configuration.
- Pre-execution events: `before_tool_call`.
- Decisions: `{block: true, blockReason}`, `requireApproval`.
- Failure default: closed on throw or timeout; default timeout 15 s.
- Payload: `sessionId`, `sessionKey`, `agentId`, `runId`, `toolCallId`.

### VS Code Copilot agent mode

Checked 2026-11-17.

- Links: [VS Code hooks](https://code.visualstudio.com/docs/copilot/customization/hooks),
  [hooks configuration](https://docs.github.com/en/copilot/reference/hooks-configuration),
  [hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference).
- Paths: `.github/hooks/*.json`; `~/.copilot/hooks/`; inline in
  `.github/copilot/settings.json` and `~/.copilot/settings.json`.
- Pre-execution events: `preToolUse`, `permissionRequest`,
  `userPromptSubmitted`.
- Decisions: `permissionDecision` allow, deny, ask.
- Failure default: a hook error denies; a timeout proceeds. Default timeout
  30 s.
- Payload: `sessionId`, `timestamp`, `cwd`, `toolName`, `toolArgs`.
- Notes: preview. Shares the Copilot harness with Copilot CLI; default since
  VS Code 1.143.

### Second survey batch

Checked 2026-11-17 in one pass over vendor documentation and source, not
cross-checked by a second reader and not run. "Not recorded" means the pass
did not establish it.

| Harness | Links | Configuration | Blocks by | Failure default | Payload | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| CodeBuddy | [hooks](https://www.workbuddy.ai/docs/cli/hooks), [Tencent Cloud](https://intl.cloud.tencent.com/document/product/1256/77296) | `~/.codebuddy/settings.json`, `<project>/.codebuddy/settings.json`, `.codebuddy/settings.local.json`; plugin `hooks/hooks.json` | Exit 2; `permissionDecision` deny, ask, allow | Not recorded | Claude-shaped | Docs |
| Command Code | [hooks reference](https://commandcode.ai/docs/hooks/reference) | `~/.commandcode/settings.json`, `.commandcode/settings.json` | Exit 2; `permissionDecision` deny | Not recorded | Claude-shaped; own tool names such as `shell_command` | Docs |
| DeepSeek Harness | [tool pipeline](https://github.com/deepseek-ai/DeepSeek-Harness/blob/HEAD/docs/tool-execution-pipeline.md), [configuration](https://github.com/deepseek-ai/DeepSeek-Harness/blob/HEAD/docs/config-catalog.md) | Plugin configuration | A plugin on `tools/pre-execute` returns deny or ask; experimental bridge plugins run Claude-format and Codex-format command hooks | Not recorded | Own plugin API | Src |
| Gajae-Code | [hooks](https://github.com/Yeachan-Heo/gajae-code/blob/HEAD/docs/hooks.md) | `~/.gjc/agent/hooks/pre/` | Handler returns `{ block: true, reason }`; a thrown error also blocks | No timeout | Pi extension API, Oh My Pi variant | Src |
| Grok Build | [hooks](https://docs.x.ai/build/features/hooks), [user guide](https://github.com/xai-org/grok-build/blob/HEAD/crates/codegen/xai-grok-pager/docs/user-guide/10-hooks.md) | `~/.grok/hooks/*.json`, `<project>/.grok/hooks/*.json`, `~/.grok/config.toml`; managed `/etc/grok/requirements.toml`; also reads Claude Code and Cursor hook files | Exit 2; `permissionDecision` allow, deny, ask, defer | Open on timeout or crash; default timeout 5 s | Own camelCase (`hookEventName`, `sessionId`, `toolName`, `toolInput`) | Docs/Src |
| Jcode | [hooks](https://github.com/1jehuang/jcode/blob/HEAD/docs/HOOKS.md) | `~/.jcode/config.toml` `[hooks]`; `JCODE_HOOK_PRE_TOOL` | Exit 2; `permissionDecision` deny; ask also blocks | Open on other failures; 5 s | Own: tool input on stdin, `JCODE_HOOK_*` environment | Src |
| Kilo Code extension | [plugins](https://kilo.ai/docs/automate/extending/plugins) | `~/.config/kilo/plugin/`, `.kilo/plugin/` | A thrown error in `tool.execute.before` | Not recorded | OpenCode plugin API, shared with Kilo | Docs |
| Kimchi | [hooks](https://github.com/getkimchi/kimchi/blob/HEAD/docs/hooks.md) | `~/.config/kimchi/harness/hooks/bash/*.sh`, `.kimchi/hooks/bash/*.sh` | Shell tool only: exit 2 or `{"decision":"block"}`. Also Pi packages and an opt-in Claude Code hook adapter | Open on other failures | Own for the shell hooks; Pi extension API | Src |
| Kimi CLI | [hooks](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/hooks.html), [earlier CLI](https://github.com/MoonshotAI/kimi-cli/blob/HEAD/docs/en/customization/hooks.md) | `~/.kimi-code/config.toml` `[[hooks]]`; earlier CLI `~/.kimi/config.toml` | Exit 2; `permissionDecision` deny | Open on error or timeout; 30 s | Claude-shaped, with `tool_call_id` | Docs/Src |
| MiniMax Code | [hooks](https://github.com/MiniMax-AI/minimax-code/blob/HEAD/docs/hooks.md) | Plugin manifest `.minimax-plugin/plugin.json` | `permissionDecision` allow, deny, ask, defer | Timeout 1 to 10 s | Claude-shaped; lowercase tool names | Src |
| MiMo Code | [plugin API](https://github.com/XiaomiMiMo/MiMo-Code/blob/HEAD/packages/plugin/src/index.ts) | `~/.config/mimocode`, `.mimocode/`, `MIMOCODE_CONFIG_DIR` | A thrown error in `tool.execute.before`, by OpenCode's semantics | Not recorded | OpenCode plugin API | Src |
| Muse Code | [extending](https://dev.meta.ai/docs/muse-code/extending), [configuration](https://dev.meta.ai/docs/muse-code/configuration) | `<project>/.muse/hooks.json`; `hooks` in `~/.config/muse/settings.json`; a managed path | Documented as able to block; the decision contract is not on the public pages | Not recorded | Not recorded | Docs, partial |
| Mux (renamed Xum) | [tool hooks](https://github.com/coder/mux/blob/HEAD/docs/hooks/tools.mdx), [plugin hooks](https://github.com/coder/mux/blob/HEAD/docs/hooks/plugins.mdx) | `.xum/tool_pre`, `~/.xum/tool_pre`; `~/.xum/plugins` | `tool_pre`: any non-zero exit. Plugin hooks: `permissionDecision` deny | `tool_pre` timeout 10 s | Own (`XUM_TOOL`, `XUM_TOOL_INPUT_PATH`) | Src |
| Oh My Pi | [hooks](https://github.com/can1357/oh-my-pi/blob/HEAD/docs/hooks.md) | `.omp/hooks/pre/`, `~/.omp/agent/hooks/pre/` | Handler returns `{ block: true, reason }` | Not recorded | Pi extension API, own variant | Src |
| Qoder | [CLI hooks](https://docs.qoder.com/cli/hooks), [reference](https://docs.qoder.com/cli/hooks-reference), [IDE hooks](https://docs.qoder.com/extensions/hooks), [Lingma edition](https://help.aliyun.com/en/lingma/guide-for-using-hooks) | `~/.qoder/settings.json`, `.qoder/settings.json`, `.qoder/settings.local.json`; Lingma uses `.lingma/` | Exit 2; `permissionDecision` deny, ask, allow | Not recorded | Claude-shaped | Docs |
| Reasonix | [extensions](https://github.com/esengine/DeepSeek-Reasonix/blob/HEAD/docs/EXTENSIONS.md) | `.reasonix/settings.json` | Exit 2, or a timeout, on gating events | Blocks on timeout | Own camelCase (`toolName`, `toolArgs`) | Src |
| Senpi | [extensions](https://github.com/code-yeongyu/senpi/blob/HEAD/packages/coding-agent/docs/extensions.md) | `~/.senpi/agent/extensions/*.ts`, `.senpi/extensions/*.ts` | Handler returns `{ block: true }` | Not recorded | Pi extension API | Src |
| Trae | [hook reference](https://docs.trae.ai/ide/hook-configuration-reference) | `~/.trae/hooks.json`, `<project>/.trae/hooks.json` | Exit 2; `permissionDecision` | Not recorded | Claude-shaped with additions (`workspace_roots`); tool names such as `RunCommand` | Docs |
| Mistral Vibe | [hooks](https://docs.mistral.ai/vibe/code/cli/hooks) | `~/.vibe/hooks.toml`, `./.vibe/hooks.toml` | Exit 0 with `{"decision":"deny"}` | A failed hook is a warning unless `strict = true` | Own, near Claude field names | Docs |
| ZCode | [hooks](https://zcode.z.ai/cn/docs/hooks) | `~/.zcode/cli/config.json` with `hooks.enabled`; plugin `hooks/hooks.json` | Exit 2; `permissionDecision` deny | Not recorded | Claude-shaped | Docs |
| Open Interpreter | [hooks](https://github.com/openinterpreter/open-interpreter/blob/HEAD/docs/hooks.md) | `~/.openinterpreter/hooks.json`, `~/.openinterpreter/config.toml` | `permissionDecision` deny | Not recorded | Codex-shaped | Src |
| Firebender | [hooks](https://docs.firebender.com/multi-agent/hooks.md) | `.firebender/hooks.json`, `~/.firebender/hooks.json` | Exit 2; `decision` deny | Not recorded | Own camelCase events | Docs |
| gptme | [hooks](https://gptme.org/docs/hooks.html) | Registered in Python; no file form | `TOOL_EXECUTE_PRE` handler denies | Not recorded | Own Python API | Docs |

Families in this batch: Kilo Code extension and MiMo Code use the OpenCode
plugin API; Gajae-Code, Oh My Pi, Senpi and Kimchi build on Pi; CodeBuddy,
Qoder, Command Code, ZCode, Kimi CLI, MiniMax Code and Trae are Claude-shaped
with their own configuration files and, in places, tool names.

### No usable hook

| Harness | State | Link |
| --- | --- | --- |
| Continue CLI | Hook code ships; the pre-tool event is not fired | [pull request](https://github.com/continuedev/continue/pull/11029) |
| Zed agent | Tool permission rules only | [tool permissions](https://zed.dev/docs/ai/tool-permissions) |
| Warp | Hooks specified, not released | [repository](https://github.com/warpdotdev/warp) (`specs/agent-hooks/architecture.md`) |
| Codebuff, Freebuff | One codebase; the SDK observes events and cannot stop a tool | [SDK](https://www.codebuff.com/docs/advanced/sdk) |
| Fx | Hook points are internal; SDK hooks only observe | [docs](https://fx.sh/docs), [observer hooks](https://github.com/vercel-labs/fx/blob/HEAD/sdk/semantic-observer-hooks.md) |
| Proma | The application's own permission callback only | [repository](https://github.com/proma-ai/Proma) |
| Plandex | Server-internal lifecycle hooks only | [source](https://github.com/plandex-ai/plandex/blob/HEAD/app/server/hooks/hooks.go) |
| OpenCodeReview | A fixed set of review tools; no hook in the README | [repository](https://github.com/alibaba/open-code-review) |
| Prime Agent | No hook in the README or file listing | [repository](https://github.com/PrimeIntellect-ai/prime-agent) |
| Trae Agent | No hook in the README or file listing; distinct from the Trae IDE | [repository](https://github.com/bytedance/trae-agent) |

Catalog clients that are not coding harnesses, judged from the site or README
only: Aside, a [browser agent](https://aside.com/); BB, which
[runs other agents' CLIs](https://github.com/get-bb/bb/blob/HEAD/docs/provider-bridge-protocol.md),
so the wrapped agent's hooks apply; Hindsight, a
[memory server](https://github.com/vectorize-io/hindsight); LM Studio, a model
runner whose [plugins](https://lmstudio.ai/docs/typescript/plugins) add tools;
and Unsloth, [model training and inference](https://github.com/unslothai/unsloth).

Aider's hook status and Roo Code's lifecycle status lack primary citations
in this survey; neither is a verified negative.

### Session stores

Hooks and stored sessions are separate evidence sources. Supported session
sources and their paths are in [Session Sources](../session-sources.md) and
the [Source Validation Matrix](../source-validation-matrix.md). Candidate
locations for other agents are in the pinned catalog
(`crates/telltale-discover/data/tokscale-registry.tsv`); a catalog entry is an
unconfirmed location, not support.

## Open questions

Settle each with a capture at a pinned version, then move the answer into the
harness's entry.

- Cross-harness hook imports: what payload an importing harness sends to a
  hook it loaded from another harness's settings.
- Gemini CLI: exit codes other than 0, 1 and 2.
- Kiro: hook timeout and a hook that cannot start.
- Cursor: `beforeReadFile` in the CLI; the default timeout.
- Antigravity: a managed hook path; pre-tool hooks in the IDE and app.
- Devin: which files still carry Windsurf-format hooks.
- Amp: a plugin handler that throws or hangs.
- Junie: hooks in the IDE plugin.
- Muse Code: the decision contract and the payload.
- Cherry Studio: whether hooks in its private agent configuration load
  ([runtime notes](https://github.com/CherryHQ/cherry-studio/blob/HEAD/packages/agent-runtime-claude-code/README.md)).
- Xiaomi MiMo AI: whether the desktop build loads plugins
  ([design note](https://github.com/XiaomiMiMo/MiMo-Code/blob/HEAD/docs/compose/spec/plugin-host-sdk.md)).
- Snowflake Cortex Code: whether it runs tools locally and loads hooks from a
  file ([SDK hooks](https://docs.snowflake.com/en/user-guide/cortex-code-agent-sdk/hooks)).
- WorkBuddy: no readable vendor page on hooks was found.
- Mux: whether installs from before the rename still read the old paths.
- Kilo Code extension: whether the older extension has any hook.

## Log

- 2026-11-17: page created. Survey stage recorded for all harnesses above
  from vendor documentation and source; all links checked. Milestones M1 to
  M4 and the generated progress page added.
- 2026-11-17: separated historical enforcement from integrated qualification; scoped M2 to the OpenCode v2 pilot and its correlation and failure gates. The November 4 E2E reports cover the earlier executable: Claude used a live model, Copilot and Codex used scripted models.
- 2026-11-17: M1 integrated canary pairs passed with scripted models: Claude 2.1.327 (separate from the 2.1.318 capture), Copilot 1.0.105, Codex 0.166.0. Same-call marker receipt and settlement checks reject inconclusive runs.
- 2026-11-17: M2 2.2.5 standalone request-only pilot passed ordinary/nested pairs, concurrent repeated inner denials, sibling control, detect-only and bounded transport-failure checks. Outcomes deliberately remain unknown; startup is fail-open and managed/service operation remains unqualified. See the integrated report for exact bounds and evidence.
- 2026-11-17: installed OpenCode 2.3.2 also passed the ordinary/nested pairs (E2E, standalone, scripted model), separately from the 2.2.5 pin. Native deny and non-auto ask controls at 2.2.5 confirmed that a plugin no-op does not loosen permissions.
- 2026-11-17: corrected the plugin deadline/reaping defect found in parent review; caller settlement no longer waits for inherited pipe closure, never signals a known-exited group, and keeps unreaped children counted. Old timeout qualification withdrawn. Corrected-plugin 2.2.5 matrix (17 cases) and installed 2.3.2 pairs (4 cases) passed; two focused process regressions fail on the old artifact and pass on the correction. Current digest and evidence are in the integrated report.
- 2026-11-17: the OpenCode v2 plugin gained a configurable waiting queue; all 17 pilot scenarios were rerun against it on installed 2.3.2 (E2E, standalone, scripted model), not on the 2.2.5 pin.
- 2026-11-17: added the Catalog column and a row for every client in the pinned client catalog, 34 of them unsurveyed; added milestones M3 to M5 and the managed-install row for OpenCode v2; the progress page gained coverage counts.
- 2026-11-17: second survey batch: the 34 catalog clients not yet covered and 11 harnesses the catalog does not list. Of the 34, 20 have a mechanism that can block a tool call (one with its contract not public), 6 have none, 5 are not coding harnesses and 3 are undetermined. One pass, Docs/Src, not cross-checked; all links checked. Added milestone M6.
- 2026-11-17: merged main's driver change (each scenario states the hook decision it expects) with the same-call join; the merged Codex and Copilot drivers passed their pairs on installed 0.167.0 and 1.0.105 (E2E, scripted models). The join now hashes tool arguments as the harness sent them.
- 2026-11-18: merged main's change that evaluates each hook call through its client's tool table; the OpenCode pilot uses OpenCode's table and all 17 of its scenarios passed again on installed 2.3.2 (E2E, scripted model).
- 2026-11-18: the Adapter stage no longer names normalization tests: since #225 a harness's built-in tools are declared in its client's tool table. The native parity test now sends OpenCode's captured shapes through its registered adapter name.
- 2026-11-18: hooks self-protection rules are Rule v2 documents (rule names unchanged); README and architecture wording updated to rule names and Rule v2, no harness facts changed.
- 2026-11-19: a payload that names no event now blocks unless both `on_error` and `on_unevaluable` are `allow`, a named pre-execution call without its tool input key is unusable, and a hook panic is recorded (`hook_panicked`). Contract tests only (Bin); no real-harness rerun. Claude Code, Codex CLI and Copilot CLI pages updated.
- 2026-11-19: `settings` pins an existing user config root on the hook command (`--user-config-dir`), so a harness launched with `HOME` or `XDG_CONFIG_HOME` changed, emptied or removed keeps the user-level settings, and adds `--expect-enforce` when the configuration enforces, so a configuration that later does not load (pinned root deleted) denies tool calls; `check` lists the roots. Removing those variables on a harness launch is a self-protection deny. Contract tests only (Bin); no real-harness rerun. Claude Code, Codex CLI and Copilot CLI pages updated.
- 2026-11-20: `settings` pins the state directory in use on the hook command (`--state-dir`; for a command with its own config roots, the one those roots configure), so a harness launched with `TELLTALE_HOOKS_STATE_DIR`, `XDG_STATE_HOME` or `HOME` moved keeps its session history and writes its records there; a missing pinned directory is created owner-only, one that cannot be used gets the strict failure policy, and `check` says whether it is pinned. Contract tests only (Bin); no real-harness rerun. Claude Code, Codex CLI and Copilot CLI pages updated.
- 2026-11-21: architecture wording for the projection: a command's head goes with its own later chunks, several command members are evaluated apart, and an input past the projection budget is recorded as `pending_input_truncated`. No harness facts changed.
- 2026-11-21: architecture and threat model: a hook bounds every wait by one 25 s deadline, below the 30 s or longer timeouts of the installed tool-call hooks (Claude Code and Codex CLI 30 s, Copilot CLI 60 s; permission-request hooks are not evaluated) (`hook_deadline` when a call has no time left before its evaluation starts; a decision already evaluated is always delivered); one scan in flight is not interrupted. Runtime tests only (Lib, Integration); no harness facts changed.
- 2026-11-21: architecture gained a load benchmark section: `make hooks-load-bench` times parallel `telltale hooks claude-code hook` processes in a temporary hooks home and `--check` asserts the deadline bound. No harness facts changed.
- 2026-11-21: load benchmark figures recorded in the architecture section (16 parallel hooks, two CPUs and the full host): every call answered, none past the 25 s deadline, slowest 12.9 s; four `state_lock_timeout` answers in one in-process same-session scenario on two CPUs.
- 2026-11-21: hooks records carry how long a call waited for its session's lock (`evaluation.lock_wait_ms`, and `lock_wait_ms` on the error record of a call that gave up with `state_lock_timeout`), and the load benchmark reports its percentiles. Runtime tests only (Lib, Integration); no harness facts changed.
- 2026-11-22: architecture: a tool call past the projection budget that has session history is also read with it after its pieces (one scan of the history and the line the call is journaled as, within the recovery budget and the piece time limit); its findings are added, the `on_unevaluable` floor stays, and `evaluation.scans.history` records how that scan went. Runtime tests only (Integration); no harness facts changed.
- 2026-11-22: a hook whose pin on the command (`--state-dir`, `--user-config-dir`) replaced a source set to a different value names that source in its `session_start` record (`lifecycle.pinned_over`, names only), and `check` prints one `pinned over:` line per name. Contract tests only (Bin); no real-harness rerun; no harness facts changed.
- 2026-11-22: records of a hook command with `--state-dir` go to that directory (or to `hooks.telemetry_path` from its settings files). Contract tests only (Bin); no real-harness rerun; no harness facts changed.
- 2026-11-22: README "Updating configuration in place": the update order for deployment tools (stage under a non-YAML name and rename, one policy file, no dangling links, `check --config-dir` first, rule files before overrides) and what a hook does while its configuration does not load. Docs only; no harness facts changed.
- 2026-11-22: tamper prevention is opt-in (`hooks.tamper_prevention.enabled`, default off): the self-protection rules stay on and become tunable by override, policy and replacement unless locked; `check` lists thresholds, the lock state and, per harness, what blocks a call from inside the harness; `check --rules` lists effective rules. Quick starts no longer use `settings --fail-closed`, and the Codex exec-policy step is marked as not part of a default install. Contract tests only (Lib, Bin); no real-harness rerun; no harness facts changed.
- 2026-11-22: enforcement test signatures (`hooks.test_signatures.enabled`, default off): `echo TELLTALE_TEST_ASK` and `echo TELLTALE_TEST_DENY` match `tth.test.ask` and `tth.test.deny`, are decided on their own score and stay out of the session's score; deny and ask reasons start with what happened to the call and name the matched rules' categories. One real-binary matrix sends the test commands through all four entry points (observe, ask, deny, each tuning). Contract tests only (Lib, Bin); no real-harness rerun; no harness facts changed.
- 2026-11-22: `hooks.ask` (`human`, the default, or `model`): with `model` every harness is given a deny whose reason tells the model to stop and ask the user, where `human` uses the approval prompt of Claude Code and Copilot CLI; failure answers now start with what happened to the call. Contract tests only (Bin) on all four harnesses; no real-harness rerun, so what a live model does with the reason is not measured; no harness facts changed.
- 2026-11-22: README tuning: an override entry may name a chain (turns it off or rescores it; a chain turned off leaves its rules their points), and an entry that names no loaded rule is left out with `override left out` instead of failing the rule build. Contract tests only (Bin); no real-harness rerun; no harness facts changed.
- 2026-11-22: `check --rules --json` prints the rules a hook evaluates as the effective configuration document (`telltale.effective_configuration.v1`); README tuning notes that policies do not merge across config roots and that overrides set only `enabled` and `score`. Contract tests only (Bin); no real-harness rerun; no harness facts changed.
- 2026-11-22: grants (`hooks.grants.enabled`, default off; ADR 0010): the user allows a stopped call by typing `telltale allow` or `telltale allow session` as a prompt of its own; taken from the user-prompt event of Claude Code, Codex CLI and Copilot CLI (`can_grant`), not on the OpenCode pilot; a subagent's prompt is refused (Codex: by its `agent_id`, shape from the existing `subagent.jsonl` capture; Copilot: mapped to `other`). Contract tests only (Bin) on all four harnesses; no real-harness rerun, so the Claude Code `UserPromptSubmit` context output is not yet exercised with a live harness; no other harness facts changed.
- 2026-11-26: added the shared strict Hooks JSONL record consumer and synthetic runtime parity coverage for registered adapters. No harness stages changed.
- 2026-11-26: the shared Hooks writer bounds native telemetry labels and assigns deterministic stand-ins. Synthetic runtime tests only; no harness stages changed.
- 2026-11-26: the shared Hooks writer caps each telemetry line at 16 MiB and replaces oversized runtime records with linked error records. No harness stages changed.
- 2026-11-26: Hooks records rotate by size and the read-only feed resumes across retained generations. Synthetic runtime and process tests; no harness stages changed.
- 2026-11-26: Hooks telemetry falls back to append without rotation after a short lock wait; rotation and cleanup failures no longer report a successful append as failed. Synthetic Linux tests; no harness stages changed.
- 2026-11-26: added read-only Hooks status and the shared `check --json` configuration view. Synthetic CLI fixtures; no harness stages changed.
- 2026-11-26: Hooks status reports existing TOML settings as `not_inspected` when readable and within the size limit. Synthetic CLI fixtures cover TOML with and without inline hooks.
- 2026-11-27: tightened shared Hooks record recovery and admission: Recent startup snapshot checkpoints, torn-tail separation, nonblocking Unix opens and hard-link refusal. Synthetic Linux tests only; no harness stages changed.
- 2026-11-27: Hooks record arrays are bounded at 1024 items in the schema and the strict reader; the writer replaces a record over the bound with `telemetry_record_too_large`. Synthetic tests only; no harness stages changed.
