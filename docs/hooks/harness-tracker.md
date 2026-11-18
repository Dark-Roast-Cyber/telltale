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
| Adapter | An adapter module is registered and its parse, render and normalization tests pass |
| E2E | A pinned real harness using the integrated `telltale hooks` install runs the permitted control, then returns the marker denial without executing the denied twin. Record build revision, harness version, platform, model mode and tested tool path ([method](harness-testing.md)). |
| Documented | Quick start, capability matrix and contract page describe the shipped behavior |

## Milestones

The bars count checklist cells. Verify the written gate against linked run
reports before declaring a milestone reached. Unassigned harnesses (`—`) are
survey candidates and do not count toward the bars. M3 to M5 are a working
proposal in priority order, not a commitment.

| Milestone | Name | Reached when |
| --- | --- | --- |
| M1 | Integrated command hooks | Linked control/deny reports for Claude Code, Copilot CLI and Codex CLI using the integrated executable |
| M2 | OpenCode v2 pilot | One pinned v2 install passes the ordinary-call, nested-call and failure gates in the OpenCode contract; report settlement limits |
| M3 | Adapter reuse | VS Code Copilot agent mode, Qwen Code and Factory Droid each have a capture and a linked control/deny report, through an existing adapter where the captured contract matches |
| M4 | Own-contract command hooks | Cursor, Gemini CLI, Antigravity and Cline each have a contract page, an adapter and a linked control/deny report |
| M5 | Plugin harnesses | OpenCode v2 passes its gates as a managed install; Kilo and Pi are enforced through a forwarding plugin with linked reports |

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
| Aside | `aside` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| BB | `bb` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Cherry Studio | `cherrystudio` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| CodeBuddy | `codebuddy` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Codebuff | `codebuff` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Command Code | `commandcode` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| DeepSeek Harness | `dsh` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Freebuff | `freebuff` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Fx | `fx` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Gajae-Code | `gjc` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Grok Build | `grok` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Hindsight | `hindsight` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Jcode | `jcode` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Kilo Code | `kilocode` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Kimchi | `kimchi` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Kimi CLI | `kimi` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| LM Studio | `lmstudio` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| MiMo Code | `micode` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| MiniMax Code | `mcode` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Mistral Vibe | `vibe` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Muse Code | `muse` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Mux | `mux` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Oh My Pi | `omp` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| OpenCodeReview | `opencodereview` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Prime Agent | `prime-agent` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Proma | `proma` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Qoder | `qoder` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Reasonix | `reasonix` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Senpi (OmO Native) | `senpi` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Trae | `trae` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Unsloth | `unsloth` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| WorkBuddy | `workbuddy` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| Xiaomi MiMo AI | `micode-desktop` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |
| ZCode | `zcode` | — | Unsurveyed | todo | todo | todo | todo | todo | todo | — | Survey |

### Shared work

Work that serves several harnesses.

| Item | Status | Notes |
| --- | --- | --- |
| E2E reports against `telltale hooks` | done | [Integrated report](e2e/2026-11-17-integrated-pilot.md); scripted models, narrow tool paths and versions only |
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

### No usable hook

| Harness | State | Link |
| --- | --- | --- |
| Continue CLI | Hook code ships; the pre-tool event is not fired | [pull request](https://github.com/continuedev/continue/pull/11029) |
| Zed agent | Tool permission rules only | [tool permissions](https://zed.dev/docs/ai/tool-permissions) |
| Warp | Hooks specified, not released | [repository](https://github.com/warpdotdev/warp) (`specs/agent-hooks/architecture.md`) |

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
