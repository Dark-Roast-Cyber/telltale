# Real-harness results: grants on Claude Code 2.1.330, 2026-11-22

Run: `scripts/hooks/harness/claude-code-grant-e2e.py` (all scenarios), Telltale
`64a9968`, the installed Claude Code 2.1.330 against a scripted Messages
provider on loopback (no login, no model tokens), each scenario in a fresh
isolated `HOME` with `hooks.grants.enabled: true`, enforce mode and the
deterministic marker rules (`tth.e2e.deny_marker`). Raw per-scenario
summaries, content-free:
[`2026-11-22-claude-code-2.1.330-grants.summary.jsonl`](2026-11-22-claude-code-2.1.330-grants.summary.jsonl).

Method: one Claude Code process per session, two user prompts sent over
`--input-format stream-json`, the second after the first turn has ended. The
scripted model first runs `touch <canary> && echo TTH_E2E_DENY_MARKER`; after
the second prompt it repeats that call. The canary is ground truth for
execution; Telltale's decision and lifecycle records and what each hook
invocation printed are read alongside it.

| Scenario | Second prompt | Decisions (returned / grant) | Grant record | Canary | Result |
| --- | --- | --- | --- | --- | --- |
| control | `TTHRETRY: please try again.` | deny / -, deny / - | none | absent | pass |
| once | `telltale allow` | deny / -, deny not returned / `once`, deny / - | `grant`, `once` | present | pass |
| session | `telltale allow session` | deny / -, deny not returned / `session`, deny not returned / `session` (another call, same detection) | `grant`, `session` | both present | pass |
| resumed | `telltale allow` in a later `-p --resume` run of the same session | deny / -, deny / - | `grant_refused`, `no_offer` | absent | pass |

Findings:

1. Every denial's reason ended with the grant offer.
2. Claude Code raised `UserPromptSubmit` for the second prompt of a running
   session with the same `session_id`, and the hook took the grant line from
   it. A covered call got no answer from the hook and ran under Claude Code's
   own permissions; the record keeps the policy's verdict (`deny`), says it was
   not returned and names the grant.
3. A `once` grant was used by the first repeat; the next identical call was
   denied and offered again. A `session` grant covered a different command
   with the same detection.
4. The hook's `systemMessage` was shown as a notice (`UserPromptSubmit says:
   Telltale Hooks: allowed once: the stopped Bash call.`), and its
   `additionalContext` was in the model's next request.
5. A run that resumes a session by ID after its process ended keeps the
   `session_id`. The session's end cleared the offer, so the grant line in the
   resumed run allowed nothing and the repeat was denied.

Not covered here: Codex CLI and Copilot CLI (no live grant run yet; their
contract tests use the real binary and captured payload shapes), a live
model's behaviour after a grant, and the interactive terminal interface.
