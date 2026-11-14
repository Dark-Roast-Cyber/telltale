# ADR 0008: Detect-only by default, enforcement by one setting, one gate

Status: Accepted. Amends points 1, 4 and 5 of
[ADR 0004](0004-decisions-and-enforcement-accounting.md).

## Context

Hooks ship in the default Telltale build, and Telltale is a detection tool
first. A hook that blocks by default, or that can block while set to observe,
makes installing it a risk to the work it watches. Observe mode existed, but
it was a check inside the runtime's happy path: the process boundary answered
unreadable payloads and invalid configuration on its own, with `ask`, `deny`
or a non-zero exit, without looking at the mode. An invalid configuration
denied every tool call whatever it was meant to say. Verdicts recorded in
observe mode counted as denials, so the record escalated on denials that
never happened and a session switched to enforce started from them.

## Decision

1. **Detect-only is the default.** `mode = "observe"` (also spelled
   `"detect"`) is what a hook runs with when nothing says otherwise.
   Enforcement is `mode = "enforce"` in the configuration: one setting, no
   rebuild, no change to the harness settings.
2. **One gate releases every answer** (`telltale_core::hooks::gate`). Nothing
   in a hook writes to stdout or chooses the exit status itself. It builds an
   `Answer`, and the gate, settled from the configuration before the payload is
   read, either releases it (enforce) or releases nothing: empty stdout, exit
   status 0. A detect-only hook also exits 0 after 20 s, so it is not a block
   where the harness blocks on a hook that times out. A panic is caught at the
   same boundary.
3. **The gate opens only for a configuration that was read and says
   `mode = "enforce"`.** No configuration, and a configuration that does not
   load and does not say so, are detect-only: detection continues on the
   defaults and a `config_invalid` record is written. A configuration that does
   not load but says `mode = "enforce"` at its top level keeps the old
   behavior and denies tool calls, so an operator's typo in an enforcing
   deployment is loud instead of silently detect-only. That one key is read
   leniently (unknown keys ignored; plain lines if the file is not TOML).
4. **Only returned denials count as denied attempts.** The repeated-denials
   escalation and `denied_attempts_before` count denials the harness was
   given. The session score is unchanged: it counts what the session did.
5. **Unreadable payloads are recorded.** The process boundary writes an
   `error` record for a payload it cannot use, in both modes, so an answer
   given outside the runtime and a detect-only hook that saw nothing are not
   silent.

## Rejected

- **A compile-time split (a detect-only build without the enforcement code).**
  The strongest form of "cannot block", but changing to block must not need a
  rebuild or a second binary. The gate gives the property at run time from one
  place that is small enough to read and test.
- **Failing closed on every configuration that does not load.** It makes a
  typo in a detect-only deployment block every tool call, which is the outcome
  detect-only exists to rule out.
- **Failing open on every configuration that does not load.** An enforcing
  deployment would stop enforcing on a typo with nothing on screen.
- **A mode flag on the hook command in the harness settings.** Two places to
  change, and the harness settings are the file that is hardest to change
  safely (Codex re-trusts a changed handler).

## Consequences

- Existing installations that relied on the old default must add
  `mode = "enforce"` to keep blocking. `telltale hooks check` prints the mode.
- Enforcement can be switched off by whoever can write the configuration
  file, by editing, damaging or deleting it. That was already true of editing
  it; the self-protection rules cover the file, and the real control is a
  configuration the agent cannot write (threat model).
- The generated settings, `settings --fail-closed` and the Codex exec-policy
  backstop are unchanged. The first two are harmless in detect-only mode
  because the hook always answers in time with exit 0; the exec-policy file
  acts natively and is for enforcing deployments only.
- The real-harness scripts set `mode = "enforce"` explicitly.
