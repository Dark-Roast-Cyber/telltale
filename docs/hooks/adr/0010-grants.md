# ADR 0010: Grants: the user can allow a stopped call

Status: Accepted. Extends [ADR 0004](0004-decisions-and-enforcement-accounting.md)
(never `allow`; the route of an ask) without changing it.

## Context

A hook's ask or deny was final for the session. On a harness with an approval
prompt a person could let one asked call run; everywhere else, and for every
deny, the only way forward was to change configuration or run the command
outside the agent. `hooks.ask: model` tells the model to ask the user, but
nothing the user answered changed what the hook did.

A harness's own permission prompt offers "this time", "for this session" and
"always". Operators and users expect the same from a tool that stops calls.
A hook cannot add choices to a harness's dialog, and half the supported
harnesses show none.

## Decision

1. **A grant removes Telltale's restriction; it is not an `allow`.** A call a
   grant covers gets no answer from the hook, so the harness's own permission
   flow decides it, as for any call Telltale has no opinion on.
2. **Three scopes.** This time (the stopped call, repeated unchanged, once),
   this session (the stopped call's detections on its tool, until the session
   ends), and always (for a project or for the user, kept in the user's
   configuration root, given by a command the user runs in a terminal).
   The first two are session state; the third is configuration.
3. **The grant line.** The user allows a stopped call by typing
   `telltale allow` or `telltale allow session` as a prompt of its own. The
   hook takes it only from the event a harness raises for the prompt of the
   person using it (`Adapter::can_grant`), only as the whole prompt, and
   applies it to the most recent stopped call. There is no code to copy: a
   code shown in the reason is readable by the model, so it would add typing
   and no protection.
4. **The prompt goes on to the model.** The hook does not swallow it. The
   model then retries without further instruction, and no harness needs a
   way to withhold a prompt. Where a harness documents context on that
   event, the hook adds what was granted.
5. **What a grant never covers.** A rule under `tth.tamper.`: Telltale's own
   protection is changed in configuration. A call the hook could not evaluate
   in full: there is no complete set of detections to grant. A call with a
   detection that was not granted: that detection decides. A deny, where the
   operator sets `hooks.grants.covers: ask`.
6. **Accounting.** The decision record of a covered call keeps the verdict
   the policy reached, its basis, score and detections, says nothing was
   returned, and names the grant (`decision.grant`). The call stays in the
   session's history, so a chain that later builds on it still fires and is
   decided on its own. It adds nothing to the session's score or attempt
   counts: what the user allowed must not make the session's other calls
   stricter. Making a grant and refusing a grant line are lifecycle records.
7. **Off by default** (`hooks.grants.enabled`), and by default a grant may
   cover a deny as well as an ask (`hooks.grants.covers: ask_and_deny`):
   a deny the user cannot lift is the dead end this decision removes.

## Trust boundary

A model must not be able to approve its own exception. Nothing a tool call
carries can grant: not a tool input, a tool result, a file, or a payload
field. A prompt written for a subagent is written by a model and is refused.
A harness with no event for the user's own prompt takes no grant line.

The user-prompt event shows that a prompt was submitted to the session, not
who typed it. An agent's process runs as the user, so a user-level install
cannot rule out automation that submits prompts; the harness's own approval
prompt has the same standing. Grants are therefore a convenience under the
user's control, recorded every time, and not a boundary. The boundary an
agent's user cannot cross remains a configuration root they cannot write:
exceptions an administrator wants enforced stay in `overrides.d` and the
policy there.

## Rejected alternatives

- **Promote an approved ask to a session grant automatically.** The user
  could not choose the scope, and harnesses that cannot ask would get
  nothing.
- **A one-time code in the reason.** See point 3.
- **Return `allow` for a granted call.** It would override the harness's own
  permission rules; ADR 0004 stands.
- **Let the hook write a permanent exception on a prompt.** A longer-lived
  effect needs the stronger channel: a command the user runs, writing
  configuration the hook only reads.
- **Count granted calls in the session's score.** A session would turn
  strict because of activity its user allowed.

## Consequences

- `Adapter` and `Context` gain `can_grant`; `SessionState` gains the offered
  call and the session's grants (bounded, cleared at session end);
  `decision.grant` is added to the record schema.
- The reason of a grantable call is one sentence longer, in both
  `reason_detail` forms.
- A session grant is as broad as the detections it names: a later call of
  the same tool with only those detections is not stopped. The decision
  record of every such call says so.
