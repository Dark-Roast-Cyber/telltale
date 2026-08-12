# Policy Modes

Telltale operates in named policy modes that control what the scanner does with detections. Modes are explicit, documented, and map to the log-review phase that Telltale occupies today.

## Current Phase: Log-Review

Telltale is a batch log-review system. It discovers agent session stores, parses transcripts, applies deterministic detection rules, and emits JSONL events for SIEM ingestion. It does not hook into agent processes, intercept tool calls, make outbound review requests, or terminate sessions.

Three policy modes are available in the current phase:

### `observe`

Emit activity and health telemetry only. No detections or detection review metadata.

| Behavior | Setting |
| --- | --- |
| Activity events | emitted |
| Health events | emitted |
| Detection events | suppressed |
| Review metadata | not applicable |
| Operational alerts | emitted |

Use `observe` when onboarding a new host or agent source and you want to confirm discovery, parsing, and schema compliance without generating security noise.

In practice, `observe` is the behavior when no detection rules match or when a policy disables all rule categories:

```yaml
# observe-policy.yaml
name: observe
disabled_categories:
  - secret_access
  - credential_pattern
  - execution
  - download
  - install
  - exfiltration
  - persistence
  - approval_bypass
  - tool_injection
  - mcp_prompt_injection
```

### `alert`

Emit detections with deterministic response metadata for analyst review. This is the default and recommended mode for production log-review deployments.

| Behavior | Setting |
| --- | --- |
| Activity events | emitted (with `--emit-activity`) |
| Health events | emitted |
| Detection events | emitted |
| Review metadata | Native Event 3.0 uses deterministic response metadata and optional `timeline_anchors`; no embedded triage verdict |
| Operational alerts | emitted |

Detections follow the standard severity-to-behavior mapping:

| Score | Severity | Review metadata | Emission |
| ---: | --- | --- | --- |
| 0–19 | informational | deterministic response metadata | informational native detection/process-chain event; activity is separate |
| 20–49 | low | deterministic response metadata | detection event with response metadata |
| 50–69 | medium | deterministic response metadata | detection event with expanded context and response metadata |
| 70–89 | high | deterministic response metadata | detection event with deterministic response metadata |
| 90+ | critical | deterministic response metadata | detection event with deterministic response metadata |

This is the mode Telltale uses when `--policy` is omitted or when the loaded policy does not suppress all detection categories.

### `simulate-block`

Mark detections that *would* have been blocked without actually blocking anything. This mode produces the same telemetry as `alert` but adds a policy simulation tag so analysts can evaluate containment rules before enabling active enforcement.

| Behavior | Setting |
| --- | --- |
| Activity events | emitted |
| Health events | emitted |
| Detection events | emitted with `policy_mode: simulate-block` |
| Review metadata | deterministic Event 3.0 response metadata |
| Operational alerts | emitted |
| Session termination | never |

`simulate-block` is not yet implemented as a distinct CLI mode. Today, the same effect can be approximated by using a strict policy with `alert` behavior and reviewing the `response.recommended_action` field on detection events. A dedicated `--mode simulate-block` flag that stamps events with the policy mode is a future enhancement.

## Future Phases: Active Hook

The following modes require integration with agent runtimes or process control. They belong to a later phase after the log-review model proves accurate and the false-positive profile is stable.

### `confirm`

Require a human to approve containment before Telltale takes action.

| Behavior | Setting |
| --- | --- |
| Detection events | emitted |
| Review metadata | deterministic Event 3.0 response metadata |
| Containment action | queued for human approval |
| Session termination | only after explicit approval |

`confirm` would integrate with a ticketing system, chat bot, or approval UI. Telltale would emit a `containment_pending` event and wait for a `containment_approved` or `containment_denied` response before acting.

### `block`

Automatically deny or terminate sessions for high-confidence detections that match configured containment rules.

| Behavior | Setting |
| --- | --- |
| Detection events | emitted |
| Triage calls | none; downstream analyst review remains outside the scanner |
| Containment action | automatic for configured rules |
| Session termination | on match, without human approval |

`block` is the most aggressive mode. It requires:
- a mature detection corpus with documented false-positive rates below 5%;
- analyst review procedures tuned per rule category;
- explicit per-rule opt-in for automatic containment;
- audit logging of every containment action;
- a kill switch to revert to `alert` or `simulate-block`.

## Policy YAML

Telltale uses policy YAML to select active rule categories and rule IDs. This is separate from the policy mode concept:

```yaml
# config/policy.yaml
name: strict-workstation
enabled_categories:
  - secret_access
  - credential_pattern
  - exfiltration
  - mcp_prompt_injection
disabled_rules:
  - network.controlled_test_domain.darkroast
```

Load a policy at scan time:

```sh
telltale scan --once --policy config/policy.yaml --root ~/.codex/sessions
```

The policy YAML controls *which rules fire*. The policy mode controls *what happens when they fire*. In the current log-review phase, the mode is implicitly `alert` for all detections that pass the policy filter.

## Relationship to Other Features

| Feature | Policy Mode Interaction |
| --- | --- |
| Allowlists | Suppressed detections are logged at `informational` with `suppressed` tag regardless of mode. |
| Analyst review | Above-threshold events carry deterministic response metadata and optional anchors; suppressed detections remain informational. |
| Response contract | `recommended_action` and `response_playbook` are emitted in all modes. `simulate-block` may add a `would_block` flag in the future. |
| Operational alerts | Emitted in all modes. Not affected by detection policy mode. |
| Correlation | Cross-session correlation operates on emitted detection events, so it works in `alert` and `simulate-block`. |

## Mode Selection Guidance

| Scenario | Recommended Mode |
| --- | --- |
| First deployment on a new host | `observe` (disable all categories) |
| Tuning rules on a developer workstation | `alert` with a permissive policy |
| Production SIEM ingestion | `alert` with a strict policy |
| Evaluating containment rules | `simulate-block` (when implemented) |
| High-confidence automated response | `block` (future, after false-positive review) |
