# Policy Modes

Telltale uses policy YAML to select Rule v1 detections. The names below describe configuration outcomes and proposed future behavior, not selectable scanner modes.

## Current Phase: Log-Review

Telltale currently operates as a batch log-review system. It discovers agent
session stores, parses transcripts, applies deterministic detection rules, and
emits JSONL events for SIEM ingestion. It does not hook into agent processes,
intercept tool calls, make outbound review requests, or terminate sessions.

The long-term
engine separates detection (produces signals) from policy (produces decisions
such as allow, observe, warn, require approval, reprompt, block, and remediate)
and capability-driven action adapters. This document's "modes" describe the
current phase's configuration vocabulary, not that future engine stage; today's
policy YAML selects active rule categories and rule IDs, and the emitted
deterministic response metadata is the review artifact downstream consumers
use.

There is no policy-mode flag and no `policy_mode` event field. `observe` and `alert` below describe configuration outcomes, not a mode enum. `simulate-block` is not implemented.

### `observe`

Suppress policy-controlled Rule v1 detections while retaining conditional health
events and activity with `--emit-activity`. Health events are emitted for dry-run
or backfill, inventory changes, scanner errors, outages, or operational alerts;
an unchanged routine scan need not emit one. Process-chain detections are independently
enabled by default; also set `detections.process_chain: false` in `settings.d`
(or `TELLTALE_PROCESS_CHAIN_DETECTIONS=0`) for a detection-free baseline scan.

| Behavior | Setting |
| --- | --- |
| Activity events | emitted only with `--emit-activity` |
| Health events | conditional on the changes, errors, execution settings, or alerts described above |
| Detection events | Rule v1 candidates disabled by policy; process-chain events require the separate setting above |
| Review metadata | absent only when neither detection path emits |
| Operational alerts | emitted |

Use this configuration when onboarding a host or source to confirm discovery,
parsing, and schema compliance without detection noise.

For the bundled Rule v1 pack, disable all of its categories as follows. Custom
packs need their own categories or rule IDs disabled too; the policy name alone
does not select any behavior.

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
  - credential_harvesting
  - supply_chain
  - mcp_enumeration
```

```sh
TELLTALE_PROCESS_CHAIN_DETECTIONS=0 telltale scan --once --emit-activity --policy observe-policy.yaml --root "$HOME"
```

### `alert`

Emit detections with deterministic response metadata for analyst review. This is
the default scan behavior, not a named mode or flag.

| Behavior | Setting |
| --- | --- |
| Activity events | emitted (with `--emit-activity`) |
| Health events | conditional, as described under `observe` |
| Detection events | emitted |
| Review metadata | Native Event 3.0 uses deterministic response metadata and optional `timeline_anchors`; no embedded triage verdict |
| Operational alerts | emitted |

Detections follow this severity mapping (the current convention; the adopted
principles treat response selection as a future policy responsibility rather
than a fixed severity table):

| Score | Severity | Review metadata | Emission |
| ---: | --- | --- | --- |
| 0–19 | informational | deterministic response metadata | informational native detection/process-chain event; activity is separate |
| 20–49 | low | deterministic response metadata | detection event with response metadata |
| 50–69 | medium | deterministic response metadata | detection event with expanded context and response metadata |
| 70–89 | high | deterministic response metadata | detection event with deterministic response metadata |
| 90+ | critical | deterministic response metadata | detection event with deterministic response metadata |

Without an effective policy, policy filtering is not applied; rule packs and
overrides still determine the active definitions. An explicit `--policy` selects
the policy file; omitting it can still load an auto-discovered `policies.d` file.
`--no-local-config` disables that discovery, not an explicit policy. An effective
policy filters Rule v1 rules; process-chain enablement is independent.

### `simulate-block`

Not implemented. There is no `--mode` flag, and events are not stamped with `policy_mode`. The table below is not current behavior.

| Behavior | Setting |
| --- | --- |
| Activity events | not implemented |
| Health events | not implemented as a distinct mode |
| Detection events | not implemented; no `policy_mode` field is emitted |
| Review metadata | not implemented as a distinct mode |
| Operational alerts | not implemented as a distinct mode |
| Session termination | never |

`simulate-block` is not yet implemented as a distinct CLI mode. Today, the same effect can be approximated by using a strict policy with `alert` behavior and reviewing the `response.recommended_action` field on detection events. A dedicated `--mode simulate-block` flag that stamps events with the policy mode is a future enhancement.

## Future Phases: Active Hook

The following modes are historical forward-looking intent predating the adopted
development principles. They require integration with agent runtimes or process
control and belong to a later phase after the log-review model proves accurate
and the false-positive profile is stable; the principles' provider-neutral
decision/action model supersedes this older mode vocabulary when that work is
accepted.

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

Telltale uses policy YAML to select active Rule v1 categories and rule IDs:

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
telltale scan --once --policy config/policy.yaml --root "$HOME"
```

Policy YAML controls which Rule v1 rules remain active, not an enforcement
response or scanner mode. Matching active rules emit the current deterministic
review metadata. Future decisions, capabilities, and enforcement degradation
belong to the separately accepted policy layer.

## Relationship to Other Features

| Feature | Configuration interaction |
| --- | --- |
| Allowlists | Suppressed detections are logged at `informational` with the `suppressed` tag. |
| Analyst review | Above-threshold events carry deterministic response metadata and optional anchors; suppressed detections remain informational. |
| Response contract | Non-suppressed emitted detections carry response metadata. Allowlist suppression clears `response`. `simulate-block` is not implemented. |
| Operational alerts | Independent of Rule v1 category/rule selection. |
| Correlation | Cross-session correlation operates on emitted detection events; there is no distinct `simulate-block` path. |

## Configuration Guidance

| Scenario | Current configuration |
| --- | --- |
| First deployment on a new host | Disable all active Rule v1 categories/rules and set `TELLTALE_PROCESS_CHAIN_DETECTIONS=0`; add `--emit-activity` for activity telemetry |
| Tuning rules on a developer workstation | Keep relevant detections active and use `--policy` to select them |
| Production SIEM ingestion | Normal scan with reviewed policy and sink configuration |
| Evaluating containment rules | Review response recommendations; no simulation mode is implemented |
| Automated response | No active blocking or termination is implemented |
