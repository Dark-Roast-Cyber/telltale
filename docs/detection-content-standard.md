# Detection Content Standard

This document defines the quality bar for Telltale detection rules, fixtures, and related documentation. Every bundled core rule must meet this standard before it ships. Embedded community rules follow the community gate in [Community Rules](#community-rules). Custom rules and packages are encouraged but not required to follow it.

## Required Rule Metadata

Rules are written in Rule v2; the [rule format](rule-format.md) defines every
key and what the loader checks. Every rule in `config/rules/tool-call-regex.yaml`
must also include the keys below, beyond what the loader requires. Keys under
`telltale:` are shown as `telltale.<key>`. `telltale.detection_class`,
`telltale.signal_type`, and `telltale.analytic_intent` may be omitted; the
defaults in this table apply, and most bundled rules omit them.

| Key | Purpose | Example |
| --- | --- | --- |
| `title` | Human-readable name of what the rule detects. | `MCP tool metadata prompt injection` |
| `id` | UUIDv4 generated once when the rule is written; never changed or reused. | `3f2504e0-4f89-41d3-9a0c-0305e82c3301` |
| `name` | Stable, dot-separated rule name used in events, overrides and policies. Never reuse a retired name. | `mcp.tool_metadata.prompt_injection` |
| `status` | `experimental`, `test` or `stable` for shipped rules. | `stable` |
| `logsource` | `product: ai_agent` and the category that fits the fields read. | `{product: ai_agent, category: tool_activity}` |
| `detection` | Selections, filters, and a condition over the [Rule v2 fields](rule-format.md#fields). | See [rule format](rule-format.md#detection) |
| `level` | One of `informational`, `low`, `medium`, `high`, `critical`. | `high` |
| `falsepositives` | Known benign scenarios that can produce the same signal. | `['Authorized release workflows may publish packages.']` |
| `tags` | Optional Sigma tags: `atlas.<id>` for MITRE ATLAS, `attack.<technique>` for ATT&CK. Runtime validation checks shape only. | `[atlas.aml.t0051]` |
| `telltale.category` | Exactly one ADR category from [threat-taxonomy.md](threat-taxonomy.md). | `mcp_prompt_injection` |
| `telltale.score` | Numeric risk contribution (0–100 per rule). Matching contributions accumulate into the emitted, uncapped `risk_score`. | `60` |
| `telltale.explanation` | One sentence describing what the rule detects and why it matters. | `MCP tool metadata appears to contain prompt-injection instructions.` |
| `telltale.tags` | One or more descriptive labels for filtering, searching, and documentation. | `[mcp, prompt-injection, tool-poisoning]` |
| `telltale.detection_class` | Why the rule exists. Defaults to `security_detection`. | `policy_violation` |
| `telltale.signal_type` | Shape of the signal. Defaults to `atomic`; chains default to `chain`. | `atomic` |
| `telltale.analytic_intent` | How analysts should use the event. Defaults to `alert`. | `hunt` |

Optional keys:

| Key | Purpose |
| --- | --- |
| `description`, `references`, `author`, `date`, `modified` | Catalog metadata; `date` and `modified` record the change history. They do not change the behaviour fingerprint. |
| `telltale.enabled` | Defaults to `true`. Set `false` to disable without removing. |
| Filters | At most one filter per selection, on the same field, used as `<selection> and not <filter>`. |
| Scope modifiers | `segment`, `exclusion_segment` or `recorded_exclusion` on `tool.command`, `tool.arguments` and `tool.url`; see [detection-model.md](detection-model.md#configurable-rules-and-policies). |

Rule v2 loading, including `rules validate`, rejects a `level` outside the five
detection severities in the table above. The [generated
vocabulary](catalog/rule-vocabulary.json) distinguishes these supported rule
values from the broader Event 3.0 vocabulary: `warning` remains valid for
operational events, but is not a rule level or an alias for a detection
severity. Shared validation and canonical detection compilation accept the same
detection severity values.

`status` is Sigma's maturity vocabulary: `experimental`, `test` and `stable`
rules load enabled, while `deprecated` and `unsupported` rules load disabled
and stay in the catalog. `telltale.enabled`, overrides and policy control
enablement otherwise. `telltale.category` remains an open behavior label for
custom rules and packages; the bundled core category convention above is a
content standard, not a validator restriction.

### Rule Purpose Metadata

All rule purposes use the same Rule v2 format and engine. Do not create a separate syntax for ad-hoc alerts, hunting detections, production alerts, or policy violations.

Allowed `telltale.detection_class` values:

- `security_detection`
- `policy_violation`
- `threat_hunting`
- `compliance_observation`
- `operational_health`
- `baseline_deviation`

Allowed `telltale.signal_type` values:

- `atomic`
- `chain`
- `correlation`
- `baseline_deviation`

Allowed `telltale.analytic_intent` values:

- `alert`
- `hunt`
- `enrich`
- `baseline`
- `audit`

Use `telltale.category` only for the observed behavior. Use the metadata fields above for rule purpose and analyst workflow. For example, `approval_bypass` is a behavior category; `policy_violation` is a detection class; `alert` is an analytic intent.

ATLAS mappings live in rule `atlas.*` tags and in the [ATLAS coverage map](https://github.com/Dark-Roast-Cyber/telltale-detections/blob/main/docs/atlas-coverage.md). ATLAS must remain offline documentation context and must not be fetched during scans, tests, or validation.

### Name and ID Convention

- Use dot-separated `name` segments: `category.specific_pattern`.
- Chains use the `chain.` prefix: `chain.mcp_injection_then_egress`.
- Keep names lowercase, alphanumeric with dots and underscores only.
- Names and `id`s are immutable once released. Renaming requires a deprecation
  entry and a new rule with a new `name` and a new `id`, linked with `related`.
- Generate the `id` UUIDv4 once, when the rule is written, and keep it through
  every later edit.

### Score Guidance

| Severity | Typical Score Range | Meaning |
| --- | --- | --- |
| `informational` | 0–19 | Activity worth logging but not alarming. |
| `low` | 20–39 | Suspicious in context but common in normal work. |
| `medium` | 40–49 | Warrants analyst attention when combined with other signals. |
| `high` | 50–79 | Strong indicator of risk; carries a security-review marker at threshold. |
| `critical` | 80–100 | Near-certain malicious or extremely high-risk behavior. |

Scores are additive across rules and chain modifiers. The emitted `risk_score` is
therefore non-negative and uncapped; it can exceed 100 when multiple rules or
chain modifiers match. Event severity derives from the configured scanner
thresholds (defaults: low 20, medium 50, high 70, critical 90), rather than
from a 0–100 score cap. A session matching multiple rules may cross higher
severity thresholds even if individual rules score lower.

### Severity Rationale

Every rule should have a documented rationale for its severity level. This rationale lives in the rule's `telltale.explanation` or in the use-case doc that introduced it. The rationale should answer:

- What behavior does this rule catch?
- How common is this behavior in legitimate developer workflows?
- What is the blast radius if this behavior is malicious?
- Does this rule fire alone or primarily as part of a chain?

## Community Rules

Community rules are developed in the
[community detections repository](https://github.com/Dark-Roast-Cyber/telltale-detections)
and ship as the `telltale.community` rule package (namespace `tdx`). Telltale
embeds a pinned release and enables it by default; see
[Install](install.md#community-rules-and-rule-packages) for the opt-out and for
installing a newer release.

- **Maturity.** Each community rule sets `status` to `experimental`,
  `test`, or `stable`. Only `test` and `stable` rules ship in a community release.
- **Evidence.** A community rule carries an adversarial scenario it must match, a
  benign look-alike it must not match, and an analyst note. Its scenario labels
  are written independently of detector output and assessed against a pinned
  Telltale revision in that repository. Telltale's local fixture requirement
  applies to core rules; `rules coverage --no-community-rules` reports it.
- **Refreshing the embedded snapshot.** Run
  `scripts/dev/vendor-community-rules.py` on a published release package with its
  `SHA256SUMS`, after `gh attestation verify`. Review the package diff as
  detection content, then run `cargo test --locked -p telltale-rules package`,
  the CLI rules tests, and `make evaluation-check`.
- **Promotion to core.** A `stable` community rule may become a core rule with a
  new non-`tdx` name and `id` once it meets this standard: fixtures, a detection
  test, use-case notes, and a changelog entry. The community repository then
  retires the `tdx` rule under [Deprecation Rules](#deprecation-rules).

## Process-Chain Rules

Process-chain rules use a different schema and a different pack
(`crates/telltale-rules/data/process-chain.yaml`). They reuse the score bands in
the table above — the compiler rejects a rule whose `score` falls outside its
declared `severity` — and they add two obligations the regex pack does not have:

- **Every match emits.** A rule may score `0`; it still produces an event,
  marked `informational`. Never delete a rule to silence it; score it `0`.
- **Overlapping interpretations are split by command line, not by severity.**
  When one parent/child pair covers both routine administration and intrusion
  activity, write two rules gated on `child_command_line_any` /
  `child_command_line_none` rather than one rule with an averaged score.

The pack is generated. Edit `scripts/dev/generate-process-chain-rules.py` and
re-run it; do not hand-edit the YAML. Full authoring guidance, including the
scoring derivation and deduplication contract, is in
[process-chain-detections.md](process-chain-detections.md).

## Chains

Chains (Rule v2 documents with `correlation.type: telltale_chain`; see
[rule format](rule-format.md#chains)) must include:

| Key | Purpose |
| --- | --- |
| `title`, `id`, `name` | As for rules; `name` uses the `chain.` prefix. |
| `telltale.score` | Additional risk score when the chain fires. |
| `telltale.explanation` | Why this combination is riskier than either signal alone. |
| Trigger | Exactly one of `correlation.categories` or `correlation.rules`. |
| `correlation.within_calls` | Optional. How close the steps must be; see below. |

Chains should not duplicate base rule logic. They exist to escalate multi-signal sessions.

### Linking steps

```yaml
title: Credential harvest followed by exfiltration
id: 2c1d7a9e-5b3f-4e6a-9d8c-7f6e5d4c3b2a
name: chain.harvest_then_exfil
taxonomy: telltale
correlation:
    type: telltale_chain
    categories: [credential_harvesting, exfiltration]
    within_calls: 3
telltale:
    score: 35
    explanation: Harvested credentials followed by an upload suggest exfiltration.
```

- `within_calls` (0 to 10): how many tool calls apart the steps may be; 0
  means one call and 1 the next call. A call and its result count once, and
  messages and other records add no distance.
- `order`: `ordered` (the default) needs the steps in the order the trigger
  lists them; `any` accepts any order. One observation that matches every step
  always links. `order` needs `within_calls`.

Session scoring and action findings apply the same link. Without
`within_calls`, a chain fires when its steps match anywhere in the session.

## Fixture Expectations

### Positive Fixtures

Every rule must have at least one positive fixture that triggers the rule. The fixture should:

- Be synthetic: no real credentials, real session transcripts, or real attacker infrastructure.
- Be minimal: include only the fields and content needed to trigger the rule.
- Live under `tests/fixtures/` in the appropriate location:
  - `tests/fixtures/rule_samples/` for standalone rule-level tests.
  - `tests/fixtures/session_stores/<client>/` for parser-to-detection coverage.
- Include a detection test that asserts:
  - The rule name appears in the matched rules.
  - The severity matches the rule's `level`.
  - Evidence fields are redacted (no raw secrets, no raw controlled-domain URLs).

### Negative Fixtures

Rules that could produce false positives on common developer activity should have at least one negative fixture demonstrating that the rule does not fire. Examples:

- `execution.shell` should not fire on a user message mentioning "bash" in prose.
- `credential.api_key.pattern` should not fire on JWT-like strings in git diffs.
- `network.download` should not fire on documentation mentioning `curl` examples.

Negative fixtures live alongside positive fixtures in the same directory structure.

### Cross-Client Coverage

High-signal use cases should exercise the supported source denominator wherever
the required evidence is actually observable. Keep exact fixture and live
qualification in the [Source Validation Matrix](source-validation-matrix.md)
and field visibility in [Agent Capability Profiles](agent-capability-profiles.md).
Do not invent unavailable fields merely to force cross-source equivalence.

## False-Positive Notes

Bundled rules and chains should include a `falsepositives` list so `telltale rules coverage` can report whether analyst guidance exists. Keep notes concrete and operational: describe the benign workflow, what context makes it safe, and whether the signal should usually be interpreted alone or as part of a chain.

## Changelog Expectations

Every new rule, rule change, or deprecation should be recorded in the relevant
detection documentation:

- **New rule**: list the rule name, category, level, and the motivation.
- **Rule change**: describe what changed (score, fields, patterns, level) and why.
- **Rule deprecation**: list the old name, the replacement name (if any), and the reason.

Detection content changes are code changes. They deserve the same review, testing, and documentation discipline as Rust source changes.

## Deprecation Rules

When a rule must be retired:

1. **Do not reuse its `name` or `id`.** A retired name may appear in historical SIEM data, saved searches, and analyst notes. Reusing it creates confusion.
2. **Add a deprecation note** in the relevant detection documentation explaining why the rule was removed or replaced.
3. **Mark it** `status: deprecated` with a `related` entry of type `obsolete` on the replacement, so it stays in the catalog but no longer runs.
4. **If replacing**, introduce the new rule alongside the old one for at least one release cycle, then remove the old one.
5. **Update fixtures** that depended on the old rule name to use the new one.
6. **Update saved searches** and dashboards that reference the old name.

## Adding a New Rule

Follow this checklist:

1. Read [threat-taxonomy.md](threat-taxonomy.md) and assign exactly one ADR category.
2. Choose a stable `name` following the naming convention, and generate a new UUIDv4 `id`.
3. Set `title`, `logsource`, `detection`, `level`, and `telltale.score`.
4. Set `telltale.detection_class`, `telltale.signal_type`, and `telltale.analytic_intent` when overriding their documented defaults; otherwise they may be omitted.
5. Add `atlas.*` tags only when the mapping is specific and update the ATLAS coverage map.
6. Write a clear `telltale.explanation` answering: what happened, why it matters, what evidence is safe.
7. Add one or more `telltale.tags` for filtering and documentation.
8. Create a positive fixture under `tests/fixtures/`.
9. Create a negative fixture if the rule could false-positive on common activity.
10. Add a detection test beside what it exercises: the tests of that module (for example `crates/telltale-detect/src/v2/session/tests.rs`), a topic file under `crates/telltale-detect/src/v2/tests/`, or `v2/action_tests.rs` for native action selection.
11. Run `telltale rules validate --rules <path>` to check the rule and its patterns, and review any `notices`.
12. Run `telltale rules test --rules <path> <fixture>` to preview matches.
13. Run `cargo test` to verify no regressions.
14. Record the rule in the relevant detection documentation.

## Quality Checklist

Before merging detection content changes:

- [ ] Rule has all required metadata keys.
- [ ] Rule name follows the naming convention and is unique; the `id` is a new UUIDv4.
- [ ] Category is a valid ADR category from threat-taxonomy.md.
- [ ] Score and level are consistent with the severity guidance table.
- [ ] At least one positive fixture exists.
- [ ] Negative fixture exists if false-positive risk is known.
- [ ] Detection test asserts rule ID, severity, and evidence redaction.
- [ ] `telltale rules validate` passes.
- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes.
- [ ] Changelog entry exists.
- [ ] Use-case doc updated if applicable.
