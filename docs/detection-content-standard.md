# Detection Content Standard

This document defines the quality bar for ADR detection rules, fixtures, and related documentation. Every bundled rule must meet this standard before it ships. Custom rules loaded via `--rules` are encouraged but not required to follow it.

## Required Rule Metadata

Every rule in `config/rules/tool-call-regex.yaml` must include:

| Field | Purpose | Example |
| --- | --- | --- |
| `id` | Stable, dot-separated identifier. Never reuse a retired ID. | `mcp.tool_metadata.prompt_injection` |
| `category` | Exactly one ADR category from [threat-taxonomy.md](threat-taxonomy.md). | `mcp_prompt_injection` |
| `detection_class` | Why the rule exists. Defaults to `security_detection` if omitted. | `policy_violation` |
| `signal_type` | Shape of the signal. Defaults to `atomic`; chain modifiers default to `chain`. | `atomic` |
| `analytic_intent` | How analysts should use the event. Defaults to `alert`. | `hunt` |
| `atlas_tags` | Optional MITRE ATLAS tags using `atlas:<id>` values. Runtime validation checks shape only. | `[atlas:AML.T0051]` |
| `severity` | One of `informational`, `low`, `medium`, `high`, `critical`. | `high` |
| `score` | Numeric risk contribution (0–100 per rule). Matching contributions accumulate into the emitted, uncapped `risk_score`. | `60` |
| `targets` | Fields the regex evaluates. Must be valid ADR targets. | `[assistant_context, arguments, tool_result]` |
| `regex` or `detection` | The matching pattern. `targets` + `regex` for simple signatures; `detection.selection` with `condition: selection` for Sigma-inspired rules. | See examples in detection-model.md |
| `tags` | One or more descriptive tags for filtering, searching, and documentation. | `[mcp, prompt-injection, tool-poisoning]` |
| `explanation` | One sentence describing what the rule detects and why it matters. | "MCP tool metadata appears to contain prompt-injection instructions." |
| `falsepositives` | Known benign scenarios that can produce the same signal. | `["Authorized release workflows may publish packages."]` |

Optional fields:

| Field | Purpose |
| --- | --- |
| `title` | Human-readable name. Defaults to `id` if absent. |
| `enabled` | Defaults to `true`. Set `false` to disable without removing. |
| `case_insensitive` | Defaults to the top-level `defaults.case_insensitive` value. |

### Rule Purpose Metadata

All rule purposes use the same rule YAML and engine. Do not create a separate syntax for ad-hoc alerts, hunting detections, production alerts, or policy violations.

Allowed `detection_class` values:

- `security_detection`
- `policy_violation`
- `threat_hunting`
- `compliance_observation`
- `operational_health`
- `baseline_deviation`

Allowed `signal_type` values:

- `atomic`
- `chain`
- `correlation`
- `baseline_deviation`

Allowed `analytic_intent` values:

- `alert`
- `hunt`
- `enrich`
- `baseline`
- `audit`

Use `category` only for the observed behavior. Use the metadata fields above for rule purpose and analyst workflow. For example, `approval_bypass` is a behavior category; `policy_violation` is a detection class; `alert` is an analytic intent.

ATLAS mappings live in rule `atlas_tags` and in [../MITRE_ATLAS_COVERAGE.md](../MITRE_ATLAS_COVERAGE.md). ATLAS must remain offline documentation context and must not be fetched during scans, tests, or validation.

### ID Naming Convention

- Use dot-separated segments: `category.specific_pattern`.
- Chain modifiers use the `chain.` prefix: `chain.mcp_injection_then_egress`.
- Keep IDs lowercase, alphanumeric with dots and underscores only.
- IDs are immutable once released. Renaming requires a deprecation entry and a new ID.

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

Every rule should have a documented rationale for its severity level. This rationale lives in the rule's `explanation` field or in the use-case doc that introduced it. The rationale should answer:

- What behavior does this rule catch?
- How common is this behavior in legitimate developer workflows?
- What is the blast radius if this behavior is malicious?
- Does this rule fire alone or primarily as part of a chain?

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

## Chain Modifiers

Chain modifiers in the `modifiers:` section must include:

| Field | Purpose |
| --- | --- |
| `id` | Stable identifier with `chain.` prefix. |
| `score` | Additional risk score when the chain fires. |
| `explanation` | Why this combination is riskier than either signal alone. |
| Trigger | Exactly one of `when_all_categories` or `when_all_rule_ids`. |

Chain modifiers should not duplicate base rule logic. They exist to escalate multi-signal sessions.

## Fixture Expectations

### Positive Fixtures

Every rule must have at least one positive fixture that triggers the rule. The fixture should:

- Be synthetic: no real credentials, real session transcripts, or real attacker infrastructure.
- Be minimal: include only the fields and content needed to trigger the rule.
- Live under `tests/fixtures/` in the appropriate location:
  - `tests/fixtures/rule_samples/` for standalone rule-level tests.
  - `tests/fixtures/session_stores/<client>/` for parser-to-detection coverage.
- Include a detection test that asserts:
  - The rule ID appears in the matched rules.
  - The severity matches the rule definition.
  - Evidence fields are redacted (no raw secrets, no raw controlled-domain URLs).

### Negative Fixtures

Rules that could produce false positives on common developer activity should have at least one negative fixture demonstrating that the rule does not fire. Examples:

- `execution.shell` should not fire on a user message mentioning "bash" in prose.
- `credential.api_key.pattern` should not fire on JWT-like strings in git diffs.
- `network.download` should not fire on documentation mentioning `curl` examples.

Negative fixtures live alongside positive fixtures in the same directory structure.

### Cross-Client Coverage

High-signal use cases (UC-001, UC-002, UC-003) should have positive fixtures across all active agent sources (Codex, OpenCode, Copilot) and at least one future source (Claude Code). This ensures parser differences do not hide detections.

See [client-capability-matrix.md](client-capability-matrix.md) for per-client field availability.

## False-Positive Notes

Each use case in [use-cases.md](use-cases.md) should document:

- Known false-positive scenarios.
- Expected false-positive rate on a developer workstation.
- Mitigation strategies (e.g., suppressing `user_context` from targets, requiring chain modifiers before escalating).

Bundled rules and chain modifiers should include a `falsepositives` list in rule YAML so `telltale rules coverage` can report whether analyst guidance exists. Keep notes concrete and operational: describe the benign workflow, what context makes it safe, and whether the signal should usually be interpreted alone or as part of a chain.

## Changelog Expectations

Every new rule, rule change, or deprecation should be recorded in the relevant
use-case or detection documentation:

- **New rule**: list the rule ID, category, severity, and the use case or motivation.
- **Rule change**: describe what changed (score, targets, regex, severity) and why.
- **Rule deprecation**: list the old ID, the replacement ID (if any), and the reason.

Detection content changes are code changes. They deserve the same review, testing, and documentation discipline as Rust source changes.

## Deprecation Rules

When a rule ID must be retired:

1. **Do not reuse the ID.** A retired ID may appear in historical SIEM data, saved searches, and analyst notes. Reusing it creates confusion.
2. **Add a deprecation note** in the relevant detection documentation explaining why the rule was removed or replaced.
3. **If replacing**, introduce the new ID alongside the old one for at least one release cycle, then remove the old one.
4. **Update fixtures** that depended on the old rule ID to use the new one.
5. **Update saved searches** and dashboards that reference the old ID.

## Adding a New Rule

Follow this checklist:

1. Read [threat-taxonomy.md](threat-taxonomy.md) and assign exactly one ADR category.
2. Choose a stable `id` following the naming convention.
3. Set `severity`, `score`, `targets`, and `regex` (or `detection` block).
4. Set `detection_class`, `signal_type`, and `analytic_intent`.
5. Add `atlas_tags` only when the mapping is specific and update `MITRE_ATLAS_COVERAGE.md`.
6. Write a clear `explanation` answering: what happened, why it matters, what evidence is safe.
7. Add one or more `tags` for filtering and documentation.
8. Create a positive fixture under `tests/fixtures/`.
9. Create a negative fixture if the rule could false-positive on common activity.
10. Add a detection test in `src/detection.rs` (or the current detection test module).
11. Run `telltale rules validate --rules <path>` to check YAML syntax and regex compilation.
12. Run `telltale rules test --rules <path> <fixture>` to preview matches.
13. Run `cargo test` to verify no regressions.
14. Record the rule in the relevant detection documentation.
15. If this rule is part of a use case, update [use-cases.md](use-cases.md).

## Quality Checklist

Before merging detection content changes:

- [ ] Rule has all required metadata fields.
- [ ] Rule ID follows the naming convention and is unique.
- [ ] Category is a valid ADR category from threat-taxonomy.md.
- [ ] Score and severity are consistent with the severity guidance table.
- [ ] At least one positive fixture exists.
- [ ] Negative fixture exists if false-positive risk is known.
- [ ] Detection test asserts rule ID, severity, and evidence redaction.
- [ ] `telltale rules validate` passes.
- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes.
- [ ] Changelog entry exists.
- [ ] Use-case doc updated if applicable.
