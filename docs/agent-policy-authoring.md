# Agent Policy Authoring

Telltale uses one detection engine for production alerts, bleeding-edge ad-hoc hunts, security detections, and policy-violation detections. A policy violation is not a separate runtime path. It is a normal ADR rule bundle, written in the same YAML syntax, validated by the same CLI commands, tested with the same synthetic fixtures, and emitted as the same SIEM-friendly detection event shape.

This document defines the first deterministic workflow for turning human-written AI agent policy into ADR detection content. The first supported policy inputs are Markdown and YAML. PDF, DOCX, and AI-assisted import are future workflow layers.

## Goals

- Help humans define what coding agents may do, must not do, and may do only under conditions.
- Map those statements to observable ADR categories, rule IDs, fixtures, and validation commands.
- Keep policy-violation content data-driven in rule YAML instead of hard-coding policy logic.
- Preserve the existing detection lifecycle: rules, fixtures, validation, coverage, changelog, and SIEM output.
- Mark unobservable controls clearly instead of pretending logs can prove behavior they cannot expose.

## Concepts

### Human Policy

The human policy is prose or structured text that describes desired agent behavior. It can start as Markdown:

```markdown
Agents must not read local secrets unless explicitly requested for a security review.
Agents must not publish packages after reading cloud credentials.
Agents may install dependencies only from approved package registries.
```

This document is source material, not executable configuration.

### Agent Behavior Policy YAML

The agent behavior policy is a normalized planning artifact. It records controls, decisions, observability, ADR mappings, and expected validation evidence. See `config/policies/examples/agent-behavior-policy.yaml`.

The first schema is intentionally simple and reviewable:

```yaml
version: 1
name: example-agent-policy
description: Example policy controls for coding agents.
controls:
  - id: agent.no_secret_exfiltration
    decision: prohibited
    summary: Agents must not read local secrets and transmit them externally.
    observability: observable
    adr_categories: [secret_access, exfiltration]
    rule_ids: [secret.env.read, exfil.outbound_upload, chain.secret_then_network]
    detection_bundle: config/rules/tool-call-regex.yaml
    validation:
      positive_fixture_required: true
      negative_fixture_required: true
```

### Detection Bundle

Detection bundles remain ADR rule YAML. Bundles can be organized by purpose:

- `config/rules/tool-call-regex.yaml` for bundled security and threat-hunting detections.
- `config/rules/ad-hoc/*.yaml` for temporary or bleeding-edge rules that should be validated before promotion.
- `config/rules/policy-violations/*.yaml` for detections whose primary purpose is policy enforcement or audit.
- Deployment-specific custom bundles passed with repeated `--rules` flags.

Policy-violation bundles use exactly the same engine and syntax as other detection bundles.

Rule purpose is described with metadata fields, not by changing syntax:

```yaml
detection_class: policy_violation
signal_type: atomic
analytic_intent: audit
atlas_tags: []
```

See `docs/detection-content-standard.md` and `MITRE_ATLAS_COVERAGE.md`.

## Control Decisions

Use one of these decisions for each control:

| Decision | Meaning |
| --- | --- |
| `allowed` | Behavior is expected and should not create a detection by itself. |
| `prohibited` | Behavior should create a detection when observable. |
| `conditional` | Behavior is allowed only with stated conditions or expected context. |
| `review` | Behavior is allowed but should be surfaced for analyst review. |
| `unobservable` | Current log sources cannot prove or disprove the behavior. |

Do not turn every `allowed` control into an allowlist. Allowlists should be precise suppressions for known expected workflows, not broad policy declarations.

## Observability

Each control must state what Telltale can see:

| Value | Meaning |
| --- | --- |
| `observable` | Existing session logs expose enough fields to detect the behavior. |
| `partially_observable` | Some clients expose enough fields, but others have gaps. |
| `unobservable` | Current sources do not expose enough evidence. |

If a control depends on missing user intent, process ancestry, network packet contents, browser state, or external identity context, mark the control as partially observable or unobservable and document the gap.

## Authoring Workflow

1. Read the human policy and extract agent behavior controls.
2. Assign each control one decision and one observability value.
3. Map each control to ADR categories from `docs/threat-taxonomy.md`.
4. Reuse existing rule IDs when they already cover the behavior.
5. Add new policy-violation rules only for observable gaps.
6. Add synthetic positive and negative fixtures.
7. Validate syntax with `adr rules validate`.
8. Preview fixture behavior with `adr rules test`.
9. Measure coverage with `adr rules coverage`.
10. Update public release notes or another reviewed change log, plus relevant use-case docs.

## Deterministic Validation

Validate existing and policy-violation bundles together:

```sh
cargo run -- rules validate \
  --rules config/rules/tool-call-regex.yaml \
  --rules config/rules/policy-violations/example-policy-violations.yaml
```

Preview a fixture:

```sh
cargo run -- rules test \
  --rules config/rules/tool-call-regex.yaml \
  --rules config/rules/policy-violations/example-policy-violations.yaml \
  tests/fixtures/rule_samples/policy-agent-guardrail-modification.jsonl
```

Scan synthetic fixtures without writing:

```sh
cargo run -- scan --once --dry-run \
  --root tests/fixtures/session_stores \
  --rules config/rules/tool-call-regex.yaml \
  --rules config/rules/policy-violations/example-policy-violations.yaml
```

## Skill-Assisted Development

Repo-local skills guide agentic development of this workflow:

- `detection-policy-author`: extract and normalize policy controls.
- `detection-rule-author`: write ADR rule YAML for approved controls.
- `detection-fixture-author`: create synthetic positive and negative fixtures.
- `detection-validator`: run deterministic validation and summarize results.

The canonical copies live under `skills/`. OpenCode loads matching project skills from `.opencode/skills/`, so this repository uses symlinks there for shared skill access.

## Guardrails

- Never use real corporate secrets, real session transcripts, auth files, or customer policy examples containing sensitive details as fixtures.
- Keep fixtures synthetic and minimal.
- Do not add rules for unobservable controls; document the gap instead.
- Do not tune policy-violation rules only against positive examples. Add a negative fixture when normal developer activity could look similar.
- Preserve evidence minimalism: emit the least redacted evidence needed to prove the detection.
- Use the same rule-quality bar as `docs/detection-content-standard.md`.
