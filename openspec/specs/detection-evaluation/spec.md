# detection-evaluation Specification

## Purpose
Defines deterministic current-behavior characterization and independently labeled synthetic efficacy without changing Event 3.0 or detector behavior.
## Requirements
### Requirement: Evaluation cases use a versioned fail-closed manifest

The evaluation system SHALL validate Manifest v1 before product evaluation and SHALL reject unsupported versions, unknown fields or enums, missing labels or rationales, duplicate case IDs, rule expectations, or tags, missing fixtures, invalid exact source identities, malformed contribution expectations, score/contribution-total contradictions, incompatible exact-rule-set expectations, and contradictory semantic tags.

#### Scenario: Invalid manifest

- **WHEN** a manifest has an unsupported version, duplicate case ID, unknown enum, or missing `label_rationale`
- **THEN** evaluation fails before scanning cases and identifies the invalid contract

### Requirement: Ground truth axes remain independent

Each case SHALL record eventfulness (`uneventful | routine | noteworthy`), disposition (`benign | malicious | unknown | not_applicable`), and expected security review (`required | not_required | not_scored`) independently.

#### Scenario: Benign signal case

- **WHEN** a benign routine case correctly matches a deterministic rule
- **THEN** it MAY remain `not_required` for security review and its rule-match result is evaluated separately

### Requirement: Efficacy expectations are independently justified

Every case SHALL provide a concise `label_rationale` that explains the intended analyst outcome without referencing observed score, matched rules, detector output, or the golden report. A contributor MUST NOT change an efficacy expectation solely to make observed detector behavior pass.

#### Scenario: Intentional product change causes a mismatch

- **WHEN** changed product behavior disagrees with an efficacy expectation
- **THEN** review explicitly corrects product behavior, changes the expectation with an independent rationale explaining why the old expectation was wrong, or marks the case `not_scored` with justification

### Requirement: Characterization remains separate from efficacy

The golden SHALL preserve exact parser/source/visibility, matched-rule, score, contribution ID, contribution point, contribution-total, modifier, and process-chain definition conformance. Those assertions SHALL be labeled current-behavior characterization and SHALL NOT be described as efficacy ground truth.

#### Scenario: Expected score differs

- **WHEN** current output differs from an exact expected score or contribution ledger
- **THEN** deterministic conformance fails even if the independent efficacy outcome is unchanged

### Requirement: Primary efficacy outcome is canonical security review

The evaluator SHALL use fixed `RiskThresholds { low: 20, medium: 50, high: 70, critical: 90 }` and SHALL define observed security review as `MatchResult.score >= 70`. It SHALL NOT load environment threshold variables for the golden evaluation.

#### Scenario: Positive low-risk signal

- **WHEN** a session scores 15
- **THEN** it is positive-risk characterization but is not observed security review

#### Scenario: High-boundary session

- **WHEN** a session scores exactly 70
- **THEN** it is observed `security_review_required`

### Requirement: Security-review confusion uses independently scored cases only

The report SHALL count TP, FP, TN, and FN only over `required` and `not_required` cases:

- TP: expected required and observed score >= 70
- FP: expected not_required and observed score >= 70
- TN: expected not_required and observed score < 70
- FN: expected required and observed score < 70

Precision SHALL be TP/(TP+FP) and recall SHALL be TP/(TP+FN). Zero denominators SHALL yield JSON `null`. No efficacy pass/fail threshold SHALL be invented.

#### Scenario: Parser-only case

- **WHEN** a source-conformance case is `not_scored`
- **THEN** its characterization remains visible and it contributes no TP, FP, TN, or FN

### Requirement: Signal and severity ladder remains visible

The report SHALL characterize the entire corpus and independently scored benign cases at score > 0, >=20, >=50, >=70, and >=90. It SHALL name these positive risk, non-informational, review-or-higher, security-review-required, and critical respectively. It SHALL NOT call positive-risk signal rate a false-positive rate.

#### Scenario: Benign shell signal

- **WHEN** a benign shell case scores 15
- **THEN** it increments benign positive-risk rate but not benign non-informational or higher rates

### Requirement: Rule-level match confusion is separate

Each case-rule relationship SHALL be `expected_match`, `expected_absent`, or `not_scored`. Unspecified rules SHALL be `not_scored` unless the case requests an exact rule set. A correct expected match SHALL NOT become a rule-level false positive merely because the scenario is benign or does not require security review.

#### Scenario: Authorized environment-file access

- **WHEN** an authorized benign case expects `secret.env.read` to match and expects security review `not_required`
- **THEN** the correct rule match is a rule-level TP while the session can be a security-review TN

### Requirement: Supported sources are represented without padding efficacy

The report SHALL represent all supported exact source identities, verify exact client/source identity and visibility, and report candidate identities separately. Source-conformance-only and candidate cases SHALL normally be `not_scored`, and synthetic fixtures SHALL NOT imply live-host support.

#### Scenario: Candidate fixture parses

- **WHEN** `codex.project_sessions` or `opencode.project_json` parses
- **THEN** it remains candidate representation and does not increment supported coverage or efficacy denominators

### Requirement: Bundled regex and modifier coverage is explicit

Every enabled bundled regex rule and modifier SHALL have an expected-match case or a precise unsupported-observability rationale. Rules that plausibly intersect benign workflows SHALL have a benign confounder with explicit rule and security-review expectations.

#### Scenario: Uncovered enabled rule

- **WHEN** an enabled bundled rule has neither positive coverage nor a valid rationale
- **THEN** the evaluation coverage gate fails with its rule ID

### Requirement: Process-chain definition conformance is not efficacy

The report SHALL distinguish process-chain definition conformance from independently labeled process-chain scenario efficacy. It SHALL report chain, standalone, correlation, definition-conformance, independent scenario, benign scenario, evaluator path, and public Pipeline integration counts/status. It SHALL NOT describe definition-backed self-matches as independent attacks or 100% efficacy.

#### Scenario: Pipeline isolation

- **WHEN** regex/session cases run through `Pipeline::evaluate_session`
- **THEN** process-chain coverage is evaluated separately without changing Pipeline

### Requirement: Reports are deterministic and golden-compared

Canonical report bytes SHALL exclude wall-clock generation time, host/user names, absolute paths, temp directories, random IDs, process IDs, secrets, raw transcripts, hash-map ordering, and Git SHA. Cases, rules, sources, and contributions SHALL be deterministically ordered. Ordinary tests SHALL compare but never rewrite the tracked golden.

#### Scenario: Golden mismatch

- **WHEN** canonical bytes differ from the tracked baseline
- **THEN** the test fails, may write actual output under `target/evaluation/`, and does not alter the tracked baseline

### Requirement: Evaluation outputs and fixture inputs remain confined

`TELLTALE_EVAL_REPORT` SHALL accept only one normal filename component and
write it below the fixed `target/evaluation/` directory. Source fixtures SHALL
be lexically repo-relative and canonicalize beneath the repository root.

#### Scenario: Escaping evaluation path

- **WHEN** an evaluation report path is absolute, traverses with `..`, or has nested components
- **THEN** evaluation rejects it before writing

#### Scenario: Fixture symlink escapes repository

- **WHEN** a repo-relative fixture symlink resolves outside the repository
- **THEN** manifest validation rejects it before parsing

### Requirement: Synthetic limits are prominent

The report and README SHALL state that characterization and synthetic efficacy are not production detection rates, production false-positive rates, or attacker-prevalence estimates.

#### Scenario: Operator reads report

- **WHEN** an operator reviews the baseline
- **THEN** characterization and synthetic efficacy purposes and limitations are separately visible

### Requirement: Evaluation material is privacy safe

Committed inputs and reports SHALL NOT contain real customer transcripts, live credentials, production session databases, or workstation-specific paths. Fixture references SHALL be repository-relative.

#### Scenario: Synthetic marker

- **WHEN** a case uses controlled test material
- **THEN** it remains synthetic and does not introduce real credentials or customer data
