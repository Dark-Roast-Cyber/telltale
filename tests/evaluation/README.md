# Evaluation Corpus v1

This corpus measures two different things. Neither is a production detection rate, production false-positive rate, or estimate of attacker prevalence.

## CHARACTERIZATION

What does the current deterministic detector do?

Exact matched and forbidden rule IDs, exact scores, exact contribution ledgers, parser/source identity, and visibility checks characterize current `main` / v0.5.0 behavior. The golden characterization snapshot is a behavioral drift detector. It is not efficacy ground truth.

Positive-risk (`score > 0`) is signal characterization only. It is not a false-positive rate and is not the primary efficacy classifier.

## SYNTHETIC EFFICACY

Against independently authored scenario expectations, does the current detector require security review for the scenarios we intend to escalate, while avoiding security-review escalation for the benign scenarios we intend not to escalate?

Primary observed outcome:

```text
observed_security_review = MatchResult.score >= 70
```

That boundary is the product's `security_review_required` escalation (`score >= high`). Evaluation uses a fixed canonical threshold set and does not load `TELLTALE_RISK_THRESHOLD_*`:

```text
low      = 20
medium   = 50
high     = 70
critical = 90
```

Each scored efficacy case has `expected_security_review` of `required` or `not_required` plus a `label_rationale` that describes the intended analyst outcome without referring to observed scores, matched rules, or the golden report.

`not_scored` cases remain visible for characterization and source conformance. They do not enter TP/FP/TN/FN.

## Label governance

A contributor MUST NOT change an efficacy expected label solely to make a failing detector result pass.

If an intentional product change causes an efficacy mismatch, one of the following must happen explicitly:

1. product behavior is corrected;
2. the scenario expectation is changed with an independent rationale explaining why the old expectation was wrong;
3. the case becomes `not_scored` with justification.

Golden characterization output and efficacy expectations are reviewable independently.

## Other families

Rule-match correctness is not security-review correctness. A benign case may correctly match `execution.shell` or `secret.env.read` while correctly remaining `not_required`.

Process-chain coverage is definition-backed self-match through `CompiledProcessChainRules::evaluate` plus correlation. It is not process-chain scenario efficacy and is not invoked by `Pipeline::scan_root`, `detect_records`, or `evaluate_session`.

Parser/source-conformance cases are normally `not_scored` unless the same fixture is also an independent efficacy scenario.

`make evaluation-check` validates the manifest and compares the generated deterministic report with the tracked baseline. `make evaluation-report` writes a current report only under `target/evaluation/`.
