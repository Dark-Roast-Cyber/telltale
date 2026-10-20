# Evaluation Corpus v1

This corpus measures two different things. Neither is a production detection rate, production false-positive rate, or estimate of attacker prevalence.

## CHARACTERIZATION

What does the current deterministic detector do?

Exact matched and forbidden rule IDs, exact scores, exact contribution ledgers, parser/source identity, and visibility checks characterize development `main` behavior, not the immutable official v0.5.0 release. The golden characterization snapshot is a behavioral drift detector. It is not efficacy ground truth.

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

Source fixtures are acquired as Canonical Observation v2 and scored by Detection v2. `execution.shell` matches command and argument text, not a tool name. A fixture whose only shell identity is `tool_name: bash` therefore does not match `execution.shell`, and a chain that requires the execution category does not fire from that name alone. `RX-OUTBOUND-001` is characterization-only for that reason: its previous review requirement depended on the retired projection counting the tool name as command text, and this corpus does not rewrite the command or retune rules to restore it. `RX-HARVEST-EXFIL-001` states the harvest-and-upload command in the Codex `command` field so the scenario remains visible without inventing a shell token.

Process-chain coverage retains definition-backed atomic matcher conformance and
adds fixed canonical Tool contracts through `evaluate_source` and `project_event3`:
six atomic cases, three observable correlations, ordering, repeat suppression,
and benign commands. Office, web-server, and RMM parent relationships cannot be
recovered from Tool command text; their three correlation visibility gaps are
explicit in the report. All six shipped correlations also have fixed session-kernel
tests in `telltale-detect`. These checks are conformance, not scenario efficacy.
The canonical runtime and every `Pipeline` scan method use this Detection v2 path.

Source-conformance cases are normally `not_scored` unless the fixture is also an
independent efficacy scenario. The denominator is all eight identities in the
public source registry; the candidate set is empty. Registering a source without
fixture representation fails the coverage check.

`uc001_fixture_conformance_covers_every_supported_source_identity` separately
acquires attack and observed benign fixtures for all eight exact registry
identities. Seven attack fixtures produce critical MCP injection/controlled
egress matches; Copilot preserves the attack but reports the contract-backed
UserContext capability gap as indeterminate, not a benign efficacy outcome.
Mutation tests reject missing/wrong/duplicate identities and bad evidence.
`uc002_copilot_credential_publish_fixture_is_critical` checks its observable
credential-harvest/publish chain. These are conformance gates, not additional
efficacy cases, and do not change the manifest or golden report.

`make evaluation-check` validates the manifest and compares the generated deterministic report with the tracked baseline. `make evaluation-report` writes a current report only under `target/evaluation/`.

## Native source inputs only

Every case is a native source fixture evaluated on the production canonical path.
Seventeen cases (`OC-RT-001`, `RX-MCP-ENUM-INJECT-001`, and the `BC-*` record
confounders) were previously authored as client-agnostic normalized records and
scored by the retired direct-record Rule v1 evaluator. They now live in
`fixtures/record-scenarios/` as `codex.sessions` JSONL with a fixed mapping: one
`session_meta` line, then each record as the matching Codex `event_msg`
(`tool_call` with `tool_name`, the record's `arguments` string as native
`arguments`, and its content as `message`; `tool_result` and `assistant_message`
carry the content as `message`). Records labeled `opencode` never exercised the
OpenCode adapter, so they are represented as Codex too; descriptions are
unchanged.

No label, expectation, score, rule set, or contribution changed: the regenerated
report differs from the previous golden only in `manifest_sha256` and
source-coverage counts (17 more `codex.sessions` cases). Fidelity matters here.
Rule v1 text selectors read native argument strings, but not structured argument
objects or arrays (see CE-* below), and the injection signature does not read the
`command` field. A fixture that moves the same text into another field is a
different scenario, not a migration.

## Canonical synthetic tranche (CE-*)

Eleven independently labeled native cases in `fixtures/canonical-efficacy/` exercise
the actual Codex adapter and bundled rules.
All are authored synthetic fixtures: fixed JSON envelopes, repeated `ordinary
review context. ` padding (220 repetitions), invented instructions/diagnostics,
and an `.invalid` destination. No transcript, credential, host environment or
session store was copied. Each filename maps to session `synthetic-<filename
stem>`, turn `turn-1`, and item `assistant` or `call-1`. The exact efficacy source
is `(codex, codex.sessions, jsonl)`; invariant tests also acquire these same inputs
under the archived and headless identities, without counting those replays as
additional efficacy cases.

| Cases | Independent analyst expectation | Exact current characterization |
| --- | --- | --- |
| LONG-BENIGN, MIRROR-BENIGN, PARTS-BENIGN | Documentation explicitly quotes prohibited approval bypass; no review | No matches, score 0; exclusion remains effective after byte 4096 and across joined parts |
| LONG-MALICIOUS | MCP instructions to steal secrets without authorization require review | Approval bypass 45 + MCP injection 60 + override/bypass chain 30 (instruction override matches at 0), score 135; TP |
| PARTS-MALICIOUS, MIRROR-MALICIOUS | Unauthorized secret theft instructions require review | Approval bypass 45 + override/bypass chain 30 (instruction override matches at 0), score 75; TP |
| OVERRIDE-DOC-BENIGN | Documentation quotes prohibited override and approval-bypass phrasing across parts; no review | No matches, score 0; both exclusions hold across joined parts |
| OVERRIDE-QUOTE-BENIGN | Reporting an observed override phrase without acting on it; no review | Instruction override only, score 0; TN (zero-point detection event, no escalation) |
| COMMAND-SUCCESS | Authorized local formatting result needs no review | No matches, score 0; reported success is not observed execution |
| COMMAND-FAILURE, COMMAND-DECLINED | Unauthorized secret-upload attempt requires review even with reported failure/decline | No matches, score 0; FN, not evidence that the attempted action was safe |

The parts/mirror attacks lack MCP-specific language; the MCP signature is
explicitly absent, not forced to match generic instruction override. Generic
override is a separate zero-point assistant-context signal,
`prompt_injection.instruction_override`. It escalates only through
`chain.instruction_override_with_approval_bypass` (30) beside approval bypass
(45), so an override quote alone stays at 0. The chain is session-scoped: an
override in one message and an unexcluded approval-bypass phrase anywhere else in
the session also combine to 75. Completed
commands preserve argv as `tool.arguments` arrays and structured result objects,
with no searchable arguments/result or `command.text`. Rule-v1 compatibility
text selectors do not serialize or join those arrays/objects. Thus these upload
attempts are visible canonical results but invisible to the bundled outbound
upload signature. No Process/File/Network execution evidence is inferred.
The ordered benign quote splits `bypass` and `approval`, which the selector joins
with a newline. The approval-bypass exclusion uses the same `bypass\s+approval`
whitespace expression as its selection, so the joined quote is excluded. (Before
that rule correction the exclusion required a literal space, and this case
carried a 45-point benign signal; its label never changed.)

New-case security-review confusion is **TP 3 / FP 0 / TN 6 / FN 2** (precision
3/3, recall 3/5); the whole corpus is **TP 13 / FP 0 / TN 25 / FN 2** (precision
13/13, recall 13/15). These small, deliberately selected synthetic populations
are not production rates. Rule-level expected absence is characterization and
does not relabel a malicious session as benign.

`canonical_efficacy_native_invariants` checks ordered parts, long text, exact
ownership, replay, mirror suppression and physical native accounting.
`canonical_efficacy_rejection_and_ambiguous_outcomes_are_not_confusion_cases`
checks unproven mirrors, malformed late command results and status/exit-code
disagreement or absence. These are coverage/rejection contracts, not extra TP/TN
samples. Existing Codex terminal tests cover capability, fidelity and provenance.

The CLI test scans all eleven fixtures with bundled rules, compares the same exact
scores/rules, validates emitted Event3 against its schema, and checks stdout,
stderr, durable JSONL and state for absence of `SYNTHETIC-EFFICACY-PRIVATE` markers.
Markers appear only as invented `api_key=` values in messages/results (LONG,
PARTS, MIRROR, RESULT); malformed test mutations use the INVALID suffix. The
CLI also verifies inputs are unchanged. These privacy/validity assertions are
separate from efficacy confusion.

The untouched report was generated before edits as `target/evaluation/pre-tranche.v1.json`
with `pre-tranche.log`. Golden changes are explicit copies of the generated
expanded report after review of characterization; ordinary tests never rewrite
the golden. Local reports/logs are ignored evidence, not portable committed
fixtures. Reproduce with:

```sh
TELLTALE_EVAL_REPORT=canonical-tranche.v1.json cargo test --test evaluation_corpus
cargo test --test cli canonical_efficacy_fixtures_cli_characterization_and_event_privacy
```
