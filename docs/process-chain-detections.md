# Process-Chain Detections

Telltale's Rule v1 content compatibility asks "does this text look risky".
Process-chain rules ask whether available evidence supports a parent/child
matcher relationship and what command context accompanies it. In the production
path, Detection v2 evaluates both: Rule v1 retains its content-compatibility
semantics, while the specialized process-chain evaluator uses the compiled
process-chain rules and shared session kernel. Rule v1 results continue through
the Event3 `detection` compatibility projection; process-chain results project
Event3 `process_chain` events. Directly observed Process evidence can support
an execution relationship. Command/tool-derived matcher context is an
interpretation and does **not** prove that one process spawned another.
Process-chain evaluation is not a parallel legacy engine running alongside
Detection v2.

- Rule pack: `crates/telltale-rules/data/process-chain.yaml` (generated)
- Generator: `scripts/dev/generate-process-chain-rules.py`
- Matching engine: `crates/telltale-rules/src/process_chain.rs`
- Configuration and command extraction: `crates/telltale-detect/src/process_chain.rs`
- Detection v2 Tool matching/session adapter:
  `crates/telltale-detect/src/v2/process_chain.rs`
- Shared suppression/correlation kernel: `crates/telltale-detect/src/process_chain_session.rs`
- Event3 compatibility projection: `crates/telltale-detect/src/v2/event3.rs`
- Event type: `process_chain`

Behavioural reference: the irflow-timeline process-tree rule library
(<https://github.com/r3nzsec/irflow-timeline>, `src/detection-rules.js`). Telltale
takes the parent/child pairs, ATT&CK mappings, and analyst reasons from that
library. Scores, categories, command-line conditions, deduplication, and
correlation are Telltale's own.

Set `TELLTALE_PROCESS_CHAIN_DETECTIONS=0` to turn the pack off for a scan.

## Detection v2 convergence status

A bounded Detection v2 path now evaluates command-derived
parent/child matcher context and standalone rules from command-bearing Canonical
Observation v2 Tool evidence,
and a caller-grouped session evaluator applies repeat suppression and the six
specialized process-chain correlations;
the exact evidence and lifecycle contract is documented in
[Detection v2](detection-v2.md#tool-derived-process-chain-boundary). Command
parsing creates private matcher working state, not Canonical Process evidence.
`CompiledProcessChainRules` remains the authoritative matcher, and matches use
ordinary Detection v2 DetectorResults, Signals, and Findings.

This path is active in the canonical scan/watch/embedding runtime. The pure
session kernel is the sole repeat/correlation semantic owner. There is no
direct-record process-chain detector or Event-based correlation adapter.
Event3 projects the canonical session result; Event4 remains inactive.

## The core rule: emission and risk are separate decisions

Every rule match emits an event. A rule may score `0`; that does not make it
silent. A zero-score match emits with:

```json
{ "event_type": "process_chain", "risk_score": 0, "severity": "informational",
  "informational": true, "risk_contributions": [] }
```

It names its entity (`risk_entity_type` / `risk_entity_value`) but adds no risk
to it. It still appears in timelines, still answers hunting queries, and — the
reason it exists — still counts as a required step in a correlation sequence.
`powershell -> hostname` is worthless alone and load-bearing when it precedes
account enumeration.

## Scoring model

The pack reuses the score bands already documented in
[detection-content-standard.md](detection-content-standard.md), so a
process-chain score means the same thing as any other Telltale rule score.

| Severity | Score band | Meaning |
| --- | --- | --- |
| `informational` | 0 | Worth placing on a timeline; contributes nothing. |
| `low` | 20–39 | Weak or common signal that becomes useful through correlation. |
| `medium` | 40–49 | Suspicious; needs context or validation. |
| `high` | 50–79 | Strongly associated with intrusion activity. |
| `critical` | 80–100 | Highly specific; likely compromise or destructive action. |

The engine enforces the bands: a rule whose `score` falls outside its declared
`severity` fails to compile.

### How a rule's number is chosen

Source severity `0..3` is only a starting point. The generator computes:

```
score = tier_base
      + 5  if the child is a purpose-built offensive tool
      + 5  if the parent materially raises confidence
      + 5  if the behaviour is destructive or irreversible
      + 3  if the rule is gated on a specific command-line condition
      clamped into the tier band
```

`tier_base` is 0 / 20 / 40 / 55 / 80. The tier itself is chosen from the
behaviour, not copied:

- **Promoted to critical** — web-server and database parents spawning a shell
  (`w3wp`, `tomcat`, `httpd`, `nginx`, `sqlservr`, Exchange workers: web-shell
  execution); any child of `lsass`, `csrss`, or `smss`; accessibility-binary
  backdoors; purpose-built credential and AD tooling (`mimikatz`, `rubeus`,
  `lazagne`, `ntdsutil`, `adfind`, `sharphound`); tunnels (`ngrok`, `chisel`);
  bulk cloud exfiltration (`rclone`, `megacmd`); and destructive actions gated
  on their actual argument.
- **Promoted to high** — Office, PDF-reader, and browser parents spawning an
  interpreter or LOLBin. This is the most reliable initial-access chain in the
  library and the parent carries nearly all of the confidence.
- **Demoted** — `cmd -> powershell`, `powershell -> cmd`, `powershell ->
  powershell`, `wsl -> cmd`, `bash -> cmd`, `cmd -> xcopy`, `gpupdate`, and
  `klist`. These are ordinary on developer and administrator hosts. Scoring them
  as the source library does would drown the signal.

Resulting distribution: 36 informational, 61 low, 115 medium, 72 high, 68
critical chain rules, plus 13 standalone indicators and 6 correlations.

### Why event severity can read lower than rule severity

`severity` on the event is derived from the scanner thresholds (`20 / 50 / 70 /
90`), exactly like every other Telltale event, because scores are additive
across rules. A single `critical` rule scoring 85 therefore bands as `high`; two
of them in one session cross 90. The rule author's intent is preserved verbatim
in `process.rule_severity`. Do not read one as a bug in the other.

Worked examples:

| Chain | Rule severity | Score | Event severity |
| --- | --- | ---: | --- |
| `powershell -> hostname` | informational | 0 | informational |
| `cmd -> whoami` | low | 20 | low |
| `winword -> powershell` | high | 60 | medium |
| `w3wp -> cmd` | critical | 85 | high |
| `cmd -> mimikatz` | critical | 90 | critical |
| `cmd -> vssadmin delete shadows` | critical | 88 | high |

## Rule shape

```yaml
- id: procchain.impact.vssadmin_shadow_delete   # stable, canonical, immutable
  title: cmd deleted Volume Shadow Copies
  category: impact
  severity: critical
  score: 88
  confidence: high
  parent: cmd
  child: vssadmin
  mitre: [T1490]
  reason: "cmd -> vssadmin - shadow copies deleted or resized away, ..."
  child_command_line_any:
    - "delete\\s+shadows"
    - "resize\\s+shadowstorage"
```

Optional per-rule fields: `child_command_line_none`, `child_path_any`,
`child_path_none`, `dedup_key`, `enabled`, `source_severity` (provenance).

Detection class, analytic intent, recommended investigation fields, and
false-positive notes are declared once per category in the pack's `categories:`
block and inherited by every rule in that category. Repeating five lines of
prose across 350 rules would guarantee drift.

Standalone indicators (`standalone:`) match `process_name`, `process_path`, or
`command_line` with `patterns` and optional `exclude`, and need no parent.
Correlations (`correlations:`) declare an ordered `sequence`, a
`window_seconds`, and an `entity`.

## Normalization

`normalize_process_name` reduces a name or full path to one comparison key:

- Basename only; both `\` and `/` separators are handled.
- Surrounding quotes and whitespace stripped.
- Lowercased.
- One trailing `.exe` removed; remaining `.` and `-` become `_`, so
  `ScreenConnect.ClientService.exe` has exactly one spelling.

Matching is **whole-key equality, never substring**. `net` does not match
`netsh`; `7z` does not match `7za`. The original path and command line are
preserved on the event (after redaction) — normalization is for matching only.

## Categories

Process-chain rules add these ADR categories, alongside the existing
`execution`, `persistence`, `exfiltration`, and `download`:

| Category | Meaning |
| --- | --- |
| `defense_evasion` | LOLBin proxy execution, log and recovery tampering, security-tool interference. |
| `command_and_control` | Download cradles, RMM abuse, tunnelling. |
| `discovery` | Host, account, network, service, and AD enumeration. |
| `credential_access` | LSASS, SAM/SECURITY hives, NTDS.dit, ticket and vault tooling. |
| `lateral_movement` | PsExec, WinRM, DCOM, SSH, GPO deployment. |
| `impact` | Shadow-copy and backup destruction, boot-recovery sabotage, wiping. |
| `collection` | Archive staging ahead of exfiltration. |

## Deduplication

Several parent/child pairs appear in more than one behavioural category in the
source library. That is deliberate and preserved, but it must not produce two
events for one action.

Matches are grouped by **dedup key**:

- chain rules: `chain:{parent}>{child}`
- process-name and path indicators: `standalone:{rule_id}:{binary}`
- command-line indicators: `standalone:{rule_id}` — one command seen at several
  interpreter nesting levels is still one finding
- correlations: a domain-separated digest over rule identity and canonical session scope

Within a group the highest score wins; ties break on severity, then rule ID for
determinism. The winner is the only rule that contributes risk. Losers survive
as `process.secondary_rule_ids`, and **every** technique ID in the group is
merged into the winner's `mitre_attack_techniques`, so no ATT&CK mapping is
lost.

Across observations, the session kernel collapses the same rule against the same
entity and matcher dedupe key inside the suppression window (1 hour by default).
The retained occurrence projects a `repeat_count` evidence entry.

### Overlaps split by command line, not collapsed

The overlaps that matter are not the same behaviour and are not deduplicated
away — they are separated by a command-line condition so that the routine case
and the intrusion case get different rules, different techniques, and different
scores:

| Pair | Routine variant | Intrusion variant |
| --- | --- | --- |
| `-> vssadmin` | create/list shadow copy (medium, T1003.003) | `delete shadows` (critical, T1490) |
| `-> wmic` | inventory query (low, T1047) | `shadowcopy delete` (critical, T1490); event subscription (medium, T1546.003) |
| `-> reg` | `query` (informational, T1012) | hive `save` of SAM/SECURITY (high, T1003.002); Run key write (medium, T1547.001) |
| `-> sc` | `query` (informational, T1007) | `create`/`config` (medium, T1543.003) |
| `-> net` | account enum (low, T1087.002); share enum (low, T1135) | `/add` to a group (high, T1136.001) |
| `-> psexec` | remote execution (medium, T1570) | `@hostlist` mass deployment (critical, T1486) |
| `-> wevtutil` | log query (informational) | `cl` clear (critical, T1070.001) |
| `-> fltmc` | enumerate filters (informational) | `unload` (critical, T1562.001) |
| `-> curl` | fetch (low, T1105) | upload flags (high, T1048) |
| `-> 7z`/`rar` | archive (low) | `-p` password flag (high, T1560.001) |
| `-> bcdedit` | inspect (informational) | `recoveryenabled no` (critical, T1490) |
| `-> certutil` | certificate work (no rule) | `-urlcache`/`-decode` cradle (high, T1105) |

This is why `cmd -> wmic` is not simply "a ransomware indicator", which is what a
blanket severity-3 mapping would claim.

## Correlation

Correlation runs over retained matcher candidates before Event3 projection,
grouped by entity and ordered by occurrence time. Six sequences ship:

| Rule | Sequence | Window | Score |
| --- | --- | ---: | ---: |
| `procchain.correlation.host_then_account_discovery` | host fingerprinting → account enumeration | 15 min | 45 |
| `procchain.correlation.discovery_then_remote_exec` | discovery → lateral movement | 30 min | 55 |
| `procchain.correlation.archive_then_cloud_transfer` | collection → exfiltration | 60 min | 65 |
| `procchain.correlation.office_script_then_download` | Office → script host → remote fetch | 10 min | 70 |
| `procchain.correlation.webshell_then_discovery` | web-server → shell → discovery | 15 min | 80 |
| `procchain.correlation.rmm_then_credential_or_evasion` | RMM → interpreter → credential access or evasion | 30 min | 60 |

Bounds that stop unbounded summation:

- **Entity boundary** — sequences never cross entities.
- **Time window** — per rule, above.
- **Sequence requirement** — steps must occur in order, not merely co-occur.
- **Per-rule throttle** — one correlation per rule per entity per scan
  (`max_correlations_per_rule_entity`).
- **Risk cap** — 150 points of correlation risk per entity per scan
  (`max_correlation_risk_per_entity`). Past the cap a correlation still emits,
  as an informational event tagged `risk_capped` with a `risk_adjustment` note.
  Evidence is never dropped for budget reasons.

Informational events contribute zero risk directly and still satisfy sequence
steps, which is the whole point of emitting them.

The production v2 session path uses the six compiled definitions and
step predicates. Its ordered candidates use source-reported `occurred_at`, not
`observed_at`; a missing occurrence time retains the atomic result but cannot
participate in timed suppression or correlation. Equal timestamps retain parser
and caller order, so statements derived from one Tool observation cannot be
reordered by detector ID. Tool-derived matcher input has no host or user in this
tranche, so the v2 path uses only the opaque canonical session ID as scope;
direct host/user scope is deferred to canonical Process evidence. Different
sessions never correlate. Correlation results remain ordinary
`DetectorKind::ProcessChain` results with `FindingKind::Correlation` and
`CorrelationScope::Sequence`, omit aggregate capability context, and do not use
the reserved generic `Sequence` or `Correlation` kinds.

Three enabled correlations require structured parent relationships that current
canonical Tool command evidence cannot supply:

- `procchain.correlation.office_script_then_download`
- `procchain.correlation.webshell_then_discovery`
- `procchain.correlation.rmm_then_credential_or_evasion`

The evaluation corpus retains definition-backed atomic matcher conformance and
fixed shipped-correlation session-kernel coverage for these rules, but it does
not demonstrate positive canonical Tool detections for them. Canonical positive
coverage awaits truthful structured Process evidence. No parent facts are
manufactured to claim runtime coverage.

## False-positive controls

Controls live in `ProcessChainContext`: `approved_admin_users`,
`management_hosts`, `approved_rmm_products`.

They **reduce** risk; they never delete an event. A demoted detection drops one
severity band to that band's base score, sets `informational` if it reaches 0,
and records why in `process.risk_adjustment`. The event, its rule ID, its
technique mapping, and its command line all survive.

Two guards keep an allowlist from becoming a blindfold:

1. **A rule gated on a command-line condition is never softened.** That rule
   fired because it saw the actual argument — `delete shadows`, `/add`,
   `-urlcache` — not because a common pair occurred. An approved admin running
   `net localgroup administrators evil /add` stays `high`.
2. **Critical rules are never demoted by user approval**, and credential-access
   and impact categories are outside the user and management-host controls
   entirely.

## Extraction from agent sessions

Agent transcripts ship a shell tool call, not a process tree. The extractor
recovers what the command line actually states and marks what it had to guess.

- **Explicit** (`source_process_inferred: false`) — an interpreter with a
  payload: `cmd /c whoami` is a real `cmd -> whoami` relationship, as are
  `powershell -Command`, `bash -c`, and `wsl -e`. Statements are split on
  `&&`, `||`, `;`, `|`, and newlines, quote-aware, and nesting recurses to
  depth 3.
- **Inferred** (`source_process_inferred: true`) — a top-level binary with no
  visible interpreter gets `cmd` as the parent only when the binary is
  Windows-only or the statement is unambiguously Windows-shaped. Inferred
  parents drop `confidence` one band.
- **Neither** — for anything else the parent is left empty. A POSIX command line
  gets no invented Windows shell. Only standalone indicators can match, which is
  why the standalone set carries the weight for `curl`, `rclone`, `7z`, and
  credential-dumping command lines.

An interpreter that carries a recoverable payload is not itself reported as a
child: its payload already describes the real children and repeats the same
text. `powershell -enc <blob>`, which has no recoverable payload, is reported.

The existing matcher can accept structured `ProcessObservation` working input
directly, but no current source supplies it. Detection v2 does not consume
direct Canonical Process observations yet; that stronger evidence path is
deferred until a real source contract requires it.

## Event fields

`process_chain` events carry the standard Telltale envelope plus:

| Field | Notes |
| --- | --- |
| `informational` | `true` when `risk_score` is 0. |
| `confidence` | `low` / `medium` / `high`. |
| `detection_reason` | Redacted analyst sentence. |
| `mitre_attack_techniques` | Winner's techniques plus every deduplicated rule's. Canonical `T1234`/`T1234.001` IDs remain readable; unexpected values are emitted as deterministic `mitre:<sha256>` identifiers. |
| `risk_entity_type` / `risk_entity_value` | `host`, `user`, or `session`. Degrades to `session` when a transcript names no host, rather than labelling a session ID as a host. |
| `process.*` | Host, user, source/target/parent process name, path, PID, and command line; `source_event_id`; `source_process_inferred`; `rule_name`; `rule_severity`; `secondary_rule_ids`; `investigation_fields`; `falsepositives`; `dedup_key`; `suppression_window_seconds`; `risk_adjustment`. |

Command lines and paths pass through `redact_sensitive_text` before emission,
and all process-chain fields cross the terminal Event privacy boundary. A
credential pasted into a command line or a manually mutated source hash or
technique value therefore does not reach the SIEM unchanged.

Process-chain risk accrues to the entity named on the event. It is deliberately
**not** folded into the session `risk_summary`, whose contract is per-session
and unchanged.

## Regenerating the pack

```sh
python3 scripts/dev/generate-process-chain-rules.py
cargo test -p telltale-rules -p telltale-detect
```

Rule IDs are immutable once released. Retire, never reuse — see the deprecation
rules in [detection-content-standard.md](detection-content-standard.md).
