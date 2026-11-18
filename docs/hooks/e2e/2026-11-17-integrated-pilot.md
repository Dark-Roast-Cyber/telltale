# Integrated Hooks qualification — 2026-11-17

**Real harnesses, scripted models.** No live accounts, paid model calls,
shared service changes or deployment. Synthetic HOME/XDG roots and
loopback-only model providers. Raw synthetic receipts remain private; the
[summary](2026-11-17-integrated-pilot.summary.jsonl) contains outcomes only.

## Tested build

- Source base: `c5ac6bf7ffbfe874b7fad34104addfea8d9ed361` plus the uncommitted
  pilot changes. This is local development evidence, not a release claim.
- Integrated executable SHA-256:
  `7705b8cf02432b49443f2b8a1f9041dae09b699e889f3c2c8d42ab09ace6f2f2`.
- Initial plugin `scripts/hooks/opencode-v2.mjs` SHA-256 (superseded):
  `c6cb246ffa41e1d9396a6715ad3007d6b7008f59f09630cfbc06e8b672c9b53e`.
- Linux x86-64, development build.
- The pinned Copilot/OpenCode platform packages were extracted locally with
  npm-registry SHA-512 integrity verification, not globally installed.

After correcting config-flag parsing so a directory named like a switch is
not consumed as a switch, the final executable SHA-256 is
`7e405fcb4cafdc22c7d9be173b6340fc2aabaee5e2c5e338b3ad282a629e4256`.
The three M1 pairs and the pinned ordinary/nested/detect-only/startup M2 checks also
passed on that executable. Earlier unchanged failure/stress evidence above is
retained under the first digest, rather than attributed to an untested build.

### Corrected plugin artifact

Parent review found that the initial plugin's timeout waited for `close`,
which inherited pipes could delay after direct-child exit. It could also
signal an exited process group. That artifact's timeout qualification is
**withdrawn**; its passing ordinary cases did not exercise this boundary.

Current plugin SHA-256:
`10726f47d1ed7f05fd0a1929ca99e36dfefeb48c6120df27bd3d1504accae709`.
Executable unchanged:
`7e405fcb4cafdc22c7d9be173b6340fc2aabaee5e2c5e338b3ad282a629e4256`.
All 17 pinned **2.2.5** scenarios in the M2 table below were rerun against this
plugin and passed. The four installed **2.3.2** ordinary/nested controls and
denials were also rerun and passed. Summary rows with `phase: deadline-fix`
identify this artifact; earlier rows are retained historical evidence only.

The caller now settles at its deadline independently of pipe closure or
reaping, destroys its stream handles, and performs cleanup once. An exited
child/group is never signaled after exit is observed. Live/unreaped children
remain counted after the caller returns, so delayed or failed cleanup cannot
open a concurrency slot.

Two bounded synthetic-process regressions failed on the initial implementation:
inherited pipe retention delayed the caller until about 4.1 s despite a 1 s
deadline, and delayed cleanup likewise delayed the caller until about 4.1 s.
Both pass now, including no signal to the known-exited group and no second
launch while the timed-out child remains live. The latter substitutes a
delayed/failed kill, not a harness: these are process regressions, not live
qualification or evidence of cleaning up detached descendants.
Independent mutations removing the known-exited guard or releasing capacity
before reaping each failed exactly its corresponding regression.

### Plugin with a waiting queue

The plugin later gained a bounded waiting queue (`maxQueued`, default 32), so
a callback that finds every child slot busy waits within its own deadline
before it takes the failure policy. Plugin SHA-256:
`a3e441fb3b54228089dd32f06de0cf5f05dde55280b0e81f435d35dd063bc31c`.
Executable unchanged.

All 17 scenarios in the M2 table below were rerun against this plugin on the
installed **2.3.2**, standalone, and passed; summary rows with `phase: queue`
record them. They were **not** rerun on the 2.2.5 pin, which was not available
to that run. No scenario fills the queue under a real harness: waiting, the
queue bound and the `maxQueued: 0` behaviour are covered by the
substituted-executable process tests only.

### After merging main

Main changed the Copilot CLI and Codex CLI drivers while this work was in
progress: every scenario now states what it expects of the hook. The merged
drivers keep that expectation and the same-call join. On the merged tree the
installed Codex CLI **0.167.0** passed `allow deny` and the installed Copilot
CLI **1.0.105** passed `benign deny`, scripted models, in-process evaluation.
Codex 0.167.0 is not the pinned version; this confirms the merged drivers,
not a new pin.

That Copilot run sent its tool arguments as a JSON string where the captured
payloads carry an object. The join hashed the parsed form and so refused to
match a correct run; it now hashes the arguments as the harness sent them,
which is what the hook records.

## M1 — command hooks

| Harness | Actual version | Pair | Result | Limits |
| --- | --- | --- | --- | --- |
| Claude Code | 2.1.327 | `benign deny` | Both passed | Installed binary; scripted Messages provider; separate from 2.1.318 historical capture |
| GitHub Copilot CLI | 1.0.105 | `benign deny` | Both passed | Pinned platform binary; scripted chat provider; in-process evaluation |
| OpenAI Codex CLI | 0.166.0 | `allow deny` | Both passed | Retained pinned binary; scripted Responses provider; hook-trust bypass flag; in-process evaluation |

Each control created its canary. Each denied twin attempted the canary-bearing
call, received the marker denial containing that decision's record ID, and
settled `not_executed`/`honored` against the same decision. The qualification
join checks the native tool/input hash, native hook output, model receipt and
outcome decision ID. Missing attempts, unrelated decisions/settlements,
failed launches or an absent canary alone cannot pass.

Drivers:

```text
uv run --no-project python scripts/hooks/harness/claude-code-scripted-e2e.py benign deny
uv run --no-project python scripts/hooks/harness/copilot-cli-e2e.py benign deny
uv run --no-project python scripts/hooks/harness/codex-cli-e2e.py allow deny
```

Set the documented binary overrides, private output roots and in-process
evaluator settings. Claude's existing live-model driver was not run. Installed
Copilot 1.0.78 and Codex 0.167.0 were version-probed, not qualified here. The
historical 2.1.318 Claude pin is not silently replaced or requalified.

## M2 — OpenCode request-only pilot

**2.2.5**, standalone, scripted custom provider, manual plugin factory install:

| Scenarios | Observed result |
| --- | --- |
| `ordinary-control`, `ordinary-deny` | Control canary created; denied canary absent; marker decision ID in native callback and model receipt |
| `nested-control`, `nested-deny` | Real inner MCP canary created only by control; outer source constructs the deny marker at runtime, so the inner request is the enforcement point |
| `nested-repeat-deny` | Three identical concurrent inner calls share a native outer ID but have three distinct occurrence IDs and three returned marker receipts; no canary |
| `parallel` | Denied twin blocked; ordinary sibling canary created |
| `detect-only` | Deny-level action recorded with `returned: false`; canary created |
| `failure-missing`, `failure-invalid`, `failure-hang` | Explicit enforce-mode transport-failure denial; no canary |
| `failure-lost` | Real Telltale marker decision recorded, reply discarded; generic transport denial, no canary; **no marker-receipt claim** |
| `failure-noop`, `detect-failure-hang`, `detect-failure-missing` | Canary created; no plugin throw |
| `init-broken` | Broken plugin skipped; canary created: upstream startup remains **fail-open** |
| `native-deny`, `native-ask` | Benign calls get no Telltale deny; native permission denial and non-auto ask still prevent the canary |

The same ordinary and nested pairs also passed on installed **2.3.2**,
standalone. That is separate narrow evidence, not a pin change or requalification
of its failure modes.

Reproduce with the scenario names above:

```text
uv run --no-project python scripts/hooks/harness/opencode-v2-e2e.py <scenario ...>
```

**Settlement limit:** every OpenCode run produced zero outcome records.
The pilot forwards requests only. It never consumes outer completion, generic
error, bus replay or turn end as a terminal event for an inner occurrence.
Calls remain pending with unknown outcomes, not inferred `honored` decisions.
No persisted replay cache or restart-stable occurrence identity is claimed.

## Regression checks and residual gates

| Command | Result |
| --- | --- |
| `cargo test --locked --test cli hooks_` | Exit 0; 92 passed |
| `cargo test --locked -p telltale-core --lib hooks::` | Exit 0; 117 passed |
| `cargo test --locked -p telltale-core --test hooks harness_contract` | Exit 0; 18 passed |
| `cargo test --locked -p telltale-core --test hooks harness_identity` | Exit 0; 5 passed after adding the new adapter's captured payload to the test table |
| `cargo test --locked -p telltale-core --test hooks normalize_parity` | Exit 0; 10 passed |
| `make clippy` | Exit 0; default and no-default-feature targets |
| `make hooks-plugin-check` | Exit 0 on corrected plugin; 7 qualification and 13 subprocess tests (16 subprocess tests with the queue) |
| `make hooks-progress-update` | Exit 0; 2 generator tests |
| `make release-public-docs-check` | Exit 0 |
| `make CARGO_LOCKED=--locked ci-linux-test` | Exit 0; 5,870 passing test executions across feature variants, 32 ignored; Event 3.0, provenance and LocalEventFeed checks passed |
| `cargo fmt --all --check`, `git diff --check` | Exit 0 |

The first broad Linux run failed because the identity fixture table omitted
the newly registered adapter. That table was corrected; both its focused
rerun and the final complete Linux gate passed.

The plugin process tests
cover explicit no-op/deny, empty output, native-allow rejection, nonzero exit,
reply bounds, missing/hung child, reaping/slot reuse, late inherited pipe
closure, post-deadline live-child capacity, detect-only and
independent occurrences. These substituted-executable tests are **not** live
harness qualification. Qualification and denial mutations were rejected.

No service-mode run, managed startup, packaged plugin installer, complete
artifact self-protection, Windows/macOS runtime, interactive ask or live-model
behavior is qualified. Live pilot tool paths are shell and inner MCP only;
read, write, edit, patch, web and subagent paths were not requalified by these
canaries. The installed Pi client was not needed; no Pi adapter
was added. Native permission and broad local gates are recorded separately
from marker enforcement; passing synthetic checks are not production efficacy.
