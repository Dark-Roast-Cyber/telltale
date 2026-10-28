# Windows lifecycle validation

Local source verification on 2026-10-13 America/Phoenix used Windows 11 Pro
build 26300, native AMD64, an ordinary non-elevated account, Windows PowerShell
5.1 and PowerShell 7.6.5. Source preparation started at
`2e8c56aa45583525e4536640adb2c977ba45d46b`; PR CI provides commit-bound evidence.
No personal agent stores, canonical installation or real scheduled task was
changed on this host. Windows Sandbox was unavailable.

Synthetic lifecycle roots were beneath
`%LOCALAPPDATA%\TelltaleLifecycleTests\telltale-lifecycle-tests-<GUID>`; early
published-artifact checks used dedicated `%TEMP%\telltale-*-check` directories.
Source download staging uses fresh current-user LocalApplicationData directories.
Only the synthetic UC001 Codex fixture was copied for runtime scans. Test logs
are retained locally; private paths and raw telemetry are not public evidence.

| Local check | Result and scope |
| --- | --- |
| Latest stable install | `v0.6.0`, source `f8e00162a3f9ac1cf8d2f270e6db078d3917d186`: exact Release/assets/checksums, source-bound attestation, nine-member ZIP, version and bundled rules passed in an isolated path with spaces. |
| Explicit published install | `v0.7.0-rc.2`, source `c3132f22f0758912fbcbc7451f5fefee514c5bdb`: the same checks passed in PowerShell 7 and 5.1; uninstall and later explicit purge passed. This is installer evidence for RC2, not RC3 qualification. |
| Development lifecycle | `tests/windows_lifecycle.ps1 -BinaryPath target/release/telltale.exe`: 93 assertions passed in each supported shell, including task-transition/rollback interruptions, recovered directory ownership, runtime configuration resolution, normalized PATH cleanup, UTF-16 task declarations and cached XML exports. Development receipts explicitly say unpublished local build. |
| Execution | Bundled rules, one expected synthetic MCP detection, complete Draft 2020-12 Event 3.0 validation and zero configured remote sinks passed. |
| Ownership and retention | Same-version repeat, different development digest, relative source after changing PowerShell location, unrelated-file retention, legacy detection, modified binary/task refusal and standard retention passed. |
| Compiled development upgrade | An earlier development compilation reporting `373c7bf1702c` was installed, then replaced by a fresh clean-tree compilation at `6fd8799f4ea2`. Source identity and executable digest changed, version/rules checks passed, and uninstall plus purge removed the isolated owned directories. Both are unpublished development builds. |
| Adversarial/recovery | Missing explicit Release without fallback, checksum failures, DOS aliases, traversal/ADS/UNC, junctions, hard links, locked/running executable, metadata-write failure, partial rollback, staged interruption and read-only WhatIf passed. A separate process proved installation/data-only purge serialization. |
| Existing ZIP/runtime suites | `tests/release_windows_zip.ps1` and `tests/verify_windows_runtime.ps1` passed. Their malformed-member, flags, CRC, length and runtime-import controls are reused by the production installer. |
| Rust formatting/Clippy | `cargo fmt --all --check` and `cargo clippy --locked --all-targets -- -D warnings` passed with Rust 1.98.0 Windows GNU. |
| Debug Rust suites | CLI 241, default library suites 1,164, CI gates 1, Codex completion 14, package metadata 8 and provenance 2 passed; two library tests were ignored. Initial failures from inherited PATH, missing Python, line endings and loaded-host timing were retained and resolved by scoped tooling fixes and focused reruns. |
| Complete optimized Rust gate | `cargo test --locked --release -- --test-threads=4`: exit 0, 1,465 tests/doctests passed, two ignored. |
| Windows CI follow-up | The initial native CI run failed an existing rules-server assertion after receiving only a formatted HTTP status prefix. The response is now assembled before writing; all six rules-server integration tests passed locally in optimized and debug builds, and strict Clippy passed again. Fresh PR CI must validate the final commit. |
| Native task schema validation | A later CI run passed the static-CRT build/import gate and all 87 then-current regression assertions, then rejected UTF-8 XML at real task registration. Generated task XML now declares UTF-16 for the [COM BSTR parameter](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertask). Local native `TASK_VALIDATE_ONLY` reproduced the UTF-8 error, accepted UTF-16 and left a unique task absent. No task was registered or executed locally. Real execution remains a disposable-runner CI check. |
| Task definition follow-up | Native CI then registered the task but its captured XML still declared disabled after setting `Enabled`, so re-registering that export disabled the synthetic action. Enable/disable now updates the complete owned definition; update-only registration prevents task recreation. Regression doubles reproduce cached XML, preserve manually disabled schedules through failed replacement, and prove recovery after interruption immediately before rollback registration. Original and rollback transition proofs remain separately durable. |
| Disposable-runner ownership | Real registration, scheduled synthetic execution, expected detection, Event 3.0 validation and exact task restoration passed. Purge then correctly rejected runtime files owned by the runner's Administrators group. The CI harness verifies refusal without file/task/PATH mutation before assigning current-user ownership to its fresh synthetic outputs and known coordination sidecars. Production ownership checks remain unchanged; this runner does not establish effective non-administrator execution. |
| macOS test portability | A Unix-only HTTP backlog test inherited nonblocking mode on an accepted socket and failed with WouldBlock. Its mock server now explicitly selects blocking reads with the existing bounded timeout. Fresh macOS/Linux CI verifies this test; it cannot execute on Windows. |
| Development build | Windows GNU optimized build passed. This is not the official MSVC static-CRT configuration. |
| Local MSVC build/runtime gate | Attempted; unavailable Microsoft linker/SDK prevented the build and resulting-binary import inspection. The authoritative Windows CI build uses `-C target-feature=+crt-static` and `verify-windows-runtime.ps1`. |
| Intermittent sharing refusal (#147) | CI refusals at the installer's executable `File.Replace` showed the installed executable available, `staged.exe` refused, and a pre-job process reported as a resource user of the stage. [`ReplaceFile`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew) opens the replacement with no sharing. On 2026-10-27 (Windows 11 build 26300, Windows PowerShell 5.1), a reader sharing read, write and delete deterministically reproduced `0x80070020` against the replacement but not the replaced file, while `File.Move` tolerated it. The installer now performs the same backup and rename under shared delete handles. The `shared-stage-reader` regression injects readers at the real swap: one that permits renaming no longer blocks it; one that forbids renaming still fails with the original HRESULT before any rename and recovers only after release. Against the previous installer the scenario fails with the CI file state. The reporting process's image was not identified. |
| #148 first CI run | [Run 40594785482](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/40594785482/job/122507819101) passed `shared-stage-reader` and `partial-rollback`, then failed after 153 assertions: uninstall in `first-install-recovery` refused an `Open` of the freshly installed executable, a fresh `File.Move` install that never used the new swap. The string rethrow hid the operation; a probe about 100 ms later found the file available. Locally, any outside reader of the installed executable, even one sharing read, write and delete, refuses uninstall's exclusive `Assert-TTUnlocked` with that message. That exclusive check is unchanged; the test now keeps the original error and queries exact-file resource users for this uninstall. That run's deliberate swap refusal also used up the single pre-rollback capture; the scenario now verifies it and re-arms. New regressions cover a stale backup, a failed second rename with undo, and recovery when the backup exists but the executable is absent. Measured contract difference: unlike `File.Replace`, the swap does not carry the old executable's explicit ACEs or named streams such as `Zone.Identifier` to the new one. [Run 40602177482](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/40602177482) at `9f553e2` then passed every job, including 175 Windows assertions and the live Scheduled Task/PATH slice, with no unexpected refusal. |
| Replaceable executables (#147, approved) | The exclusive probe refused any outside reader, so a transient reader could still fail reinstall, rollback or uninstall. Natively, a probe that requests write and delete access while sharing everything still refuses a running image and readers that forbid writing or deletion, but tolerates a reader that shares everything. Managed executables now use it; journal rollback uses the shared swap instead of `File.Replace`; data and configuration purge checks remain exclusive. With delete sharing, deleting a held executable frees its name immediately on this host. `shared-executable-reader` covers reinstall, rollback and uninstall under such readers, and a reader that forbids deletion still blocks uninstall. Reinstallation keeps only inherited permissions, as a first install does. CI-only attribution now adds the image basename of each reported resource user, only when its live creation time matches. On 2026-10-27, with Visual Studio Build Tools 2026 (MSVC 14.51), Rust 1.99.1 and `-C target-feature=+crt-static`, `scripts/build-windows-development.ps1` built `telltale 0.7.0-rc.3 (f463602e29bb)` (SHA-256 `90b4b9804f272a70cad64522a558dea9769d2f932683c88d4d499c473e82c54e`), and `verify-windows-runtime.ps1` passed. With that binary and the real validator (Python 3.13.15, jsonschema 4.26.0), the local-mode matrix passed 169 assertions in Windows PowerShell 5.1.26100 and PowerShell 7.6.9. The desktop app that ran these tests redirects `%LOCALAPPDATA%` writes into its package `LocalCache`, which is NTFS on the same volume; un-redirected paths, attribution and the live Scheduler/PATH slice are covered by CI only. |

The isolated Python test environment supplies the repository's existing
`jsonschema` dependency. A malformed quote in inherited PATH was corrected only
in child processes; persistent user settings were not changed. Git attributes
preserve LF for digest-pinned JSON and all copies of the canonical positive
fixture. Existing RC2 pin contents, digests and source-specific evidence are
unchanged.

An additional `cargo test --locked --workspace --exclude telltale-cli` exploration
hit the existing disabled-OpenCode assertion when dependency feature unification
enabled SQLite in the sources crate but not the core crate. The required default
member/feature libraries passed. This extra configuration is not claimed passed;
no embedding API or feature behavior was changed by this lifecycle work.

`windows-latest` additionally runs the real current-user Scheduled Task, owned
PATH round trip, separate configuration-purge consent and canonical default
installation/runtime/uninstall/purge in its disposable account. Local scheduling,
PATH mutation, authored-config purge and canonical-directory operations were not
performed on this personal host. CI results must be read at the PR's exact head.

Independent automated reviews identified compatibility, alias, task absence,
concurrency and PATH-update defects; fixes and regressions precede merge. Neither
this report nor a source build accepts an RC3 freeze or qualifies a published
RC3 artifact. Tagging/publication, five-platform artifact verification,
candidate-specific clean-host qualification, live canary and stable promotion
remain controlled separately under Issue #87.

## Issue #147 recovery observation correction (2026-10-27)

The fresh Windows session reused #148's clean existing branch,
`claude/issue-147-investigation-46b328`, at
`baf34dcc77c84a86e4bc6da09ba0eff836c66a97` (tree
`b74c2f3ddbb0410baa3fe5b20dbe38350ec9b304`). The maintainer explicitly transferred
implementation ownership to this session. The original `main` checkout remained
clean at `7c67cb0c2be72e94d946a3c8fbecb8991ef19c71`; no existing edits were removed.

`shared-executable-reader` now models interruption after both executable swap
and receipt write. While the installed executable and backup have outside sharing
readers, it calls the real `Restore-TTTransaction` under the lifecycle mutex and
installation file lock. Before any subsequent install, it verifies the exact
previous executable digest, exact previous receipt bytes and installation ID,
transaction cleanup and still-open readers. A separate install then changes the
digest again. The refusal/release and interruption cases remain intact. No
production helper, installer, uninstaller, Rust or diagnostic behavior changed.

The tested working source is the HEAD above plus the test correction; it is not
a new committed head. `tests/windows_lifecycle.ps1` SHA-256 was
`c24ad400dfe6ef99bf76844d0ca4c5872dbf84bdb0ab77edfee016ffeb13fbd6` throughout
validation. The raw `git diff --no-ext-diff --binary HEAD -- tests/windows_lifecycle.ps1`
patch SHA-256 was `7d5c674c1831b4d714150fd651455956dd3e1d8afe8f2b506aff5ebc1693f706`.
This documentation was added after the executable/test checks.

The repository development-build helper produced `telltale 0.7.0-rc.3 (baf34dcc77c8)`
for `x86_64-pc-windows-msvc`, Rust/Cargo 1.99.1, MSVC 14.51.36231, optimized with
`-C target-feature=+crt-static`. Binary SHA-256:
`b8ed46fcc0be6fef7d15f1087e55749ead7c2ebddade433f85b4703a777b6e33`.
`verify-windows-runtime.ps1` passed using MSVC `dumpbin.exe`. Rust build inputs
match HEAD; this is an unpublished development binary. The real validator used
Python 3.12.14 and `jsonschema[format-nongpl]` 4.26.0 in an isolated local venv.

| Check | Native result |
| --- | --- |
| Focused actual `shared-executable-reader` scenario | 11 assertions passed in Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5. |
| Focused negative controls in both shells | Omitting recovery fails the previous-executable assertion; changing valid receipt metadata after recovery fails the exact-previous-receipt assertion. |
| Complete local lifecycle matrix, real validator | 172 assertions passed in each shell; 108.74 seconds in 5.1 and 136.93 seconds in 7.6.5. |
| Existing breakpoint scope/order/error suite | Passed separately in both shells and within both matrices. |
| Source checks | PowerShell parse and `git diff --check` passed; test and binary hashes stayed unchanged. |

Commands ran from the existing checkout with child-process-only execution policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-windows-development.ps1
$binary = (Resolve-Path target/x86_64-pc-windows-msvc/release/telltale.exe).Path
$python = (Resolve-Path target/issue-147-review-20261027/validator-venv/Scripts/python.exe).Path
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/verify-windows-runtime.ps1 -BinaryPath $binary
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/windows_lifecycle_breakpoints.ps1
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File tests/windows_lifecycle_breakpoints.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/windows_lifecycle.ps1 -BinaryPath $binary -Python $python
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File tests/windows_lifecycle.ps1 -BinaryPath $binary -Python $python
```

The focused local harness extracted the actual scenario/setup from the repository
test and is retained with raw logs, full command arguments, attempt outcomes and
hash manifests under ignored `target/issue-147-review-20261027`. Setup attempts
initially encountered execution policy, missing validator/network access, CRLF
extraction and sandbox-user ownership refusal. Native tests used the real
non-administrator account, with ownership guards intact and existing parent
permissions unchanged.
An initial receipt negative control was caught earlier by the production
digest/receipt guard; the corrected control reached the intended assertion.
Those harness/setup failures and their corrections are recorded locally and are
not unexpected sharing reproductions. No full matrix needed a rerun.

The specific permissions acceptance is recorded in the maintainer's
[Approved change / Permissions bullet](https://github.com/Dark-Roast-Cyber/telltale/issues/147#issuecomment-6457521336).
It covers inherited permissions and not carrying the old executable's explicit
ACEs or alternate streams. Existing acceptance is preserved; required custom
permissions must still be reapplied after reinstall, as documented in the install
guide. This session made no further permissions-policy change.

`GITHUB_ACTIONS` remained unset, Scheduler was substituted, and
`-TestScheduledTask` was not used. The desktop package LocalCache redirection
limitation remains; unredirected production-path equivalence is not established
by these runs. CI-only attribution/pre-rollback capture and live Scheduler/PATH
remain disposable-runner coverage. Full Rust tests and Clippy were not repeated
for this PowerShell-test-only correction. Historical holder/share-mode attribution
remains unknown; passing controls do not eliminate all possible refusals.

[CI 40606167394](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/40606167394)
passed all 14 jobs at the old head, and CodeQL passed; those checks predate this
correction. This local-validation snapshot precedes publication and final-source
CI. The maintainer subsequently authorized committing and pushing the correction,
one complete normal CI run, and one additional Windows job execution at the same
unchanged source, both with the real validator and live disposable-runner slice.
Record actual checkout/tree and binary identities; inspect any unexpected refusal
before spending further runs. Merge, diagnostic cleanup, release, deployment and
issue closure remain separate decisions.
