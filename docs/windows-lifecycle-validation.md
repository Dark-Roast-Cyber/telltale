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
| Development lifecycle | `tests/windows_lifecycle.ps1 -BinaryPath target/release/telltale.exe`: 76 assertions passed in each supported shell, including task-transition interruptions. Development receipts explicitly say unpublished local build. |
| Execution | Bundled rules, one expected synthetic MCP detection, complete Draft 2020-12 Event 3.0 validation and zero configured remote sinks passed. |
| Ownership and retention | Same-version repeat, different development digest, relative source after changing PowerShell location, unrelated-file retention, legacy detection, modified binary/task refusal and standard retention passed. |
| Adversarial/recovery | Missing explicit Release without fallback, checksum failures, DOS aliases, traversal/ADS/UNC, junctions, hard links, locked/running executable, metadata-write failure, partial rollback, staged interruption and read-only WhatIf passed. A separate process proved installation/data-only purge serialization. |
| Existing ZIP/runtime suites | `tests/release_windows_zip.ps1` and `tests/verify_windows_runtime.ps1` passed. Their malformed-member, flags, CRC, length and runtime-import controls are reused by the production installer. |
| Rust formatting/Clippy | `cargo fmt --all --check` and `cargo clippy --locked --all-targets -- -D warnings` passed with Rust 1.98.0 Windows GNU. |
| Debug Rust suites | CLI 241, default library suites 1,164, CI gates 1, Codex completion 14, package metadata 8 and provenance 2 passed; two library tests were ignored. Initial failures from inherited PATH, missing Python, line endings and loaded-host timing were retained and resolved by scoped tooling fixes and focused reruns. |
| Complete optimized Rust gate | `cargo test --locked --release -- --test-threads=4`: exit 0, 1,465 tests/doctests passed, two ignored. |
| Development build | Windows GNU optimized build passed. This is not the official MSVC static-CRT configuration. |
| Local MSVC build/runtime gate | Attempted; unavailable Microsoft linker/SDK prevented the build and resulting-binary import inspection. The authoritative Windows CI build uses `-C target-feature=+crt-static` and `verify-windows-runtime.ps1`. |

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
