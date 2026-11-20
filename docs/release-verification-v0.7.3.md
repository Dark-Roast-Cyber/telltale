# Telltale v0.7.3 native verification

All five published targets passed native verification in GitHub Actions. The independent Windows run also passed and produced the same archive and executable SHA-256 digests as the Windows job. [GitHub Actions run 44823131496](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496)

| Release | GitHub Release ID | Release source commit | Verification workflow commit on `main` |
| --- | --- | --- | --- |
| `v0.7.3` | `453067866` | `7da3922168ab2173d652a38124b22ce326d66438` | `d54e8f21b03cde0d84d2376f2fef6cc6f96be1d5` |

## GitHub Actions evidence

Every `NATIVE_RELEASE_EVIDENCE` block recorded version `telltale 0.7.3 (7da3922168ab)` and reported `PASS` for `bundled_rules`, `positive_fixture`, `event_3_0`, and `provenance`. Each job executed its downloaded release binary.

| Target | Observed OS | Observed architecture | Runner label | Result | Job log |
| --- | --- | --- | --- | --- | --- |
| `x86_64-pc-windows-msvc` | Windows | `AMD64` | `windows-latest` | PASS | [Windows x64](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842601) |
| `x86_64-apple-darwin` | macOS | `x86_64` | `macos-15-intel` | PASS | [macOS Intel](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842806) |
| `aarch64-apple-darwin` | macOS | `arm64` | `macos-latest` | PASS | [macOS ARM](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842329) |
| `x86_64-unknown-linux-gnu` | Linux | `x86_64` | `ubuntu-latest` | PASS | [Linux x64](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842713) |
| `aarch64-unknown-linux-gnu` | Linux | `aarch64` | `ubuntu-24.04-arm` | PASS | [Linux ARM](https://github.com/Dark-Roast-Cyber/telltale/actions/runs/44823131496/job/136588842242) |

### SHA-256 digests

All five archive digests and all five executable digests matched the release pin. The Windows executable was `telltale.exe`. The other executables were named `telltale`.

```text
telltale-v0.7.3-x86_64-pc-windows-msvc.zip
  archive  6e056825c3e0ec20a03a658bbc8bcf53b1787b5ed20fb35cd136fa5731a7efbf
  binary   b8e7db27630d9eb3f4accda624b4ecc6e7e3d97a7a63e06eba66f79ef7e3b5e9

telltale-v0.7.3-x86_64-apple-darwin.tar.gz
  archive  2233ce2c85def80d8280445641979d86b9bce5efa9022212cfb9dcc75f32bc4d
  binary   4a8bdf1d21610244e4b515be9cfe78fc60339faa2dc783ba895b2ef28a8bc7f8

telltale-v0.7.3-aarch64-apple-darwin.tar.gz
  archive  7850a1d02da79921e94049b1448b76c21e72e1a797b5b2708fdcf3c0d9cd815b
  binary   1cd98b10132842c04423d6cf7f4d71a49b0bf7a5b0515dc02a9dadeb48797388

telltale-v0.7.3-x86_64-unknown-linux-gnu.tar.gz
  archive  95d419f0a47460a8ad0e1f9b2610dd8346eef2ff2c49416ae64e54ab04b3ebc5
  binary   1f9ff50a5c3ecf67e8999f08ef52d6fe2dd6a92fd9e8a063b64a3f78cec281d5

telltale-v0.7.3-aarch64-unknown-linux-gnu.tar.gz
  archive  ac3ca715072b46c746b3f2ef5400f509eeffe33d71ba337c66a8ffc9bddf31a8
  binary   40240176f8a09a9ac92192d2aad38fe4a91f3af01e399c7a87a7ecb69ec5e7ad
```

## Independent local Windows evidence

The published ZIP ran natively on Windows 11 Pro 26H2, build `26300.10075`, on x86_64 (`AMD64`). Microsoft Visual C++ v14 Redistributable `14.51.36247.0` was installed for x64 and x86.

| Gate | Result | Evidence |
| --- | --- | --- |
| Archive SHA-256 | PASS | Matched both `SHA256SUMS` and the release pin |
| Attestation | PASS | Signed source ref `refs/tags/v0.7.3` and source digest `7da3922168ab2173d652a38124b22ce326d66438` |
| Executable SHA-256 | PASS | Matched the release pin and the Windows job above |
| `telltale.exe --version` | PASS | `telltale 0.7.3 (7da3922168ab)` |
| Native verification script | PASS | Exit code `0` |

The local verifier ended with these four lines.

```text
bundled_rules=PASS
positive_fixture=PASS
event_3_0=PASS
provenance=PASS
```

### Local Windows deviations

- The procedure ran in PowerShell using the host’s authenticated GitHub CLI and a temporary sparse checkout of `main` at the workflow commit above. The verifier printed `verification_workflow_sha=not-provided`.
- The two archive checksum comparisons ran before attestation. The attestation command used `--format json` to confirm the signed source ref and digest.
- The Event 3.0 validator dependency was installed in a scratch Python virtual environment.
- `RUNNER_LABEL=windows-latest` was set manually for the verifier invocation only. The script checked the actual Windows OS and architecture.

The scratch directory was deleted and its removal was confirmed.
