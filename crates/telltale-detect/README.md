# telltale-detect


Detection v2 over Canonical Observation v2: Rule v1 content compilation,
canonical session evaluation, process-chain correlation, Event3 projection,
timelines, baseline models, allowlists, and optional MCP analysis. Source
acquisition belongs to `telltale-sources`; scan/watch orchestration belongs to
`telltale-core` and the CLI.

```rust
let rules = telltale_rules::load_default_rule_set()?;
let plan = telltale_detect::v2::compile_rule_v1(&rules.compatibility_export())?;
let _identity = plan.semantic_provenance();
# Ok::<(), Box<dyn std::error::Error>>(())
```

`allowlist::Allowlist::suppression_provenance()` provides the separate
domain-separated suppression identity used by the provenance manifest. It
declares canonicalization `suppression-v1-effective-v1`. Criteria remain in the
digest preimage only; public materialization exposes only suppression state,
count, canonicalization, and fingerprint, not names or criteria.

The default `source-io` feature enables source-dependent support such as MCP
inventory and its I/O dependencies (`telltale-sources`, `walkdir`). It does not
expose a filesystem-backed detection/parser pipeline. Detection v2 evaluation
remains I/O-free; consumers can use
`default-features = false` to omit source I/O, SQLite, and `walkdir`. Pair the
crate with `telltale-rules` and `telltale-schema` for rule sets and record types.

Process-chain evaluation uses canonical Tool observations through
`v2::session::evaluate_source` and projects Event3 through `v2::event3`.
`process_chain::ProcessChainConfig` remains public; command extraction and the
single suppression/correlation kernel are crate-private.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
