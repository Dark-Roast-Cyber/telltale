# telltale-rules

[![crates.io](https://img.shields.io/crates/v/telltale-rules.svg)](https://crates.io/crates/telltale-rules)

The I/O-free Telltale rule engine: YAML parsing and validation, policy and rule
merging, regex compilation, and in-memory evaluation. It does not read files,
watch directories, or access a database. The bundled default rule document is
embedded in the package; `config/rules/tool-call-regex.yaml` remains the
repository source of truth.

```rust
let rules = telltale_rules::load_default_rule_set()?;
assert!(rules.rule_count() > 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`CompiledRuleSet::compatibility_export()` exposes the effective compiled Rule v1
semantics used by the public provenance manifest. Its `fingerprint()` is
domain-separated and does not hash source YAML, formatting, filesystem paths,
policy names, or descriptive rule metadata (`title`, `description`, and
`falsepositives`). Rule and modifier order remains identity-bearing because
evaluation emits ordered rule IDs; `explanation` remains because it becomes the
risk-contribution rationale.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [API documentation](https://docs.rs/telltale-rules)
- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
