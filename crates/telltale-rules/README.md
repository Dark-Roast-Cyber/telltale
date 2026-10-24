# telltale-rules


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

`package` validates `telltale-rule-package/v1` documents: identified, versioned,
namespaced Rule v1 content that only adds definitions. The community package
(`telltale.community`, namespace `tdx`) is embedded from a published release of
the community detections repository; `scripts/dev/vendor-community-rules.py`
refreshes it. `resolve_rule_packages` selects the effective packages, letting a
supplied community package replace the embedded snapshot:

```rust
use telltale_rules::package::{CommunityRules, RulePackage, resolve_rule_packages};

let supplied: Vec<RulePackage> = Vec::new(); // RulePackage::parse(&text)? per package
let mut rule_sets = vec![telltale_rules::bundled_default_rule_set()?];
for resolved in resolve_rule_packages(CommunityRules::Embedded, supplied)? {
    rule_sets.extend(resolved.package.into_documents());
}
let rules = telltale_rules::compile_rule_sets(rule_sets, None)?;
assert!(rules.rule_count() > 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`CompiledRuleSet::compatibility_export()` exposes the effective compiled Rule v1
semantics used by the public provenance manifest. The export's
`evaluate_matched()` supplies the same session-level Rule v1 content decisions
used by `CompiledRuleSet::evaluate()` and Detection v2; canonical applicability
and evidence selection remain with Detection v2. Detection v2 session evaluation
calls `evaluate_matched_without()` to withhold a modifier whose steps are not
linked in the session: outside its declared `link`, or, for the bundled
`chain.download_then_execute`, without downloaded content that runs. A modifier
without a `link` is never withheld. Its `fingerprint()` is
domain-separated and does not hash source YAML, formatting, filesystem paths,
policy names, or descriptive rule metadata (`title`, `description`, and
`falsepositives`). Rule and modifier order remains identity-bearing because
evaluation emits ordered rule IDs; `explanation` remains because it becomes the
risk-contribution rationale.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
