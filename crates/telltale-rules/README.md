# telltale-rules


The I/O-free Telltale rule engine: Rule v2 (Telltale's Sigma profile) parsing
and validation, policy and rule merging, regex compilation, and in-memory
evaluation. The rule format is documented in
[docs/rule-format.md](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/rule-format.md). It does not read files,
watch directories, or access a database. The bundled default rule document is
embedded in the package; `config/rules/tool-call-regex.yaml` remains the
repository source of truth.

```rust
let rules = telltale_rules::load_default_rule_set()?;
assert!(rules.rule_count() > 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`package` validates `telltale-rule-package/v2` packages: a YAML stream of a
header document, then identified, versioned, namespaced Rule v2 rules and chains,
one per document, that only add definitions. The community package
(`telltale.community`, namespace `tdx`) is embedded from a published release of
the community detections repository; `scripts/dev/vendor-community-rules.py`
refreshes it. `resolve_rule_packages` selects the effective packages, letting a
supplied community package replace the embedded snapshot:

```rust
use telltale_rules::package::{CommunityRules, RulePackage, resolve_rule_packages};

let supplied: Vec<RulePackage> = Vec::new(); // RulePackage::parse(&text)? per package
let mut parts = vec![telltale_rules::bundled_default_rules()?];
for resolved in resolve_rule_packages(CommunityRules::Embedded, supplied)? {
    parts.extend(resolved.package.into_documents());
}
let rules = telltale_rules::LoadedRules::merge(parts)?.compile(None)?;
assert!(rules.rule_count() > 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`LoadedRules::parse` reads one rule file of Rule v2 documents;
`CompiledRuleSet::notices()` lists findings that did not stop a rule from
loading; a Rule v1 document fails to load. Rule v2 compiles into the compiled
rule form, still named `RuleV1Compatibility*` so that fingerprints and
identities never change, so
`CompiledRuleSet::compatibility_export()` exposes the effective compiled
semantics used by the public provenance manifest. The export's
`evaluate_matched()` supplies the same session-level Rule v1 content decisions
used by `CompiledRuleSet::evaluate()` and Detection v2; canonical applicability
and evidence selection remain with Detection v2. Detection v2 session evaluation
calls `evaluate_matched_without()` to withhold a modifier whose steps are not
linked in the session: outside its declared link (a chain's `within_calls`), or, for the bundled
`chain.download_then_execute`, without downloaded content that runs. A modifier
without a link is never withheld. Its `fingerprint()` is
domain-separated and does not hash source YAML, formatting, filesystem paths,
policy names, or descriptive rule metadata (`title`, `description`,
`falsepositives`, and the other Sigma metadata such as `references` and
`date`). Rule and modifier order remains identity-bearing because
evaluation emits ordered rule IDs; `explanation` remains because it becomes the
risk-contribution rationale.

This package follows Telltale's pre-1.0 release and compatibility policy.

- [Repository](https://github.com/Dark-Roast-Cyber/telltale)
