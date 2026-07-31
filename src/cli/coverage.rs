use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::detection::detect_sources_with_rules;
use crate::discovery::discover_sources_best_effort;
use crate::rules::{
    RuleLoadMode, RulePackPaths,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};

pub(crate) fn run_rules_coverage(
    root: &Path,
    rule_pack_paths: &RulePackPaths,
    rule_paths: &[PathBuf],
    override_paths: &[PathBuf],
    policy_path: Option<&Path>,
    rule_load_mode: RuleLoadMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        rule_pack_paths,
        rule_paths,
        policy_path,
        rule_load_mode,
        override_paths,
        &[],
    )?;
    let rule_set = &resolution.rule_set;
    let (all_falsepositives, all_rule_categories) = load_rule_metadata(&resolution.merged_rule_set);

    let sources = discover_sources_best_effort(root);
    if sources.is_empty() {
        println!("No fixture sources found under {}", root.display());
        return Ok(());
    }

    let detections = detect_sources_with_rules(&sources, rule_set);

    // Build coverage map: rule_id -> (positive session_ids, clients).
    let mut positive_sessions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rule_clients: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut all_rule_ids: BTreeSet<String> = BTreeSet::new();
    let mut detected_source_paths: BTreeSet<String> = BTreeSet::new();

    for rule_summary in rule_set.summaries() {
        all_rule_ids.insert(rule_summary.id);
    }

    for (source, event) in &detections {
        if event.event_type == "scanner_error" {
            let detail = event
                .evidence
                .iter()
                .find(|evidence| evidence.field == "error")
                .map(|evidence| evidence.redacted_value.as_str())
                .unwrap_or("scanner error");
            return Err(format!(
                "rules coverage failed for {}: {detail}",
                source.path.display()
            )
            .into());
        }
        if event.event_type != "detection" {
            continue;
        }
        detected_source_paths.insert(source.path.to_string_lossy().to_string());
        for rule_id in &event.rule_ids {
            all_rule_ids.insert(rule_id.clone());
            positive_sessions
                .entry(rule_id.clone())
                .or_default()
                .insert(event.session_id.clone());
            rule_clients
                .entry(rule_id.clone())
                .or_default()
                .insert(source.client.as_str().to_string());
        }
    }

    // Count benign fixtures (sources with no detections).
    let total_fixture_sources = sources.len();
    let sources_with_detections = sources
        .iter()
        .filter(|s| detected_source_paths.contains(&s.path.to_string_lossy().to_string()))
        .count();
    let benign_count = total_fixture_sources - sources_with_detections;

    println!(
        "RULE COVERAGE REPORT ({} rules, {} fixture sources, {} benign)\n",
        all_rule_ids.len(),
        total_fixture_sources,
        benign_count
    );

    println!(
        "{:<45} {:<10} {:<10} {:<20} FALSE_POSITIVES",
        "RULE_ID", "POSITIVE", "CLIENTS", "CATEGORIES"
    );
    println!("{}", "-".repeat(120));

    for rule_id in &all_rule_ids {
        let pos_count = positive_sessions.get(rule_id).map_or(0, |s| s.len());
        let client_count = rule_clients.get(rule_id).map_or(0, |s| s.len());
        let fps = all_falsepositives
            .get(rule_id)
            .map_or(String::new(), |v| v.join("; "));

        // Find category from rule set summaries.
        let category = all_rule_categories
            .get(rule_id)
            .cloned()
            .unwrap_or_else(|| {
                rule_set
                    .summaries()
                    .iter()
                    .find(|s| s.id == *rule_id)
                    .map_or(String::new(), |s| s.category.clone())
            });

        println!(
            "{:<45} {:<10} {:<10} {:<20} {}",
            rule_id, pos_count, client_count, category, fps
        );
    }

    // Summary of gaps.
    let zero_coverage: Vec<&String> = all_rule_ids
        .iter()
        .filter(|id| !positive_sessions.contains_key(*id))
        .collect();
    if !zero_coverage.is_empty() {
        println!(
            "\nCOVERAGE GAPS ({} rules with no positive fixtures):",
            zero_coverage.len()
        );
        for id in zero_coverage {
            println!("  - {}", id);
        }
    }

    Ok(())
}

fn load_rule_metadata(rule_set: &crate::rules::RuleSet) -> RuleMetadata {
    let mut all_falsepositives: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut all_rule_categories: BTreeMap<String, String> = BTreeMap::new();
    for rule in &rule_set.rules {
        all_rule_categories.insert(rule.id.clone(), rule.category.clone());
        if !rule.falsepositives.is_empty() {
            all_falsepositives.insert(rule.id.clone(), rule.falsepositives.clone());
        }
    }
    for modifier in &rule_set.modifiers {
        if !modifier.when_all_categories.is_empty() {
            all_rule_categories.insert(modifier.id.clone(), modifier.when_all_categories.join("+"));
        } else if !modifier.when_all_rule_ids.is_empty() {
            all_rule_categories.insert(modifier.id.clone(), modifier.when_all_rule_ids.join("+"));
        }
        if !modifier.falsepositives.is_empty() {
            all_falsepositives.insert(modifier.id.clone(), modifier.falsepositives.clone());
        }
    }

    (all_falsepositives, all_rule_categories)
}

type RuleMetadata = (BTreeMap<String, Vec<String>>, BTreeMap<String, String>);

#[cfg(test)]
mod tests {
    use super::load_rule_metadata;
    #[test]
    fn coverage_metadata_uses_embedded_default_rules() {
        let default = crate::rules::bundled_default_rule_set().expect("default rules");
        let (falsepositives, categories) = load_rule_metadata(&default);

        assert_eq!(
            categories.get("secret.env.read").map(String::as_str),
            Some("secret_access")
        );
        assert!(
            falsepositives
                .get("secret.env.read")
                .expect("secret false positives")
                .iter()
                .any(|note| note.contains("env-style files"))
        );
    }
}
