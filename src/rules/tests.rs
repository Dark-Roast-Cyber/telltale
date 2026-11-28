use std::fs;
use std::path::PathBuf;

use tempfile::tempdir;

use super::{
    CommunityRules, RuleLoadMode, RulePackPaths,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};

fn rules(content: &super::LoadedRules) -> impl Iterator<Item = &super::LoadedDefinition> {
    content
        .definitions()
        .iter()
        .filter(|definition| definition.kind() == super::DefinitionKind::Rule)
}

fn modifiers(content: &super::LoadedRules) -> impl Iterator<Item = &super::LoadedDefinition> {
    content
        .definitions()
        .iter()
        .filter(|definition| definition.kind() == super::DefinitionKind::Modifier)
}

/// A UUIDv4-shaped id derived from `name`, so synthetic rules with different
/// names never share one and a replacement keeps the id of what it replaces.
fn synthetic_uuid(name: &str) -> String {
    let hash = |seed: u64| {
        name.bytes().fold(seed, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
    };
    let (high, low) = (hash(0xcbf2_9ce4_8422_2325), hash(0x84222325_cbf29ce4));
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        high >> 32,
        (high >> 16) & 0xffff,
        high & 0xfff,
        low >> 52,
        low & 0xffff_ffff_ffff
    )
}

fn rule_yaml(id: &str, regex: &str, score: u64) -> String {
    let uuid = synthetic_uuid(id);
    format!(
        r#"title: Synthetic test rule
id: {uuid}
name: {id}
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: '{regex}'
    condition: selection
level: low
telltale:
    category: test
    score: {score}
    explanation: 'Synthetic test rule.'
    tags: [test]
"#
    )
}

fn write_rule(path: &std::path::Path, id: &str, regex: &str, score: u64) {
    fs::create_dir_all(path.parent().expect("rule parent")).expect("rule parent");
    fs::write(path, rule_yaml(id, regex, score)).expect("rule file");
}

fn fixture_pack_paths(name: &str) -> RulePackPaths {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rule_packs")
        .join(name);
    let discovered = crate::config::discover_local_config_files(
        std::slice::from_ref(&root),
        false,
        crate::config::LocalConfigDiscoveryKind::Rules,
    )
    .expect("fixture pack discovery");
    RulePackPaths {
        organization: discovered.organization_rule_paths,
        deployment: discovered.deployment_rule_paths,
        local: discovered.local_rule_paths,
        ..RulePackPaths::default()
    }
}

fn package_yaml(id: &str, namespace: &str, document: &str) -> String {
    format!(
        "format: telltale-rule-package/v2\nid: {id}\ntitle: Synthetic package\nversion: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: {namespace}\n---\n{document}"
    )
}

const UUID_A: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const UUID_B: &str = "9b2d6c8e-1f4a-4c3b-8d2e-5a6f7b8c9d0e";

fn v2_rule_yaml(name: &str, uuid: &str, marker: &str, score: u64) -> String {
    format!(
        "title: Synthetic v2 rule\nid: {uuid}\nname: {name}\ntaxonomy: telltale\n\
             status: test\nlogsource:\n    product: ai_agent\n    category: tool_activity\n\
             detection:\n    selection:\n        tool.command|contains: {marker}\n    condition: selection\n\
             level: low\ntelltale:\n    category: test\n    score: {score}\n    explanation: Synthetic v2 rule.\n"
    )
}

fn write_v2(path: &std::path::Path, name: &str, uuid: &str, marker: &str, score: u64) {
    fs::create_dir_all(path.parent().expect("rule parent")).expect("rule parent");
    fs::write(path, v2_rule_yaml(name, uuid, marker, score)).expect("rule file");
}

fn custom(paths: &RulePackPaths, explicit: &[PathBuf]) -> Result<super::RuleResolution, String> {
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        paths,
        explicit,
        None,
        RuleLoadMode::CustomOnly,
        &[],
        &[],
    )
    .map_err(|error| error.to_string())
}

mod loader_parity;
mod overrides;
mod rule_v2;
mod tier_resolution;
