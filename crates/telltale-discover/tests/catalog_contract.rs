//! Independently extracted pinned core registry versus the public catalog.

use std::collections::BTreeSet;
use telltale_discover::catalog::{CatalogRoot, TOKSCALE_REVISION, catalog};

#[test]
fn entire_ordered_catalog_matches_independent_upstream_fixture() {
    let rows: Vec<Vec<&str>> = include_str!("../data/tokscale-registry.tsv")
        .lines()
        .skip(1)
        .map(|line| line.split('\t').collect())
        .collect();
    assert_eq!(rows.len(), 61);
    assert_eq!(catalog().len(), rows.len());
    let mut ids = BTreeSet::new();
    for (index, (entry, row)) in catalog().iter().zip(rows).enumerate() {
        assert_eq!(row.len(), 9);
        assert_eq!(row[0].parse::<usize>().unwrap(), index);
        assert!(!row[1].is_empty());
        assert_eq!(entry.id, row[2]);
        assert!(ids.insert(entry.id));
        assert_eq!(entry.display_name, row[3]);
        let root = match entry.upstream_root {
            CatalogRoot::Home => "Home",
            CatalogRoot::Data => "XdgData",
            CatalogRoot::TokscaleConfig => "Config",
            CatalogRoot::AppData => "AppData",
            CatalogRoot::ReasonixHome => "ReasonixHome",
            CatalogRoot::EnvironmentFallback {
                variable,
                home_relative,
            } => {
                assert_eq!(variable, row[5]);
                assert_eq!(home_relative, row[6]);
                "EnvVar"
            }
        };
        assert_eq!(root, row[4]);
        if root != "EnvVar" {
            assert_eq!((row[5], row[6]), ("", ""));
        }
        assert_eq!(entry.upstream_relative_path, row[7]);
        assert_eq!(entry.upstream_pattern, row[8]);
        assert!(!entry.upstream_relative_path.starts_with('/'));
        assert!(!entry.upstream_relative_path.split('/').any(|s| s == ".."));
    }
    assert_eq!(
        TOKSCALE_REVISION,
        "6ff87bdd4eb1e9e3d26a51b0b788d4ccaa154a5e"
    );
    for attribution in ["synthetic", "9router", "cc-mirror"] {
        assert!(!ids.contains(attribution));
    }
}

#[test]
fn adopted_metadata_attribution_is_shipped() {
    let provenance = include_str!("../data/TOKSCALE-PROVENANCE.md");
    assert!(provenance.contains(TOKSCALE_REVISION));
    assert!(provenance.contains("crates/tokscale-core/src/clients.rs"));
    assert!(provenance.contains("crates/tokscale-core/src/scanner.rs"));
    let license = include_str!("../data/TOKSCALE-LICENSE-MIT");
    assert_eq!(license.lines().next(), Some("MIT License"));
    assert!(license.contains("Copyright (c) 2025 Junho Yeo"));
    assert!(license.contains("OUT OF OR IN CONNECTION WITH THE SOFTWARE"));
}
