//! Exercise the real supported registry through its compatibility entry points.

use crate::{clients::supported_clients, discovery};
use telltale_schema::clients::{ClientId, SourceKind};

#[test]
fn supported_registry_drives_shared_discovery_without_broadening_sources() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    for path in [
        ".codex/sessions/synthetic.jsonl",
        ".claude/projects/synthetic/session.jsonl",
        ".pi/agent/sessions/synthetic.jsonl",
        ".gemini/tmp/synthetic.json",
    ] {
        let path = root.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"metadata only, not parsed").unwrap();
    }
    let sources = discovery::discover_sources(root.path()).unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].client, ClientId::Claude);
    assert_eq!(sources[1].client, ClientId::Codex);
    assert_eq!(sources[1].kind, SourceKind::Jsonl);
    assert_eq!(sources[1].source_id, "codex.sessions");
    assert_eq!(
        sources,
        telltale_discover::discovery::discover_sources(root.path(), supported_clients()).unwrap()
    );
    assert_eq!(
        sources,
        discovery::discover_sources_best_effort(root.path())
    );
    assert!(!discovery::is_fixture_root(root.path()));
    for source in &sources {
        let bounded =
            discovery::discover_sources_bounded(root.path(), source.client, 1024).unwrap();
        assert_eq!(bounded.as_slice(), std::slice::from_ref(source));
    }
}

#[test]
fn caller_owned_empty_registry_discovers_no_sources_or_watch_roots() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    std::fs::create_dir_all(root.path().join("codex/sessions")).unwrap();
    std::fs::write(root.path().join("codex/sessions/synthetic.jsonl"), b"{}").unwrap();
    assert!(
        telltale_discover::discovery::discover_sources(root.path(), &[])
            .unwrap()
            .is_empty()
    );
    assert!(telltale_discover::discovery::discover_watch_roots(root.path(), &[]).is_empty());
    assert!(!telltale_discover::discovery::is_fixture_root(
        root.path(),
        &[]
    ));
    assert!(discovery::is_fixture_root(root.path()));
}

/// Hook-journal identities are host-fed: a hooks state tree under the roots
/// every session source searches is never discovered as a source of any client.
#[test]
fn a_hooks_state_tree_is_never_discovered_as_a_hook_journal() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    for path in [
        ".claude/projects/synthetic/session.jsonl",
        ".claude/projects/hooks/sessions/synthetic-key/journal.jsonl",
        ".claude/projects/hooks/sessions/synthetic-key/window.jsonl",
        ".codex/sessions/hooks/sessions/synthetic-key/journal.jsonl",
        ".local/state/telltale/hooks/sessions/synthetic-key/journal.jsonl",
        ".local/state/telltale/hooks/sessions/synthetic-key/window.jsonl",
        "logs/copilot/hooks/sessions/synthetic-key/window.jsonl",
    ] {
        let path = root.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"{}\n").unwrap();
    }
    let mut found = discovery::discover_sources(root.path()).unwrap();
    found.extend(discovery::discover_sources_best_effort(root.path()));
    for client in supported_clients() {
        found.extend(discovery::discover_sources_bounded(root.path(), client.id, 1024).unwrap());
    }
    assert!(!found.is_empty());
    let registered: Vec<&str> = supported_clients()
        .iter()
        .flat_map(|client| client.sources.iter().map(|source| source.id))
        .collect();
    for source in &found {
        assert!(
            !source.source_id.ends_with(".hooks"),
            "{}",
            source.source_id
        );
        assert!(registered.contains(&source.source_id.as_str()));
    }
}
