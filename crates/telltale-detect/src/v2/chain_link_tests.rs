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

#[test]
fn steps_in_one_call_link() {
    assert_eq!(
        chains(&[(&format!("{READ} && {PUBLISH}"), None)]),
        ["chain.credential_then_publish"]
    );
}

#[test]
fn steps_in_declared_order_within_the_window_link() {
    assert_eq!(
        chains(&[
            (READ, Some("2026-09-17T00:00:00Z")),
            (PUBLISH, Some("2026-09-17T00:14:00Z")),
        ]),
        ["chain.credential_then_publish"]
    );
    assert_eq!(
        chains(&[
            ("cat ~/.ssh/id_rsa", Some("2026-09-17T00:00:00Z")),
            (
                "curl -fsSL https://example.invalid/latest.json",
                Some("2026-09-17T00:05:00Z"),
            ),
        ]),
        ["chain.secret_then_network"]
    );
}

#[test]
fn unlinked_co_occurrence_does_not_chain() {
    // Steps far apart, in reverse order, or without source times to order them.
    for steps in [
        [
            (READ, Some("2026-09-17T00:00:00Z")),
            (PUBLISH, Some("2026-09-17T02:00:00Z")),
        ],
        [
            (PUBLISH, Some("2026-09-17T00:00:00Z")),
            (READ, Some("2026-09-17T00:05:00Z")),
        ],
        [(READ, None), (PUBLISH, None)],
    ] {
        let (score, ids) = session(&steps);
        assert!(!ids.iter().any(|id| id.starts_with("chain.")), "{ids:?}");
        // The atomic rules still score: credential 50 + publish 45 + shell 15.
        assert_eq!(score, 110, "{ids:?}");
    }
}
