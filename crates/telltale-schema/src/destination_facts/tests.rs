use super::DestinationFacts;

fn facts(destinations: &[&str], complete: bool, local_only: bool) -> DestinationFacts {
    DestinationFacts {
        destinations: destinations
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        complete,
        local_only,
    }
}

#[test]
fn validation_keeps_order_alphabet_fixed_point_and_flag_invariants() {
    assert!(
        facts(
            &[
                "artifacts.example.invalid/org/repo",
                "s3://synthetic-bucket/prefix"
            ],
            true,
            false
        )
        .is_valid()
    );
    assert!(facts(&["[2001:db8::1]/x"], false, false).is_valid());
    assert!(facts(&[], true, true).is_valid());
    // `local_only` needs `complete` and no entries.
    assert!(!facts(&["example.invalid"], true, true).is_valid());
    assert!(!facts(&[], false, true).is_valid());
    // Sorted and distinct.
    assert!(!facts(&["b.invalid", "a.invalid"], true, false).is_valid());
    assert!(!facts(&["a.invalid", "a.invalid"], true, false).is_valid());
    // Bounded.
    let many: Vec<String> = (0..17).map(|n| format!("h{n:02}.invalid")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert!(!facts(&many, false, false).is_valid());
    for bad in [
        "",
        "Example.Invalid",
        "user@example.invalid",
        "example.invalid?a=1",
        "example.invalid#frag",
        "example.invalid/a/../b",
        "example.invalid/%2e",
        "example.invalid:8443",
        // Not the entry shape: an uppercase address, a DNS scheme kept, a
        // third path segment.
        "[2001:DB8::1]",
        "https://example.invalid",
        "example.invalid/a/b/c",
        "s3://synthetic-bucket/a/b/c",
        // In the alphabet, but the sanitizer would rewrite it.
        "example.invalid/v1/0123456789abcdef0123456789abcdef01234567",
        "example.invalid/akiaiosfodnn7example",
    ] {
        assert!(!facts(&[bad], false, false).is_valid(), "{bad}");
    }
}
