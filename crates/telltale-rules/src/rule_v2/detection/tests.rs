use super::{glob_match, wildcard_pattern};

#[test]
fn wildcards_follow_sigma_escaping() {
    for (value, pattern) in [
        ("abc", "abc"),
        ("a*c", "a(?s:.*)c"),
        ("a?c", "a(?s:.)c"),
        (r"a\*c", r"a\*c"),
        (r"a\?c", r"a\?c"),
        (r"a\\*c", r"a\\(?s:.*)c"),
        (r"a\\\*c", r"a\\\*c"),
        (r"C:\Windows", r"C:\\Windows"),
        (r"C:\\Windows", r"C:\\Windows"),
        (r"\\\\", r"\\\\"),
        ("end\\", r"end\\"),
        ("1.2+(x)", r"1\.2\+\(x\)"),
    ] {
        assert_eq!(wildcard_pattern(value), pattern, "{value}");
    }
}

#[test]
fn wildcards_match_across_lines() {
    let star = regex::Regex::new(&format!("^(?:{})$", wildcard_pattern("cat *.pem"))).unwrap();
    assert!(star.is_match("cat <<'EOF' a\nb.pem"));
    let one = regex::Regex::new(&format!("^(?:{})$", wildcard_pattern("a?b"))).unwrap();
    assert!(one.is_match("a\nb"));
    assert!(!one.is_match("ab"));
}

#[test]
fn identifier_patterns_match_whole_names() {
    assert!(glob_match("selection*", "selection"));
    assert!(glob_match("selection*", "selection_command"));
    assert!(glob_match("*_command", "selection_command"));
    assert!(glob_match("sel*_*d", "selection_command"));
    assert!(!glob_match("selection*", "filter_command"));
    assert!(!glob_match("selection", "selection_command"));
    assert!(!glob_match("a*a", "a"));
    assert!(glob_match("*", "anything"));
}
