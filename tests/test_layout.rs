//! Keeps the test layout rule in `README.md` ("Test layout") from regressing.
//!
//! The scan walks every `.rs` file under `src/` and `crates/*/src/` and reports
//! test modules that break the rule. Known violations are listed with a reason
//! in `tests/test_layout_exceptions.txt`; the list may only shrink.
//!
//! Standard library only, so it also builds standalone:
//! `rustc --edition 2024 --test tests/test_layout.rs -o <out> && <out>`
//! from the repository root.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const INLINE_OVER_40: &str = "inline-over-40";
const INLINE_NOT_NAMED_TESTS: &str = "inline-not-named-tests";
const PATH_WIRED_TEST_MODULE: &str = "path-wired-test-module";
const SIBLING_TEST_FILE: &str = "sibling-test-file";
const OVERSIZE_TEST_FILE: &str = "oversize-test-file";
const KINDS: [&str; 5] = [
    INLINE_OVER_40,
    INLINE_NOT_NAMED_TESTS,
    OVERSIZE_TEST_FILE,
    PATH_WIRED_TEST_MODULE,
    SIBLING_TEST_FILE,
];

const INLINE_BODY_LIMIT: usize = 40;
const TEST_FILE_LINE_LIMIT: usize = 800;
const MIN_REASON_CHARS: usize = 20;
const EXCEPTIONS_FILE: &str = "tests/test_layout_exceptions.txt";
const HEADER: &str = "\
# Known exceptions to the test layout rule in README.md (\"Test layout\").
# Checked by tests/test_layout.rs. One entry per line:
#   <kind><TAB><path><TAB><reason>
# Sorted by kind, then path. The reason is required (at least 20 characters).
# Remove an entry when its violation is fixed; the test fails on stale entries.
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Violation {
    kind: &'static str,
    path: String,
    line: usize,
    detail: String,
}

// ---------------------------------------------------------------------------
// Lexer: blank comments and literals so braces and keywords inside them are
// not seen. Byte offsets and newlines are preserved.
// ---------------------------------------------------------------------------

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

fn utf8_len(first: u8) -> usize {
    match first {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

/// End offset (exclusive) of a `"..."` literal whose opening quote is at `q`.
fn string_end(src: &[u8], q: usize) -> usize {
    let mut j = q + 1;
    while j < src.len() {
        match src[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    src.len()
}

/// End offset of a raw string whose `"` is at `q`, closed by `"` and `hashes` `#`.
fn raw_string_end(src: &[u8], q: usize, hashes: usize) -> usize {
    let mut j = q + 1;
    while j < src.len() {
        if src[j] == b'"'
            && src.len() - (j + 1) >= hashes
            && src[j + 1..j + 1 + hashes].iter().all(|&b| b == b'#')
        {
            return j + 1 + hashes;
        }
        j += 1;
    }
    src.len()
}

/// End offset of a char literal at `q` (`'`), or `None` when it is a lifetime or label.
fn char_literal_end(src: &[u8], q: usize) -> Option<usize> {
    let next = *src.get(q + 1)?;
    if next == b'\\' {
        // Escape: the closing quote comes after at least one escaped byte.
        let mut j = q + 3;
        while j < src.len() && src[j] != b'\'' && src[j] != b'\n' {
            j += 1;
        }
        return Some((j + 1).min(src.len()));
    }
    let close = q + 1 + utf8_len(next);
    (src.get(close) == Some(&b'\'') && next != b'\n').then_some(close + 1)
}

fn sanitize(src: &[u8]) -> Vec<u8> {
    let n = src.len();
    let mut out = src.to_vec();
    let mut blank = |from: usize, to: usize| {
        for b in &mut out[from..to.min(n)] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    let mut i = 0;
    while i < n {
        let c = src[i];
        let next = src.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            let end = src[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(n, |p| i + p);
            blank(i, end);
            i = end;
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            let (mut depth, mut j) = (1usize, i + 2);
            while j < n && depth > 0 {
                if src[j] == b'/' && src.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if src[j] == b'*' && src.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(i, j);
            i = j;
            continue;
        }
        let starts_token = i == 0 || !is_ident_byte(src[i - 1]);
        if starts_token && matches!(c, b'b' | b'c' | b'r') {
            // Literal prefixes: b"", b'', c"", r"", r#""#, br#""#, cr#""#.
            let mut j = i;
            if matches!(src[j], b'b' | b'c') {
                j += 1;
            }
            if src.get(j) == Some(&b'r') {
                let mut k = j + 1;
                while src.get(k) == Some(&b'#') {
                    k += 1;
                }
                if src.get(k) == Some(&b'"') {
                    let end = raw_string_end(src, k, k - j - 1);
                    blank(i, end);
                    i = end;
                    continue;
                }
            } else if j > i && src.get(j) == Some(&b'"') {
                let end = string_end(src, j);
                blank(i, end);
                i = end;
                continue;
            } else if j > i
                && src[i] == b'b'
                && src.get(j) == Some(&b'\'')
                && let Some(end) = char_literal_end(src, j)
            {
                blank(i, end);
                i = end;
                continue;
            }
            // An identifier (or raw identifier): skip it whole.
            while i < n && is_ident_byte(src[i]) {
                i += 1;
            }
            continue;
        }
        if c == b'"' {
            let end = string_end(src, i);
            blank(i, end);
            i = end;
            continue;
        }
        if c == b'\''
            && let Some(end) = char_literal_end(src, i)
        {
            blank(i, end);
            i = end;
            continue;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Item scan over the sanitized text.
// ---------------------------------------------------------------------------

fn idents(bytes: &[u8]) -> impl Iterator<Item = &str> {
    bytes
        .split(|&b| !is_ident_byte(b))
        .filter(|t| !t.is_empty())
        .map(|t| std::str::from_utf8(t).unwrap_or(""))
}

/// Whether an attribute body (inside `#[...]`, sanitized) is a `cfg` that mentions `test`.
fn is_test_cfg(body: &[u8]) -> bool {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    compact.starts_with(b"cfg(")
        && compact != b"cfg(not(test))"
        && idents(&compact).any(|t| t == "test")
}

/// The value of a `path = "..."` attribute, read from the original text.
fn path_value(body: &[u8], original: &[u8]) -> Option<String> {
    if idents(body).next() != Some("path") {
        return None;
    }
    let start = original.iter().position(|&b| b == b'"')? + 1;
    let len = original[start..].iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(&original[start..start + len]).into_owned())
}

struct Attr {
    test_cfg: bool,
    path: Option<String>,
}

struct OpenModule {
    name: String,
    line: usize,
    test_gated: bool,
}

struct Frame {
    module: Option<OpenModule>,
    /// Inside a test-gated inline module (this one or an ancestor).
    test_scope: bool,
}

/// Scan one file's text. `rel` is the repository-relative path with `/` separators.
fn scan_file(rel: &str, text: &str) -> Vec<Violation> {
    let text = text.replace('\r', "");
    let mut found = Vec::new();
    let push = |found: &mut Vec<Violation>, kind, line, detail: String| {
        found.push(Violation {
            kind,
            path: rel.to_string(),
            line,
            detail,
        });
    };

    let file_lines = text.lines().count();
    let components: Vec<&str> = rel.split('/').collect();
    let file_name = components.last().copied().unwrap_or("");
    if let Some(src_at) = components.iter().position(|c| *c == "src") {
        let dirs = &components[src_at + 1..components.len().saturating_sub(1)];
        if file_name.ends_with("_tests.rs") {
            push(
                &mut found,
                SIBLING_TEST_FILE,
                1,
                "file name ends with _tests.rs".into(),
            );
        }
        let is_test_file = file_name == "tests.rs" || dirs.contains(&"tests");
        if is_test_file && file_lines > TEST_FILE_LINE_LIMIT {
            push(
                &mut found,
                OVERSIZE_TEST_FILE,
                1,
                format!("{file_lines} lines"),
            );
        }
    }

    let src = text.as_bytes();
    let s = sanitize(src);
    let newlines: Vec<usize> = s
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .map(|(i, _)| i)
        .collect();
    let line_of = |offset: usize| newlines.partition_point(|&p| p < offset) + 1;

    let mut stack: Vec<Frame> = Vec::new();
    let mut attrs: Vec<Attr> = Vec::new();
    let in_test_scope = |stack: &Vec<Frame>| stack.last().is_some_and(|f| f.test_scope);
    let n = s.len();
    let mut i = 0;
    while i < n {
        let c = s[i];
        if c == b'#' {
            let mut j = i + 1;
            let inner = s.get(j) == Some(&b'!');
            if inner {
                j += 1;
            }
            while j < n && s[j].is_ascii_whitespace() {
                j += 1;
            }
            if s.get(j) == Some(&b'[') {
                let (mut depth, mut k) = (0usize, j);
                while k < n {
                    match s[k] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
                let end = k.min(n);
                if !inner {
                    let body = &s[j + 1..end];
                    attrs.push(Attr {
                        test_cfg: is_test_cfg(body),
                        path: path_value(body, &src[j + 1..end]),
                    });
                }
                i = end + 1;
                continue;
            }
            i += 1;
            continue;
        }
        if is_ident_byte(c) && (i == 0 || !is_ident_byte(s[i - 1])) {
            let start = i;
            while i < n && is_ident_byte(s[i]) {
                i += 1;
            }
            if &s[start..i] != b"mod" {
                continue;
            }
            let mut j = i;
            while j < n && s[j].is_ascii_whitespace() {
                j += 1;
            }
            let name_start = j;
            while j < n && is_ident_byte(s[j]) {
                j += 1;
            }
            if name_start == j {
                continue;
            }
            let name = String::from_utf8_lossy(&s[name_start..j]).into_owned();
            while j < n && s[j].is_ascii_whitespace() {
                j += 1;
            }
            let test_gated = attrs.iter().any(|a| a.test_cfg);
            let line = line_of(start);
            if let Some(path) = attrs.iter().find_map(|a| a.path.clone()) {
                let path_file = path.rsplit(['/', '\\']).next().unwrap_or("");
                if test_gated || name.contains("test") || path_file.contains("test") {
                    push(
                        &mut found,
                        PATH_WIRED_TEST_MODULE,
                        line,
                        format!("mod {name} at #[path = \"{path}\"]"),
                    );
                }
            }
            match s.get(j) {
                Some(b'{') => {
                    let test_scope = in_test_scope(&stack) || test_gated;
                    stack.push(Frame {
                        module: Some(OpenModule {
                            name,
                            line: line_of(j),
                            test_gated,
                        }),
                        test_scope,
                    });
                    attrs.clear();
                    i = j + 1;
                }
                Some(b';') => {
                    attrs.clear();
                    i = j + 1;
                }
                _ => i = j,
            }
            continue;
        }
        match c {
            b'{' => {
                let test_scope = in_test_scope(&stack);
                stack.push(Frame {
                    module: None,
                    test_scope,
                });
                attrs.clear();
            }
            b'}' => {
                if let Some(Frame {
                    module: Some(m), ..
                }) = stack.pop()
                {
                    close_module(&mut found, rel, &m, line_of(i), in_test_scope(&stack));
                }
                attrs.clear();
            }
            b';' => attrs.clear(),
            _ => {}
        }
        i += 1;
    }
    // Unclosed modules (malformed input) end at the last line.
    let last_line = line_of(n);
    while let Some(frame) = stack.pop() {
        if let Some(m) = frame.module {
            close_module(&mut found, rel, &m, last_line, in_test_scope(&stack));
        }
    }
    found
}

fn close_module(
    found: &mut Vec<Violation>,
    rel: &str,
    m: &OpenModule,
    close_line: usize,
    parent_test_scope: bool,
) {
    // Only the outermost test-gated module is judged; nested ones belong to it.
    if !m.test_gated || parent_test_scope {
        return;
    }
    let body = close_line.saturating_sub(m.line + 1);
    if body > INLINE_BODY_LIMIT {
        found.push(Violation {
            kind: INLINE_OVER_40,
            path: rel.to_string(),
            line: m.line,
            detail: format!("mod {} body is {body} lines", m.name),
        });
    }
    if m.name != "tests" {
        found.push(Violation {
            kind: INLINE_NOT_NAMED_TESTS,
            path: rel.to_string(),
            line: m.line,
            detail: format!("inline test module named {}", m.name),
        });
    }
}

// ---------------------------------------------------------------------------
// Tree walk and exceptions.
// ---------------------------------------------------------------------------

fn repository_root() -> PathBuf {
    match option_env!("CARGO_MANIFEST_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir().expect("current directory"),
    }
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "target" {
            continue;
        }
        if path.is_dir() {
            collect_rs(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn scan_tree(root: &Path) -> Vec<Violation> {
    let mut files = Vec::new();
    collect_rs(&root.join("src"), &mut files);
    if let Ok(crates) = fs::read_dir(root.join("crates")) {
        for krate in crates.flatten() {
            collect_rs(&krate.path().join("src"), &mut files);
        }
    }
    files.sort();
    let mut found = Vec::new();
    for file in files {
        let bytes = fs::read(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        found.extend(scan_file(
            &relative(root, &file),
            &String::from_utf8_lossy(&bytes),
        ));
    }
    found
}

type Key = (String, String);

struct Exceptions {
    entries: BTreeMap<Key, String>,
    problems: Vec<String>,
}

fn parse_exceptions(text: &str) -> Exceptions {
    let mut entries = BTreeMap::new();
    let mut problems = Vec::new();
    let mut previous: Option<Key> = None;
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let [kind, path, reason] = fields[..] else {
            problems.push(format!(
                "{EXCEPTIONS_FILE}:{line_no}: expected <kind><TAB><path><TAB><reason>: {line:?}"
            ));
            continue;
        };
        if !KINDS.contains(&kind) {
            problems.push(format!(
                "{EXCEPTIONS_FILE}:{line_no}: unknown kind {kind:?}"
            ));
            continue;
        }
        if path.trim().is_empty() || path != path.trim() || path.contains('\\') {
            problems.push(format!("{EXCEPTIONS_FILE}:{line_no}: bad path {path:?}"));
            continue;
        }
        if reason.trim().chars().count() < MIN_REASON_CHARS {
            problems.push(format!(
                "{EXCEPTIONS_FILE}:{line_no}: reason for {kind} {path} must be at least {MIN_REASON_CHARS} characters"
            ));
        }
        let key = (kind.to_string(), path.to_string());
        if previous.as_ref().is_some_and(|p| *p >= key) && !entries.contains_key(&key) {
            problems.push(format!(
                "{EXCEPTIONS_FILE}:{line_no}: not sorted by kind then path: {kind} {path}"
            ));
        }
        if entries.contains_key(&key) {
            problems.push(format!(
                "{EXCEPTIONS_FILE}:{line_no}: duplicate entry {kind} {path}"
            ));
            continue;
        }
        previous = Some(key.clone());
        entries.insert(key, reason.trim().to_string());
    }
    Exceptions { entries, problems }
}

/// Compare violations with the exceptions; returns problems and the file the tree needs.
fn compare(violations: &[Violation], exceptions: &Exceptions) -> (Vec<String>, String) {
    let mut by_key: BTreeMap<Key, Vec<&Violation>> = BTreeMap::new();
    for v in violations {
        by_key
            .entry((v.kind.to_string(), v.path.clone()))
            .or_default()
            .push(v);
    }
    let mut problems = exceptions.problems.clone();
    for (key, hits) in &by_key {
        if !exceptions.entries.contains_key(key) {
            for v in hits {
                problems.push(format!(
                    "unlisted {}: {}:{}: {}",
                    v.kind, v.path, v.line, v.detail
                ));
            }
        }
    }
    for key in exceptions.entries.keys() {
        if !by_key.contains_key(key) {
            problems.push(format!(
                "stale exception {} {}: no longer violated; remove the entry",
                key.0, key.1
            ));
        }
    }
    let mut expected = String::from(HEADER);
    for key in by_key.keys() {
        let reason = exceptions
            .entries
            .get(key)
            .map_or("TODO: reason", String::as_str);
        expected.push_str(&format!("{}\t{}\t{}\n", key.0, key.1, reason));
    }
    (problems, expected)
}

#[test]
fn tree_follows_test_layout_rule() {
    let root = repository_root();
    if !root.join("crates").is_dir() || !root.join("src").is_dir() {
        println!(
            "test_layout: skipped, no repository layout (src/ and crates/) at {}",
            root.display()
        );
        return;
    }
    let text = fs::read_to_string(root.join(EXCEPTIONS_FILE)).unwrap_or_default();
    let exceptions = parse_exceptions(&text);
    let (problems, expected) = compare(&scan_tree(&root), &exceptions);
    if !problems.is_empty() {
        let mut message = format!(
            "test layout rule (README.md, \"Test layout\"): {} problem(s)\n",
            problems.len()
        );
        for p in &problems {
            message.push_str(&format!("  {p}\n"));
        }
        message.push_str(&format!(
            "\nThe current tree needs this {EXCEPTIONS_FILE} (write a reason for each TODO):\n\
             ----- BEGIN {EXCEPTIONS_FILE} -----\n{expected}----- END {EXCEPTIONS_FILE} -----\n"
        ));
        panic!("{message}");
    }
}

// ---------------------------------------------------------------------------
// Scanner tests on synthetic input.
// ---------------------------------------------------------------------------

const FILE: &str = "crates/x/src/lib.rs";

fn kinds(text: &str) -> Vec<&'static str> {
    scan_file(FILE, text).into_iter().map(|v| v.kind).collect()
}

fn test_module(attr: &str, name: &str, body_lines: usize) -> String {
    let mut text = format!("{attr}\nmod {name} {{\n");
    for i in 0..body_lines {
        text.push_str(&format!("    const C{i}: u8 = 0;\n"));
    }
    text.push_str("}\n");
    text
}

#[test]
fn module_of_exactly_40_body_lines_passes_and_41_fails() {
    assert_eq!(
        kinds(&test_module("#[cfg(test)]", "tests", 40)),
        Vec::<&str>::new()
    );
    assert_eq!(
        kinds(&test_module("#[cfg(test)]", "tests", 41)),
        vec![INLINE_OVER_40]
    );
}

#[test]
fn braces_in_strings_and_raw_strings_do_not_close_the_module() {
    let mut text = String::from("#[cfg(test)]\nmod tests {\n");
    text.push_str("    const A: &str = \"}}}\\\"}\";\n");
    text.push_str("    const B: &str = r#\"}\" }}\"#;\n");
    text.push_str("    const C: &str = r##\"\"# }\"##;\n");
    text.push_str("    const D: &[u8] = b\"}\";\n");
    text.push_str("    const E: &[u8] = br#\"}\"#;\n");
    text.push_str(&"    const F: u8 = 0;\n".repeat(40));
    text.push_str("}\n");
    assert_eq!(kinds(&text), vec![INLINE_OVER_40]);
}

#[test]
fn char_literal_brace_and_lifetimes_are_told_apart() {
    let mut text = String::from("#[cfg(test)]\nmod tests {\n");
    text.push_str("    fn f<'a>(x: &'a str) -> char { let _ = x; '{' }\n");
    text.push_str(
        "    const B: u8 = b'}';\n    const Q: char = '\\'';\n    const U: char = 'é';\n",
    );
    text.push_str("    fn g<'b>(_: &'b u8) {}\n");
    text.push_str(&"    const F: u8 = 0;\n".repeat(36));
    text.push_str("}\n");
    // 41 body lines: the module only closes at the real brace.
    assert_eq!(kinds(&text), vec![INLINE_OVER_40]);
}

#[test]
fn nested_block_comments_and_line_comments_are_skipped() {
    let mut text = String::from("#[cfg(test)]\nmod tests {\n");
    text.push_str("    /* outer { /* inner } */ still comment } */\n");
    text.push_str("    // } mod helper {\n");
    text.push_str(&"    const F: u8 = 0;\n".repeat(39));
    text.push_str("}\n");
    assert_eq!(kinds(&text), vec![INLINE_OVER_40]);
}

#[test]
fn compound_cfg_with_test_is_test_gated() {
    let attr = "#[cfg(all(test, feature = \"x\"))]";
    assert_eq!(kinds(&test_module(attr, "tests", 41)), vec![INLINE_OVER_40]);
    assert_eq!(
        kinds(&test_module(attr, "helpers", 1)),
        vec![INLINE_NOT_NAMED_TESTS]
    );
    // `test` only inside a string, or `not(test)`, is not a test gate.
    assert!(kinds(&test_module("#[cfg(feature = \"test\")]", "helpers", 60)).is_empty());
    assert!(kinds(&test_module("#[cfg(not(test))]", "helpers", 60)).is_empty());
}

#[test]
fn large_non_test_inline_module_is_not_reported() {
    assert!(kinds(&test_module("#[cfg(unix)]", "platform", 500)).is_empty());
    assert!(kinds(&test_module("", "inner", 500)).is_empty());
}

#[test]
fn modules_nested_in_a_test_module_are_not_reported() {
    let text = "#[cfg(test)]\nmod tests {\n    mod support {\n        fn f() {}\n    }\n    #[cfg(test)]\n    mod more {}\n}\n";
    assert!(kinds(text).is_empty());
}

#[test]
fn path_attribute_on_test_modules_is_reported() {
    assert_eq!(
        kinds("#[cfg(test)]\n#[path = \"other.rs\"]\nmod tests;\n"),
        vec![PATH_WIRED_TEST_MODULE]
    );
    assert_eq!(
        kinds("#[path = \"a_tests.rs\"]\nmod helpers;\n"),
        vec![PATH_WIRED_TEST_MODULE]
    );
    assert_eq!(
        kinds("#[path = \"a.rs\"]\npub(crate) mod bound_tests;\n"),
        vec![PATH_WIRED_TEST_MODULE]
    );
    assert!(
        kinds("#[cfg(windows)]\n#[path = \"anchored/windows.rs\"]\nmod platform;\n").is_empty()
    );
    assert!(kinds("#[cfg(test)]\nmod tests;\n").is_empty());
}

#[test]
fn crlf_input_counts_like_lf() {
    let lf = test_module("#[cfg(test)]", "tests", 41);
    assert_eq!(kinds(&lf.replace('\n', "\r\n")), vec![INLINE_OVER_40]);
    let lf = test_module("#[cfg(test)]", "tests", 40);
    assert!(kinds(&lf.replace('\n', "\r\n")).is_empty());
}

#[test]
fn file_name_rules() {
    let long = "fn f() {}\n".repeat(801);
    let short = "fn f() {}\n".repeat(800);
    let at = |path: &str, text: &str| {
        scan_file(path, text)
            .into_iter()
            .map(|v| v.kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        at("src/a/b_tests.rs", "fn f() {}\n"),
        vec![SIBLING_TEST_FILE]
    );
    assert_eq!(
        at("crates/x/src/a/tests.rs", &long),
        vec![OVERSIZE_TEST_FILE]
    );
    assert_eq!(
        at("crates/x/src/a/tests/topic.rs", &long),
        vec![OVERSIZE_TEST_FILE]
    );
    assert!(at("crates/x/src/a/tests.rs", &short).is_empty());
    assert!(at("crates/x/src/a/big.rs", &long).is_empty());
    assert!(at("crates/x/src/a/tests.rs", &short.replace('\n', "\r\n")).is_empty());
}

#[test]
fn exceptions_file_is_validated() {
    let ok = "# comment\n\n\
              inline-over-40\tsrc/a.rs\tOver forty lines; to be moved.\n\
              sibling-test-file\tsrc/b_tests.rs\tOther modules call helpers here.\n";
    assert!(parse_exceptions(ok).problems.is_empty());
    assert_eq!(parse_exceptions(ok).entries.len(), 2);
    let bad = "sibling-test-file\tsrc/b.rs\tOther modules call helpers here.\n\
               inline-over-40\tsrc/a.rs\tOver forty lines; to be moved.\n\
               inline-over-40\tsrc/a.rs\tOver forty lines; to be moved.\n\
               inline-over-40\tsrc/c.rs\tshort\n\
               unknown\tsrc/d.rs\tA long enough reason here.\n\
               inline-over-40 src/e.rs no tabs at all here\n";
    let problems = parse_exceptions(bad).problems;
    assert_eq!(problems.len(), 5, "{problems:#?}");
}

#[test]
fn compare_reports_unlisted_and_stale_and_renders_the_needed_file() {
    let violations = vec![Violation {
        kind: SIBLING_TEST_FILE,
        path: "src/a_tests.rs".into(),
        line: 1,
        detail: String::new(),
    }];
    let exceptions =
        parse_exceptions("inline-over-40\tsrc/gone.rs\tOver forty lines; to be moved.\n");
    let (problems, expected) = compare(&violations, &exceptions);
    assert_eq!(problems.len(), 2, "{problems:#?}");
    assert!(expected.starts_with(HEADER));
    assert!(expected.ends_with("sibling-test-file\tsrc/a_tests.rs\tTODO: reason\n"));
}
