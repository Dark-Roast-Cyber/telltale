//! Shared native activity lexical semantics, independent of state.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    Source,
    Test,
    Documentation,
    Config,
    BuildManifest,
    SecretStore,
    Home,
    Temp,
    Other,
}

pub fn path_classes(input: &str) -> Vec<PathClass> {
    tokenize(input)
        .into_iter()
        .filter_map(|token| classify_path_token(&token))
        .collect()
}

pub fn classify_path_token(token: &str) -> Option<PathClass> {
    let trimmed = token.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | ',' | ';' | ':' | ')' | '(' | '[' | ']' | '{' | '}'
        )
    });
    if trimmed.is_empty() || trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let looks_like_path = lower.contains('/')
        || lower.starts_with("~/")
        || lower.starts_with("./")
        || lower.starts_with("../")
        || lower.contains('.');

    if !looks_like_path {
        return None;
    }

    if lower.contains(".env")
        || lower.contains("id_rsa")
        || lower.contains("id_ed25519")
        || lower.contains(".aws/credentials")
        || lower.contains(".ssh/")
        || lower.contains("credentials")
        || lower.contains("token")
    {
        return Some(PathClass::SecretStore);
    }
    if lower.starts_with("/tmp/")
        || lower.starts_with("tmp/")
        || lower.starts_with("/var/tmp/")
        || lower.starts_with("/users/") && lower.contains("/appdata/local/temp/")
        || lower.starts_with("c:/users/") && lower.contains("/appdata/local/temp/")
    {
        return Some(PathClass::Temp);
    }
    if lower.starts_with("~/")
        || lower.starts_with("/home/")
        || lower.starts_with("/users/")
        || lower.starts_with("c:/users/")
        || lower.starts_with("$home/")
    {
        return Some(PathClass::Home);
    }
    if lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.starts_with("test/")
        || lower.starts_with("tests/")
        || lower.ends_with("_test.rs")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
    {
        return Some(PathClass::Test);
    }
    if lower.ends_with(".md")
        || lower.starts_with("docs/")
        || lower.contains("/docs/")
        || lower.ends_with(".rst")
    {
        return Some(PathClass::Documentation);
    }
    if lower.ends_with("cargo.toml")
        || lower.ends_with("package.json")
        || lower.ends_with("pyproject.toml")
        || lower.ends_with("go.mod")
        || lower.ends_with("pom.xml")
    {
        return Some(PathClass::BuildManifest);
    }
    if lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".toml")
        || lower.ends_with(".json")
        || lower.ends_with(".ini")
        || lower.ends_with(".conf")
    {
        return Some(PathClass::Config);
    }
    if lower.ends_with(".rs")
        || lower.ends_with(".py")
        || lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".go")
        || lower.ends_with(".java")
        || lower.ends_with(".c")
        || lower.ends_with(".cpp")
        || lower.ends_with(".h")
    {
        return Some(PathClass::Source);
    }

    Some(PathClass::Other)
}

pub fn network_hosts(input: &str) -> Vec<String> {
    tokenize(input)
        .into_iter()
        .filter_map(|token| host_from_url_token(&token))
        .collect()
}

pub fn host_from_url_token(token: &str) -> Option<String> {
    let trimmed = token.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | ',' | ';' | ')' | '(' | '[' | ']' | '{' | '}' | '<' | '>'
        )
    });
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;
    let authority = without_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or_default()
        .trim();
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn tokenize(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|c: char| c.is_ascii_control())
                .to_string()
        })
        .filter(|token| !token.is_empty())
        .collect()
}
