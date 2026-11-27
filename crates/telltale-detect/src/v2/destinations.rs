//! Upload destination facts beside an `exfil.outbound_upload` action finding.
//!
//! Evidence text is redacted, so an embedding host cannot tell an upload to an
//! unknown host from one to its own artifact host or to a local service. These
//! facts say where the command sends, so the host can decide; they never
//! change rule matching, scores or semantic identities.
//!
//! Each upload stage is read once, by the reading the upload rule itself uses
//! ([`super::actions::upload`]), so the rule and its facts cannot disagree about
//! what is a URL, an option value or a reroute. This module only formats what
//! that reading names and applies the field-level gates.
//!
//! An entry is built from parsed URL parts in the closed alphabet
//! `[a-z0-9._~-/:[]]` and kept only when the evidence sanitizer leaves it
//! unchanged; it never passes through the sanitizer's output. Both flags fail
//! closed: anything the reading cannot account for makes them false.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Range;

use telltale_rules::command_effect::Reading;
use telltale_schema::destination_facts::{
    DNS_SCHEMES, DestinationFacts, MAX_DESTINATION_LEN, MAX_DESTINATION_SEGMENTS, MAX_DESTINATIONS,
};

use super::actions::{Upload, consumes_stdin_code, redact, upload};
use super::http::{assignment, client_name};
use super::session::{ProcessingError, RetentionBudget};

/// Distinct URLs formatted per field. Past this the facts are incomplete, which
/// bounds the sanitizer work a field of many URLs can ask for.
const MAX_FORMATTED_URLS: usize = 4 * MAX_DESTINATIONS;
/// Words that name a proxy, a client config file or a host alias table: in an
/// assignment, a `wgetrc` command or a PowerShell call, each can reroute a
/// request without a URL in the field.
const REROUTE_NAMES: [&str; 5] = ["proxy", "curlrc", "curl_home", "wgetrc", "hostaliases"];
/// Assignments that move where a client finds its config file.
const CONFIG_HOMES: [&str; 4] = ["home=", "xdg_config_home=", "userprofile=", "appdata="];
/// Variable prefixes the cloud clients read their profile, config file or
/// endpoint from, and those the dynamic loader reads, which can put other
/// code in any client.
const REROUTE_VARIABLE_PREFIXES: [&str; 5] = ["AWS_", "BOTO_", "CLOUDSDK_", "LD_", "DYLD_"];
/// Shells whose `-c` script `local_only` may unwrap once.
const UNWRAP_SHELLS: [&str; 4] = ["bash", "sh", "zsh", "dash"];
/// Commands that only print what a request returns.
const FORMATTERS: [&str; 11] = [
    "jq",
    "head",
    "tail",
    "grep",
    "wc",
    "cat",
    "convertto-json",
    "format-list",
    "format-table",
    "out-string",
    "select-object",
];

/// What a request target names.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// `localhost`, 127.0.0.0/8, `[::1]` or `0.0.0.0` (IPv4-mapped 127/8
    /// included), which the facts do not list.
    Loopback,
    Listed(String),
    /// Not a URL, or one an entry cannot name whole.
    Unnamed,
}

/// The destination facts of one action's `command` field: its text without the
/// here-document bodies the reader took out, the field as recorded, the
/// readings of its stages and their byte ranges in the text.
pub(super) fn upload_destinations(
    command: &str,
    recorded: &str,
    stages: &[Vec<String>],
    spans: &[Range<usize>],
    budget: &mut RetentionBudget,
) -> Result<DestinationFacts, ProcessingError> {
    let mut complete = literal_field(command, budget)?;
    // A body is part of the recorded field: a URL in it is one no stage sends to.
    let (written, schemed) = written_urls(recorded, budget)?;
    complete &= schemed;

    let mut targets = std::collections::BTreeSet::new();
    let mut formatted = BTreeMap::new();
    let mut listed: Vec<String> = Vec::new();
    let mut loopback = false;
    let mut uploads = 0usize;
    // Per reading: whether it uploads, and whether by a curl, wget or cmdlet
    // request whose client is its first word.
    let mut simple = Vec::with_capacity(stages.len());
    for tokens in stages {
        for token in tokens {
            budget.charge(token.len())?;
        }
        for token in tokens {
            budget.charge(token.len())?;
        }
        complete &= !consumes_stdin_code(tokens) && !names_reroute(tokens);
        let Some((at, reading)) = upload(tokens, budget)? else {
            simple.push(None);
            continue;
        };
        uploads += 1;
        // An assignment before the client can set a proxy or a config home.
        complete &= !tokens[..at].iter().any(|token| assignment(token));
        let sends: Vec<(&str, bool)> = match &reading {
            Upload::Http(request) => {
                complete &= !request.unread;
                request
                    .targets
                    .iter()
                    .map(|target| (*target, true))
                    .collect()
            }
            Upload::Transfers(transfers) => transfers
                .iter()
                .map(|transfer| {
                    let read = transfer.reading == Reading::Certain && !transfer.endpoint_override;
                    (transfer.destination, read)
                })
                .collect(),
            Upload::Azure => Vec::new(),
        };
        let mut named = false;
        for (target, read) in sends {
            complete &= read;
            targets.insert(target);
            let next = formatted.len();
            let target = match formatted.get(target) {
                Some(known) => Target::clone(known),
                None if next >= MAX_FORMATTED_URLS => Target::Unnamed,
                None => {
                    let found = destination(target, budget)?;
                    formatted.insert(target, found.clone());
                    found
                }
            };
            match target {
                Target::Loopback => {
                    loopback = true;
                    named = true;
                }
                Target::Listed(entry) => {
                    named = true;
                    if !listed.contains(&entry) {
                        if listed.len() < MAX_DESTINATIONS {
                            listed.push(entry);
                        } else {
                            complete = false;
                        }
                    }
                }
                Target::Unnamed => complete = false,
            }
        }
        // Every upload stage names where it sends.
        complete &= named;
        // A path-qualified client is not known to be the real one, and one
        // that may follow a redirect can re-send the body elsewhere.
        simple.push(Some(
            matches!(&reading, Upload::Http(request) if !request.redirects)
                && at == 0
                && bare(&tokens[0]),
        ));
    }
    complete &= uploads > 0;
    // Every URL written in the field is one an upload stage sends to.
    for url in written {
        budget.charge(url.len())?;
        complete &= targets.contains(url);
    }
    let local_only = complete
        && loopback
        && listed.is_empty()
        && one_simple_request(command, stages, spans, &simple);
    listed.sort();
    let facts = DestinationFacts {
        destinations: listed,
        complete,
        local_only,
    };
    debug_assert!(facts.is_valid(), "{facts:?}");
    Ok(facts)
}

/// Whether the field holds no expansion, substitution, escape another shell
/// reads differently, unquoted here-document or network redirection. Each is
/// a pass over the field, charged before it runs.
fn literal_field(command: &str, budget: &mut RetentionBudget) -> Result<bool, ProcessingError> {
    // `$` expands in POSIX shells and PowerShell; a backtick substitutes in one
    // and escapes in the other. A doubled backslash is a UNC share's start.
    budget.charge(command.len())?;
    if command.contains(['$', '`'])
        || command.contains(">(")
        || command.contains("<(")
        || command.contains("\\\\")
        || command.contains("/dev/tcp/")
        || command.contains("/dev/udp/")
    {
        return Ok(false);
    }
    // `cmd.exe` expands `%NAME%`.
    budget.charge(command.len())?;
    let mut rest = command;
    while let Some(at) = rest.find('%') {
        rest = &rest[at + 1..];
        let name = rest
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .map_or(rest, |end| &rest[..end]);
        if name.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
            && rest[name.len()..].starts_with('%')
        {
            return Ok(false);
        }
    }
    // An unquoted here-document expands its body, which the reader may have
    // taken out of the field. A quoted one is literal.
    budget.charge(command.len())?;
    let mut rest = command;
    while let Some(at) = rest.find("<<") {
        rest = &rest[at + 2..];
        if let Some(string) = rest.strip_prefix('<') {
            rest = string;
            continue;
        }
        let delimiter = rest.trim_start_matches('-').trim_start_matches([' ', '\t']);
        if !delimiter.starts_with(['\'', '"']) {
            return Ok(false);
        }
    }
    // A UNC path written with slashes, as a word or a redirection's target.
    budget.charge(command.len())?;
    Ok(!command.split_whitespace().any(|word| {
        word.trim_start_matches(['<', '>', '&', '|', '0', '1', '2'])
            .starts_with("//")
    }))
}

/// Every `scheme://` URL written in the text, up to the end of its shell word,
/// and whether each `://` has a scheme before it. A URL inside another (a query
/// value) is part of it. One forward pass, charged before it runs.
fn written_urls<'a>(
    text: &'a str,
    budget: &mut RetentionBudget,
) -> Result<(Vec<&'a str>, bool), ProcessingError> {
    budget.charge(text.len())?;
    let bytes = text.as_bytes();
    let mut urls = Vec::new();
    let mut schemed = true;
    // Where the run of scheme characters before `at` starts.
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at..].starts_with(b"://") {
            let mut end = at + 3;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(
                    bytes[end],
                    b'\'' | b'"' | b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')'
                )
            {
                end += 1;
            }
            if bytes[start..at]
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            {
                urls.push(&text[start..end]);
            } else {
                schemed = false;
            }
            at = end;
            start = end;
            continue;
        }
        if !(bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'+' | b'-' | b'.')) {
            start = at + 1;
        }
        at += 1;
    }
    Ok((urls, schemed))
}

/// Whether a reading names a proxy, client config file or host alias table
/// outside a URL (a URL no stage sends to fails on its own), or moves a
/// config home.
fn names_reroute(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        // A cloud client's profile, config file or endpoint, a loader
        // variable or the search path that finds the client, set anywhere.
        if let Some((name, _)) = token.split_once('=') {
            let name = name.to_ascii_uppercase();
            if name == "PATH"
                || REROUTE_VARIABLE_PREFIXES
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            {
                return true;
            }
        }
        if token.contains("://") {
            return false;
        }
        let lower = token.to_ascii_lowercase();
        REROUTE_NAMES.iter().any(|name| lower.contains(name))
            || CONFIG_HOMES.iter().any(|home| lower.starts_with(home))
    })
}

/// What one request target names, as an entry built from its parsed parts.
fn destination(text: &str, budget: &mut RetentionBudget) -> Result<Target, ProcessingError> {
    budget.charge(text.len())?;
    let Some((scheme, rest)) = text.split_once("://") else {
        return Ok(Target::Unnamed);
    };
    if !scheme.starts_with(|ch: char| ch.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Ok(Target::Unnamed);
    }
    let scheme = scheme.to_ascii_lowercase();
    let dns = DNS_SCHEMES.contains(&scheme.as_str());
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(end);
    let Some((canonical, original, loopback)) = host(authority) else {
        return Ok(Target::Unnamed);
    };
    if dns && loopback {
        return Ok(Target::Loopback);
    }
    let path = after.strip_prefix('/').map_or("", |path| {
        &path[..path.find(['?', '#']).unwrap_or(path.len())]
    });
    let segments: Vec<&str> = path
        .split('/')
        .take_while(|segment| plain_name(segment))
        .take(MAX_DESTINATION_SEGMENTS)
        .collect();
    let prefix = |host: &str| {
        if dns {
            host.to_owned()
        } else {
            format!("{scheme}://{host}")
        }
    };
    // The longest entry that is a fixed point of the sanitizer, as written and
    // as listed; a segment that would break that is cut with all after it.
    for kept in (0..=segments.len()).rev() {
        let mut written = prefix(original);
        let mut entry = prefix(&canonical);
        for segment in &segments[..kept] {
            written.push('/');
            written.push_str(segment);
            entry.push('/');
            entry.push_str(&segment.to_ascii_lowercase());
        }
        if entry.len() > MAX_DESTINATION_LEN {
            continue;
        }
        if redact(&written, budget)? == written && redact(&entry, budget)? == entry {
            return Ok(Target::Listed(entry));
        }
    }
    Ok(Target::Unnamed)
}

/// A URL authority's host, canonical and as written, and whether it is
/// loopback. Userinfo and a port are dropped; anything an entry cannot hold,
/// or that URL parsers read differently, names no host.
fn host(authority: &str) -> Option<(String, &str, bool)> {
    if !authority.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']' | b'@')
    }) {
        return None;
    }
    let host_port = match authority.split_once('@') {
        Some((_, host)) if !host.contains('@') => host,
        Some(_) => return None,
        None => authority,
    };
    let port = |port: &str| port.parse::<u16>().is_ok();
    if let Some(bracketed) = host_port.strip_prefix('[') {
        let (inner, suffix) = bracketed.split_once(']')?;
        if !suffix.is_empty() && !suffix.strip_prefix(':').is_some_and(port) {
            return None;
        }
        let IpAddr::V6(ip) = inner.parse::<IpAddr>().ok()? else {
            return None;
        };
        let loopback = ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback());
        return Some((format!("[{ip}]"), &host_port[..inner.len() + 2], loopback));
    }
    let written = match host_port.split_once(':') {
        Some((written, after)) if port(after) => written,
        Some(_) => return None,
        None => host_port,
    };
    let written = written.strip_suffix('.').unwrap_or(written);
    let name = written.to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name.split('.').any(str::is_empty)
        || name.contains(['[', ']'])
    {
        return None;
    }
    // Resolvers read `127.1`, `0x7f.0.0.1` and `2130706433` as addresses, and
    // URL parsers disagree on them: only a dotted quad is an address.
    let numeric = name.split('.').all(|label| {
        label.bytes().all(|b| b.is_ascii_digit())
            || label
                .strip_prefix("0x")
                .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
    });
    if numeric {
        let quad = name.split('.').count() == 4
            && name
                .split('.')
                .all(|label| label == "0" || !label.starts_with('0') && label.len() <= 3);
        let ip = quad.then(|| name.parse::<Ipv4Addr>().ok()).flatten()?;
        return Some((name, written, ip.is_loopback() || ip.is_unspecified()));
    }
    let loopback = name == "localhost";
    Some((name, written, loopback))
}

/// A path segment that reads as a plain name rather than an identifier or a
/// token: a short run of name characters with few digits. Anything a secret
/// can look like beyond this is the sanitizer's to judge.
fn plain_name(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 48
        && segment != "."
        && !segment.contains("..")
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
        && segment.bytes().filter(u8::is_ascii_digit).count() <= 4
        && segment
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .all(|run| run.len() <= 24)
}

/// Whether the field is one simple request: one stage read as a curl, wget or
/// PowerShell web cmdlet upload with its client first, optionally inside one
/// `bash|sh|zsh|dash -c|-lc` script that is the whole field, and optionally
/// piped into one formatter, with nothing else.
fn one_simple_request(
    command: &str,
    stages: &[Vec<String>],
    spans: &[Range<usize>],
    simple: &[Option<bool>],
) -> bool {
    let mut request = None;
    for (span, upload) in spans.iter().zip(simple) {
        match upload {
            Some(true) if request.is_none_or(|request| request == span) => request = Some(span),
            Some(_) => return false,
            None => {}
        }
    }
    let Some(request) = request else {
        return false;
    };
    let mut wrapper = None;
    let mut formatter = None;
    for ((span, tokens), upload) in spans.iter().zip(stages).zip(simple) {
        if span == request {
            if upload.is_none() {
                return false;
            }
            continue;
        }
        let unwrap = tokens.len() == 3
            && bare(&tokens[0])
            && UNWRAP_SHELLS.contains(&client_name(&tokens[0]).as_str())
            && matches!(tokens[1].as_str(), "-c" | "-lc")
            && span.start <= request.start
            && request.end <= span.end
            && command[..span.start].trim().is_empty()
            && command[span.end..].trim().is_empty();
        let formats = tokens
            .first()
            .is_some_and(|word| bare(word) && FORMATTERS.contains(&client_name(word).as_str()))
            && span.start >= request.end
            && command[request.end..span.start].trim() == "|";
        if unwrap && wrapper.is_none_or(|wrapper| wrapper == span) {
            wrapper = Some(span);
        } else if formats && formatter.is_none_or(|formatter| formatter == span) {
            formatter = Some(span);
        } else {
            return false;
        }
    }
    wrapper.is_some() || command[..request.start].trim().is_empty()
}

/// A program named without a path, which the shell finds on its search path
/// (a `.exe` suffix is still a bare name).
fn bare(word: &str) -> bool {
    !word.contains(['/', '\\'])
}

#[cfg(test)]
mod tests;
