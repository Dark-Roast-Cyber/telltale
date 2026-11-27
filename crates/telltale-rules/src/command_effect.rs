//! Reads the transfer a tokenized command segment requests: an object-storage
//! copy, move or sync with the AWS CLI (`aws s3`), `gsutil` or `rclone`, or a
//! GitHub CLI publication of a file (an issue or pull request body file, or a
//! gist file). It also reads, experimentally, a Python one-liner that fetches
//! an HTTP(S) response and runs it as code ([`fetched_code`]).
//!
//! A [`Transfer`] is what the command text asks for, never what ran: this
//! does not know whether the command executed, succeeded or moved any bytes.
//! Its source and destination are the operands as the shell passed them, so
//! raw evidence and provenance stay with the caller.
//!
//! This is shared by the detection views and is not a supported embedding
//! API.

/// The client that requests a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Client {
    /// The AWS CLI `s3` command group.
    Aws,
    Gsutil,
    Rclone,
    /// The GitHub CLI.
    Gh,
}

/// The requested operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    Copy,
    Move,
    Sync,
    /// A GitHub CLI issue or pull request body file, or a gist file.
    Publish,
}

/// Where the requested transfer sends data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The source is local.
    Outbound,
    /// A remote source to a local destination.
    Inbound,
    /// A remote source to a remote destination.
    Remote,
}

/// How sure the operand reading is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    Certain,
    /// rclone's second reading, after unlisted long options read as taking a
    /// value left no complete transfer.
    Fallback,
}

/// A transfer a command requests, not one it performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer<'a> {
    pub client: Client,
    pub operation: Operation,
    /// The source operand as the shell passed it; for the GitHub CLI, the
    /// body or gist file.
    pub source: &'a str,
    /// The destination operand; for the GitHub CLI, `github:issue`,
    /// `github:pr` or `github:gist`.
    pub destination: &'a str,
    pub direction: Direction,
    pub reading: Reading,
    /// An option names the service endpoint or selects configuration that can
    /// (`aws --endpoint-url` or `--profile`, a gsutil `-o` boto setting), so
    /// the destination operand does not say which host receives the data.
    pub endpoint_override: bool,
}

/// The transfers one tokenized command segment requests: at most one for an
/// object-storage call, one per file for a GitHub CLI publication.
pub fn transfers(tokens: &[String]) -> Vec<Transfer<'_>> {
    let Some(command) = invocation(tokens, &["aws", "gsutil", "rclone", "gh"]) else {
        return Vec::new();
    };
    let client = client_name(&command[0]);
    // The operands after options and their values: the command group,
    // subcommand, then the source and destination of a copy, move or sync.
    // The group and verb are found among the operands, so the value of an
    // unlisted global option before them does not hide the transfer.
    let args = &command[1..];
    let operands = match client.as_str() {
        "aws" => operands(args, |word, _| takes_next(word, AWS_VALUE_OPTIONS, "")),
        // gsutil letters that take a value before the verb can be flags after it.
        "gsutil" => operands(args, |word, after_verb| {
            takes_next(word, &[], if after_verb { "ajLsxyz" } else { "hiou" })
        }),
        // rclone reads its own operands (`rclone_transfer`).
        _ => operands(args, |word, _| takes_next(word, &["repo", "hostname"], "R")),
    };
    // The first operand that `verb` accepts, with the source and destination
    // that follow it.
    let transfer = |verb: fn(&str) -> bool| match operands.iter().position(|word| verb(word)) {
        Some(at) => match operands.get(at..at + 3) {
            Some(&[verb, source, destination]) => Some([verb, source, destination]),
            _ => None,
        },
        None => None,
    };
    let (client, [verb, source, destination], reading) = match (client.as_str(), &operands[..]) {
        ("gh", [group, verb, ..]) => return publications(command, group, verb),
        // The verb directly follows the `s3` group.
        ("aws", _) => match operands.windows(4).find(|words| words[0] == "s3") {
            Some(&[_, verb, source, destination]) if matches!(verb, "cp" | "mv" | "sync") => {
                (Client::Aws, [verb, source, destination], Reading::Certain)
            }
            _ => return Vec::new(),
        },
        ("gsutil", _) => match transfer(|word| matches!(word, "cp" | "mv" | "rsync")) {
            Some(words) => (Client::Gsutil, words, Reading::Certain),
            None => return Vec::new(),
        },
        ("rclone", _) => match rclone_transfer(args) {
            Some((words, reading)) => (Client::Rclone, words, reading),
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let operation = match verb {
        "mv" | "move" => Operation::Move,
        "sync" | "rsync" => Operation::Sync,
        _ => Operation::Copy,
    };
    let remote = if client == Client::Rclone {
        rclone_remote
    } else {
        object_url
    };
    let endpoint_override = args.iter().any(|word| match client {
        Client::Aws => ["--endpoint-url", "--profile"].iter().any(|option| {
            word == option
                || word
                    .strip_prefix(option)
                    .is_some_and(|rest| rest.starts_with('='))
        }),
        // gsutil's `-o` takes a boto setting, which can name any host.
        Client::Gsutil => {
            word.starts_with('-') && !word.starts_with("--") && word[1..].contains('o')
        }
        _ => false,
    });
    let direction = match (remote(source), remote(destination)) {
        (false, _) => Direction::Outbound,
        (true, false) => Direction::Inbound,
        (true, true) => Direction::Remote,
    };
    vec![Transfer {
        client,
        operation,
        source,
        destination,
        direction,
        reading,
        endpoint_override,
    }]
}

/// The AWS CLI long options that take a separate value.
const AWS_VALUE_OPTIONS: &[&str] = &[
    "profile",
    "color",
    "cli-binary-format",
    "region",
    "endpoint-url",
    "output",
    "query",
    "ca-bundle",
    "cli-read-timeout",
    "cli-connect-timeout",
    "source-region",
    "storage-class",
    "acl",
    "include",
    "exclude",
    "content-type",
    "cache-control",
    "expires",
    "sse-kms-key-id",
];

/// The rclone long options that take no value.
const RCLONE_FLAGS: &[&str] = &[
    "progress",
    "verbose",
    "quiet",
    "dry-run",
    "interactive",
    "checksum",
    "size-only",
    "ignore-existing",
    "ignore-times",
    "ignore-size",
    "ignore-checksum",
    "update",
    "no-traverse",
    "no-check-dest",
    "no-update-modtime",
    "create-empty-src-dirs",
    "delete-before",
    "delete-during",
    "delete-after",
    "delete-excluded",
    "fast-list",
    "immutable",
    "inplace",
    "links",
    "copy-links",
    "skip-links",
    "metadata",
    "check-first",
    "use-server-modtime",
    "human-readable",
    "stats-one-line",
    "no-gzip-encoding",
    "server-side-across-configs",
];

/// The verb, source and destination of an rclone copy, sync or move that
/// names both. A long option that is not a listed flag is first read as
/// taking the next word as its value, so a value never reads as the source.
/// When that reading leaves no complete transfer, the unlisted options were
/// flags, and the words after them are read as operands: a fallback reading.
fn rclone_transfer(args: &[String]) -> Option<([&str; 3], Reading)> {
    let read = |unlisted_take_a_value: bool| {
        let operands = operands(args, |word, _| {
            unlisted_take_a_value
                && word
                    .strip_prefix("--")
                    .is_some_and(|name| !name.contains('=') && !RCLONE_FLAGS.contains(&name))
        });
        let verb = operands
            .iter()
            .position(|word| word.starts_with("copy") || matches!(*word, "sync" | "move"))?;
        match operands.get(verb..verb + 3) {
            Some(&[verb, source, destination]) => Some([verb, source, destination]),
            _ => None,
        }
    };
    read(true)
        .map(|words| (words, Reading::Certain))
        .or_else(|| read(false).map(|words| (words, Reading::Fallback)))
}

/// The operands among a command's arguments: the words that are neither an
/// option nor the separate value of one, and every word after `--`. A lone
/// `-` (standard input or output) is an operand. `takes_value` reads an
/// option and whether an operand came before it.
fn operands(args: &[String], takes_value: impl Fn(&str, bool) -> bool) -> Vec<&str> {
    let mut operands = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if word == "--" {
            operands.extend(words.map(String::as_str));
            break;
        }
        if word.len() > 1 && word.starts_with('-') {
            if takes_value(word, !operands.is_empty()) {
                words.next();
            }
        } else {
            operands.push(word.as_str());
        }
    }
    operands
}

/// The files a GitHub CLI call publishes: every word of `gist create` that is
/// not an option, or the body file of an `issue` or `pr` `comment` or
/// `create`. A secret gist is unlisted, not private, so either is readable by
/// others.
fn publications<'a>(command: &'a [String], group: &str, verb: &str) -> Vec<Transfer<'a>> {
    let rest = command[1..].iter().map(String::as_str).collect::<Vec<_>>();
    let (files, destination): (Vec<&str>, _) = match (group, verb) {
        ("gist", "create") => (
            rest.iter()
                .copied()
                .filter(|word| !word.starts_with('-') && *word != group && *word != verb)
                .collect(),
            "github:gist",
        ),
        ("issue" | "pr", "comment" | "create") => (
            rest.iter()
                .enumerate()
                .filter_map(|(at, &word)| match word {
                    "-F" | "--body-file" => rest.get(at + 1).copied(),
                    _ => word
                        .strip_prefix("--body-file=")
                        .or_else(|| word.strip_prefix("-F").filter(|file| !file.is_empty())),
                })
                .collect(),
            if group == "issue" {
                "github:issue"
            } else {
                "github:pr"
            },
        ),
        _ => return Vec::new(),
    };
    files
        .into_iter()
        .map(|source| Transfer {
            client: Client::Gh,
            operation: Operation::Publish,
            source,
            destination,
            direction: Direction::Outbound,
            reading: Reading::Certain,
            endpoint_override: false,
        })
        .collect()
}

/// Whether `value` starts with `prefix`, ignoring ASCII case.
pub fn scheme(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// An `s3://` or `gs://` location.
fn object_url(value: &str) -> bool {
    scheme(value, "s3://") || scheme(value, "gs://")
}

/// An rclone remote: an on-the-fly backend (a leading colon) or a name of a
/// letter and one or more word characters, dots or dashes before a colon that
/// `//` does not follow. A drive letter or a URL is local.
fn rclone_remote(value: &str) -> bool {
    value.starts_with(':')
        || value.split_once(':').is_some_and(|(name, rest)| {
            name.len() >= 2
                && name.starts_with(|c: char| c.is_ascii_alphabetic())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                && !rest.starts_with("//")
        })
}

/// A program that runs its operands as a command: on this host, on a remote
/// host, in a container or under a runner.
struct Wrapper {
    name: &'static str,
    /// The subcommand that must follow the name (`docker exec`), if any.
    subcommand: &'static str,
    /// The short options that take a value.
    values: &'static str,
    /// The positionals before the command: a `timeout` duration, an `ssh`
    /// destination, a container or a profile.
    positionals: usize,
    /// Whether options and `--` may also stand between the positionals and
    /// the command (`ssh host -t cmd`, `aws-vault exec prod -- cmd`).
    options_after: bool,
    /// When not empty, the command starts after the first of these words
    /// (`kubectl exec … --`, `cmd /c`).
    markers: &'static [&'static str],
    /// Options that run a script file: the words after one are the script's.
    files: &'static [&'static str],
    /// How the program hands its command to a shell, if it does.
    script: Script,
    /// Whether the command runs on another host or in a container.
    elsewhere: bool,
}

/// How a wrapper hands its command words to a shell.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// It runs them as a program and its arguments.
    None,
    /// It joins them with blanks for a shell (`ssh`, `watch`, PowerShell).
    Joined,
    /// Its shell reads a quoted command as written (`cmd /c "…"`).
    Quoted,
}

const fn wrapper(name: &'static str, values: &'static str, positionals: usize) -> Wrapper {
    Wrapper {
        name,
        subcommand: "",
        values,
        positionals,
        options_after: false,
        markers: &[],
        files: &[],
        script: Script::None,
        elsewhere: false,
    }
}

/// The programs read as running their operands as a command, each with the
/// options that take a value and the words that come before its command.
const WRAPPERS: [Wrapper; 27] = [
    wrapper("sudo", "ugCDhprtTU", 0),
    wrapper("doas", "uC", 0),
    wrapper("env", "uCS", 0),
    wrapper("xargs", "adEILnPs", 0),
    wrapper("timeout", "sk", 1),
    wrapper("nice", "n", 0),
    wrapper("ionice", "cnp", 0),
    wrapper("stdbuf", "ioe", 0),
    wrapper("time", "fo", 0),
    wrapper("nohup", "", 0),
    wrapper("command", "", 0),
    wrapper("exec", "a", 0),
    wrapper("torsocks", "", 0),
    wrapper("proxychains", "f", 0),
    wrapper("proxychains4", "f", 0),
    // Remote hosts and containers.
    Wrapper {
        options_after: true,
        script: Script::Joined,
        elsewhere: true,
        ..wrapper("ssh", "BbcDEeFIiJLlmOoPpQRSWw", 1)
    },
    Wrapper {
        subcommand: "exec",
        elsewhere: true,
        ..wrapper("docker", "euw", 1)
    },
    Wrapper {
        subcommand: "exec",
        elsewhere: true,
        ..wrapper("podman", "euw", 1)
    },
    Wrapper {
        subcommand: "exec",
        markers: &["--"],
        elsewhere: true,
        ..wrapper("kubectl", "", 0)
    },
    // Runners.
    Wrapper {
        subcommand: "exec",
        options_after: true,
        ..wrapper("aws-vault", "dt", 1)
    },
    Wrapper {
        script: Script::Joined,
        ..wrapper("watch", "nq", 0)
    },
    Wrapper {
        script: Script::Joined,
        ..wrapper("parallel", "aCdEIjLNnPSs", 0)
    },
    Wrapper {
        subcommand: "run",
        ..wrapper("uv", "p", 0)
    },
    wrapper("npx", "pc", 0),
    // Other shells' command strings.
    Wrapper {
        markers: &["/c", "/k"],
        script: Script::Quoted,
        ..wrapper("cmd", "", 0)
    },
    Wrapper {
        markers: &["-c", "-command", "/c", "/command"],
        files: &["-file", "-f", "/file"],
        script: Script::Joined,
        ..wrapper("powershell", "", 0)
    },
    Wrapper {
        markers: &["-c", "-command", "/c", "/command"],
        files: &["-file", "-f", "/file"],
        script: Script::Joined,
        ..wrapper("pwsh", "", 0)
    },
];

impl Wrapper {
    /// The row of the program `tokens[at]` invokes.
    fn at(tokens: &[String], at: usize) -> Option<&'static Wrapper> {
        let name = client_name(&tokens[at]);
        WRAPPERS.iter().find(|wrapper| {
            name == wrapper.name
                && (wrapper.subcommand.is_empty()
                    || tokens
                        .get(at + 1)
                        .is_some_and(|word| word == wrapper.subcommand))
        })
    }

    /// Where the command this invocation at `at` runs starts.
    fn command(&self, tokens: &[String], at: usize) -> Option<usize> {
        let mut index = at + 1 + usize::from(!self.subcommand.is_empty());
        if !self.markers.is_empty() {
            let words = tokens.get(index..)?;
            let listed = |list: &[&str], word: &String| {
                list.iter().any(|item| word.eq_ignore_ascii_case(item))
            };
            let found = words
                .iter()
                .position(|word| listed(self.markers, word) || listed(self.files, word))?;
            return (!listed(self.files, &words[found])).then_some(index + found + 1);
        }
        // Options come before each positional, and after the last one where
        // the row says so.
        let rounds = self.positionals + usize::from(self.positionals == 0 || self.options_after);
        for round in 0..rounds {
            while let Some(option) = tokens
                .get(index)
                .filter(|token| token.len() > 1 && token.starts_with('-'))
            {
                index += 1;
                if option == "--" {
                    break;
                }
                index += usize::from(takes_next(option, &WRAPPER_VALUE_OPTIONS, self.values));
            }
            index += usize::from(round < self.positionals);
        }
        Some(index)
    }
}

/// The text a wrapper hands to another shell, as that shell receives it: its
/// command words joined with blanks when one of them holds a blank, as a
/// quoted command does (`ssh host '…'`, `powershell -Command "…"`), or for
/// `cmd`, a quoted command of its own (`cmd /c "…"`). With it come the words
/// that send the command to another host (`ssh host`), which a reading of the
/// command keeps in front of it. The caller reads the text as it reads a
/// `bash -c` script.
pub fn launched_script(tokens: &[String]) -> Option<(&[String], String)> {
    let (at, wrapper, elsewhere) = walk(tokens, &[], true)?;
    let wrapper = wrapper?;
    let start = wrapper.command(tokens, at)?;
    let words = tokens.get(start..)?;
    let blank = |word: &String| word.contains(char::is_whitespace);
    let script = match wrapper.script {
        Script::None => false,
        Script::Joined => words.iter().any(blank),
        Script::Quoted => words.first().is_some_and(blank),
    };
    let kept = if elsewhere || wrapper.elsewhere {
        &tokens[..start]
    } else {
        &[]
    };
    script.then(|| (kept, words.join(" ")))
}

/// Wrapper long options that take a separate value (`--user deploy`).
const WRAPPER_VALUE_OPTIONS: [&str; 34] = [
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
    "env",
    "env-file",
    "workdir",
    "detach-keys",
    "duration",
    "region",
    "mfa-token",
    "interval",
    "with",
    "with-requirements",
    "with-editable",
    "python",
    "project",
    "directory",
    "package",
];

/// A leading `NAME=value` shell assignment.
pub fn assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
            && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    })
}

/// A reserved word after which the next word is still a command.
pub fn reserved_word(word: &str) -> bool {
    matches!(
        word,
        "if" | "elif" | "then" | "else" | "while" | "until" | "do" | "!"
    )
}

/// The client invocation of a command segment: its command word, after any
/// leading reserved words, assignments, the opening of a group or a function
/// body, and wrappers such as `sudo -u user`, `env A=1`, `xargs -n1`,
/// `timeout 30`, `ssh host`, `docker exec c`, `kubectl exec pod --`, `watch
/// -n5` or `cmd /c`, or the command `find` runs for each file it finds
/// (`-exec`, `-execdir`, `-ok`, `-okdir`). A client named as an argument
/// (`git fetch`, `echo curl`, `which wget`) is not an invocation.
pub fn invocation<'a>(tokens: &'a [String], clients: &[&str]) -> Option<&'a [String]> {
    walk(tokens, clients, false).map(|(at, ..)| &tokens[at..])
}

/// Whether the client invocation of a command segment runs on another host
/// or in a container: an `ssh`, `docker exec`, `podman exec` or `kubectl exec`
/// leads to it, directly or through other wrappers.
pub fn runs_elsewhere(tokens: &[String], clients: &[&str]) -> bool {
    walk(tokens, clients, false).is_some_and(|(.., elsewhere)| elsewhere)
}

/// Where [`invocation`] finds a client, or with `scripts`, the first wrapper
/// that hands its command to a shell, with that wrapper's row; and whether a
/// wrapper before it runs its command on another host or in a container.
fn walk(
    tokens: &[String],
    clients: &[&str],
    scripts: bool,
) -> Option<(usize, Option<&'static Wrapper>, bool)> {
    let mut index = 0;
    let mut elsewhere = false;
    while let Some(token) = tokens.get(index) {
        let name = client_name(token);
        if clients.contains(&name.as_str()) {
            return Some((index, None, elsewhere));
        }
        if assignment(token) || reserved_word(token) || token == "{" {
            index += 1;
            continue;
        }
        // A function definition's name: `f() {`, `f () {`, `function f {`.
        let opens = |at: usize| tokens.get(at).is_some_and(|word| word == "{");
        if token == "function" && tokens.get(index + 1).is_some() {
            index += 2;
            index += usize::from(tokens.get(index).is_some_and(|word| word == "()"));
            continue;
        }
        if token.ends_with("()") && token.len() > 2 && opens(index + 1) {
            index += 1;
            continue;
        }
        if tokens.get(index + 1).is_some_and(|word| word == "()") && opens(index + 2) {
            index += 2;
            continue;
        }
        if name == "find" {
            // Each command `find` runs is read in turn.
            return tokens[index + 1..]
                .iter()
                .enumerate()
                .filter(|(_, token)| {
                    matches!(token.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir")
                })
                .find_map(|(at, _)| {
                    let from = index + at + 2;
                    walk(&tokens[from..], clients, scripts)
                        .map(|(at, row, inner)| (from + at, row, elsewhere || inner))
                });
        }
        let wrapper = Wrapper::at(tokens, index)?;
        if scripts && wrapper.script != Script::None {
            return Some((index, Some(wrapper), elsewhere));
        }
        elsewhere |= wrapper.elsewhere;
        index = wrapper.command(tokens, index)?;
    }
    None
}

/// A Python one-liner that fetches a response and runs it as code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchedCode<'a> {
    /// The HTTP(S) URL the code fetches.
    pub url: &'a str,
    /// Whether a wrapper runs the one-liner on another host or in a container.
    pub elsewhere: bool,
}

/// The fetch a Python one-liner's `-c` code runs as code (experimental): a
/// `python`, `python3`, `python3.x` or `py` invocation, read through wrappers
/// as other clients are, whose code passes a fetched response to `exec` or
/// `eval`, as [`fetch_then_exec`] reads it from the code's names, calls and
/// string literals.
pub fn fetched_code(tokens: &[String]) -> Option<FetchedCode<'_>> {
    tokens
        .iter()
        .map(|token| client_name(token))
        .filter(|name| python(name))
        .find_map(|name| {
            let (at, _, elsewhere) = walk(tokens, &[name.as_str()], false)?;
            let url = fetch_then_exec(python_code(&tokens[at + 1..])?)?;
            Some(FetchedCode { url, elsewhere })
        })
}

/// A Python launcher's command word.
fn python(name: &str) -> bool {
    name == "py"
        || name
            .strip_prefix("python")
            .is_some_and(|version| version.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// The code after a Python launcher's `-c`, behind options that take no value,
/// `-W`/`-X` and their values, and a `py` version (`-3`, `-3.12`).
fn python_code(args: &[String]) -> Option<&str> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let flags = arg.strip_prefix('-').filter(|flags| !flags.is_empty())?;
        for (at, flag) in flags.char_indices() {
            match flag {
                'c' => {
                    let rest = &flags[at + 1..];
                    return if rest.is_empty() {
                        args.next().map(String::as_str)
                    } else {
                        Some(rest)
                    };
                }
                'W' | 'X' => {
                    if at + 1 == flags.len() {
                        args.next();
                    }
                    break;
                }
                'b'
                | 'B'
                | 'd'
                | 'E'
                | 'I'
                | 'O'
                | 'P'
                | 'q'
                | 's'
                | 'S'
                | 'u'
                | 'v'
                | 'x'
                | '0'..='9'
                | '.' => {}
                _ => return None,
            }
        }
    }
    None
}

/// Bounds the work spent reading one `-c` word.
const MAX_FETCHED_CODE: usize = 4096;

/// The HTTP fetch calls read, by dotted name. A bare `urlopen` counts after
/// `from urllib.request import urlopen`.
const FETCHES: [&str; 6] = [
    "urllib.request.urlopen",
    "requests.get",
    "requests.post",
    "httpx.get",
    "urllib3.request",
    "urlopen",
];

/// What a fetched response may be read through before it runs: methods
/// called, then attributes.
const RESPONSE_METHODS: [&str; 2] = ["read", "decode"];
const RESPONSE_ATTRIBUTES: [&str; 3] = ["text", "content", "data"];

/// One piece of Python code: a dotted name (`a.b`, or `.b` after a call), a
/// string literal's body, or another character.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Piece<'a> {
    Name(&'a str),
    Text(&'a str),
    Mark(u8),
}

/// The pieces of Python code, or `None` for an unterminated string. Comments
/// are left out; a newline is a mark.
fn pieces(code: &str) -> Option<Vec<Piece<'_>>> {
    let bytes = code.as_bytes();
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.';
    let mut pieces = Vec::new();
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'#' {
            at = code[at..].find('\n').map_or(bytes.len(), |end| at + end);
        } else if byte == b'\'' || byte == b'"' {
            let quote = if bytes[at..].starts_with(&[byte; 3]) {
                &bytes[at..at + 3]
            } else {
                &bytes[at..=at]
            };
            let start = at + quote.len();
            let mut end = start;
            loop {
                match bytes.get(end) {
                    None => return None,
                    Some(b'\\') => end += 2,
                    Some(_) if bytes[end..].starts_with(quote) => break,
                    Some(_) => end += 1,
                }
            }
            pieces.push(Piece::Text(code.get(start..end)?));
            at = end + quote.len();
        } else if word(byte) && !byte.is_ascii_digit() {
            let start = at;
            while bytes.get(at).is_some_and(|&b| word(b)) {
                at += 1;
            }
            let name = &code[start..at];
            // A string prefix (`b'…'`, `rb"…"`) is part of the string.
            let prefix = name.len() <= 2
                && name.bytes().all(|b| b"rRbBuUfF".contains(&b))
                && matches!(bytes.get(at), Some(b'\'' | b'"'));
            if !prefix {
                pieces.push(Piece::Name(name));
            }
        } else {
            if !matches!(byte, b' ' | b'\t' | b'\r') {
                pieces.push(Piece::Mark(byte));
            }
            at += 1;
        }
    }
    Some(pieces)
}

/// The index of the `)` closing the `(` at `open`.
fn closing(pieces: &[Piece<'_>], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, piece) in pieces.iter().enumerate().skip(open) {
        match piece {
            Piece::Mark(b'(') => depth += 1,
            Piece::Mark(b')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// What one-liner code has bound so far: whether `urlopen` was imported, the
/// names bound to a URL and the names bound to a fetched response,
/// each with its URL.
#[derive(Default)]
struct Bindings<'a> {
    urlopen: bool,
    urls: Vec<(&'a str, &'a str)>,
    fetched: Vec<(&'a str, &'a str)>,
}

/// An HTTP(S) URL string.
fn http_url(text: &str) -> bool {
    (scheme(text, "http://") && text.len() > 7) || (scheme(text, "https://") && text.len() > 8)
}

impl<'a> Bindings<'a> {
    /// The fetched response that starts at `at`, read through response
    /// methods and attributes or `compile(…)`: where it ends and its URL.
    fn fetched(&self, pieces: &[Piece<'a>], at: usize) -> Option<(usize, &'a str)> {
        let Piece::Name(name) = *pieces.get(at)? else {
            return None;
        };
        let call = pieces.get(at + 1) == Some(&Piece::Mark(b'('));
        if name == "compile" && call {
            let (end, url) = self.fetched(pieces, at + 2)?;
            if !matches!(pieces.get(end)?, Piece::Mark(b',' | b')')) {
                return None;
            }
            return Some((closing(pieces, at + 1)? + 1, url));
        }
        // The fetch or bound name, then what the name reads of it.
        let (url, mut rest, mut end) = match FETCHES.iter().find(|fetch| **fetch == name) {
            Some(&fetch) if call && (fetch != "urlopen" || self.urlopen) => {
                let close = closing(pieces, at + 1)?;
                let url = pieces[at + 2..close]
                    .iter()
                    .find_map(|piece| match *piece {
                        Piece::Text(text) if http_url(text) => Some(text),
                        Piece::Name(name) => self.url(name),
                        _ => None,
                    })?;
                (url, "", close + 1)
            }
            _ => {
                let (base, rest) = name.split_once('.').unwrap_or((name, ""));
                let url = self.fetched.iter().find(|(bound, _)| *bound == base)?.1;
                (url, rest, at + 1)
            }
        };
        loop {
            let members = rest.split('.').filter(|member| !member.is_empty());
            let count = members.clone().count();
            for (index, member) in members.enumerate() {
                // Only the last member of a name is followed by its call.
                let called = index + 1 == count && pieces.get(end) == Some(&Piece::Mark(b'('));
                if RESPONSE_METHODS.contains(&member) && called {
                    end = closing(pieces, end)? + 1;
                } else if called || !RESPONSE_ATTRIBUTES.contains(&member) {
                    return None;
                }
            }
            match pieces.get(end) {
                Some(Piece::Name(next)) if next.starts_with('.') => {
                    rest = next;
                    end += 1;
                }
                _ => return Some((end, url)),
            }
        }
    }

    /// The URL a name is bound to.
    fn url(&self, name: &str) -> Option<&'a str> {
        self.urls
            .iter()
            .find(|(bound, _)| *bound == name)
            .map(|(_, url)| *url)
    }

    /// Reads one statement: an import of `urlopen`, a name bound to a URL or
    /// a fetched response, or an `exec`/`eval` of a fetched response, whose
    /// URL it returns.
    fn statement(&mut self, statement: &[Piece<'a>]) -> Option<&'a str> {
        match statement {
            [
                Piece::Name("from"),
                Piece::Name("urllib.request"),
                Piece::Name("import"),
                names @ ..,
            ] => {
                self.urlopen |= names.iter().enumerate().any(|(at, piece)| {
                    *piece == Piece::Name("urlopen")
                        && names.get(at + 1) != Some(&Piece::Name("as"))
                });
            }
            // A name bound again holds only its new value.
            [Piece::Name(name), Piece::Mark(b'='), value @ ..]
                if !name.contains('.') && value.first() != Some(&Piece::Mark(b'=')) =>
            {
                let url = match value {
                    [Piece::Text(text)] if http_url(text) => Some((true, *text)),
                    _ => self
                        .fetched(value, 0)
                        .filter(|(end, _)| *end == value.len())
                        .map(|(_, url)| (false, url)),
                };
                self.urls.retain(|(bound, _)| bound != name);
                self.fetched.retain(|(bound, _)| bound != name);
                match url {
                    Some((true, url)) => self.urls.push((name, url)),
                    Some((false, url)) => self.fetched.push((name, url)),
                    None => {}
                }
            }
            _ => {}
        }
        statement.windows(2).enumerate().find_map(|(at, pair)| {
            let [Piece::Name("exec" | "eval"), Piece::Mark(b'(')] = pair else {
                return None;
            };
            // An attribute of another object (`obj . exec(…)`) is not the builtin.
            let attribute = at.checked_sub(1).and_then(|before| statement.get(before));
            if matches!(attribute, Some(Piece::Mark(b'.')))
                || matches!(attribute, Some(Piece::Name(name)) if name.ends_with('.'))
            {
                return None;
            }
            let (end, url) = self.fetched(statement, at + 2)?;
            matches!(statement.get(end)?, Piece::Mark(b',' | b')')).then_some(url)
        })
    }
}

/// The URL whose response one-liner code runs: code that calls a listed fetch
/// of an HTTP(S) URL (a string, or a name bound to one) and passes the response
/// itself, a response method or attribute, or a name bound to one of these to
/// `exec` or `eval`, directly or through `compile`.
fn fetch_then_exec(code: &str) -> Option<&str> {
    if code.len() > MAX_FETCHED_CODE {
        return None;
    }
    let pieces = pieces(code)?;
    let mut bindings = Bindings::default();
    let mut depth = 0usize;
    let mut start = 0;
    for (at, piece) in pieces.iter().enumerate() {
        match piece {
            Piece::Mark(b'(' | b'[' | b'{') => depth += 1,
            Piece::Mark(b')' | b']' | b'}') => depth = depth.checked_sub(1)?,
            Piece::Mark(b';' | b'\n') if depth == 0 => {
                if let Some(url) = bindings.statement(&pieces[start..at]) {
                    return Some(url);
                }
                start = at + 1;
            }
            _ => {}
        }
    }
    bindings.statement(&pieces[start..])
}

/// Whether an option word takes the next token as its value: a `long` option
/// without an attached `=value` (`--user deploy`), or a short cluster whose
/// first value-taking letter in `short` ends it (`-u deploy`, `-iu deploy`,
/// but not `-uroot`).
fn takes_next(option: &str, long: &[&str], short: &str) -> bool {
    match option.strip_prefix("--") {
        Some(name) => long.contains(&name),
        None => option[1..]
            .char_indices()
            .find(|(_, letter)| short.contains(*letter))
            .is_some_and(|(offset, _)| offset + 1 == option.len() - 1),
    }
}

/// The normalized command word: basename, lowercase, no `.exe`, and the
/// command of an `X=$(command` assignment.
pub fn client_name(token: &str) -> String {
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

#[cfg(test)]
mod tests;
