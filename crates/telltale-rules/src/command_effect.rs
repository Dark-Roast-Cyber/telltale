//! Reads the transfer a tokenized command segment requests: an object-storage
//! copy, move or sync with the AWS CLI (`aws s3`), `gsutil` or `rclone`, or a
//! GitHub CLI publication of a file (an issue or pull request body file, or a
//! gist file).
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
    /// When not empty, the command starts after the first of these words
    /// (`kubectl exec … --`, `cmd /c`), whatever comes before it.
    markers: &'static [&'static str],
}

const fn wrapper(name: &'static str, values: &'static str, positionals: usize) -> Wrapper {
    Wrapper {
        name,
        subcommand: "",
        values,
        positionals,
        markers: &[],
    }
}

/// The programs read as running their operands as a command. An option that
/// is not listed reads as a flag, so its value reads as the positional or
/// the command and the command after it is not read; only the rows with
/// markers read past words they do not know.
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
    wrapper("ssh", "BbcDEeFIiJLlmOoPpQRSWw", 1),
    Wrapper {
        subcommand: "exec",
        ..wrapper("docker", "euw", 1)
    },
    Wrapper {
        subcommand: "exec",
        ..wrapper("podman", "euw", 1)
    },
    Wrapper {
        subcommand: "exec",
        markers: &["--"],
        ..wrapper("kubectl", "", 0)
    },
    Wrapper {
        subcommand: "exec",
        ..wrapper("aws-vault", "dt", 1)
    },
    // Runners.
    wrapper("watch", "nq", 0),
    wrapper("parallel", "aCdEIjLNnPSs", 0),
    Wrapper {
        subcommand: "run",
        ..wrapper("uv", "p", 0)
    },
    wrapper("npx", "pc", 0),
    // Other shells' command strings.
    Wrapper {
        markers: &["/c", "/k"],
        ..wrapper("cmd", "", 0)
    },
    Wrapper {
        markers: &["-c", "-command", "/c", "/command"],
        ..wrapper("powershell", "", 0)
    },
    Wrapper {
        markers: &["-c", "-command", "/c", "/command"],
        ..wrapper("pwsh", "", 0)
    },
];

impl Wrapper {
    /// Whether `tokens[at]` invokes this program.
    fn invoked(&self, tokens: &[String], at: usize) -> bool {
        client_name(&tokens[at]) == self.name
            && (self.subcommand.is_empty()
                || tokens
                    .get(at + 1)
                    .is_some_and(|word| word == self.subcommand))
    }

    /// Where the command this invocation at `at` runs starts.
    fn command(&self, tokens: &[String], at: usize) -> Option<usize> {
        let mut index = at + 1 + usize::from(!self.subcommand.is_empty());
        if !self.markers.is_empty() {
            let words = tokens.get(index..)?;
            let marker = words.iter().position(|word| {
                self.markers
                    .iter()
                    .any(|marker| word.eq_ignore_ascii_case(marker))
            })?;
            return Some(index + marker + 1);
        }
        for positional in 0..=self.positionals {
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
            index += usize::from(positional < self.positionals);
        }
        Some(index)
    }
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
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        let name = client_name(token);
        if clients.contains(&name.as_str()) {
            return Some(&tokens[index..]);
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
                .find_map(|(at, _)| invocation(&tokens[index + at + 2..], clients));
        }
        let wrapper = WRAPPERS
            .iter()
            .find(|wrapper| wrapper.invoked(tokens, index))?;
        index = wrapper.command(tokens, index)?;
    }
    None
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
mod tests {
    use super::{Client, Direction, Operation, Reading, Transfer, transfers};

    fn words(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    fn transfer<'a>(
        client: Client,
        operation: Operation,
        source: &'a str,
        destination: &'a str,
        direction: Direction,
    ) -> Transfer<'a> {
        Transfer {
            client,
            operation,
            source,
            destination,
            direction,
            reading: Reading::Certain,
        }
    }

    #[test]
    fn aws_s3_copy_move_and_sync_from_a_local_source_are_outbound() {
        assert_eq!(
            transfers(&words("aws s3 cp dump.sql s3://synthetic-bucket/")),
            [transfer(
                Client::Aws,
                Operation::Copy,
                "dump.sql",
                "s3://synthetic-bucket/",
                Direction::Outbound
            )]
        );
        assert_eq!(
            transfers(&words("aws s3 mv dump.sql s3://synthetic-bucket/")),
            [transfer(
                Client::Aws,
                Operation::Move,
                "dump.sql",
                "s3://synthetic-bucket/",
                Direction::Outbound
            )]
        );
        assert_eq!(
            transfers(&words(
                "aws --profile fixture s3 sync --exclude *.tmp ./dist s3://synthetic-bucket/site/"
            )),
            [transfer(
                Client::Aws,
                Operation::Sync,
                "./dist",
                "s3://synthetic-bucket/site/",
                Direction::Outbound
            )]
        );
    }

    #[test]
    fn object_storage_from_a_remote_source_is_inbound_or_remote() {
        assert_eq!(
            transfers(&words(
                "aws s3 cp --profile prod s3://synthetic-bucket/a ./a"
            )),
            [transfer(
                Client::Aws,
                Operation::Copy,
                "s3://synthetic-bucket/a",
                "./a",
                Direction::Inbound
            )]
        );
        assert_eq!(
            transfers(&words(
                "aws s3 sync s3://synthetic-bucket/site s3://other-bucket/site"
            )),
            [transfer(
                Client::Aws,
                Operation::Sync,
                "s3://synthetic-bucket/site",
                "s3://other-bucket/site",
                Direction::Remote
            )]
        );
        assert_eq!(
            transfers(&words("gsutil mv gs://synthetic-bucket/a.tar .")),
            [transfer(
                Client::Gsutil,
                Operation::Move,
                "gs://synthetic-bucket/a.tar",
                ".",
                Direction::Inbound
            )]
        );
        assert_eq!(
            transfers(&words(
                "rclone move synthetic-remote:archive other-remote:archive"
            )),
            [transfer(
                Client::Rclone,
                Operation::Move,
                "synthetic-remote:archive",
                "other-remote:archive",
                Direction::Remote
            )]
        );
    }

    #[test]
    fn gsutil_and_rclone_verbs_map_to_copy_move_and_sync() {
        assert_eq!(
            transfers(&words(
                "gsutil -m rsync -d -r ./dist gs://synthetic-bucket/site"
            )),
            [transfer(
                Client::Gsutil,
                Operation::Sync,
                "./dist",
                "gs://synthetic-bucket/site",
                Direction::Outbound
            )]
        );
        assert_eq!(
            transfers(&words(
                "gsutil -u fixture-project cp gs://synthetic-bucket/a ./a"
            )),
            [transfer(
                Client::Gsutil,
                Operation::Copy,
                "gs://synthetic-bucket/a",
                "./a",
                Direction::Inbound
            )]
        );
        assert_eq!(
            transfers(&words("rclone copyto ./a synthetic-remote:b/a")),
            [transfer(
                Client::Rclone,
                Operation::Copy,
                "./a",
                "synthetic-remote:b/a",
                Direction::Outbound
            )]
        );
        assert_eq!(
            transfers(&words("rclone sync -P synthetic-remote:archive ./reports")),
            [transfer(
                Client::Rclone,
                Operation::Sync,
                "synthetic-remote:archive",
                "./reports",
                Direction::Inbound
            )]
        );
    }

    #[test]
    fn the_client_is_read_behind_wrappers_assignments_and_an_exe_suffix() {
        assert_eq!(
            transfers(&words(
                "AWS_PROFILE=fixture sudo -u deploy aws.exe s3 cp f s3://synthetic-bucket/"
            )),
            [transfer(
                Client::Aws,
                Operation::Copy,
                "f",
                "s3://synthetic-bucket/",
                Direction::Outbound
            )]
        );
    }

    #[test]
    fn a_transfer_run_on_a_remote_host_or_in_a_container_is_read() {
        let upload = |source| {
            [transfer(
                Client::Aws,
                Operation::Copy,
                source,
                "s3://synthetic-bucket/k",
                Direction::Outbound,
            )]
        };
        for command in [
            "ssh host aws s3 cp ./d s3://synthetic-bucket/k",
            "ssh -p 2222 -i key -o BatchMode=yes user@host aws s3 cp ./d s3://synthetic-bucket/k",
            "ssh -t host -- aws s3 cp ./d s3://synthetic-bucket/k",
            "sudo -u app ssh host aws s3 cp ./d s3://synthetic-bucket/k",
            "docker exec c aws s3 cp ./d s3://synthetic-bucket/k",
            "docker exec -it -u root --env-file vars c aws s3 cp ./d s3://synthetic-bucket/k",
            "podman exec -w /srv c aws s3 cp ./d s3://synthetic-bucket/k",
            "kubectl exec pod -- aws s3 cp ./d s3://synthetic-bucket/k",
            "kubectl exec -n ns pod -c ctr -- aws s3 cp ./d s3://synthetic-bucket/k",
            "aws-vault exec prod -- aws s3 cp ./d s3://synthetic-bucket/k",
            "aws-vault exec -d 1h prod aws s3 cp ./d s3://synthetic-bucket/k",
        ] {
            assert_eq!(transfers(&words(command)), upload("./d"), "{command}");
        }
    }

    #[test]
    fn a_transfer_a_runner_or_another_shell_starts_is_read() {
        let upload = |source| {
            [transfer(
                Client::Aws,
                Operation::Copy,
                source,
                "s3://synthetic-bucket/k",
                Direction::Outbound,
            )]
        };
        for (command, source) in [
            ("watch -n5 aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
            ("watch -n 5 -d aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
            (
                "parallel -j 4 aws s3 cp {} s3://synthetic-bucket/k ::: *.gz",
                "{}",
            ),
            ("uv run aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
            (
                "uv run --with awscli aws s3 cp ./d s3://synthetic-bucket/k",
                "./d",
            ),
            ("npx --yes aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
            ("cmd /c aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
            (
                "cmd.exe /d /s /C aws s3 cp ./d s3://synthetic-bucket/k",
                "./d",
            ),
            (
                "powershell -NoProfile -Command aws s3 cp ./d s3://synthetic-bucket/k",
                "./d",
            ),
            ("pwsh -c aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
        ] {
            assert_eq!(transfers(&words(command)), upload(source), "{command}");
        }
    }

    #[test]
    fn a_transfer_in_a_group_or_a_function_body_is_read() {
        for command in [
            "{ aws s3 cp ./d s3://synthetic-bucket/k",
            "f() { aws s3 cp ./d s3://synthetic-bucket/k",
            "f () { aws s3 cp ./d s3://synthetic-bucket/k",
            "function f { aws s3 cp ./d s3://synthetic-bucket/k",
        ] {
            assert_eq!(
                transfers(&words(command)),
                [transfer(
                    Client::Aws,
                    Operation::Copy,
                    "./d",
                    "s3://synthetic-bucket/k",
                    Direction::Outbound
                )],
                "{command}"
            );
        }
    }

    #[test]
    fn a_launcher_reads_the_direction_and_command_it_runs() {
        assert_eq!(
            transfers(&words("ssh host aws s3 cp s3://synthetic-bucket/k ./d")),
            [transfer(
                Client::Aws,
                Operation::Copy,
                "s3://synthetic-bucket/k",
                "./d",
                Direction::Inbound
            )]
        );
        assert_eq!(
            transfers(&words(
                "ssh host echo aws s3 cp ./d s3://synthetic-bucket/k"
            )),
            []
        );
        assert_eq!(transfers(&words("docker exec c grep aws s3 cp f")), []);
        assert_eq!(
            transfers(&words(
                "kubectl exec pod -- echo aws s3 cp ./d s3://synthetic-bucket/k"
            )),
            []
        );
        assert_eq!(
            transfers(&words(
                "watch -n5 echo aws s3 cp ./d s3://synthetic-bucket/k"
            )),
            []
        );
    }

    #[test]
    fn rclone_after_an_unlisted_flag_is_a_fallback_reading() {
        assert_eq!(
            transfers(&words(
                "rclone sync --s3-no-check-bucket ./dump synthetic-remote:b"
            )),
            [Transfer {
                client: Client::Rclone,
                operation: Operation::Sync,
                source: "./dump",
                destination: "synthetic-remote:b",
                direction: Direction::Outbound,
                reading: Reading::Fallback,
            }]
        );
    }

    #[test]
    fn github_cli_publishes_each_body_or_gist_file() {
        assert_eq!(
            transfers(&words(
                "gh -R synthetic/repo issue create --title t --body-file docs/issue.md"
            )),
            [transfer(
                Client::Gh,
                Operation::Publish,
                "docs/issue.md",
                "github:issue",
                Direction::Outbound
            )]
        );
        assert_eq!(
            transfers(&words("gh pr comment 7 -Fnotes.md")),
            [transfer(
                Client::Gh,
                Operation::Publish,
                "notes.md",
                "github:pr",
                Direction::Outbound
            )]
        );
        assert_eq!(
            transfers(&words("gh gist create --public notes.md setup.md")),
            [
                transfer(
                    Client::Gh,
                    Operation::Publish,
                    "notes.md",
                    "github:gist",
                    Direction::Outbound
                ),
                transfer(
                    Client::Gh,
                    Operation::Publish,
                    "setup.md",
                    "github:gist",
                    Direction::Outbound
                ),
            ]
        );
    }

    #[test]
    fn commands_that_request_no_transfer_read_as_none() {
        assert_eq!(transfers(&words("aws s3 ls s3://synthetic-bucket/")), []);
        assert_eq!(transfers(&words("aws s3 cp help")), []);
        assert_eq!(transfers(&words("aws cp x y")), []);
        assert_eq!(
            transfers(&words("echo aws s3 cp ./d s3://synthetic-bucket/")),
            []
        );
        assert_eq!(transfers(&words("gh issue comment 1 --body text")), []);
        assert_eq!(transfers(&words("gh gist view 1234abcd")), []);
        assert_eq!(transfers(&words("rclone ls synthetic-remote:b")), []);
    }
}
