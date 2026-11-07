//! Reads command text the way a POSIX shell parses it, without running it:
//! which bytes are comments, which lines are here-document bodies, and where
//! each command stage starts and ends. Action evaluation takes its stages from
//! here instead of finding them again with a rougher grammar.
//!
//! Text leaves evaluation only when the reader is sure a shell would not run
//! it. A comment leaves stage parsing because a shell skips it. A body leaves
//! evaluation only when every command it can reach is a known data reader: any
//! other command may run it, because programs that relay standard input to a
//! shell cannot be listed. Once a group opens, or anything else the reader may
//! be misreading, every later body in that text stays: a group's output can go
//! anywhere, no closer says for sure where it ended, and a body whose own
//! substitution does this stays whole. Doubt costs a false positive, not a
//! hidden command. Only an `if`, a loop or a test closed before a body leaves it
//! alone, and only under the closers `close_compound` trusts.
//!
//! A substitution's and a shell script's commands run wherever they stand, inside
//! a word or a quote, so each is read on its own as well as in the stage around
//! it, at any depth. A command that holds another repeats what it holds, so such
//! commands read whole only up to a multiple of the text's length and past that only
//! up to what they hold, which keeps the bytes read on their own in step with the
//! text.
//!
//! This is one reading, a POSIX shell's, and other shells split text elsewhere: a
//! backslash is literal to Windows shells, and only some shells have `$'`, `$[`
//! or arithmetic `((`. So the action view also splits the code this returns.
//!
//! This reads grammar only. It does no expansion and follows no variable or
//! file. `eval` and `trap` run words this may not read whole, so unless those words
//! are literal they leave it in doubt.

use std::ops::Range;

use super::http::{assignment, client_name};

/// How many bodies may hold further shell text; deeper text is not parsed.
const MAX_NESTING: usize = 4;
/// How many open quotes and substitutions a here-document may sit inside. A
/// deeper one is not read, which keeps its text.
const MAX_FRAMES: usize = 64;
/// The longest word classified. Closing a nested substitution returns to the
/// enclosing word, so classifying every length would be quadratic.
const MAX_WORD: usize = 256;
/// The most words of a command read to judge a substitution among them. More
/// stay doubtful, which keeps the body and bounds the work when one command
/// holds many substitutions.
const MAX_ENCLOSING_WORDS: usize = 64;
/// How many times the text's length may go to commands read whole that hold other
/// commands. Past this such a command reads only up to the first it holds: the rest
/// of its words stay in the stage around it, where field rules still read them.
const SPANNING_COMMAND_READS: usize = 2;
/// How many times its length a text's readings may take, before one reads only once.
const READINGS: usize = 4;
pub(super) const SHELLS: [&str; 10] = [
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "ash",
    "fish",
    "pwsh",
    "powershell",
];
/// Programs a body is data to: they print, store or compute over it, or read
/// it as another language's source. Matched with or without a version suffix.
const DATA_READERS: [&str; 72] = [
    // Builtins.
    ":",
    "true",
    "false",
    "read",
    "mapfile",
    "readarray",
    "export",
    "local",
    "declare",
    "typeset",
    "readonly",
    // Text tools.
    "cat",
    "tee",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "sed",
    "awk",
    "gawk",
    "mawk",
    "cut",
    "sort",
    "uniq",
    "wc",
    "tr",
    "nl",
    "diff",
    "jq",
    "yq",
    "patch",
    "base64",
    "xxd",
    "envsubst",
    "less",
    "more",
    "bat",
    "tac",
    "rev",
    "fold",
    "paste",
    "column",
    "od",
    "strings",
    "gzip",
    "md5sum",
    "sha1sum",
    "sha256sum",
    // Other languages.
    "python",
    "pypy",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "tsx",
    "ts-node",
    // Clients that take a document.
    "git",
    "gh",
    "glab",
    "psql",
    "mysql",
    "mariadb",
    "sqlite",
    "duckdb",
    "curl",
    "openssl",
    "gpg",
];
/// Commands that run the command after them. Only without an option: an option
/// may name another program or take the next word as its value.
const WRAPPERS: [&str; 10] = [
    "sudo", "doas", "env", "nohup", "nice", "command", "exec", "npx", "pnpx", "bunx",
];
/// Runners of a project's tools, judged by the command after their `run` or `exec`.
const TOOL_RUNNERS: [&str; 6] = ["uv", "poetry", "pipenv", "pnpm", "npm", "yarn"];
/// Clients whose document verbs take a manifest and whose other verbs may not.
const MANIFEST_CLIENTS: [&str; 2] = ["kubectl", "oc"];

#[derive(Debug, Default)]
pub(super) struct ShellText {
    /// The command without here-document bodies a data reader takes. Comments
    /// stay, so whole-field rules and evidence read what the call recorded.
    pub(super) command: String,
    /// `command` with each comment blanked byte for byte, at the same offsets.
    pub(super) code: String,
    /// The command stages, as ranges of both texts. A stage inside a quote is
    /// part of the quoted word, and may be blank or end in a comment.
    pub(super) stages: Vec<Range<usize>>,
    /// The commands a substitution or a shell's script holds, as ranges of both
    /// texts. Each also lies inside a stage above, so reading one is reading further
    /// into the same text: it finds more and is never part of what the call recorded.
    pub(super) inner_commands: Vec<Range<usize>>,
    /// Offsets of the pipes between stages.
    pub(super) pipes: Vec<usize>,
    /// Bodies written to a file.
    pub(super) authored: String,
    /// Bytes visited, for the caller's work budget.
    pub(super) work: usize,
    /// The reader met something it may be misreading.
    doubted: bool,
}

impl ShellText {
    /// Adds another reading's text as lines of its own.
    fn append(&mut self, inner: ShellText) {
        let base = self.code.len();
        if !inner.command.is_empty() {
            self.command.push_str(&inner.command);
            self.command.push('\n');
            self.code.push_str(&inner.code);
            self.code.push('\n');
        }
        self.stages.extend(
            inner
                .stages
                .into_iter()
                .map(|stage| stage.start + base..stage.end + base),
        );
        self.inner_commands.extend(
            inner
                .inner_commands
                .into_iter()
                .map(|command| command.start + base..command.end + base),
        );
        self.pipes
            .extend(inner.pipes.into_iter().map(|pipe| pipe + base));
        self.authored.push_str(&inner.authored);
        self.work += inner.work;
    }
}

pub(super) fn read(text: &str) -> ShellText {
    // An array-form command is joined with a trailing space, and a terminator
    // must match its whole line. A lone carriage return ends a line to PowerShell.
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    read_at(text.trim_end(), 0, Mode::Commands, false)
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Commands,
    /// The text of a body a shell expands: only its substitutions reach the
    /// output, each as a command of its own.
    Body,
}

/// `doubt`: no body in this text may leave, because the text itself is a body
/// that may run, and what its commands print goes where the outer command prints.
fn read_at(text: &str, nesting: usize, mode: Mode, doubt: bool) -> ShellText {
    if nesting > MAX_NESTING {
        return unplaced(text);
    }
    let stage = Stage::fresh(0, 0);
    let frames = if mode == Mode::Body {
        vec![Frame {
            kind: Kind::Body,
            limit: text.len(),
            outer: stage,
            started: 0,
            words: 0,
            outer_cases: 0,
            output_runs: None,
            split: false,
            command_start: 0,
            first_inner: None,
            holder: None,
        }]
    } else {
        Vec::new()
    };
    let bytes = text.as_bytes();
    Reader {
        text,
        bytes,
        at: 0,
        copied: 0,
        out: ShellText {
            work: text.len(),
            ..ShellText::default()
        },
        nesting,
        frames,
        stage,
        stage_start: 0,
        pending: Vec::new(),
        deferred: Vec::new(),
        quoted: 0,
        layers: 0,
        doubt,
        cases: 0,
        in_test: false,
        compounds: Vec::new(),
        words: Vec::new(),
        last_route: last_route(text),
        spanning: 0,
    }
    .run()
}

/// Text the reader cannot place: it may be a body or a command, and a body's
/// quotes pair with nothing. So every separator splits, quoted or not, and no
/// comment is trusted. At worst a quoted word reads as a command.
fn unplaced(text: &str) -> ShellText {
    let mut out = ShellText {
        command: text.to_owned(),
        code: text.to_owned(),
        work: text.len(),
        doubted: true,
        ..ShellText::default()
    };
    let bytes = text.as_bytes();
    let (mut start, mut at) = (0, 0);
    while at < bytes.len() {
        let width = match bytes[at] {
            b'|' | b'&' if bytes.get(at + 1) == Some(&bytes[at]) => 2,
            b'|' | b'&' | b';' | b'\n' => 1,
            _ => {
                at += 1;
                continue;
            }
        };
        if bytes[at] == b'|' && width == 1 {
            out.pipes.push(at);
        }
        out.stages.push(start..at);
        at += width;
        start = at;
    }
    out.stages.push(start..bytes.len());
    out
}

/// What the current command has said so far, for reading what follows it.
#[derive(Clone, Copy)]
struct Stage {
    /// Where the current logical line starts in the output.
    scope: usize,
    /// Where this command's words start in the reader's word stack.
    first_word: usize,
    word: Option<usize>,
    at_word_start: bool,
    /// The next word is in command position, where reserved words count.
    at_command: bool,
    shell: bool,
    /// The last word is a shell's `-c`.
    after_c: bool,
    /// A word other than an assignment has named the command.
    named: bool,
    /// The command is a Windows shell, where backslash is literal and `#` may
    /// open no comment. Reading a comment as code costs a false positive.
    windows: bool,
    /// The next word is a redirection's target.
    after_redirection: bool,
    /// The command writes through `>(...)`, which is not read here.
    opaque: bool,
    /// The previous command pipes into this one.
    after_pipe: bool,
    /// A here-document opened in this pipeline, at or before this command.
    document: bool,
    /// A command on this line may run a here-document's text.
    may_run: bool,
    /// `time`, `-p` or `--` came first: a keyword to some shells, a program or
    /// its options to others, so the word after it may be an argument.
    timed: bool,
    /// The command names `exec`, whose redirections outlast it.
    exec: bool,
    /// The command is `eval` or `trap`, so its words may run as a script.
    runs_words: bool,
}

impl Stage {
    fn fresh(scope: usize, first_word: usize) -> Self {
        Self {
            scope,
            first_word,
            word: None,
            at_word_start: true,
            at_command: true,
            shell: false,
            after_c: false,
            named: false,
            windows: false,
            after_redirection: false,
            opaque: false,
            after_pipe: false,
            document: false,
            may_run: false,
            timed: false,
            exec: false,
            runs_words: false,
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    DoubleQuote,
    /// `$(...)` or `<(...)`: `)` closes it outside nested parentheses and `case`.
    Substitution {
        parens: usize,
    },
    Backtick,
    /// The quoted script of `sh -c`. `escaped`: inside its `\"...\"`.
    Script {
        quote: u8,
        escaped: bool,
    },
    /// `$((...))`, `((...))`, `$[...]` or `${...}`: `<<` and `#` are no operators.
    Expansion {
        open: u8,
        close: u8,
        depth: usize,
    },
    /// The text of an expanded body, where only substitutions are commands.
    Body,
}

impl Kind {
    /// Separators inside this are part of a quoted word.
    fn quotes(self) -> bool {
        matches!(self, Self::DoubleQuote | Self::Script { .. })
    }

    /// This takes off a level of escapes before the text inside is parsed.
    fn rewrites(self) -> bool {
        matches!(self, Self::Backtick | Self::Script { quote: b'"', .. })
    }

    /// The text inside this is commands, each read on its own.
    fn holds_commands(self) -> bool {
        matches!(
            self,
            Self::Substitution { .. } | Self::Backtick | Self::Script { .. }
        )
    }
}

#[derive(Clone, Copy)]
struct Frame {
    kind: Kind,
    /// Where this frame must end: the closer of the nearest script or backtick.
    limit: usize,
    outer: Stage,
    /// Where the frame's text starts.
    started: usize,
    /// The word stack's height outside the frame.
    words: usize,
    /// Open `case` commands outside the frame.
    outer_cases: usize,
    /// Once read: whether what the frame prints may run.
    output_runs: Option<bool>,
    /// A stage ended inside the frame, so the last one ends with the frame.
    split: bool,
    /// Where the frame's current command starts in the output.
    command_start: usize,
    /// Where the first command this one holds starts, once it holds one.
    first_inner: Option<usize>,
    /// The nearest frame around this one that holds commands, whatever lies between.
    holder: Option<usize>,
}

struct HereDocument {
    word: Vec<u8>,
    /// The word when a `$` before a quote is an ANSI-C or locale quote.
    unprefixed: Vec<u8>,
    strip_tabs: bool,
    quoted: bool,
    depth: usize,
}

impl HereDocument {
    fn stripped<'a>(&self, line: &'a [u8]) -> &'a [u8] {
        if self.strip_tabs {
            let tabs = line.iter().take_while(|byte| **byte == b'\t').count();
            &line[tabs..]
        } else {
            line
        }
    }

    fn ends(&self, line: &[u8]) -> bool {
        let line = self.stripped(line);
        line == self.word || line == self.unprefixed
    }

    /// The bytes that end the body when `line` ends it inside `$(...)`, where
    /// bash also accepts the word followed by the closing parenthesis.
    fn ends_substitution(&self, line: &[u8]) -> Option<usize> {
        let stripped = self.stripped(line);
        [&self.word, &self.unprefixed]
            .into_iter()
            .find(|word| stripped.starts_with(word) && stripped[word.len()..].contains(&b')'))
            .map(|word| line.len() - stripped.len() + word.len())
    }

    /// Whether a continued line of an unquoted body could join into the word.
    fn continues_into(&self, line: &[u8]) -> bool {
        self.stripped(line)
            .strip_suffix(b"\\")
            .is_some_and(|head| self.word.starts_with(head) || self.unprefixed.starts_with(head))
    }
}

struct Reader<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
    /// Start of the text not yet copied to the output.
    copied: usize,
    out: ShellText,
    nesting: usize,
    frames: Vec<Frame>,
    stage: Stage,
    /// Where the current output stage starts.
    stage_start: usize,
    pending: Vec<HereDocument>,
    /// Commands read inside a quote. They follow the quote's logical line,
    /// because they are no part of the quoted word.
    deferred: Vec<ShellText>,
    /// Open frames that quote their separators.
    quoted: usize,
    /// Open frames that rewrite escapes.
    layers: usize,
    /// No body may leave. See [`read_at`]; also set once the text holds a group
    /// or anything else this reader may be misreading.
    doubt: bool,
    /// Open `case` commands in this substitution, where `)` ends a pattern.
    cases: usize,
    /// Inside `[[ ... ]]`, where bash reads `#` and `<<` as part of a pattern.
    in_test: bool,
    /// The `if` and loop commands still open: each one's closer, and how many
    /// frames were open around it.
    compounds: Vec<(&'static str, usize)>,
    /// The words of the commands being read, one stage per open frame.
    words: Vec<String>,
    /// The last place in the text that output can leave through to what may run it.
    last_route: Option<usize>,
    /// Bytes of commands holding others that were read whole on their own.
    spanning: usize,
}

impl Reader<'_> {
    fn run(mut self) -> ShellText {
        while self.at < self.bytes.len() {
            if self.frames.last().is_some_and(|f| self.at >= f.limit) {
                self.close_at_limit();
                continue;
            }
            match self.frames.last().map(|frame| frame.kind) {
                Some(Kind::DoubleQuote) => self.double_quoted(),
                Some(Kind::Expansion { .. }) => self.expansion(),
                Some(Kind::Body) => self.body_text(),
                _ => self.commands(),
            }
        }
        // A quote still open here was no quote to the shell that took this text:
        // a Windows path's `\"`, or a word this reader misread.
        if let Some(frame) = self.frames.iter().find(|frame| frame.kind.quotes()) {
            self.leave_unplaced(frame.started.max(self.copied));
        }
        self.end_body_substitution();
        self.copy_to(self.bytes.len());
        let end = self.out.code.len();
        self.out.stages.push(self.stage_start.min(end)..end);
        self.flush_deferred();
        let keep = self.out.command.trim_end().len();
        self.out.command.truncate(keep);
        self.out.code.truncate(keep);
        for stage in self
            .out
            .stages
            .iter_mut()
            .chain(&mut self.out.inner_commands)
        {
            stage.end = stage.end.min(keep);
            stage.start = stage.start.min(stage.end);
        }
        self.out.doubted = self.in_doubt();
        self.out
    }

    /// No body may leave: the reader is unsure, or a test or compound is open.
    fn in_doubt(&self) -> bool {
        self.doubt || self.in_test || !self.compounds.is_empty()
    }

    fn limit(&self) -> usize {
        self.frames
            .last()
            .map_or(self.bytes.len(), |frame| frame.limit)
    }

    fn next_byte(&self) -> Option<u8> {
        self.bytes.get(self.at + 1).copied()
    }

    /// Offset of `at` in the output, once the text before it is copied.
    fn out_at(&self, at: usize) -> usize {
        self.out.code.len() + at - self.copied
    }

    fn copy_to(&mut self, end: usize) {
        let end = end.min(self.bytes.len());
        if end > self.copied {
            self.out.command.push_str(&self.text[self.copied..end]);
            self.out.code.push_str(&self.text[self.copied..end]);
            self.copied = end;
        }
    }

    fn find(&self, needle: u8, from: usize, to: usize) -> Option<usize> {
        self.bytes
            .get(from..to)?
            .iter()
            .position(|byte| *byte == needle)
            .map(|offset| from + offset)
    }

    /// The next `needle` a backslash does not escape.
    fn find_unescaped(&self, needle: u8, from: usize, to: usize) -> Option<usize> {
        let mut at = from;
        while at < to {
            match self.bytes[at] {
                b'\\' => at += 2,
                byte if byte == needle => return Some(at),
                _ => at += 1,
            }
        }
        None
    }

    fn push(&mut self, kind: Kind, limit: usize, new_stage: bool) {
        let command_start = self.out_at(self.at);
        let holder = self.frames.last().and_then(|frame| {
            if frame.kind.holds_commands() {
                Some(self.frames.len() - 1)
            } else {
                frame.holder
            }
        });
        if kind.holds_commands()
            && let Some(holder) = holder
        {
            self.frames[holder].first_inner.get_or_insert(command_start);
        }
        self.frames.push(Frame {
            kind,
            limit,
            outer: self.stage,
            started: self.at,
            words: self.words.len(),
            outer_cases: self.cases,
            output_runs: None,
            split: false,
            command_start,
            first_inner: None,
            holder,
        });
        self.quoted += usize::from(kind.quotes());
        self.layers += usize::from(kind.rewrites());
        if new_stage {
            self.stage = Stage::fresh(self.out_at(self.at), self.words.len());
            self.cases = 0;
        }
    }

    fn pop(&mut self) -> Option<Frame> {
        let frame = self.frames.pop()?;
        // A here-document opened in the closed frame has no body left to read:
        // the lines after this point are commands.
        let depth = self.frames.len();
        while self.pending.last().is_some_and(|doc| doc.depth > depth) {
            self.pending.pop();
        }
        self.quoted -= usize::from(frame.kind.quotes());
        self.layers -= usize::from(frame.kind.rewrites());
        self.words.truncate(frame.words);
        self.cases = frame.outer_cases;
        self.stage = frame.outer;
        Some(frame)
    }

    fn close_at_limit(&mut self) {
        self.end_frame_command(1);
        let Some(frame) = self.pop() else {
            return;
        };
        if matches!(frame.kind, Kind::Script { .. } | Kind::Backtick) {
            self.at = self.at.max(frame.limit + 1).min(self.bytes.len());
        } else {
            // Still open at its closer's byte: a quote nests inside a
            // substitution in a double-quoted script, so that was no closer.
            self.leave_unplaced(self.at);
        }
    }

    /// The reader can no longer tell body from command, or quote from text.
    fn leave_unplaced(&mut self, from: usize) {
        let from = from.min(self.bytes.len());
        self.copy_to(from);
        // What was read past this point is read again below, at other offsets.
        let copied = self.out.code.len();
        self.out.stages.retain(|stage| stage.end <= copied);
        self.out.inner_commands.retain(|stage| stage.end <= copied);
        self.out.pipes.retain(|pipe| *pipe < copied);
        self.frames.clear();
        self.pending.clear();
        self.words.clear();
        self.quoted = 0;
        self.layers = 0;
        let end = self.out.code.len();
        self.out.stages.push(self.stage_start.min(end)..end);
        if !self.out.command.is_empty() && !self.out.command.ends_with('\n') {
            self.out.command.push('\n');
            self.out.code.push('\n');
        }
        let rest = self.text.get(from..).unwrap_or_default();
        self.read_both(unplaced(rest), rest);
        self.at = self.bytes.len();
        self.copied = self.bytes.len();
        self.stage = Stage::fresh(self.stage_start, 0);
    }

    fn begin_word(&mut self) {
        if self.stage.word.is_none() {
            self.stage.word = Some(self.at);
        }
        self.stage.at_word_start = false;
    }

    fn end_word(&mut self, end: usize) {
        let Some(start) = self.stage.word.take() else {
            return;
        };
        let after_c = std::mem::take(&mut self.stage.after_c);
        let at_command = std::mem::take(&mut self.stage.at_command);
        if std::mem::take(&mut self.stage.after_redirection) {
            return;
        }
        if end - start > MAX_WORD {
            // This may be any word at all, even a continued `{`. An empty word
            // names no program either, so its command stays doubtful too.
            self.doubt = true;
            self.stage.named = true;
            self.words.push(String::new());
            return;
        }
        self.out.work += end - start;
        let text = self.text;
        let word = text[start..end].replace("\\\n", "");
        match word.as_str() {
            "]]" => self.in_test = false,
            // These open a group wherever they stand, or under a listed keyword
            // or none: `for x do`, `function f {`, `repeat 1; do`.
            "{" | "function" | "repeat" => self.doubt = true,
            // Only a `do` in its place belongs to a loop this reader saw open.
            "do" if !at_command || self.compounds.last().is_none_or(|open| open.0 != "done") => {
                self.doubt = true;
            }
            _ => {}
        }
        let prefix = at_command && self.command_word(&word);
        // These start a command wherever they stand: `for x do`, `function f {`.
        self.stage.at_command |= matches!(word.as_str(), "{" | "do");
        let bare = word.replace(['\'', '"', '\\'], "");
        self.stage.exec |= bare == "exec";
        // These run the words after them. Only in a program's place are they themselves,
        // and only a literal script is one this reader reads as it will run.
        let program = !self.stage.named
            || matches!(
                self.words.last().map(String::as_str),
                Some("command" | "builtin")
            );
        let scripted = program && matches!(bare.as_str(), "eval" | "trap");
        self.doubt |= self.stage.runs_words && !literal_word(&word, after_c);
        self.stage.runs_words |= scripted;
        // `--` ends a shell's options, and its script still comes next.
        self.stage.after_c = scripted
            || (after_c && bare == "--")
            || bare
                .strip_prefix('-')
                .is_some_and(|flags| !flags.starts_with('-') && flags.contains('c'));
        let name = client_name(&bare);
        self.stage.shell |= scripted
            || SHELLS.contains(&name.as_str())
            || matches!(bare.as_str(), "$SHELL" | "${SHELL}");
        if !prefix && !self.stage.named && !assignment(&bare) {
            self.stage.named = true;
            self.stage.windows = matches!(name.as_str(), "cmd" | "powershell" | "pwsh");
            // A POSIX shell may be what reads this, where such a name proves nothing.
            self.doubt |= self.stage.windows;
        }
        if !prefix {
            self.words.push(bare);
        }
    }

    /// Notes what a word in command position opens, and returns whether it only
    /// prefixes the command that follows it. `esac` after a pipe is a pattern.
    fn command_word(&mut self, word: &str) -> bool {
        match word {
            "if" => self.open_compound("fi"),
            "while" | "until" | "for" | "select" => self.open_compound("done"),
            "fi" | "done" => self.close_compound(word),
            "coproc" => self.doubt = true,
            "case" => {
                self.doubt = true;
                self.cases += 1;
            }
            "esac" if !self.stage.after_pipe => self.cases = self.cases.saturating_sub(1),
            "[[" => self.in_test = true,
            _ => {}
        }
        let prefix = reserved_word(word) || matches!(word, "{" | "time" | "coproc");
        // `time -p` and `time --` still have a command to come.
        let timing = matches!(word, "-p" | "--");
        self.stage.at_command = prefix || timing;
        self.stage.timed |= timing || word == "time";
        prefix
    }

    /// A pipe hands what it carries to the whole compound, which no closer ends.
    fn open_compound(&mut self, closer: &'static str) {
        self.doubt |= self.stage.after_pipe || self.stage.document;
        self.compounds.push((closer, self.frames.len()));
    }

    /// A closer counts only where every shell reads it as one: it matches the
    /// innermost compound, at that compound's frame, and no `time` comes before
    /// it. Inside `[[` its spelling is an operand. Anything else leaves the reader
    /// unsure which compound is still open.
    fn close_compound(&mut self, closer: &str) {
        let frames = self.frames.len();
        let closes = self
            .compounds
            .last()
            .is_some_and(|open| open.0 == closer && open.1 == frames);
        if closes && !self.stage.timed && !self.in_test {
            self.compounds.pop();
        } else {
            self.doubt = true;
        }
    }

    /// A blank ends the word, not the command.
    fn boundary(&mut self) {
        self.end_word(self.at);
        self.stage.at_word_start = true;
        self.at += 1;
    }

    /// `>`, `>>`, `>&`, `<&`, `<>` or `>|`: the word after it is no argument.
    fn redirection(&mut self) {
        self.boundary();
        // What the rest of the text prints goes where `exec` sends it.
        self.doubt |= self.stage.exec;
        while let Some(byte @ (b'>' | b'&' | b'|')) = self.bytes.get(self.at).copied() {
            if byte == b'>' && self.next_byte() == Some(b'(') {
                break;
            }
            self.at += 1;
        }
        self.stage.after_redirection = true;
    }

    /// Judges a finished command by its own words. Only a command at or after
    /// the operator can receive the body, directly or through a pipe.
    fn finish_stage(&mut self, width: usize) {
        let words = &self.words[self.stage.first_word..];
        if self.stage.document && (self.stage.opaque || !stage_reads_data(words)) {
            self.stage.may_run = true;
        }
        self.end_frame_command(width);
        self.words.truncate(self.stage.first_word);
    }

    /// Records the command that just ended inside a substitution or a script, unless
    /// it is a body's own data reader, which names no file. A command holding another
    /// repeats what it holds, so it reads whole only while the bound allows, then only
    /// up to the first it holds. The next one starts `width` bytes on.
    fn end_frame_command(&mut self, width: usize) {
        let end = self.out_at(self.at);
        let words = self.words.get(self.stage.first_word..).unwrap_or_default();
        let only_a_reader = self.stage.document && words.len() <= 1 && stage_reads_data(words);
        let Some(frame) = self
            .frames
            .last_mut()
            .filter(|frame| frame.kind.holds_commands())
        else {
            return;
        };
        let start = std::mem::replace(&mut frame.command_start, end + width);
        let first_inner = frame.first_inner.take();
        if only_a_reader || start >= end {
            return;
        }
        let length = end - start;
        let end = match first_inner {
            Some(inner) if self.spanning + length > SPANNING_COMMAND_READS * self.bytes.len() => {
                inner
            }
            Some(_) => {
                self.spanning += length;
                end
            }
            None => end,
        };
        if start < end {
            self.out.inner_commands.push(start..end);
        }
    }

    /// Ends the output stage at `at`. The next one starts `width` bytes on.
    fn split_stage(&mut self, width: usize) {
        if self.quoted == 0 {
            let end = self.out_at(self.at);
            self.out.stages.push(self.stage_start..end);
            self.stage_start = end + width;
            if let Some(frame) = self.frames.last_mut() {
                frame.split = true;
            }
        }
    }

    /// A pipe keeps the pipeline's here-document in reach of the next command.
    /// Commands are read only outside a quote or in a substitution within one, so
    /// this is always a pipe.
    fn pipe(&mut self) {
        let width = if self.next_byte() == Some(b'&') { 2 } else { 1 };
        self.end_word(self.at);
        self.finish_stage(width);
        self.out.pipes.push(self.out_at(self.at));
        self.split_stage(width);
        self.at += width;
        self.stage = Stage {
            document: self.stage.document,
            may_run: self.stage.may_run,
            after_pipe: true,
            ..Stage::fresh(self.stage.scope, self.stage.first_word)
        };
    }

    /// `;`, `&`, `&&`, `||` or a parenthesis: the next command starts over.
    fn end_pipeline(&mut self, width: usize) {
        self.end_word(self.at);
        self.finish_stage(width);
        self.split_stage(width);
        self.at += width;
        self.stage = Stage {
            may_run: self.stage.may_run,
            ..Stage::fresh(self.stage.scope, self.stage.first_word)
        };
    }

    /// The text of a double-quoted `sh -c` script that is inside its own `\"`.
    fn literal(&self) -> bool {
        matches!(
            self.frames.last().map(|frame| frame.kind),
            Some(Kind::Script { escaped: true, .. })
        )
    }

    fn opens_comment(&self) -> bool {
        // A backtick's nested `\`` can close a comment the reader cannot see.
        !self.stage.windows
            && !self.in_test
            && !self.literal()
            && !matches!(
                self.frames.last().map(|frame| frame.kind),
                Some(Kind::Backtick)
            )
    }

    fn at_reserved_word(&self) -> bool {
        self.stage.word.is_some_and(|start| {
            let word = &self.text[start..self.at];
            reserved_word(word) || matches!(word, "for" | "time" | "coproc")
        })
    }

    fn commands(&mut self) {
        let next = self.next_byte();
        match self.bytes[self.at] {
            b'\\' => self.backslash(next),
            b'\'' => self.single_quote(),
            b'"' => self.double_quote(),
            b'$' => {
                self.begin_word();
                self.dollar(next, true);
            }
            b'`' => {
                self.begin_word();
                self.backtick();
            }
            b'#' if self.stage.at_word_start && self.opens_comment() => self.comment(),
            // A shell may read this as a comment, and `<<` in it as nothing.
            b'#' if self.stage.at_word_start => {
                self.doubt = true;
                self.begin_word();
                self.at += 1;
            }
            b'<' if next == Some(b'<') && !self.literal() && !self.in_test => {
                self.here_document_operator();
            }
            b'<' | b'>' if next == Some(b'(') => {
                self.stage.opaque |= self.bytes[self.at] == b'>';
                self.end_word(self.at);
                self.begin_word();
                self.at += 2;
                self.open_substitution();
            }
            b'(' if next == Some(b'(') && (self.stage.at_word_start || self.at_reserved_word()) => {
                self.doubt = true;
                self.end_word(self.at);
                self.begin_word();
                self.at += 2;
                self.push(
                    Kind::Expansion {
                        open: b'(',
                        close: b')',
                        depth: 2,
                    },
                    self.limit(),
                    false,
                );
            }
            b'(' => {
                self.doubt = true;
                let in_case = self.cases > 0;
                if !in_case
                    && let Some(Frame {
                        kind: Kind::Substitution { parens },
                        ..
                    }) = self.frames.last_mut()
                {
                    *parens += 1;
                }
                self.end_pipeline(1);
                // After a case's `(`, `esac` is a pattern.
                self.stage.after_pipe = in_case;
            }
            b')' => self.close_paren(),
            b'\n' => self.newline(),
            b'|' if next == Some(b'|') => self.end_pipeline(2),
            b'|' => self.pipe(),
            b'&' if next == Some(b'>') => {
                self.end_word(self.at);
                self.at += 1;
                self.redirection();
            }
            b';' | b'&' => self.end_pipeline(1),
            b'<' | b'>' => self.redirection(),
            b' ' | b'\t' => self.boundary(),
            _ => {
                self.begin_word();
                self.at += 1;
            }
        }
    }

    fn backslash(&mut self, next: Option<u8>) {
        // A continued line joins words: `a\<newline>#b` is one word.
        if next == Some(b'\n') {
            self.at += 2;
            return;
        }
        self.begin_word();
        if self.stage.windows {
            self.at += 1;
            return;
        }
        if next == Some(b'"')
            && let Some(Frame {
                kind:
                    Kind::Script {
                        quote: b'"',
                        escaped,
                    },
                ..
            }) = self.frames.last_mut()
        {
            *escaped = !*escaped;
        }
        self.at += 2;
    }

    fn opens_script(&self) -> bool {
        self.stage.shell && self.stage.after_c && self.stage.word.is_none()
    }

    fn open_script(&mut self, quote: u8, closer: Option<usize>) {
        let limit = closer.unwrap_or(self.limit());
        self.begin_word();
        self.at += 1;
        self.push(
            Kind::Script {
                quote,
                escaped: false,
            },
            limit,
            true,
        );
    }

    fn single_quote(&mut self) {
        let closer = self.find(b'\'', self.at + 1, self.limit());
        if self.opens_script() {
            self.open_script(b'\'', closer);
            return;
        }
        self.begin_word();
        match closer {
            Some(closer) => self.at = closer + 1,
            // As with an open `"`: this was no quote to the shell that took it.
            None => self.leave_unplaced(self.at + 1),
        }
    }

    fn double_quote(&mut self) {
        if self.opens_script() {
            let closer = if self.stage.windows {
                self.find(b'"', self.at + 1, self.limit())
            } else {
                self.find_unescaped(b'"', self.at + 1, self.limit())
            };
            self.open_script(b'"', closer);
            return;
        }
        self.begin_word();
        self.at += 1;
        self.push(Kind::DoubleQuote, self.limit(), false);
    }

    fn double_quoted(&mut self) {
        let next = self.next_byte();
        match self.bytes[self.at] {
            b'\\' if self.stage.windows => self.at += 1,
            b'\\' => self.at += 2,
            b'"' => {
                self.at += 1;
                self.pop();
            }
            b'$' => self.dollar(next, false),
            b'`' => self.backtick(),
            _ => self.at += 1,
        }
    }

    fn expansion(&mut self) {
        let next = self.next_byte();
        let byte = self.bytes[self.at];
        match byte {
            b'\\' => self.at += 2,
            b'\'' => {
                self.at = self
                    .find(b'\'', self.at + 1, self.limit())
                    .map_or(self.limit(), |closer| closer + 1);
            }
            b'"' => {
                self.at += 1;
                self.push(Kind::DoubleQuote, self.limit(), false);
            }
            b'$' => {
                let quoted = matches!(
                    self.frames.iter().rev().nth(1).map(|frame| frame.kind),
                    Some(Kind::DoubleQuote)
                );
                self.dollar(next, !quoted);
            }
            b'`' => self.backtick(),
            _ => {
                self.at += 1;
                let after = self.bytes.get(self.at).copied();
                let mut closed = false;
                let mut no_arithmetic = false;
                if let Some(Frame {
                    kind: Kind::Expansion { open, close, depth },
                    ..
                }) = self.frames.last_mut()
                {
                    if byte == *open {
                        *depth += 1;
                    } else if byte == *close {
                        *depth -= 1;
                        closed = *depth == 0;
                        no_arithmetic = *close == b')' && *depth == 1 && after != Some(b')');
                    }
                }
                if closed {
                    self.pop();
                } else if no_arithmetic {
                    self.reopen_as_commands();
                }
            }
        }
    }

    /// `((` that does not end in `))` is a subshell in a subshell, and `$((` a
    /// substitution that starts with a subshell.
    fn reopen_as_commands(&mut self) {
        self.doubt = true;
        match self.frames.last_mut() {
            Some(frame) if frame.started >= 3 && self.bytes[frame.started - 3] == b'$' => {
                frame.kind = Kind::Substitution { parens: 0 };
            }
            _ => {
                self.pop();
            }
        }
    }

    /// The text between a body's substitutions, which nothing runs.
    fn body_text(&mut self) {
        self.end_body_substitution();
        match self.bytes[self.at] {
            b'\\' => self.at += 2,
            b'$' if self.next_byte() == Some(b'(') => {
                self.at += 2;
                self.copied = self.at;
                self.open_substitution();
                return;
            }
            b'`' => {
                self.at += 1;
                self.copied = self.at;
                let closer = self.find_unescaped(b'`', self.at, self.limit());
                self.push(Kind::Backtick, closer.unwrap_or(self.limit()), true);
                return;
            }
            _ => self.at += 1,
        }
        self.copied = self.at;
    }

    /// A substitution in a body just closed: its text is a command, without its
    /// one-byte closer. Text with no closer runs to the end of the body.
    fn end_body_substitution(&mut self) {
        if matches!(self.frames.last().map(|frame| frame.kind), Some(Kind::Body))
            && self.copied < self.at
        {
            self.copy_to(self.at - 1);
            let end = self.out.code.len();
            self.out.stages.push(self.stage_start.min(end)..end);
            self.out.command.push('\n');
            self.out.code.push('\n');
            self.copied = self.at;
            self.stage_start = self.out.code.len();
        }
    }

    fn dollar(&mut self, next: Option<u8>, ansi_quotes: bool) {
        let expansion = |open, close, depth| Kind::Expansion { open, close, depth };
        match next {
            Some(b'(') if self.bytes.get(self.at + 2) == Some(&b'(') => {
                self.at += 3;
                self.push(expansion(b'(', b')', 2), self.limit(), false);
            }
            Some(b'(') => {
                self.at += 2;
                self.open_substitution();
            }
            // `${` closes at the first `}`: a `{` inside it opens nothing.
            Some(b'{') => {
                self.at += 2;
                self.push(expansion(0, b'}', 1), self.limit(), false);
            }
            Some(b'[') => {
                self.at += 2;
                self.push(expansion(b'[', b']', 1), self.limit(), false);
            }
            Some(b'\'') if ansi_quotes => {
                let closer = self.find_unescaped(b'\'', self.at + 2, self.limit());
                // Only some shells have `$'`, so a quote may pair differently.
                self.doubt |= closer != self.find(b'\'', self.at + 2, self.limit());
                self.at = closer.map_or(self.limit(), |closer| closer + 1);
            }
            _ => self.at += 1,
        }
    }

    fn open_substitution(&mut self) {
        self.push(Kind::Substitution { parens: 0 }, self.limit(), true);
    }

    fn backtick(&mut self) {
        let closer = self.find_unescaped(b'`', self.at + 1, self.limit());
        let limit = closer.unwrap_or(self.limit());
        self.at += 1;
        self.push(Kind::Backtick, limit, true);
    }

    fn close_paren(&mut self) {
        self.end_word(self.at);
        // `)` ends a `case` pattern and closes nothing.
        if self.cases > 0 {
            self.end_pipeline(1);
            return;
        }
        match self.frames.last_mut() {
            Some(Frame {
                kind: Kind::Substitution { parens: 0 },
                ..
            }) => {
                self.end_frame_command(1);
                if self.pop().is_some_and(|frame| frame.split) {
                    self.split_stage(1);
                }
                self.at += 1;
                return;
            }
            Some(Frame {
                kind: Kind::Substitution { parens },
                ..
            }) => *parens -= 1,
            _ => {}
        }
        self.end_pipeline(1);
    }

    fn comment(&mut self) {
        let limit = self.limit();
        let end = self.find(b'\n', self.at, limit).unwrap_or(limit);
        self.copy_to(self.at);
        self.out.command.push_str(&self.text[self.at..end]);
        self.out.code.push_str(&" ".repeat(end - self.at));
        self.at = end;
        self.copied = end;
    }

    fn here_document_operator(&mut self) {
        self.end_word(self.at);
        if self.bytes.get(self.at + 2) == Some(&b'<') {
            self.at += 3;
            self.stage.at_word_start = true;
            self.stage.after_redirection = true;
            return;
        }
        // A compound prints this body wherever it sends its output, and a closer
        // on the same line does not change that.
        self.doubt |= !self.compounds.is_empty();
        self.stage.document = true;
        let mut cursor = self.at + 2;
        let strip_tabs = self.bytes.get(cursor) == Some(&b'-');
        cursor += usize::from(strip_tabs);
        while matches!(self.bytes.get(cursor), Some(b' ' | b'\t')) {
            cursor += 1;
        }
        let delimiter = self.delimiter(&mut cursor);
        let cursor = cursor.min(self.bytes.len());
        self.stage.at_word_start = false;
        match delimiter {
            Some((word, unprefixed, quoted))
                if !word.is_empty() && self.frames.len() < MAX_FRAMES =>
            {
                self.at = cursor;
                self.pending.push(HereDocument {
                    word,
                    unprefixed,
                    strip_tabs,
                    quoted,
                    depth: self.frames.len(),
                });
            }
            _ => self.leave_unplaced(cursor),
        }
    }

    /// The delimiter word, without its quotes, and whether any part was quoted.
    /// `None` when a shell computes a word the reader does not: an expansion
    /// that may hold blanks, escapes inside `$'...'`, or an escape an outer layer
    /// rewrites first.
    fn delimiter(&self, cursor: &mut usize) -> Option<(Vec<u8>, Vec<u8>, bool)> {
        let limit = self.limit();
        let script_quote = matches!(
            self.frames.last().map(|frame| frame.kind),
            Some(Kind::Script { quote: b'"', .. })
        );
        let mut word = Vec::new();
        let mut unprefixed = Vec::new();
        let mut quoted = false;
        // Inside a double-quoted script's `\"`, whose end this reader cannot
        // place when a separator comes first.
        let mut in_escaped_quote = false;
        while *cursor < limit {
            let byte = self.bytes[*cursor];
            let next = self.bytes.get(*cursor + 1).copied();
            match byte {
                b'(' | b'`' => return None,
                b'$' if self.layers > 0 || matches!(next, Some(b'{' | b'[')) => return None,
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b')' | b'<' | b'>' => {
                    if in_escaped_quote {
                        return None;
                    }
                    break;
                }
                // A continued line quotes nothing and is not part of the word.
                b'\\' if next == Some(b'\n') => *cursor += 2,
                b'\\' if self.layers > 0 && !(script_quote && next == Some(b'"')) => return None,
                b'\\' => {
                    quoted = true;
                    // `\"` quotes the word of a double-quoted script.
                    in_escaped_quote ^= script_quote && next == Some(b'"');
                    if *cursor + 1 < limit
                        && !(script_quote && next == Some(b'"'))
                        && let Some(next) = next
                    {
                        word.push(next);
                        unprefixed.push(next);
                    }
                    *cursor += 2;
                }
                b'\'' | b'"' => {
                    quoted = true;
                    let ansi = byte == b'\'' && word.last() == Some(&b'$');
                    let closer = if byte == b'"' {
                        self.find_unescaped(b'"', *cursor + 1, limit)
                    } else {
                        self.find(b'\'', *cursor + 1, limit)
                    };
                    let end = closer.unwrap_or(limit);
                    let part = self.text.get(*cursor + 1..end).unwrap_or_default();
                    if (ansi && part.contains('\\')) || (self.layers > 0 && part.contains('$')) {
                        return None;
                    }
                    let part = if byte == b'"' {
                        unescape(part)
                    } else {
                        part.to_owned()
                    };
                    word.extend_from_slice(part.as_bytes());
                    unprefixed.extend_from_slice(part.as_bytes());
                    *cursor = (end + 1).min(limit);
                }
                _ => {
                    word.push(byte);
                    if !(byte == b'$' && matches!(next, Some(b'\'' | b'"'))) {
                        unprefixed.push(byte);
                    }
                    *cursor += 1;
                }
            }
        }
        Some((word, unprefixed, quoted))
    }

    fn newline(&mut self) {
        self.end_word(self.at);
        // A pipe at the end of the line continues past the body, to a command
        // not reached yet.
        let continues = self.stage.after_pipe && self.words.len() == self.stage.first_word;
        self.finish_stage(1);
        self.split_stage(1);
        self.at += 1;
        let depth = self.frames.len();
        let first = self.pending.partition_point(|doc| doc.depth < depth);
        if first < self.pending.len() {
            let documents = self.pending.split_off(first);
            self.copy_to(self.at);
            let scope = &self.out.code[self.stage.scope..];
            let writes = (scope.contains("cat") && scope.contains('>')) || scope.contains("tee ");
            self.out.work += scope.len();
            let commands =
                self.in_doubt() || self.stage.may_run || continues || self.enclosing_output_runs();
            for document in &documents {
                if !self.body(document, commands, writes) {
                    break;
                }
            }
        }
        self.stage = Stage::fresh(self.out_at(self.at), self.stage.first_word);
        if self.frames.is_empty() {
            self.copy_to(self.at);
            self.flush_deferred();
            self.stage.scope = self.out_at(self.at);
        }
    }

    /// Whether a frame around the current text hands what it prints to
    /// something that may run it.
    fn enclosing_output_runs(&mut self) -> bool {
        for index in 0..self.frames.len() {
            let frame = self.frames[index];
            let runs = frame
                .output_runs
                .unwrap_or_else(|| self.output_runs(index, frame));
            self.frames[index].output_runs = Some(runs);
            if runs {
                return true;
            }
        }
        false
    }

    /// The commands after a substitution are not known yet, so `echo` and
    /// `printf`, whose output a pipe may carry, are no data readers.
    fn output_runs(&self, index: usize, frame: Frame) -> bool {
        match frame.kind {
            // A script's output follows its own command, whose route comes later.
            Kind::Script { quote, .. } => {
                let from = if quote == b'\'' {
                    frame.limit + 1
                } else {
                    self.at
                };
                return self.last_route.is_some_and(|route| route >= from);
            }
            Kind::Substitution { .. } | Kind::Backtick => {}
            _ => return false,
        }
        match index.checked_sub(1).map(|parent| self.frames[parent].kind) {
            // Its output is one line of a body, already found to be data.
            Some(Kind::Body) => return false,
            // Its output becomes script text.
            Some(Kind::Script { quote: b'"', .. }) => return true,
            _ => {}
        }
        // What reads a here-string or a process substitution can forward it.
        let process = matches!(frame.kind, Kind::Substitution { .. })
            && frame
                .started
                .checked_sub(2)
                .and_then(|at| self.bytes.get(at))
                != Some(&b'$');
        if process || frame.outer.after_redirection {
            return true;
        }
        // A frame reopened as commands may have ended its stage's words.
        let words = self
            .words
            .get(frame.outer.first_word..frame.words)
            .unwrap_or_default();
        if words.len() > MAX_ENCLOSING_WORDS {
            return true;
        }
        if words.iter().all(|word| assignment(word)) {
            // With no command yet, the word it sits in is one more assignment
            // or names the command.
            return match frame.outer.word {
                Some(start) if frame.started - start > MAX_WORD => true,
                Some(start) => !assignment(&self.text[start..frame.started]),
                None => true,
            };
        }
        !command_reads_data(words)
    }

    /// Reads one body. False when it has no terminator.
    fn body(&mut self, document: &HereDocument, commands: bool, writes: bool) -> bool {
        let limit = self.limit();
        let start = self.at;
        let in_substitution = matches!(
            self.frames.last().map(|frame| frame.kind),
            Some(Kind::Substitution { .. })
        );
        let mut line = start;
        let mut found = None;
        let mut bash_only = false;
        while line < limit {
            let end = self.find(b'\n', line, limit).unwrap_or(limit);
            let text = &self.bytes[line..end];
            if document.ends(text) {
                found = Some((line, (end + 1).min(limit)));
                break;
            }
            if in_substitution && let Some(length) = document.ends_substitution(text) {
                found = Some((line, line + length));
                bash_only = true;
                break;
            }
            if !document.quoted && document.continues_into(text) {
                break;
            }
            line = end + 1;
        }
        self.out.work += line.min(limit) - start;
        let Some((end, after)) = found else {
            self.leave_unplaced(start);
            return false;
        };
        let text = self.text;
        let body = &text[start..end];
        // An outer layer rewrites these before the inner shell reads the body,
        // so neither its terminator nor its substitutions are the raw text's.
        let rewritten = self.layers > 0 && body.contains(['\\', '$', '`']);
        // Only bash ends a body at `E)`: to other shells this text goes on.
        self.doubt |= bash_only;
        // What a data reader prints of its substitution can reach a later pipe.
        let routed = !self.frames.is_empty() && self.last_route.is_some_and(|route| route >= after);
        let kept = commands || rewritten || bash_only || routed;
        let data = (!kept && !document.quoted)
            .then(|| read_at(&joined(body), self.nesting + 1, Mode::Body, false));
        // A substitution the reader doubts may have closed early, so the text it
        // took for data may be more of the substitution.
        if kept || data.as_ref().is_some_and(|data| data.doubted) {
            self.out.work += data.map_or(0, |data| data.work);
            let lines = read_at(body, self.nesting + 1, Mode::Commands, true);
            let expanded = if rewritten {
                body.replace('\\', "")
            } else {
                joined(body)
            };
            self.read_both(lines, &expanded);
        } else {
            if writes {
                self.out.authored.push_str(body);
            }
            if let Some(data) = data {
                self.nested(data);
            }
        }
        self.at = after;
        self.copied = after;
        true
    }

    /// Text that may be read as lines or as a body's text: both readings count,
    /// and both see a lifted substitution's pipes, which are one each. A body inside a
    /// body would double at each level, so past a multiple of the text's length the
    /// lines stand alone, where every separator still splits and field rules read it.
    fn read_both(&mut self, mut lines: ShellText, text: &str) {
        let read = self.out.code.len() + lines.code.len() + text.len();
        if read > READINGS * self.bytes.len() {
            self.nested(lines);
            return;
        }
        let lifted = read_at(text, self.nesting + 1, Mode::Body, true);
        if !lifted.pipes.is_empty() {
            lines.pipes.clear();
        }
        self.nested(lines);
        self.nested(lifted);
    }

    fn nested(&mut self, inner: ShellText) {
        if self.quoted > 0 {
            self.deferred.push(inner);
        } else {
            self.append(inner);
        }
    }

    fn append(&mut self, inner: ShellText) {
        self.out.append(inner);
        self.stage_start = self.out.code.len();
        if let Some(frame) = self.frames.last_mut() {
            frame.command_start = self.stage_start;
            frame.first_inner = None;
        }
    }

    fn flush_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        if !self.out.command.ends_with('\n') {
            self.out.command.push('\n');
            self.out.code.push('\n');
        }
        for inner in std::mem::take(&mut self.deferred) {
            self.append(inner);
        }
    }
}

/// A reserved word after which the next word is still a command.
fn reserved_word(word: &str) -> bool {
    matches!(
        word,
        "if" | "elif" | "then" | "else" | "while" | "until" | "do" | "!"
    )
}

/// What a double-quoted string leaves of `text`.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' && matches!(chars.peek(), Some('$' | '`' | '"' | '\\')) {
            out.extend(chars.next());
        } else {
            out.push(character);
        }
    }
    out
}

/// `text` once a shell joins its lines and takes its backslashes. A Windows path
/// loses its own too, so this is a further reading of the text and never the only
/// one. Quotes stay, for whatever reads words out of this.
pub(super) fn unescaped(text: &str) -> String {
    joined(text).replace('\\', "")
}

/// `text` with the quotes around its words gone, for matching what a word spells.
/// What a double quote holds stays as written, so an escaped quote in a message
/// keeps its marks. A line whose quote does not close may hold text no shell reads
/// as a quote, an apostrophe in a body, so that quote opens nothing and hides
/// nothing after it. A substitution or a script inside a quote is read on its own.
pub(super) fn unquoted(text: &str) -> String {
    let text = joined(text);
    let mut out = String::with_capacity(text.len());
    let mut lines = text.split('\n').peekable();
    while let Some(line) = lines.next() {
        unquote_line(line, &mut out);
        if lines.peek().is_some() {
            out.push('\n');
        }
    }
    out
}

/// Linear: a quote that finds no closer leaves none of its kind to search for.
fn unquote_line(line: &str, out: &mut String) {
    let mut rest = line;
    while let Some(at) = rest.find(['\\', '\'', '"']) {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        rest = match rest.as_bytes()[at] {
            b'\\' => {
                let mut chars = after.chars();
                out.extend(chars.next());
                chars.as_str()
            }
            b'\'' => match after.find('\'') {
                Some(close) => {
                    out.push_str(&after[..close]);
                    &after[close + 1..]
                }
                None => after,
            },
            _ => match closing_double_quote(after) {
                Some(close) => {
                    out.push_str(&after[..close]);
                    &after[close + 1..]
                }
                None => after,
            },
        };
    }
    out.push_str(rest);
}

/// The next `"` no backslash escapes.
fn closing_double_quote(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'"' => return Some(at),
            _ => at += 1,
        }
    }
    None
}

/// `text` without its continued lines. A backslash before a backslash quotes
/// it, so only an unquoted one continues its line.
fn joined(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
        } else if let Some(next) = chars.next().filter(|next| *next != '\n') {
            out.push(character);
            out.push(next);
        }
    }
    out
}

/// The last pipe or `>(` that output may run through. `||` carries nothing. A pipe
/// into a command known to read data runs nothing it carries, and neither does
/// anything after that command's own separator, which starts another pipeline.
fn last_route(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut end = bytes.len();
    for at in (0..bytes.len()).rev() {
        match bytes[at] {
            b'(' if at > 0 && bytes[at - 1] == b'>' => return Some(at),
            b'|' if bytes.get(at + 1) == Some(&b'|') || at > 0 && bytes[at - 1] == b'|' => {
                end = at;
            }
            b'|' => {
                // `|&` hands the same command its standard error as well.
                let receiver = &text[at + 1..end];
                if !receiver_reads_data(receiver.strip_prefix('&').unwrap_or(receiver)) {
                    return Some(at);
                }
                end = at;
            }
            _ => {}
        }
    }
    None
}

/// Whether the command at the start of `text` is plainly a data reader. Its program
/// has to be plain. Its arguments may be quoted, unless they run a command themselves.
fn receiver_reads_data(text: &str) -> bool {
    let command = text.split(['&', ';', '\n']).next().unwrap_or_default();
    let words: Vec<String> = command
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    !command.contains(['`', '<']) && !command.contains("$(") && command_reads_data(&words)
}

/// A command of nothing but assignments, or whose program is a data reader.
fn stage_reads_data(words: &[String]) -> bool {
    words.iter().all(|word| plain(word) && assignment(word)) || command_reads_data(words)
}

pub(super) fn reads_data(name: &str) -> bool {
    DATA_READERS.contains(&name)
        || DATA_READERS.contains(&name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'))
}

/// A word that is one program's name or path: no blank or operator a shell
/// would read inside a quoted script, and no substitution that computes it.
fn plain(word: &str) -> bool {
    word.chars()
        .all(|c| c.is_ascii_alphanumeric() || "_-./+:=@%,~${}".contains(c))
}

/// A word a shell passes on as written. A quoted one counts only as the script itself,
/// and only as one quote: joined pieces are not read together here.
fn literal_word(word: &str, script: bool) -> bool {
    let quoted = |quote: char, expands: &[char]| {
        word.strip_prefix(quote)
            .and_then(|inner| inner.strip_suffix(quote))
            .is_some_and(|inner| !inner.contains(quote) && !inner.contains(expands))
    };
    (plain(word) && !word.contains('$'))
        || (script && (quoted('\'', &[]) || quoted('"', &['$', '`', '\\'])))
}

/// A shell's flag cluster ending in `c`, as in `-c` or `-lc`.
pub(super) fn script_flag(word: &str) -> bool {
    word.strip_prefix('-')
        .is_some_and(|flags| flags.ends_with('c') && flags.chars().all(|c| c.is_ascii_lowercase()))
}

/// Whether a command is known to treat its input as data. The words are the
/// shell's own, so anything not recognised here stays doubtful.
fn command_reads_data(words: &[String]) -> bool {
    let mut rest = words;
    while let Some((word, tail)) = rest.split_first() {
        rest = tail;
        if !plain(word) {
            return false;
        }
        if assignment(word) {
            continue;
        }
        let name = client_name(word);
        let name = name.as_str();
        if reads_data(name) {
            return true;
        }
        if MANIFEST_CLIENTS.contains(&name) {
            return rest
                .first()
                .is_some_and(|verb| matches!(verb.as_str(), "apply" | "create" | "replace"));
        }
        if TOOL_RUNNERS.contains(&name) {
            match rest.split_first() {
                Some((verb, tail)) if matches!(verb.as_str(), "run" | "exec") => rest = tail,
                _ => return false,
            }
        } else if SHELLS.contains(&name) {
            // An array-form command loses its script's quotes: `bash -lc cat > f`.
            // A script is judged only when it is one plain program.
            return rest
                .iter()
                .position(|word| !word.starts_with('-') || script_flag(word))
                .filter(|flag| script_flag(&rest[*flag]))
                .and_then(|flag| rest.get(flag + 1))
                .is_some_and(|script| {
                    plain(script) && !assignment(script) && reads_data(&client_name(script))
                });
        } else if !WRAPPERS.contains(&name) {
            return false;
        }
    }
    false
}
