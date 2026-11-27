//! Read-only transcript inspection (`telltale investigate transcript`).
//!
//! Exports one page of bounded, redacted session records in store order from
//! one supported session source. Writes no scanner state, checkpoint or event.
//! A page that may be incomplete says so and names the continuation; a failed
//! read exits non-zero with its closed code.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Serialize;
use telltale_core::{
    ClientId, DEFAULT_SESSION_RECORD_MAX_BYTES, DEFAULT_SESSION_RECORD_MAX_RECORDS,
    DEFAULT_SESSION_RECORD_MAX_TOTAL_BYTES, MAX_SESSION_RECORD_SOURCE_BYTES, PipelineError,
    SessionRecordContent, SessionRecordOptions, SessionRecordPage, Source, SourceKind,
    discover_sources, read_session_records,
};
use telltale_schema::event::terminal_session_id;

#[derive(Args)]
pub(super) struct InvestigateArgs {
    #[command(subcommand)]
    command: InvestigateCommand,
}

#[derive(Subcommand)]
enum InvestigateCommand {
    /// Export one page of bounded, redacted records from one session source.
    Transcript(TranscriptArgs),
}

#[derive(Args)]
struct TranscriptArgs {
    /// One supported session source (requires --client and --source-id).
    /// Without --root it is resolved once, then opened without following
    /// links.
    #[arg(long, requires_all = ["client", "source_id"])]
    source: Option<PathBuf>,

    /// Approved discovery root. The source is opened under the root's trust
    /// anchors, refusing links (a --source outside the root: refusing a link
    /// anywhere in its path); without --source, the source holding --session
    /// is found by discovery.
    #[arg(long, required_unless_present = "source")]
    root: Option<PathBuf>,

    /// Client of the source (claude, codex, copilot, opencode, openclaw, pi, qwen).
    #[arg(long)]
    client: Option<String>,

    /// Source identity (for example claude.projects or opencode.sqlite).
    #[arg(long)]
    source_id: Option<String>,

    /// Only records of this session (raw or terminal form). Required for
    /// opencode.sqlite and with --root.
    #[arg(long)]
    session: Option<String>,

    /// Continue after this record ordinal (from the previous page).
    #[arg(long)]
    after_ordinal: Option<u64>,

    /// The record key at --after-ordinal (from the previous page). The read
    /// fails as session_record_cursor_changed if that record changed.
    #[arg(long, requires = "after_ordinal")]
    after_key: Option<String>,

    /// Inclusive RFC 3339 lower bound on the source time.
    #[arg(long)]
    since: Option<String>,

    /// Exclusive RFC 3339 upper bound on the source time.
    #[arg(long)]
    until: Option<String>,

    /// Include tool results and command output the harness stored as user
    /// messages (off by default).
    #[arg(long)]
    include_tool_results: bool,

    /// Include records that are neither messages nor tool calls (off by default).
    #[arg(long)]
    include_other: bool,

    /// Records per page (1..=4096).
    #[arg(long, default_value_t = DEFAULT_SESSION_RECORD_MAX_RECORDS)]
    max_records: usize,

    /// Redacted text bytes per page (max-record-bytes..=4194304).
    #[arg(long, default_value_t = DEFAULT_SESSION_RECORD_MAX_TOTAL_BYTES)]
    max_total_bytes: usize,

    /// Redacted text bytes per record (64..=4096).
    #[arg(long, default_value_t = DEFAULT_SESSION_RECORD_MAX_BYTES)]
    max_record_bytes: usize,

    /// Source bytes one read may load (1..=134217728).
    #[arg(long, default_value_t = MAX_SESSION_RECORD_SOURCE_BYTES)]
    max_source_bytes: usize,

    /// Print one JSON page document instead of JSON lines and a status line.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct RecordRow<'a> {
    ordinal: u64,
    session_id: Option<&'a str>,
    occurred_at: Option<&'a str>,
    kind: &'static str,
    tool_name: Option<&'a str>,
    text: &'a str,
    truncated: bool,
    imported: bool,
    record_key: &'a str,
}

#[derive(Serialize)]
struct PageDocument<'a> {
    client: &'static str,
    source_id: &'a str,
    has_more: bool,
    next_after_ordinal: Option<u64>,
    next_after_record_key: Option<&'a str>,
    quarantined_units: usize,
    total_bytes: usize,
    records: Vec<RecordRow<'a>>,
}

/// A failed transcript read: a closed code, never a path or session content.
#[derive(Debug)]
struct TranscriptFailure(String);

impl std::fmt::Display for TranscriptFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TranscriptFailure {}

fn read_failure(error: &PipelineError) -> TranscriptFailure {
    let code = match error {
        PipelineError::SessionRecords(error) => error.code().to_owned(),
        other => other.to_string(),
    };
    TranscriptFailure(format!("investigate transcript failed: {code}"))
}

pub(super) fn run(args: InvestigateArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        InvestigateCommand::Transcript(transcript) => run_transcript(transcript),
    }
}

fn run_transcript(args: TranscriptArgs) -> Result<(), Box<dyn std::error::Error>> {
    let content = {
        let mut value = SessionRecordContent::transcript_without_results();
        value.tool_results = args.include_tool_results;
        value.other = args.include_other;
        value
    };
    let options = {
        let mut value = SessionRecordOptions::default();
        value.after_ordinal = args.after_ordinal;
        value.after_record_key = args.after_key.clone();
        value.since = args.since.clone();
        value.until = args.until.clone();
        value.session_id = args.session.as_deref().map(terminal_session_id);
        value.max_records = args.max_records;
        value.max_total_bytes = args.max_total_bytes;
        value.max_record_bytes = args.max_record_bytes;
        value.max_source_bytes = args.max_source_bytes;
        value.content = content;
        value.root = args.root.clone();
        value
    };
    let source = resolve_source(&args, &options)?;
    let page = read_session_records(&source, &options).map_err(|error| read_failure(&error))?;
    let rows = page.records().iter().map(record_row).collect::<Vec<_>>();
    if args.json {
        let document = PageDocument {
            client: source.client.as_str(),
            source_id: &source.source_id,
            has_more: page.has_more(),
            next_after_ordinal: page.next_after_ordinal(),
            next_after_record_key: page.next_after_record_key(),
            quarantined_units: page.quarantined_units(),
            total_bytes: page.total_bytes(),
            records: rows,
        };
        println!("{}", serde_json::to_string(&document)?);
    } else {
        for row in &rows {
            println!("{}", serde_json::to_string(row)?);
        }
        eprintln!("{}", status_line(&page));
    }
    Ok(())
}

fn record_row(record: &telltale_core::SessionRecord) -> RecordRow<'_> {
    RecordRow {
        ordinal: record.ordinal(),
        session_id: record.session_id(),
        occurred_at: record.occurred_at(),
        kind: record.kind().as_str(),
        tool_name: record.tool_name(),
        text: record.text(),
        truncated: record.truncated(),
        imported: record.imported(),
        record_key: record.record_key(),
    }
}

/// Whether the page is complete, and how to continue when it may not be.
fn status_line(page: &SessionRecordPage) -> String {
    let count = page.records().len();
    let mut line = match (
        page.has_more(),
        page.next_after_ordinal(),
        page.next_after_record_key(),
    ) {
        (true, Some(ordinal), Some(key)) => format!(
            "telltale: {count} records; more may remain: continue with \
             --after-ordinal {ordinal} --after-key {key}"
        ),
        // An empty page resumes from a store position, which has no key.
        (true, Some(ordinal), None) => format!(
            "telltale: {count} records; more may remain: continue with \
             --after-ordinal {ordinal}"
        ),
        (true, None, _) => format!("telltale: {count} records; more may remain"),
        (false, ..) => format!("telltale: complete: {count} records"),
    };
    if page.quarantined_units() > 0 {
        line.push_str(&format!(
            "; {} native units left out (over a bound)",
            page.quarantined_units()
        ));
    }
    line
}

fn resolve_source(
    args: &TranscriptArgs,
    options: &SessionRecordOptions,
) -> Result<Source, Box<dyn std::error::Error>> {
    let client = args
        .client
        .as_deref()
        .map(|name| ClientId::from_name(name).ok_or("unsupported client"))
        .transpose()?;
    if let Some(path) = &args.source {
        let source_id = args
            .source_id
            .clone()
            .ok_or("--source requires --source-id")?;
        return Ok(Source {
            client: client.ok_or("--source requires --client")?,
            kind: transcript_source_kind(&source_id).ok_or("unsupported source identity")?,
            source_id,
            path: path.clone(),
        });
    }
    let (Some(root), Some(_)) = (&args.root, &options.session_id) else {
        return Err("pass --source with --client and --source-id, or --root with --session".into());
    };
    // Probe with the export's own options, so the chosen source is the one
    // that holds records this export would return.
    let probe = {
        let mut value = options.clone();
        value.after_ordinal = None;
        value.after_record_key = None;
        value.max_records = 1;
        value
    };
    let mut matching = Vec::new();
    for candidate in discover_sources(root)? {
        if client.is_some_and(|client| candidate.client != client)
            || args
                .source_id
                .as_deref()
                .is_some_and(|id| candidate.source_id != id)
            || transcript_source_kind(&candidate.source_id).is_none()
        {
            continue;
        }
        let page = read_session_records(&candidate, &probe).map_err(|error| {
            TranscriptFailure(format!(
                "{} ({} {}); pass --source to read another source",
                read_failure(&error),
                candidate.client.as_str(),
                candidate.source_id
            ))
        })?;
        if !page.records().is_empty() {
            matching.push(candidate);
        }
    }
    match matching.len() {
        0 => Err("no discovered source holds records of the session".into()),
        1 => Ok(matching.remove(0)),
        _ => Err("several discovered sources hold the session; pass --client or --source".into()),
    }
}

/// The kind of each source identity a transcript can be read from.
fn transcript_source_kind(source_id: &str) -> Option<SourceKind> {
    match source_id {
        "claude.projects" | "codex.sessions" | "openclaw.agents" | "qwen.projects"
        | "pi.sessions" => Some(SourceKind::Jsonl),
        "codex.archived_sessions" => Some(SourceKind::ArchivedJsonl),
        "codex.headless_sessions" => Some(SourceKind::HeadlessJsonl),
        "opencode.sqlite" => Some(SourceKind::Sqlite),
        "copilot.process_log" => Some(SourceKind::CopilotProcessLog),
        _ => None,
    }
}
