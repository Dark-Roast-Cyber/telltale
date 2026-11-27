//! Ordered transcript reads for on-demand inspection: one source's canonical
//! observations in store order, each at a position that stays the same while
//! the store only grows. Harness knowledge stays in the source modules; this
//! is the one place that dispatches to them.

use std::path::Path;

use telltale_schema::clients::ClientId;
use telltale_schema::observation::{
    CanonicalObservationV2, ContentPartKind, JsonValue, MessageObservation, MessageRole,
    ObservationBody,
};
use telltale_schema::source::Source;

use super::{
    AcquisitionError, AcquisitionOptions, AnchoredRead, QuarantinedUnit, SourceAccess,
    acquire_source_impl,
};
use crate::source_read::{BoundedReadError, PRODUCTION_SOURCE_BYTES};

/// The largest source byte bound a transcript read accepts: the production
/// scan bound, so a transcript reads every source a scan reads.
#[doc(hidden)]
pub const MAX_TRANSCRIPT_SOURCE_BYTES: usize = PRODUCTION_SOURCE_BYTES;

/// Controls for [`acquire_transcript`].
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct TranscriptReadOptions<'a> {
    /// The approved discovery root: the store is opened under its trust
    /// anchors, as bounded discovery does. With `None`, `source.path` must be
    /// already resolved, and it is walked strictly from the filesystem root.
    pub root: Option<&'a Path>,
    /// Source bytes this read may load, `1..=MAX_TRANSCRIPT_SOURCE_BYTES`. A
    /// whole-source read over it fails as `source_limit_exceeded`; a windowed
    /// read stops after the row that reaches it.
    pub max_source_bytes: usize,
    /// The terminal session to read, required by stores read per session.
    pub session_id: Option<&'a str>,
    /// A windowed read starts at the store row that holds this position.
    /// Whole-source reads return every position.
    pub from_position: Option<u64>,
}

/// One observation at its transcript position.
#[derive(Debug)]
#[doc(hidden)]
pub struct TranscriptEntry {
    /// Increases in store order and is stable while the store only grows; not
    /// dense.
    pub position: u64,
    pub observation: CanonicalObservationV2,
    /// The harness stored tool or command output as this user message.
    pub harness_output: bool,
}

/// The entries of one transcript read.
#[derive(Debug)]
#[doc(hidden)]
pub struct TranscriptBatch {
    pub entries: Vec<TranscriptEntry>,
    /// Native units left out because their own values exceed a bound.
    pub quarantined: Vec<QuarantinedUnit>,
    /// Store rows after this batch were not read: the next read continues
    /// with this as [`TranscriptReadOptions::from_position`]. Always `None`
    /// for a whole-source read.
    pub continue_from: Option<u64>,
    /// Store bytes a windowed read loaded; 0 for a whole-source read, which
    /// [`TranscriptReadOptions::max_source_bytes`] bounds as a whole.
    pub bytes_read: usize,
}

/// The text a transcript shows for a message: its text parts joined by
/// newlines, or its string content when it has no parts. Tool use, tool
/// result, reasoning, image and other parts never enter it.
#[doc(hidden)]
pub fn message_text(message: &MessageObservation) -> String {
    if message.content_parts().is_empty() {
        return match message.content() {
            Some(JsonValue::String(text)) => text.clone(),
            _ => String::new(),
        };
    }
    message
        .content_parts()
        .iter()
        .filter(|part| part.kind() == ContentPartKind::Text)
        .filter_map(|part| match part.value() {
            JsonValue::String(text) if !text.is_empty() => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether a projected user message holds harness output in one of
/// `elements` (tag names a harness wraps stored output in) rather than only a
/// prompt. `text` is the message text a transcript shows (text parts joined
/// by newlines). The rule is applied to it and to the text parts joined with
/// nothing between them, so a tag split across parts still counts. Without
/// case, the text is output when a line opens (after leading whitespace,
/// marks and punctuation: anything before its first letter, digit or `<`)
/// with an opening tag of one of `elements`, or when an opening tag anywhere
/// has that element's closing tag after it. A record mixing a prompt with
/// output is output, shown only when results are asked for; a prompt that
/// names a tag inside a sentence stays a prompt.
///
/// This recognizes what a harness writes. Text shaped to pass as a prompt (a
/// tag name broken by other characters, an unclosed tag after words on its
/// line) is a user message, redacted like any other. Which elements a harness
/// writes is its source module's knowledge.
pub(crate) fn user_message_holds_element(
    observation: &CanonicalObservationV2,
    text: &str,
    elements: &[&str],
) -> bool {
    let ObservationBody::Message(message) = observation.body() else {
        return false;
    };
    if message.role() != Some(MessageRole::User) {
        return false;
    }
    let unseparated: String = message
        .content_parts()
        .iter()
        .filter(|part| part.kind() == ContentPartKind::Text)
        .filter_map(|part| match part.value() {
            JsonValue::String(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    holds_element(text, elements) || holds_element(&unseparated, elements)
}

fn holds_element(text: &str, elements: &[&str]) -> bool {
    let text = text.to_ascii_lowercase();
    elements.iter().any(|element| {
        let open = format!("<{element}");
        let close = format!("</{element}>");
        let is_open_tag = |after: &str| {
            after.is_empty()
                || after.starts_with(|next: char| matches!(next, '>' | '/') || next.is_whitespace())
        };
        text.split(['\n', '\r']).any(|line| {
            line.trim_start_matches(|lead: char| !lead.is_alphanumeric() && lead != '<')
                .strip_prefix(&open)
                .is_some_and(is_open_tag)
        }) || text.match_indices(&open).any(|(at, _)| {
            let after = &text[at + open.len()..];
            is_open_tag(after) && after.contains(&close)
        })
    })
}

/// Rows of one OpenCode window and the stored bytes it may load.
#[cfg(feature = "opencode-sqlite")]
const OPENCODE_WINDOW_ROWS: usize = 256;
#[cfg(feature = "opencode-sqlite")]
const OPENCODE_WINDOW_BYTES: usize = 32 * 1024 * 1024;
/// An OpenCode position is `seq << 20 | content index << 4 | stage slot`.
#[cfg(feature = "opencode-sqlite")]
const POSITION_ROW_SHIFT: u32 = 20;

/// Read one source's transcript with production semantics, opened without
/// following a link. JSONL and log sources are read whole; their position is
/// the observation's index. The OpenCode store is read one session at a time
/// in `seq` order, in windows. Hook journals are not transcripts
/// (`unsupported_source_identity`).
#[doc(hidden)]
pub fn acquire_transcript(
    source: &Source,
    options: AcquisitionOptions,
    read: TranscriptReadOptions<'_>,
) -> Result<TranscriptBatch, AcquisitionError> {
    if read.max_source_bytes == 0 || read.max_source_bytes > MAX_TRANSCRIPT_SOURCE_BYTES {
        return Err(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded,
        ));
    }
    if source.client == ClientId::OpenCode && source.source_id == "opencode.sqlite" {
        return opencode_transcript(source, options, read);
    }
    let batch = acquire_source_impl(
        source,
        options,
        SourceAccess::Anchored(AnchoredRead {
            root: read.root,
            max_bytes: read.max_source_bytes,
        }),
    )?;
    let entries = batch
        .observations
        .into_iter()
        .enumerate()
        .map(|(index, observation)| TranscriptEntry {
            position: index as u64,
            harness_output: match observation.body() {
                ObservationBody::Message(message) => {
                    let text = message_text(message);
                    match source.client {
                        ClientId::Claude => {
                            crate::sources::claude::canonical::is_harness_output_message(
                                &observation,
                                &text,
                            )
                        }
                        ClientId::Codex => {
                            crate::sources::codex::canonical::is_harness_output_message(
                                &observation,
                                &text,
                            )
                        }
                        _ => false,
                    }
                }
                _ => false,
            },
            observation,
        })
        .collect();
    Ok(TranscriptBatch {
        entries,
        quarantined: batch.quarantined,
        continue_from: None,
        bytes_read: 0,
    })
}

#[cfg(not(feature = "opencode-sqlite"))]
fn opencode_transcript(
    source: &Source,
    _: AcquisitionOptions,
    _: TranscriptReadOptions<'_>,
) -> Result<TranscriptBatch, AcquisitionError> {
    if source.kind != telltale_schema::clients::SourceKind::Sqlite {
        return Err(AcquisitionError::SourceKindMismatch);
    }
    Err(AcquisitionError::CapabilityNotCompiled)
}

/// Positions are `seq`-based, so a session's rows must each hold a distinct
/// integer `seq`; otherwise, and for the legacy schema, which orders nothing
/// per session, the read fails as `transcript_order_unavailable`. Stages of
/// one tool keep their slots as the row is updated in place.
#[cfg(feature = "opencode-sqlite")]
fn opencode_transcript(
    source: &Source,
    options: AcquisitionOptions,
    read: TranscriptReadOptions<'_>,
) -> Result<TranscriptBatch, AcquisitionError> {
    use crate::sources::opencode::session_message::{SessionTranscript, read_session_transcript};
    use crate::sources::opencode::session_message_canonical::{
        RowProjection, SessionMessageProjector,
    };

    if source.kind != telltale_schema::clients::SourceKind::Sqlite {
        return Err(AcquisitionError::SourceKindMismatch);
    }
    let session = read
        .session_id
        .ok_or(AcquisitionError::TranscriptSessionRequired)?;
    if let Some(root) = read.root {
        check_store_under_root(root, &source.path)?;
    }
    let from_seq = read
        .from_position
        .map_or(0, |position| position >> POSITION_ROW_SHIFT);
    let rows = match read_session_transcript(
        &source.path,
        session,
        from_seq,
        OPENCODE_WINDOW_ROWS,
        read.max_source_bytes,
        OPENCODE_WINDOW_BYTES,
    )
    .map_err(|error| match error {
        crate::source_read::SourceReadError::Bounded(reason) => {
            AcquisitionError::BoundedSourceRead(reason)
        }
        crate::source_read::SourceReadError::UnsupportedSchema => {
            AcquisitionError::UnsupportedSourceSchema
        }
        _ => AcquisitionError::SourceRead,
    })? {
        SessionTranscript::Rows(rows) => rows,
        SessionTranscript::Legacy | SessionTranscript::Unordered => {
            return Err(AcquisitionError::TranscriptOrderUnavailable);
        }
    };

    let mut projector = SessionMessageProjector::new(&options.observed_at);
    let mut entries = Vec::new();
    let mut quarantined = Vec::new();
    for record in &rows.records {
        let unit = |code, bound| QuarantinedUnit {
            session_id: record.session_id.clone(),
            native_id: record.source_id.clone().unwrap_or_default(),
            source_sequence: record.seq,
            code,
            bound,
        };
        match projector.row(record).map_err(super::map_canonical_error)? {
            RowProjection::Mapped(observations) => {
                let mut previous_child = None;
                let mut slot = 0u64;
                for observation in observations {
                    let child = observation.identity_basis().child_ordinal();
                    if previous_child == Some(child) {
                        slot += 1;
                    } else {
                        previous_child = Some(child);
                        slot = 0;
                    }
                    let position = opencode_position(record.seq, child, slot)
                        .ok_or(AcquisitionError::TranscriptOrderUnavailable)?;
                    entries.push(TranscriptEntry {
                        position,
                        observation,
                        harness_output: false,
                    });
                }
            }
            RowProjection::Quarantined(error) => {
                quarantined.push(unit(error.code(), error.bound_context()));
            }
            RowProjection::OversizedCell => quarantined.push(unit("oversized_native_cell", None)),
        }
    }
    // `seq` is distinct per row, so the next window starts after the last
    // row read.
    let continue_from = match (rows.more, rows.records.last()) {
        (false, _) => None,
        (true, Some(last)) => Some(
            last.seq
                .checked_add(1)
                .and_then(|seq| opencode_position(seq, 0, 0))
                .ok_or(AcquisitionError::TranscriptOrderUnavailable)?,
        ),
        // The first row does not fit the read's byte budget.
        (true, None) => {
            return Err(AcquisitionError::BoundedSourceRead(
                BoundedReadError::LimitExceeded,
            ));
        }
    };
    Ok(TranscriptBatch {
        entries,
        quarantined,
        continue_from,
        bytes_read: rows.bytes,
    })
}

#[cfg(feature = "opencode-sqlite")]
fn opencode_position(seq: u64, child: u32, slot: u64) -> Option<u64> {
    (seq < 1 << (64 - POSITION_ROW_SHIFT) && child < 1 << 16 && slot < 1 << 4)
        .then(|| seq << POSITION_ROW_SHIFT | u64::from(child) << 4 | slot)
}

/// The store and its journal sidecars, checked under the root's trust anchors
/// before SQLite opens them by name.
#[cfg(feature = "opencode-sqlite")]
fn check_store_under_root(root: &Path, path: &Path) -> Result<(), AcquisitionError> {
    use telltale_discover::discovery::{BoundedDiscoveryError, check_sqlite_store};
    let reason = match check_sqlite_store(root, path) {
        Ok(true) => return Ok(()),
        Ok(false) => BoundedReadError::Missing,
        Err(BoundedDiscoveryError::SymlinkRoot | BoundedDiscoveryError::Traversal) => {
            BoundedReadError::NonRegularSource
        }
        Err(BoundedDiscoveryError::PermissionDenied) => BoundedReadError::PermissionDenied,
        Err(BoundedDiscoveryError::LimitExceeded) => BoundedReadError::LimitExceeded,
        Err(BoundedDiscoveryError::InvalidLimit) => BoundedReadError::Unreadable,
    };
    Err(AcquisitionError::BoundedSourceRead(reason))
}
