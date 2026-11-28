//! Read-only incremental polling of a Hooks records file and its rotations.
//! This module does not require the hooks runtime.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use telltale_sources::journal::{
    self, DEFAULT_MAX_DIRECTORY_ENTRIES, GENERATION_HEAD_BYTES, JournalDiscovery, JournalFile,
    JournalGeneration,
};

use crate::{FeedNotice, FeedNoticeCode, HOOKS_RECORD_MAX_INPUT_BYTES, HooksRecordV1, StartupMode};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_GENERATIONS: usize = 256;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HooksRecordFeedConfig {
    pub path: PathBuf,
    pub startup: StartupMode,
    /// Nonempty complete lines (including rejections) examined in one poll.
    pub max_records_per_poll: usize,
    /// Journal data bytes read in one poll, at least one maximal Hooks line.
    /// Generation identity checks read at most 64 additional bytes per open.
    pub max_bytes_per_poll: usize,
    pub max_generations: usize,
    pub max_directory_entries: usize,
}

impl HooksRecordFeedConfig {
    pub fn new(path: impl Into<PathBuf>, startup: StartupMode) -> Self {
        Self {
            path: path.into(),
            startup,
            max_records_per_poll: 256,
            max_bytes_per_poll: 2 * HOOKS_RECORD_MAX_INPUT_BYTES,
            max_generations: MAX_GENERATIONS,
            max_directory_entries: DEFAULT_MAX_DIRECTORY_ENTRIES,
        }
    }
}

/// An opaque checkpoint. Serialize it with serde and pass it back to
/// [`HooksRecordFeed::resume`]. Contains no path, open frame, or raw head bytes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksRecordCursor {
    version: u8,
    generation: String,
    head_len: u8,
    head: [u8; 32],
    offset: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HooksRecordFeedError {
    InvalidLimit,
    InvalidRecentLimit,
    InvalidCursor,
}

impl std::fmt::Display for HooksRecordFeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "invalid Hooks feed limit",
            Self::InvalidRecentLimit => "invalid Hooks feed recent limit",
            Self::InvalidCursor => "invalid Hooks feed cursor",
        })
    }
}

impl std::error::Error for HooksRecordFeedError {}

/// A complete rejected line, with its opaque generation and start offset.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HooksRecordRejection {
    pub generation: String,
    pub byte_offset: u64,
    pub code: &'static str,
}

#[derive(Debug, Default)]
pub struct HooksRecordBatch {
    pub records: Vec<HooksRecordV1>,
    pub rejections: Vec<HooksRecordRejection>,
    pub notices: Vec<FeedNotice>,
    pub bytes_read: usize,
    /// Sum of the wire sizes (including LF) of returned records.
    pub record_bytes: usize,
    pub caught_up: bool,
}

impl HooksRecordBatch {
    fn notice(&mut self, code: FeedNoticeCode) {
        self.notices.push(FeedNotice { code, count: 1 });
    }
}

#[derive(Default)]
struct Frame {
    read: u64,
    bytes: Vec<u8>,
    oversized: bool,
}

impl Frame {
    fn is_empty_line(&self) -> bool {
        self.bytes == b"\n"
    }

    fn push(&mut self, piece: &[u8]) {
        self.read += piece.len() as u64;
        if self.read > HOOKS_RECORD_MAX_INPUT_BYTES as u64 && !self.oversized {
            self.oversized = true;
            self.bytes = Vec::new();
        }
        if !self.oversized {
            self.bytes.extend_from_slice(piece);
        }
    }

    fn parse(self) -> Result<(HooksRecordV1, usize), &'static str> {
        if self.oversized {
            return Err(telltale_schema::hooks_record::HooksRecordError::INPUT_TOO_LARGE_CODE);
        }
        HooksRecordV1::from_json(&self.bytes)
            .map(|record| (record, self.bytes.len()))
            .map_err(|error| error.code())
    }
}

/// Visit complete records in a bounded snapshot of one active file. A
/// possibly clipped first line and an incomplete tail are not counted.
#[cfg(feature = "hooks")]
pub(crate) fn visit_active_suffix(
    file: &mut JournalFile,
    max_bytes: u64,
    mut visit: impl FnMut(Result<HooksRecordV1, &'static str>),
) -> io::Result<bool> {
    let length = file.len();
    let start = length.saturating_sub(max_bytes);
    let mut clipped = start != 0;
    let mut offset = start;
    let mut frame = Frame::default();
    while offset < length {
        let requested = (length - offset).min(READ_CHUNK_BYTES as u64) as usize;
        let chunk = file.read_at(offset, requested)?;
        if chunk.len() != requested {
            return Err(io::Error::other("journal changed during read"));
        }
        offset += chunk.len() as u64;
        for piece in chunk.split_inclusive(|byte| *byte == b'\n') {
            let complete = piece.ends_with(b"\n");
            if clipped {
                clipped = !complete;
                continue;
            }
            frame.push(piece);
            if complete {
                let line = std::mem::take(&mut frame);
                if !line.is_empty_line() {
                    visit(line.parse().map(|(record, _)| record));
                }
            }
        }
    }
    Ok(start == 0 && frame.read == 0)
}

struct EndSearch {
    snapshot: HooksRecordCursor,
    scan_to: u64,
}

/// A synchronous poller. The caller owns checkpoint persistence.
pub struct HooksRecordFeed {
    config: HooksRecordFeedConfig,
    cursor: Option<HooksRecordCursor>,
    frame: Frame,
    end_after_recent: bool,
    end_search: Option<EndSearch>,
}

impl HooksRecordFeed {
    pub fn new(config: HooksRecordFeedConfig) -> Result<Self, HooksRecordFeedError> {
        if config.max_records_per_poll == 0
            || config.max_bytes_per_poll < HOOKS_RECORD_MAX_INPUT_BYTES
            || config.max_generations == 0
            || config.max_directory_entries == 0
        {
            return Err(HooksRecordFeedError::InvalidLimit);
        }
        if let StartupMode::Recent {
            max_events,
            max_bytes,
        } = config.startup
            && (max_events == 0 || max_bytes == 0 || max_bytes > config.max_bytes_per_poll)
        {
            return Err(HooksRecordFeedError::InvalidRecentLimit);
        }
        Ok(Self {
            config,
            cursor: None,
            frame: Frame::default(),
            end_after_recent: false,
            end_search: None,
        })
    }

    pub fn resume(
        config: HooksRecordFeedConfig,
        cursor: HooksRecordCursor,
    ) -> Result<Self, HooksRecordFeedError> {
        if cursor.version != 1
            || usize::from(cursor.head_len) > GENERATION_HEAD_BYTES
            || cursor.generation.len() != 64
            || !cursor
                .generation
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(HooksRecordFeedError::InvalidCursor);
        }
        let mut feed = Self::new(config)?;
        feed.cursor = Some(cursor);
        Ok(feed)
    }

    /// Checkpoint after the last complete line consumed. Incomplete bytes
    /// are deliberately absent, so a resumed feed can read the whole line.
    pub fn cursor(&self) -> Option<HooksRecordCursor> {
        self.cursor.clone()
    }

    pub fn poll(&mut self) -> HooksRecordBatch {
        use FeedNoticeCode::*;
        let mut batch = HooksRecordBatch::default();
        let discovery = match journal::discover_generations(
            &self.config.path,
            self.config.max_directory_entries,
        ) {
            Ok(discovery) => discovery,
            Err(error) => {
                batch.notice(if error.kind() == io::ErrorKind::Other {
                    ReadRace
                } else {
                    JournalUnavailable
                });
                return batch;
            }
        };
        self.poll_discovery(discovery)
    }

    fn poll_discovery(&mut self, discovery: JournalDiscovery) -> HooksRecordBatch {
        use FeedNoticeCode::*;
        let mut batch = HooksRecordBatch::default();
        let generations = discovery.generations;
        if discovery.directory_bound_reached {
            batch.notice(DirectoryBound);
            return batch;
        }
        if generations.len() > self.config.max_generations {
            batch.notice(GenerationBound);
            return batch;
        }
        if generations.is_empty() {
            batch.notice(JournalUnavailable);
            return batch;
        }

        let start = match self.poll_start(&generations, &mut batch) {
            Ok(Some(start)) => start,
            Ok(None) => return batch,
            Err(_) => {
                batch.notice(ReadRace);
                return batch;
            }
        };
        for generation in &generations[start..] {
            let result = self.read_generation(generation, &mut batch);
            match result {
                Ok(true) => {}
                Ok(false) => return batch,
                Err(_) => {
                    batch.notice(ReadRace);
                    return batch;
                }
            }
        }
        batch.caught_up = !batch
            .notices
            .iter()
            .any(|notice| notice.code == GenerationGap);
        batch
    }

    fn poll_start(
        &mut self,
        generations: &[JournalGeneration],
        batch: &mut HooksRecordBatch,
    ) -> io::Result<Option<usize>> {
        use FeedNoticeCode::*;
        if let Some(cursor) = &self.cursor {
            if let Some(index) = generations
                .iter()
                .position(|g| g.identity == cursor.generation)
            {
                let mut file = open(&generations[index])?;
                let offset = cursor.offset.saturating_add(self.frame.read);
                if offset <= file.len()
                    && head_matches(cursor, &mut file)?
                    && (cursor.offset == 0 || file.read_at(cursor.offset - 1, 1)? == b"\n")
                {
                    return Ok(Some(index));
                }
                batch.notice(if offset > file.len() {
                    TruncatedGeneration
                } else {
                    ReplacedGeneration
                });
            }
            batch.notice(GenerationGap);
            self.cursor = None;
            self.frame = Frame::default();
            return Ok(Some(0));
        }
        match if self.end_after_recent {
            StartupMode::End
        } else {
            self.config.startup
        } {
            StartupMode::Beginning => Ok(Some(0)),
            StartupMode::End => self.find_end(generations, batch),
            StartupMode::Recent {
                max_events,
                max_bytes,
            } => {
                if let Some((index, cursor)) = recent_position(
                    generations,
                    max_events,
                    max_bytes,
                    batch,
                    &mut self.end_search,
                )? {
                    self.cursor = Some(cursor);
                    self.end_search = None;
                    Ok(Some(index))
                } else {
                    self.end_after_recent = true;
                    self.find_end(generations, batch)
                }
            }
        }
    }

    fn find_end(
        &mut self,
        generations: &[JournalGeneration],
        batch: &mut HooksRecordBatch,
    ) -> io::Result<Option<usize>> {
        let last = generations.len() - 1;
        if self.end_search.is_none() {
            let mut file = open(&generations[last])?;
            let length = file.len();
            self.end_search = Some(EndSearch {
                snapshot: position(&mut file, length)?,
                scan_to: length,
            });
        }
        let search = self.end_search.as_mut().expect("end search initialized");
        let gap = |batch: &mut HooksRecordBatch| {
            batch.notice(FeedNoticeCode::GenerationGap);
            Ok(Some(0))
        };
        let Some(index) = generations
            .iter()
            .position(|generation| generation.identity == search.snapshot.generation)
        else {
            self.end_search = None;
            return gap(batch);
        };
        let mut file = open(&generations[index])?;
        if file.len() < search.snapshot.offset || !head_matches(&search.snapshot, &mut file)? {
            self.end_search = None;
            return gap(batch);
        }
        while search.scan_to > 0 && batch.bytes_read < self.config.max_bytes_per_poll {
            let amount = (self.config.max_bytes_per_poll - batch.bytes_read)
                .min(READ_CHUNK_BYTES)
                .min(search.scan_to.try_into().unwrap_or(usize::MAX));
            let start = search.scan_to - amount as u64;
            let bytes = file.read_at(start, amount)?;
            if bytes.len() != amount {
                return Err(io::Error::other("journal end changed during read"));
            }
            batch.bytes_read += amount;
            if let Some(last_lf) = bytes.iter().rposition(|byte| *byte == b'\n') {
                self.cursor = Some(position(&mut file, start + last_lf as u64 + 1)?);
                self.end_search = None;
                return Ok(Some(index));
            }
            search.scan_to = start;
        }
        if search.scan_to == 0 {
            self.cursor = Some(position(&mut file, 0)?);
            self.end_search = None;
            Ok(Some(index))
        } else {
            Ok(None)
        }
    }

    fn read_generation(
        &mut self,
        generation: &JournalGeneration,
        batch: &mut HooksRecordBatch,
    ) -> io::Result<bool> {
        if !self.has_budget(batch) {
            return Ok(false);
        }
        let mut file = open(generation)?;
        let length = file.len();
        let cursor = match &self.cursor {
            Some(cursor) if cursor.generation == generation.identity => cursor.clone(),
            _ => {
                self.frame = Frame::default();
                position(&mut file, 0)?
            }
        };
        if !head_matches(&cursor, &mut file)? {
            return Err(io::Error::other("journal changed before read"));
        }
        let mut offset = cursor.offset;
        let mut next = offset.saturating_add(self.frame.read);
        if next > length {
            return Err(io::Error::other("journal truncated before read"));
        }
        // Refresh the head when a generation that was empty or short grows.
        self.cursor = Some(position(&mut file, offset)?);
        while next < length && self.has_budget(batch) {
            let requested = (self.config.max_bytes_per_poll - batch.bytes_read)
                .min(READ_CHUNK_BYTES)
                .min((length - next).try_into().unwrap_or(usize::MAX));
            let chunk = file.read_at(next, requested)?;
            if chunk.len() != requested {
                return Err(io::Error::other("journal changed during read"));
            }
            batch.bytes_read += chunk.len();
            for piece in chunk.split_inclusive(|byte| *byte == b'\n') {
                let complete = piece.ends_with(b"\n");
                let frame_len = self.frame.read + piece.len() as u64;
                if complete
                    && frame_len <= HOOKS_RECORD_MAX_INPUT_BYTES as u64
                    && frame_len as usize > self.config.max_bytes_per_poll - batch.record_bytes
                {
                    return Ok(false);
                }
                self.frame.push(piece);
                next += piece.len() as u64;
                if !complete {
                    continue;
                }
                self.finish_line(generation, offset, batch);
                offset = next;
                self.cursor.as_mut().expect("open cursor").offset = offset;
                if batch.records.len() + batch.rejections.len() == self.config.max_records_per_poll
                {
                    return Ok(false);
                }
            }
        }
        // An archived file cannot complete its tail; move on without a
        // rejection. An active partial line stays at the last safe offset.
        Ok(next == length && (!generation.is_active || self.frame.read == 0))
    }

    fn finish_line(
        &mut self,
        generation: &JournalGeneration,
        offset: u64,
        batch: &mut HooksRecordBatch,
    ) {
        let line = std::mem::take(&mut self.frame);
        if line.is_empty_line() {
            return;
        }
        let code = match line.parse() {
            Ok((record, bytes)) => {
                batch.records.push(record);
                batch.record_bytes += bytes;
                return;
            }
            Err(code) => code,
        };
        batch.rejections.push(HooksRecordRejection {
            generation: generation.identity.clone(),
            byte_offset: offset,
            code,
        });
    }

    fn has_budget(&self, batch: &HooksRecordBatch) -> bool {
        batch.bytes_read < self.config.max_bytes_per_poll
            && batch.records.len() + batch.rejections.len() < self.config.max_records_per_poll
    }
}

fn open(generation: &JournalGeneration) -> io::Result<JournalFile> {
    let file = JournalFile::open(&generation.path)?;
    if file.identity() != generation.identity {
        return Err(io::Error::other("journal generation changed while opening"));
    }
    Ok(file)
}

fn position(file: &mut JournalFile, offset: u64) -> io::Result<HooksRecordCursor> {
    let head = file.read_head(file.len())?;
    Ok(HooksRecordCursor {
        version: 1,
        generation: file.identity().to_owned(),
        head_len: head.len() as u8,
        head: Sha256::digest(head).into(),
        offset,
    })
}

fn head_matches(cursor: &HooksRecordCursor, file: &mut JournalFile) -> io::Result<bool> {
    let head = file.read_head(u64::from(cursor.head_len))?;
    Ok(head.len() == usize::from(cursor.head_len)
        && cursor.head == <[u8; 32]>::from(Sha256::digest(head)))
}

// Search the bounded suffix newest-first. The delimiter before a complete
// line is its start, except at physical offset zero in each generation.
fn recent_position(
    generations: &[JournalGeneration],
    max_events: usize,
    max_bytes: usize,
    batch: &mut HooksRecordBatch,
    end_search: &mut Option<EndSearch>,
) -> io::Result<Option<(usize, HooksRecordCursor)>> {
    let mut remaining = max_bytes;
    let mut selected = 0;
    let mut floor = None;
    for (index, generation) in generations.iter().enumerate().rev() {
        let mut file = open(generation)?;
        let mut end = file.len();
        if index == generations.len() - 1 {
            // If no complete line is selected, End must use this snapshot,
            // not one taken after an active tail has been completed.
            *end_search = Some(EndSearch {
                snapshot: position(&mut file, end)?,
                scan_to: end,
            });
        }
        let mut oldest = None;
        let mut started_line = false;
        let mut reversed = Vec::new();
        while end > 0 && remaining > 0 && selected < max_events {
            let amount = remaining
                .min(READ_CHUNK_BYTES)
                .min(end.try_into().unwrap_or(usize::MAX));
            let start = end - amount as u64;
            let bytes = file.read_at(start, amount)?;
            if bytes.len() != amount {
                return Err(io::Error::other("recent journal boundary changed"));
            }
            batch.bytes_read += amount;
            remaining -= amount;
            for (index, byte) in bytes.into_iter().enumerate().rev() {
                if byte == b'\n' {
                    if started_line {
                        oldest = Some(start + index as u64 + 1);
                        selected += usize::from(valid_recent_line(&mut reversed));
                        if selected == max_events {
                            break;
                        }
                    }
                    started_line = true;
                }
                if started_line && reversed.len() <= HOOKS_RECORD_MAX_INPUT_BYTES {
                    reversed.push(byte);
                }
            }
            end = start;
        }
        if end == 0 && started_line && selected < max_events {
            oldest = Some(0);
            selected += usize::from(valid_recent_line(&mut reversed));
        }
        if index == generations.len() - 1 && end == 0 && !started_line {
            // This snapshot has no LF. Its safe checkpoint is already known,
            // even if the recent scan exhausted this poll's byte budget.
            end_search.as_mut().expect("initial snapshot").scan_to = 0;
        }
        if let Some(offset) = oldest {
            floor = Some((index, position(&mut file, offset)?));
        }
        if selected == max_events || remaining == 0 {
            break;
        }
    }
    Ok(floor)
}

fn valid_recent_line(reversed: &mut Vec<u8>) -> bool {
    let valid = if reversed.len() <= HOOKS_RECORD_MAX_INPUT_BYTES {
        reversed.reverse();
        HooksRecordV1::from_json(reversed).is_ok()
    } else {
        false
    };
    reversed.clear();
    valid
}

#[cfg(all(test, feature = "hooks"))]
mod tests;
