//! Pure, local-only acquisition. See the frozen profile in the crate README.
//! Never log nested schema bodies, local values, or their accessor results.
mod anthropic;
mod facts;
mod framing;
mod json;
mod mapping;
mod ollama;
mod responses;

use std::fmt;
use telltale_schema::observation::*;

pub const PROFILE: &str = "openai-chat-v1-subset-2026-10-01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    OpenAiChat,
    AnthropicMessages,
    OpenAiResponses,
    OllamaChat,
}
impl Profile {
    pub const fn version(self) -> &'static str {
        match self {
            Self::OpenAiChat => PROFILE,
            Self::AnthropicMessages => "anthropic-messages-2023-06-01-subset-2026-10-01",
            Self::OpenAiResponses => "openai-responses-v1-subset-2026-10-01",
            Self::OllamaChat => "ollama-chat-subset-2026-10-01",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    ReplayUnverifiable,
    Capacity,
    Malformed,
    Unsupported,
    Conflict,
    Incomplete,
    Cancelled,
    UpstreamError,
    TransportFailure,
    Timeout,
    InvalidState,
    CaptureDisabled,
    Schema,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReplayUnverifiable => "replay_unverifiable",
            Self::Capacity => "capacity",
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
            Self::Conflict => "conflict",
            Self::Incomplete => "incomplete",
            Self::Cancelled => "cancelled",
            Self::UpstreamError => "upstream_error",
            Self::TransportFailure => "transport_failure",
            Self::Timeout => "timeout",
            Self::InvalidState => "invalid_state",
            Self::CaptureDisabled => "capture_disabled",
            Self::Schema => "schema",
        })
    }
}
impl std::error::Error for Failure {}
impl From<ObservationError> for Failure {
    fn from(_: ObservationError) -> Self {
        Self::Schema
    }
}

/// Caller attests scope and coordinates are durable, verified and attempt-specific.
/// Native coordinate is a capture/source coordinate, not an invented request ID.
pub struct Identity<'a> {
    pub verified_installation: Option<&'a str>,
    pub native_coordinate: Option<&'a str>,
    pub stable_sequence: Option<(&'a str, u64)>,
    /// Only an explicit source-reported request ID; never an attempt token.
    pub request_id: Option<&'a str>,
}
impl fmt::Debug for Identity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identity { .. }")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePolicy {
    Disabled,
    LocalSensitive,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseFormat {
    Json,
    Sse,
    Ndjson,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Complete,
    Eof,
    Cancelled,
    UpstreamError,
    TransportFailure,
    Timeout,
}

/// Limits can only tighten the frozen profile's ceilings. Byte limits count wire
/// bytes after caller-owned decompression. Frame bytes include line delimiters.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub frame_bytes: usize,
    pub frames: usize,
    pub items: usize,
    pub output_observations: usize,
    pub json_depth: usize,
    pub json_members: usize,
    pub json_array_items: usize,
    pub string_bytes: usize,
    pub idle_ms: u64,
    pub total_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            request_bytes: 1_048_576,
            response_bytes: 4_194_304,
            frame_bytes: 65_536,
            frames: 4096,
            items: 256,
            output_observations: 1024,
            json_depth: 16,
            json_members: 32,
            json_array_items: 256,
            string_bytes: 4096,
            idle_ms: 30_000,
            total_ms: 300_000,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<Self, Failure> {
        let max = Self::default();
        for (value, ceiling) in [
            (self.request_bytes, max.request_bytes),
            (self.response_bytes, max.response_bytes),
            (self.frame_bytes, max.frame_bytes),
            (self.frames, max.frames),
            (self.items, max.items),
            (self.output_observations, max.output_observations),
            (self.json_depth, max.json_depth),
            (self.json_members, max.json_members),
            (self.json_array_items, max.json_array_items),
            (self.string_bytes, max.string_bytes),
        ] {
            if value == 0 || value > ceiling {
                return Err(Failure::Capacity);
            }
        }
        if self.idle_ms == 0
            || self.idle_ms > max.idle_ms
            || self.total_ms == 0
            || self.total_ms > max.total_ms
        {
            return Err(Failure::Capacity);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    New,
    Requested,
    Response(ResponseFormat),
    Closed,
}

pub struct Normalizer {
    profile: Profile,
    source: SourceProvenance,
    correlation: CorrelationIds,
    limits: Limits,
    state: State,
    requested_model: String,
    streaming: bool,
    response: Vec<u8>,
    frame_bytes: usize,
    line_bytes: usize,
    frames: usize,
    last_elapsed: u64,
    last_progress: u64,
}
impl fmt::Debug for Normalizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Normalizer { .. }")
    }
}
impl Normalizer {
    pub fn new(
        identity: Identity<'_>,
        capture: CapturePolicy,
        limits: Limits,
    ) -> Result<Self, Failure> {
        Self::with_profile(Profile::OpenAiChat, identity, capture, limits)
    }
    pub fn with_profile(
        profile: Profile,
        identity: Identity<'_>,
        capture: CapturePolicy,
        limits: Limits,
    ) -> Result<Self, Failure> {
        let limits = limits.validate()?;
        let scope = identity
            .verified_installation
            .ok_or(Failure::ReplayUnverifiable)?;
        if scope.len() != 32
            || !scope
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Failure::ReplayUnverifiable);
        }
        if identity.native_coordinate.is_none() && identity.stable_sequence.is_none() {
            return Err(Failure::ReplayUnverifiable);
        }
        if capture == CapturePolicy::Disabled {
            return Err(Failure::CaptureDisabled);
        }
        let mut source = SourceProvenance::new(
            IngestionMode::Gateway,
            "inference",
            format!("inference.boundary:installation:{scope}"),
            Fidelity::PartialStructured,
        )?
        .with_adapter_version(profile.version())?;
        if let Some((namespace, ordinal)) = identity.stable_sequence {
            bounded_identity(namespace)?;
            source = source
                .with_identity_source_sequence(namespace, ordinal)
                .map_err(|_| Failure::ReplayUnverifiable)?;
        }
        if let Some(native) = identity.native_coordinate {
            bounded_identity(native)?;
            source = source
                .with_native_id(native)
                .map_err(|_| Failure::ReplayUnverifiable)?;
        }
        let mut correlation = CorrelationIds::new();
        if let Some(id) = identity.request_id {
            bounded_identity(id)?;
            correlation = correlation.with_request_id(CorrelationId::source_reported(id)?);
        }
        Ok(Self {
            profile,
            source,
            correlation,
            limits,
            state: State::New,
            requested_model: String::new(),
            streaming: false,
            response: Vec::new(),
            frame_bytes: 0,
            line_bytes: 0,
            frames: 0,
            last_elapsed: 0,
            last_progress: 0,
        })
    }
    fn close(&mut self) {
        self.state = State::Closed;
        self.response = Vec::new();
        self.requested_model.clear();
    }
    pub fn accept_request(
        &mut self,
        bytes: &[u8],
        observed_at: ObservedAt,
    ) -> Result<Vec<CanonicalObservationV2>, Failure> {
        let result = (|| {
            if self.state != State::New {
                return Err(Failure::InvalidState);
            }
            if bytes.len() > self.limits.request_bytes {
                return Err(Failure::Capacity);
            }
            let value = json::parse(bytes, self.limits)?;
            self.requested_model = mapping::text(&value, "model")?.to_owned();
            self.streaming = match value.get("stream") {
                None => self.profile == Profile::OllamaChat,
                Some(v) => v.as_bool().ok_or(Failure::Malformed)?,
            };
            let batch = match self.profile {
                Profile::OpenAiChat => mapping::request(self, &value, observed_at),
                Profile::AnthropicMessages => anthropic::request(self, &value, observed_at),
                Profile::OpenAiResponses => responses::request(self, &value, observed_at),
                Profile::OllamaChat => ollama::request(self, &value, observed_at),
            }?;
            self.state = State::Requested;
            Ok(batch)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// No lifecycle fact is inferred from transport metadata. Format is selected
    /// explicitly and must agree with the accepted request's stream flag.
    pub fn begin_response(&mut self, format: ResponseFormat) -> Result<(), Failure> {
        let expected = if !self.streaming {
            ResponseFormat::Json
        } else if self.profile == Profile::OllamaChat {
            ResponseFormat::Ndjson
        } else {
            ResponseFormat::Sse
        };
        if self.state != State::Requested || format != expected {
            self.close();
            return Err(Failure::InvalidState);
        }
        self.state = State::Response(format);
        Ok(())
    }
    fn clock(&mut self, elapsed_ms: u64) -> Result<(), Failure> {
        if elapsed_ms < self.last_elapsed {
            return Err(Failure::InvalidState);
        }
        if elapsed_ms > self.limits.total_ms
            || elapsed_ms - self.last_progress > self.limits.idle_ms
        {
            return Err(Failure::Timeout);
        }
        self.last_elapsed = elapsed_ms;
        Ok(())
    }
    /// Never releases observations, including when this chunk contains [DONE].
    /// An empty push supplies a caller-owned deadline notification during silence.
    pub fn push_response(&mut self, bytes: &[u8], elapsed_ms: u64) -> Result<(), Failure> {
        let result = (|| {
            let State::Response(format) = self.state else {
                return Err(Failure::InvalidState);
            };
            self.clock(elapsed_ms)?;
            let size = self
                .response
                .len()
                .checked_add(bytes.len())
                .ok_or(Failure::Capacity)?;
            if size > self.limits.response_bytes {
                return Err(Failure::Capacity);
            }
            if format != ResponseFormat::Json {
                for &byte in bytes {
                    if format == ResponseFormat::Ndjson && self.frame_bytes == 0 {
                        self.frames += 1;
                        if self.frames > self.limits.frames {
                            return Err(Failure::Capacity);
                        }
                    }
                    self.frame_bytes += 1;
                    if self.frame_bytes > self.limits.frame_bytes {
                        return Err(Failure::Capacity);
                    }
                    if byte == b'\n' {
                        if self.line_bytes == 0 || format == ResponseFormat::Ndjson {
                            if format == ResponseFormat::Sse {
                                self.frames += 1;
                                if self.frames > self.limits.frames {
                                    return Err(Failure::Capacity);
                                }
                            }
                            self.frame_bytes = 0;
                        }
                        self.line_bytes = 0;
                    } else if byte != b'\r' {
                        self.line_bytes += 1;
                    }
                }
            }
            self.response.reserve_exact(bytes.len());
            self.response.extend_from_slice(bytes);
            if !bytes.is_empty() {
                self.last_progress = elapsed_ms;
            }
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn buffered_bytes(&self) -> usize {
        self.response.len()
    }
    /// Consumes the attempt, validates all trailing input, then atomically commits.
    /// EOF is explicitly an interruption; only Complete can commit.
    pub fn finish(
        mut self,
        reason: EndReason,
        observed_at: ObservedAt,
        elapsed_ms: u64,
    ) -> Result<Vec<CanonicalObservationV2>, Failure> {
        let State::Response(format) = self.state else {
            return Err(Failure::InvalidState);
        };
        self.clock(elapsed_ms)?;
        match reason {
            EndReason::Complete => {}
            EndReason::Eof => return Err(Failure::Incomplete),
            EndReason::Cancelled => return Err(Failure::Cancelled),
            EndReason::UpstreamError => return Err(Failure::UpstreamError),
            EndReason::TransportFailure => return Err(Failure::TransportFailure),
            EndReason::Timeout => return Err(Failure::Timeout),
        }
        match self.profile {
            Profile::OpenAiChat => mapping::response(&self, format, observed_at),
            Profile::AnthropicMessages => anthropic::response(&self, format, observed_at),
            Profile::OpenAiResponses => responses::response(&self, format, observed_at),
            Profile::OllamaChat => ollama::response(&self, format, observed_at),
        }
    }
}
fn bounded_identity(value: &str) -> Result<(), Failure> {
    if value.len() > 4096 {
        Err(Failure::ReplayUnverifiable)
    } else {
        Ok(())
    }
}
