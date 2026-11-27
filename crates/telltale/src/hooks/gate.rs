//! The one place a hook's answer is released to the harness.
//!
//! A harness hook can stop a tool call in three ways: a decision on stdout, a
//! non-zero exit status, or by not returning in time when the harness is set
//! to block on a failed hook. In detect-only mode none of them may happen,
//! whatever the rest of the hook did: a rule matched, the payload was
//! unreadable, the configuration is broken, or the code panicked. So nothing
//! in the hook writes to stdout or picks the exit status on its own. It
//! builds an [`Answer`], and the [`Gate`] decides what leaves the process.
//!
//! The gate is closed unless the configuration was read and says
//! `mode: enforce`. Every other state is detect-only, including "no
//! configuration" and "a configuration that could not be loaded and never
//! asked for enforcement".

use std::time::Duration;

use serde_json::Value;

use crate::hooks::config::{Config, Mode};

/// What a hook would give the harness: stdout JSON and an exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub output: Option<Value>,
    pub exit_code: i32,
}

impl Answer {
    /// No opinion: nothing on stdout, success.
    pub const NONE: Self = Self {
        output: None,
        exit_code: 0,
    };

    /// `output` on stdout (if any) and success.
    pub fn output(output: Option<Value>) -> Self {
        Self {
            output,
            exit_code: 0,
        }
    }

    /// Nothing on stdout and a failure status. What that means is the
    /// harness's business: Copilot CLI blocks the call, others carry on.
    pub fn exit(exit_code: i32) -> Self {
        Self {
            output: None,
            exit_code,
        }
    }
}

/// Whether this hook invocation may influence the harness at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Nothing reaches the harness: empty stdout, exit status 0, on time.
    DetectOnly,
    /// The answer is released as built.
    Enforce,
}

/// How long a detect-only hook may run before it gives up and exits 0, so
/// that a stalled hook is never a block where the harness is set to block on
/// a hook that times out. Below the 30 s the generated settings give a
/// pre-execution hook; an operator who sets a shorter timeout together with a
/// block-on-failure option has asked for blocking by other means.
pub const DETECT_ONLY_DEADLINE: Duration = Duration::from_secs(20);

impl Gate {
    /// The gate for a configuration as the host loaded it. `declares_enforce`
    /// is asked only when the configuration did not load: whether what could
    /// not be loaded still asks for enforcement.
    pub fn for_config<E>(
        loaded: &Result<Config, E>,
        declares_enforce: impl FnOnce() -> bool,
    ) -> Self {
        match loaded {
            Ok(config) => Self::for_mode(config.mode),
            Err(_) if declares_enforce() => Self::Enforce,
            Err(_) => Self::DetectOnly,
        }
    }

    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Enforce => Self::Enforce,
            Mode::Observe => Self::DetectOnly,
        }
    }

    /// What the harness is given for `answer`.
    pub fn release(self, answer: Answer) -> Answer {
        match self {
            Self::DetectOnly => Answer::NONE,
            Self::Enforce => answer,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DetectOnly => "detect_only",
            Self::Enforce => "enforce",
        }
    }
}

#[cfg(test)]
mod tests;
