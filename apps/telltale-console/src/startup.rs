use clap::{Parser, ValueEnum};
use std::{path::PathBuf, time::Duration};
use telltale_core::{FeedBatch, LocalEventFeedConfig, PathProfile, StartupMode};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    #[default]
    User,
    System,
    Project,
}

#[derive(Debug, Parser)]
#[command(
    name = "telltale-console",
    version,
    about = "Read-only local Telltale Event3 console"
)]
pub struct Options {
    #[arg(long, value_enum, default_value = "user")]
    pub path_profile: Profile,
    #[arg(long, value_name = "PATH")]
    pub log_path: Option<PathBuf>,
}

impl Options {
    pub fn feed_config(&self) -> LocalEventFeedConfig {
        let profile = match self.path_profile {
            Profile::User => PathProfile::User,
            Profile::System => PathProfile::System,
            Profile::Project => PathProfile::Project,
        };
        LocalEventFeedConfig::for_profile(
            profile,
            self.log_path.clone(),
            StartupMode::Recent {
                max_events: 100,
                max_bytes: 256 * 1024,
            },
        )
    }
}

pub fn poll_delay(batch: &FeedBatch) -> Duration {
    // An incomplete tail or persistent integrity bound is not drainable backlog.
    if batch.caught_up || (batch.bytes_read == 0 && batch.records.is_empty()) {
        Duration::from_millis(500)
    } else {
        Duration::from_millis(1)
    }
}
