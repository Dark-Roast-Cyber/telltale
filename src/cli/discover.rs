//! Read-only, content-free tool inventory. This is not a detection scan.
//!
//! One independent inventory snapshot is written to stdout, never to the
//! Event3 journal or scanner state. Clocks and root selection belong to the CLI.

use clap::Args;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use telltale_discover::inventory::{InventoryContext, InventoryLimits, Platform};

#[derive(Args)]
pub(super) struct DiscoverArgs {
    /// Home directory to inspect. Defaults to HOME, then USERPROFILE.
    /// An explicit root ignores all ambient root variables.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Explicit generic data directory; must already exist.
    #[arg(long)]
    data_root: Option<PathBuf>,
    /// Explicit generic configuration directory; must already exist.
    #[arg(long)]
    config_root: Option<PathBuf>,
    /// Explicit platform application-data directory; must already exist.
    #[arg(long)]
    app_data_root: Option<PathBuf>,
    /// Aggregate metadata-operation budget, including root validation.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..=65536))]
    max_checks: u32,
    /// Print embedded third-party copyright/license terms without inspecting the host.
    #[arg(long, conflicts_with_all = ["root", "data_root", "config_root", "app_data_root"])]
    licenses: bool,
}

fn absolute(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::path::absolute(path).map_err(|_| "inventory root resolution failed".into())
}

pub(super) fn run(args: DiscoverArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.licenses {
        println!(
            "Tokscale MIT core catalog, revision {}\n\n{}",
            telltale_discover::catalog::TOKSCALE_REVISION,
            telltale_discover::TOKSCALE_LICENSE
        );
        return Ok(());
    }
    let home = args
        .root
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .ok_or("inventory home unavailable")?;
    let platform = if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Unknown
    };
    let mut context = InventoryContext::from_home(absolute(&home)?, platform);
    context.data_dir = args.data_root.as_deref().map(absolute).transpose()?;
    context.config_dir = args.config_root.as_deref().map(absolute).transpose()?;
    context.app_data_dir = args.app_data_root.as_deref().map(absolute).transpose()?;
    let observed_at = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "inventory clock unavailable")?
            .as_millis(),
    )
    .map_err(|_| "inventory clock out of range")?;
    let snapshot = telltale_discover::inventory::discover(
        &context,
        observed_at,
        InventoryLimits {
            max_checks: args.max_checks,
        },
    )?;
    println!("{}", serde_json::to_string(&snapshot)?);
    Ok(())
}
