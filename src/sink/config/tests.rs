use std::path::PathBuf;

use tempfile::tempdir;
#[cfg(unix)]
use tempfile::tempdir_in;

use super::{
    CliSinkOverrides, DeliveryConfig, SecretValue, SinkKind, SinkSpec, build_sink_set,
    build_sink_set_with_presence_and_delivery_for_platform, load_outputs_config_with_delivery,
};
#[cfg(not(windows))]
use super::{
    ConfigDeliveryPolicy, JsonlSpec, build_sink_set_with_presence_and_delivery_for_validation,
};
#[cfg(not(windows))]
use crate::sink::outbox::{CapacityLimits, DEFAULT_MAX_PENDING_BYTES, DEFAULT_MAX_PENDING_EVENTS};
use crate::sink::{DeliveryError, DeliveryErrorClass};

fn load_outputs_config(paths: &[PathBuf]) -> Result<Vec<SinkSpec>, Box<dyn std::error::Error>> {
    Ok(load_outputs_config_with_delivery(paths)?.sinks)
}
use crate::sink::RotationConfig;

fn write_outputs(dir: &std::path::Path, file_name: &str, contents: &str) -> PathBuf {
    let path = dir.join(file_name);
    std::fs::write(&path, contents).expect("write outputs yaml");
    path
}

fn cli_defaults<'a>(log_path: &'a std::path::Path) -> CliSinkOverrides<'a> {
    CliSinkOverrides {
        log_path,
        rotation: RotationConfig::default(),
        splunk_hec_endpoint: None,
        splunk_hec_token: None,
    }
}

#[cfg(unix)]
fn pure_durable_sink_set(
    log_path: &std::path::Path,
    outbox_path: &std::path::Path,
) -> Result<crate::sink::SinkSet, Box<dyn std::error::Error>> {
    let specs = [SinkSpec {
        name: "canonical".to_string(),
        enabled: true,
        kind: SinkKind::Jsonl(JsonlSpec {
            path: Some(log_path.to_path_buf()),
            rotation: None,
        }),
        origin_path: None,
    }];
    let delivery = DeliveryConfig {
        policy: ConfigDeliveryPolicy::Durable,
        outbox_path: Some(outbox_path.to_path_buf()),
        capacity_limits: CapacityLimits::default(),
    };
    build_sink_set_with_presence_and_delivery_for_validation(
        &specs,
        true,
        &cli_defaults(log_path),
        &delivery,
        false,
    )
}

mod building;
mod durable_mode;
mod parsing;
#[cfg(unix)]
mod path_aliases;
