//! The `telltale` binary. All behavior lives in the `telltale-cli` library;
//! this only maps the result to an exit code and sanitizes the error text.

use telltale_cli::run;
use telltale_schema::event::{PrivacySanitizer, SanitizationContext};

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let rendered = error.to_string();
            eprintln!(
                "{}",
                PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
            );
            std::process::ExitCode::FAILURE
        }
    }
}
