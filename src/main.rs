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
