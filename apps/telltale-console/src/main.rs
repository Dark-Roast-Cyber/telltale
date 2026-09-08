use clap::Parser;
use std::time::{Duration, Instant};
use telltale_console::{
    startup::{Options, poll_delay},
    state::ConsoleState,
    ui::ConsoleUi,
};
use telltale_core::LocalEventFeed;

struct ConsoleApp {
    feed: LocalEventFeed,
    state: ConsoleState,
    ui: ConsoleUi,
    location: String,
    next_poll: Instant,
    feed_error: bool,
}

impl eframe::App for ConsoleApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if Instant::now() >= self.next_poll {
            let delay = match self.feed.poll() {
                Ok(batch) => {
                    let delay = poll_delay(&batch);
                    self.state.ingest(batch);
                    delay
                }
                Err(_) => {
                    self.state.mark_feed_error();
                    self.feed_error = true;
                    Duration::from_millis(500)
                }
            };
            self.next_poll = Instant::now() + delay;
        }
        ctx.request_repaint_after(self.next_poll.saturating_duration_since(Instant::now()));
    }

    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.ui.render(root, &mut self.state, &self.location);
        if self.feed_error {
            egui::Window::new("Feed configuration error")
                .collapsible(false)
                .show(root.ctx(), |ui| {
                    ui.label(
                        "The local feed could not be polled. Restart with a valid configuration.",
                    );
                });
        }
    }
}

fn main() -> std::process::ExitCode {
    let options = Options::parse();
    let config = options.feed_config();
    let location = format!(
        "Profile: {:?} · Event3 journal: {}",
        options.path_profile,
        config.path.display()
    );
    let Ok(feed) = LocalEventFeed::new(config) else {
        eprintln!("Telltale Console: invalid local feed configuration.");
        return std::process::ExitCode::FAILURE;
    };
    let app = ConsoleApp {
        feed,
        state: ConsoleState::default(),
        ui: ConsoleUi::default(),
        location,
        next_poll: Instant::now(),
        feed_error: false,
    };
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([640.0, 400.0]),
        ..Default::default()
    };
    if eframe::run_native("Telltale Console", native, Box::new(|_| Ok(Box::new(app)))).is_err() {
        eprintln!("Telltale Console: native display initialization or rendering failed.");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
