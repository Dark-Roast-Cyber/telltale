use super::super::discovery::ProjectConfigurationAccounting;
use super::*;
use telltale_schema::clients::{ClientId, SourceKind};

fn change(path: PathBuf) -> NotifyEvent {
    NotifyEvent::new(EventKind::Modify(notify::event::ModifyKind::Any)).add_path(path)
}

mod event_admission;
mod heartbeat;
mod rescan_planning;
mod sqlite_sidecars;
