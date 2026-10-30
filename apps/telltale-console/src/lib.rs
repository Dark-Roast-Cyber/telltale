//! Telltale Console: a local desktop viewer for a Telltale JSONL event log.
//! It reads through `LocalEventFeed` and never writes events, state or
//! configuration; detection stays in the scanner.

pub mod startup;
pub mod state;
pub mod ui;
