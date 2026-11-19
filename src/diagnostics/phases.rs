//! A monotonic clock that splits one run into contiguous named phases.
//!
//! Entering a phase closes the current one at the same instant, so the time
//! spent in every phase adds up exactly to the run's total. A phase entered
//! more than once accumulates. A phase never entered has no time (`None`),
//! which is different from a phase that ran and took no measurable time.

use std::time::{Duration, Instant};

/// A closed set of phases. `ALL` lists every phase once.
pub(crate) trait Phase: Copy + Eq + 'static {
    const ALL: &'static [Self];

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|phase| *phase == self)
            .expect("every phase is listed in ALL")
    }
}

pub(crate) struct PhaseClock<P: Phase> {
    started: Instant,
    current: P,
    since: Instant,
    spent: Vec<Option<Duration>>,
}

impl<P: Phase> PhaseClock<P> {
    /// Starts timing `phase` at `at`.
    pub(crate) fn start_at(phase: P, at: Instant) -> Self {
        Self {
            started: at,
            current: phase,
            since: at,
            spent: vec![None; P::ALL.len()],
        }
    }

    pub(crate) fn enter(&mut self, phase: P) {
        self.enter_at(phase, Instant::now());
    }

    /// Closes the current phase at `at` and starts `phase` there.
    pub(crate) fn enter_at(&mut self, phase: P, at: Instant) {
        self.close_at(at);
        self.current = phase;
    }

    /// Closes the current phase at `at`; it stays current, so a later
    /// failure can still be attributed to it.
    pub(crate) fn close_at(&mut self, at: Instant) {
        let elapsed = at.saturating_duration_since(self.since);
        let slot = &mut self.spent[self.current.index()];
        *slot = Some(slot.unwrap_or_default().saturating_add(elapsed));
        self.since = at;
    }

    pub(crate) fn current(&self) -> P {
        self.current
    }

    /// Time spent in `phase`, or `None` if it was never entered.
    pub(crate) fn spent(&self, phase: P) -> Option<Duration> {
        self.spent[phase.index()]
    }

    /// From the start to the last time a phase was closed.
    pub(crate) fn total(&self) -> Duration {
        self.since.saturating_duration_since(self.started)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        First,
        Second,
        Unused,
    }

    impl Phase for Step {
        const ALL: &'static [Self] = &[Self::First, Self::Second, Self::Unused];
    }

    #[test]
    fn phases_are_contiguous_and_add_up_to_the_total() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut clock = PhaseClock::start_at(Step::First, start);
        clock.enter_at(Step::Second, at(3));
        clock.enter_at(Step::First, at(10));
        clock.close_at(at(12));

        assert_eq!(clock.spent(Step::First), Some(Duration::from_millis(5)));
        assert_eq!(clock.spent(Step::Second), Some(Duration::from_millis(7)));
        assert_eq!(clock.spent(Step::Unused), None);
        assert_eq!(clock.total(), Duration::from_millis(12));
        assert_eq!(clock.current(), Step::First);
    }

    #[test]
    fn a_phase_that_ran_instantly_has_zero_time_not_none() {
        let start = Instant::now();
        let mut clock = PhaseClock::start_at(Step::First, start);
        clock.enter_at(Step::Second, start);
        clock.close_at(start);
        assert_eq!(clock.spent(Step::First), Some(Duration::ZERO));
        assert_eq!(clock.spent(Step::Second), Some(Duration::ZERO));
    }
}
