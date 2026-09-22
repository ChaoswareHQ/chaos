//! Per-shape counters and the gap detector.
//!
//! `attempted` counts events whose shape the translator recognised;
//! `mapped` counts those that produced a wire event. The difference is
//! `undecodable`, and `unrecognised` covers events whose `(provider, id)`
//! was not in [`super::shape_of`] at all.
//!
//! # Windowed counts
//!
//! [`detect_gaps`](super::Translator::detect_gaps) distinguishes three
//! conditions:
//!
//! * **DecodeFailure** — this run attempted the shape and did not map it.
//! * **Silent** — the shape fired in a *previous* window and has not fired
//!   in this one, while a shape of the opposite kind is still active.
//! * **Healthy** — either everything is working, or the shape has never
//!   fired and there is no evidence it should.
//!
//! The `Silent` case is only distinguishable from `Healthy` if the
//! per-window counters are reset periodically while the "has this shape
//! ever fired" flag survives the reset. [`ShapeCounts::reset_window`]
//! does that. A caller that wants a real gap detector calls it on a
//! timer; a caller that only wants per-run totals never calls it, and
//! the `Silent` verdict is unreachable, which is the correct behavior
//! for a single-window run.

use super::shape::Shape;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapeCounts {
    attempted: [u64; Shape::ALL.len()],
    mapped: [u64; Shape::ALL.len()],
    ever_fired: [bool; Shape::ALL.len()],
    unrecognised: u64,
}

impl Default for ShapeCounts {
    fn default() -> Self {
        Self {
            attempted: [0; Shape::ALL.len()],
            mapped: [0; Shape::ALL.len()],
            ever_fired: [false; Shape::ALL.len()],
            unrecognised: 0,
        }
    }
}

impl ShapeCounts {
    /// The index of `shape` in the per-shape arrays.
    #[inline]
    fn index(shape: Shape) -> usize {
        Shape::ALL
            .iter()
            .position(|s| *s == shape)
            .expect("every Shape variant is in Shape::ALL")
    }

    pub(crate) fn note_attempt(&mut self, shape: Shape) {
        let i = Self::index(shape);
        self.attempted[i] += 1;
        self.ever_fired[i] = true;
    }

    pub(crate) fn note_mapped(&mut self, shape: Shape) {
        self.mapped[Self::index(shape)] += 1;
    }

    pub(crate) fn note_unrecognised(&mut self) {
        self.unrecognised += 1;
    }

    /// Reset the per-window counters, keeping the "has this shape ever
    /// fired" flags.
    ///
    /// `detect_gaps` distinguishes "never fired" (untested, healthy)
    /// from "fired in a previous window and stopped" (suspicious). Those
    /// two cases are only distinguishable if the counts are reset
    /// periodically: without a reset, `attempted` grows monotonically
    /// and `ever_fired` is set the moment `attempted` becomes non-zero,
    /// so the "was firing, now silent" branch can never fire.
    ///
    /// A caller that wants a real gap detector calls this on a timer —
    /// once a minute, once every ten minutes, the interval is a
    /// deployment choice. A caller that only wants the per-run totals
    /// never calls it, and `ever_fired` plus the run's `attempted` are
    /// the totals they read.
    pub fn reset_window(&mut self) {
        self.attempted = [0; Shape::ALL.len()];
        self.mapped = [0; Shape::ALL.len()];
        // `ever_fired` and `unrecognised` are preserved.
    }

    pub fn attempted(&self, shape: Shape) -> u64 {
        self.attempted[Self::index(shape)]
    }

    pub fn mapped(&self, shape: Shape) -> u64 {
        self.mapped[Self::index(shape)]
    }

    pub fn undecodable(&self, shape: Shape) -> u64 {
        self.attempted(shape).saturating_sub(self.mapped(shape))
    }

    pub fn ever_fired(&self, shape: Shape) -> bool {
        self.ever_fired[Self::index(shape)]
    }

    pub fn unrecognised(&self) -> u64 {
        self.unrecognised
    }

    pub fn by_shape(&self) -> impl Iterator<Item = (Shape, u64, u64)> + '_ {
        Shape::ALL
            .iter()
            .copied()
            .map(|s| (s, self.attempted(s), self.mapped(s)))
    }

    pub fn total_attempted(&self) -> u64 {
        self.attempted.iter().sum()
    }

    pub fn total_mapped(&self) -> u64 {
        self.mapped.iter().sum()
    }

    pub fn kernel_side_active(&self) -> bool {
        Shape::ALL
            .iter()
            .copied()
            .filter(|s| s.is_kernel_side())
            .any(|s| self.attempted(s) > 0)
    }

    pub fn user_mode_active(&self) -> bool {
        Shape::ALL
            .iter()
            .copied()
            .filter(|s| s.is_user_mode())
            .any(|s| self.attempted(s) > 0)
    }
}

/// How serious a gap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapSeverity {
    Healthy,
    DecodeFailure,
    Silent,
}

/// A shape that should be producing events and is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryGap {
    pub shape: Shape,
    pub attempted: u64,
    pub mapped: u64,
    pub severity: GapSeverity,
}

impl TelemetryGap {
    pub fn describe(&self) -> String {
        match self.severity {
            GapSeverity::Healthy => format!("{}: healthy", self.shape.as_str()),
            GapSeverity::DecodeFailure => format!(
                "{}: {} of {} events failed to decode (table problem, not an attack)",
                self.shape.as_str(),
                self.attempted - self.mapped,
                self.attempted
            ),
            GapSeverity::Silent => format!(
                "{}: silent while other shapes are active (possible ETW bypass)",
                self.shape.as_str()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_indexed_by_shape() {
        let mut c = ShapeCounts::default();
        c.note_attempt(Shape::ProcessStart);
        c.note_attempt(Shape::ProcessStart);
        c.note_mapped(Shape::ProcessStart);
        c.note_attempt(Shape::ImageLoad);
        c.note_unrecognised();

        assert_eq!(c.attempted(Shape::ProcessStart), 2);
        assert_eq!(c.mapped(Shape::ProcessStart), 1);
        assert_eq!(c.undecodable(Shape::ProcessStart), 1);
        assert_eq!(c.attempted(Shape::ImageLoad), 1);
        assert_eq!(c.unrecognised(), 1);
        assert_eq!(c.total_attempted(), 3);
        assert_eq!(c.total_mapped(), 1);
    }

    #[test]
    fn kernel_and_user_mode_activity_are_independent() {
        let mut c = ShapeCounts::default();
        c.note_attempt(Shape::ImageLoad);
        assert!(c.kernel_side_active());
        assert!(!c.user_mode_active());

        let mut c = ShapeCounts::default();
        c.note_attempt(Shape::DnsQuery);
        assert!(!c.kernel_side_active());
        assert!(c.user_mode_active());
    }

    #[test]
    fn ever_fired_tracks_attempts_not_mappings() {
        let mut c = ShapeCounts::default();
        assert!(!c.ever_fired(Shape::RegistrySet));
        c.note_attempt(Shape::RegistrySet);
        assert!(c.ever_fired(Shape::RegistrySet));
        // Still true even though nothing mapped.
        assert_eq!(c.mapped(Shape::RegistrySet), 0);
    }

    #[test]
    fn the_arrays_are_sized_for_every_shape() {
        let c = ShapeCounts::default();
        // The count is `Shape::ALL.len()` and changes whenever a shape
        // is added. Fifteen today: six original (ProcessStart, ProcessExit,
        // ImageLoad, RegistrySet, DnsQuery, ScriptBlock), six from
        // Phase 1 (FileCreate, FileRename, FileDelete, NetworkConnect,
        // NetworkDisconnect, ProcessStartAudit), and three from Phase 2
        // (WmiProcess, WmiSubscription, TaskRegistered).
        assert_eq!(Shape::ALL.len(), 15);
        // Every shape must be indexable without panicking.
        for shape in Shape::ALL {
            assert_eq!(c.attempted(*shape), 0);
            assert_eq!(c.mapped(*shape), 0);
            assert!(!c.ever_fired(*shape));
        }
    }

    #[test]
    fn by_shape_iterates_in_declaration_order() {
        let c = ShapeCounts::default();
        let seen: Vec<Shape> = c.by_shape().map(|(s, _, _)| s).collect();
        assert_eq!(seen, Shape::ALL.to_vec());
    }

    #[test]
    fn gap_severity_orders_silent_above_decode_failure() {
        assert!(GapSeverity::Silent > GapSeverity::DecodeFailure);
        assert!(GapSeverity::DecodeFailure > GapSeverity::Healthy);
    }

    #[test]
    fn a_gap_describes_itself() {
        let silent = TelemetryGap {
            shape: Shape::ScriptBlock,
            attempted: 0,
            mapped: 0,
            severity: GapSeverity::Silent,
        };
        let text = silent.describe();
        assert!(text.contains("script_block"));
        assert!(text.contains("silent"));

        let decode = TelemetryGap {
            shape: Shape::RegistrySet,
            attempted: 10,
            mapped: 3,
            severity: GapSeverity::DecodeFailure,
        };
        let text = decode.describe();
        assert!(text.contains("registry_set"));
        assert!(text.contains("7 of 10"));
    }

    #[test]
    fn reset_window_clears_the_attempts_but_keeps_ever_fired() {
        let mut c = ShapeCounts::default();
        c.note_attempt(Shape::DnsQuery);
        c.note_mapped(Shape::DnsQuery);
        c.note_unrecognised();

        assert_eq!(c.attempted(Shape::DnsQuery), 1);
        assert!(c.ever_fired(Shape::DnsQuery));

        c.reset_window();

        assert_eq!(c.attempted(Shape::DnsQuery), 0, "attempts are per-window");
        assert_eq!(c.mapped(Shape::DnsQuery), 0, "mappings are per-window");
        assert!(
            c.ever_fired(Shape::DnsQuery),
            "the ever-fired flag is what makes the next window able to say silent"
        );
        assert_eq!(
            c.unrecognised(),
            1,
            "the unrecognised counter is a run total, not a window total"
        );
    }
}
