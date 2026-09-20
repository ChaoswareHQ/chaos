//! Per-shape counters and the gap detector.
//!
//! `attempted` counts events whose shape the translator recognised;
//! `mapped` counts those that produced a wire event. The difference is
//! `undecodable`, and `unrecognised` covers events whose `(provider, id)`
//! was not in [`super::shape_of`] at all. The three together close the
//! accounting: `delivered == mapped + undecodable + unrecognised`.
//!
//! The per-shape arrays are sized by `Shape::ALL.len()` rather than a
//! literal, so adding a shape in `shape.rs` cannot leave these arrays the
//! wrong size. That was the point of the macro.

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
    ///
    /// This is its position in [`Shape::ALL`], which the macro guarantees
    /// equals the enum discriminant. Computed rather than cast so that
    /// reordering `ALL` without reordering the enum fails loudly here.
    #[inline]
    fn index(shape: Shape) -> usize {
        // `position` on a six-element slice is a linear scan of at most
        // six comparisons, cheaper than the atomic increments around it.
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
///
/// Order matters: [`GapSeverity::Silent`] sorts above
/// [`GapSeverity::DecodeFailure`] so the gap list puts the suspicious
/// findings first.
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
        assert_eq!(Shape::ALL.len(), 6);
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
}
