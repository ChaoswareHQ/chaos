//! Per-shape counters and the gap detector.
//!
//! `attempted` counts events whose shape the translator recognised;
//! `mapped` counts those that produced a wire event. The difference is
//! `undecodable`, and `unrecognised` covers events whose `(provider, id)`
//! was not in `shape_of` at all. The three together close the accounting:
//! `delivered == mapped + undecodable + unrecognised`.

use super::shape::Shape;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShapeCounts {
    attempted: [u64; 6],
    mapped: [u64; 6],
    ever_fired: [bool; 6],
    unrecognised: u64,
}

impl ShapeCounts {
    pub(crate) fn note_attempt(&mut self, shape: Shape) {
        self.attempted[shape as usize] += 1;
        self.ever_fired[shape as usize] = true;
    }

    pub(crate) fn note_mapped(&mut self, shape: Shape) {
        self.mapped[shape as usize] += 1;
    }

    pub(crate) fn note_unrecognised(&mut self) {
        self.unrecognised += 1;
    }

    pub fn attempted(&self, shape: Shape) -> u64 {
        self.attempted[shape as usize]
    }

    pub fn mapped(&self, shape: Shape) -> u64 {
        self.mapped[shape as usize]
    }

    pub fn undecodable(&self, shape: Shape) -> u64 {
        self.attempted(shape).saturating_sub(self.mapped(shape))
    }

    pub fn ever_fired(&self, shape: Shape) -> bool {
        self.ever_fired[shape as usize]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapSeverity {
    Healthy,
    DecodeFailure,
    Silent,
}

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
}
