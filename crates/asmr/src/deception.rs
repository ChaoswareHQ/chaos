//! Implements A17 (Deception and Active Defense).
//!
//! The formal object is the deception operator: instrumentation that produces
//! observations an honest environment would not, so that an adversary's
//! presence becomes measurable rather than merely inferable.
//!
//! The reason a monitoring algebra wants this: detection based only on
//! production traffic is bounded by how closely malicious activity resembles
//! benign activity. A decoy — a credential that should never be used, a file
//! that should never be read — breaks that ambiguity, because there is no
//! benign explanation for touching it. The cost is `fidelity`: a decoy that is
//! obviously fake is not touched, and one that is indistinguishable from real
//! data is a liability if it fails.
#![forbid(unsafe_code)]

/// A single piece of instrumentation.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoy {
    pub id: u32,
    pub kind: Box<str>,
    /// How convincing it is, in `[0, 1]`.
    pub fidelity: f64,
    /// Probability that an interaction with it is recorded, in `[0, 1]`.
    pub trip_rate: f64,
}

impl Decoy {
    pub fn new(id: u32, kind: &str, fidelity: f64, trip_rate: f64) -> Self {
        Self {
            id,
            kind: kind.into(),
            fidelity: fidelity.clamp(0.0, 1.0),
            trip_rate: trip_rate.clamp(0.0, 1.0),
        }
    }

    /// Expected detections per interaction: a convincing decoy is interacted
    /// with more, and a well-instrumented one reports more of what happens.
    fn yield_per_interaction(&self) -> f64 {
        self.fidelity * self.trip_rate
    }
}

/// A deployed set of decoys.
#[derive(Debug, Clone, Default)]
pub struct DecoySet {
    decoys: Vec<Decoy>,
}

impl DecoySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, d: Decoy) {
        self.decoys.push(d);
    }

    pub fn len(&self) -> usize {
        self.decoys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decoys.is_empty()
    }

    /// Expected detections from `interactions` interactions spread over the set.
    pub fn expected_detections(&self, interactions: f64) -> f64 {
        if interactions <= 0.0 {
            return 0.0;
        }
        self.decoys
            .iter()
            .map(|d| d.yield_per_interaction())
            .sum::<f64>()
            * interactions
    }

    /// The decoy to deploy first if you only get one.
    pub fn best(&self) -> Option<&Decoy> {
        self.decoys
            .iter()
            .fold(None, |best: Option<&Decoy>, d| match best {
                Some(b) if b.yield_per_interaction() >= d.yield_per_interaction() => Some(b),
                _ => Some(d),
            })
    }
}

/// A17: how much detection the deception buys you, as an absolute improvement.
///
/// Floors at zero on purpose. A decoy that makes detection *worse* is a real
/// failure mode — attention, storage and triage capacity all moved onto
/// something that does not catch attackers — but that harm belongs to the
/// decoy's own cost, not to a negative "gain". Report the cost separately.
pub fn deception_gain(p_detect_with: f64, p_detect_without: f64) -> f64 {
    (p_detect_with - p_detect_without).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_parameters_are_clamped_at_construction() {
        let d = Decoy::new(1, "credential", 1.5, -0.2);
        assert_eq!(d.fidelity, 1.0);
        assert_eq!(d.trip_rate, 0.0);
    }

    #[test]
    fn expected_detections_sum_over_the_set() {
        let mut s = DecoySet::new();
        s.add(Decoy::new(1, "credential", 1.0, 1.0)); // yields 1.0
        s.add(Decoy::new(2, "file", 0.5, 0.5)); // yields 0.25
        assert_eq!(s.expected_detections(10.0), 12.5);
        assert_eq!(s.expected_detections(0.0), 0.0);
        assert_eq!(s.expected_detections(-5.0), 0.0);
    }

    #[test]
    fn best_is_the_highest_yield_not_the_highest_fidelity() {
        let mut s = DecoySet::new();
        // Convincing but unseen.
        s.add(Decoy::new(1, "perfect", 1.0, 0.0));
        // Less convincing but actually instrumented.
        s.add(Decoy::new(2, "wired", 0.5, 1.0));
        assert_eq!(s.best().map(|d| d.id), Some(2));
    }

    #[test]
    fn an_empty_set_has_no_best_and_no_yield() {
        let s = DecoySet::new();
        assert_eq!(s.best(), None);
        assert_eq!(s.expected_detections(100.0), 0.0);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn gain_floors_at_zero_when_the_decoy_does_not_help() {
        assert_eq!(deception_gain(0.8, 0.3), 0.5);
        assert_eq!(deception_gain(0.3, 0.3), 0.0);
        assert_eq!(deception_gain(0.1, 0.9), 0.0, "harm is not a negative gain");
    }
}
