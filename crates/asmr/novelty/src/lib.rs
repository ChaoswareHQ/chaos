//! Implements A22 (Novelty Measurement).
//!
//! The formal object is novelty relative to what has been observed: a function
//! from an item to how surprising it is given the history, plus an estimate of
//! how much of the population that history covers.
//!
//! For an XDR pipeline the value is in the first-seen case. A binary that has
//! never appeared on this host is interesting even if nothing is known to be
//! wrong with it, and that signal is only available if you kept the set of what
//! you have seen. The coverage estimate is the honest counterpart: it says how
//! much you should trust "we have not seen this before" as evidence.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// Counts of everything seen so far.
#[derive(Debug, Clone, Default)]
pub struct NoveltyModel {
    counts: BTreeMap<Box<str>, u32>,
    total: u64,
}

impl NoveltyModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sighting and return the item's new count.
    pub fn observe(&mut self, item: &str) -> u32 {
        self.total += 1;
        let entry = self.counts.entry(item.into()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    pub fn count(&self, item: &str) -> u32 {
        self.counts.get(item).copied().unwrap_or(0)
    }

    pub fn distinct(&self) -> usize {
        self.counts.len()
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn is_novel(&self, item: &str) -> bool {
        self.count(item) == 0
    }

    /// `1.0` for a never-seen item, then `1 / (1 + count)`.
    ///
    /// The harmonic shape is deliberate: the drop from first to second sighting
    /// is the informative one, and further sightings should decay slowly rather
    /// than fall off a cliff.
    pub fn score(&self, item: &str) -> f64 {
        1.0 / (1.0 + f64::from(self.count(item)))
    }
}

/// Share of sightings that were first sightings.
pub fn novelty_rate(novel: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (novel as f64 / total as f64).clamp(0.0, 1.0)
}

/// Good-Turing-flavoured coverage estimate: of the distinct items we have seen
/// plus the novel sightings that kept arriving, what fraction is the seen part?
///
/// A high novel-sighting count means the population keeps surprising us, so our
/// "seen it before" set is a poor description of it. This is the number to
/// subtract from confidence in any novelty-based verdict.
pub fn coverage_estimate(distinct: usize, novel_sightings: u64) -> f64 {
    let denominator = distinct as f64 + novel_sightings as f64;
    if denominator == 0.0 {
        return 1.0;
    }
    (distinct as f64 / denominator).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sighting_is_maximally_novel_then_decays() {
        let mut m = NoveltyModel::new();
        assert!(m.is_novel("a.exe"));
        assert_eq!(m.score("a.exe"), 1.0);

        assert_eq!(m.observe("a.exe"), 1);
        assert!(!m.is_novel("a.exe"));
        assert_eq!(m.score("a.exe"), 0.5);

        assert_eq!(m.observe("a.exe"), 2);
        assert_eq!(m.score("a.exe"), 1.0 / 3.0);
    }

    #[test]
    fn bookkeeping_counts_items_and_sightings_separately() {
        let mut m = NoveltyModel::new();
        m.observe("a");
        m.observe("a");
        m.observe("b");
        assert_eq!(m.distinct(), 2);
        assert_eq!(m.total(), 3);
        assert_eq!(m.count("a"), 2);
        assert_eq!(m.count("missing"), 0);
    }

    #[test]
    fn novelty_rate_boundaries() {
        assert_eq!(novelty_rate(0, 0), 0.0);
        assert_eq!(novelty_rate(0, 10), 0.0);
        assert_eq!(novelty_rate(10, 10), 1.0);
        assert_eq!(novelty_rate(5, 10), 0.5);
        // Clamped: a caller passing nonsense must not get a rate above 1.
        assert_eq!(novelty_rate(20, 10), 1.0);
    }

    #[test]
    fn coverage_is_one_until_novelty_is_observed() {
        assert_eq!(coverage_estimate(0, 0), 1.0);
        assert_eq!(coverage_estimate(10, 0), 1.0);
        assert_eq!(coverage_estimate(10, 10), 0.5);
        assert!(coverage_estimate(10, 90) < 0.11);
    }

    #[test]
    fn a_saturated_model_stops_claiming_novelty() {
        let mut m = NoveltyModel::new();
        for _ in 0..10 {
            m.observe("seen.exe");
        }
        assert!(!m.is_novel("seen.exe"));
        assert!(m.score("seen.exe") < 0.1);
        assert_eq!(coverage_estimate(m.distinct(), 0), 1.0);
    }
}
