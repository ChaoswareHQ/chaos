//! A breakdown of events the translator did not recognise.
//!
//! The `unrecognised` counter in [`super::ShapeCounts`] is a single number:
//! it says the translator is dropping events but not which. This map answers
//! the only question that matters when deciding whether to widen
//! [`super::shape::shape_of`]: *what is actually inside the dropped traffic*.
//!
//! Bounded growth: an attacker who emits a million distinct event ids would
//! otherwise grow this map without limit. Once `MAX_KEYS` is reached, new
//! keys are folded into a single count.

use std::collections::BTreeMap;

/// After this many distinct `(provider, id)` pairs, new keys are folded
/// into a catch-all. A busy Windows host produces ~30 distinct pairs; a
/// host producing thousands is doing something deliberate.
const MAX_KEYS: usize = 512;

#[derive(Debug, Default, Clone)]
pub struct UnrecognisedHistogram {
    counts: BTreeMap<(String, u16), u64>,
    folded: u64,
    total: u64,
}

impl UnrecognisedHistogram {
    pub fn note(&mut self, provider: &str, event_id: u16) {
        self.total += 1;
        if let Some(slot) = self.counts.get_mut(&(provider.to_string(), event_id)) {
            *slot += 1;
            return;
        }
        if self.counts.len() >= MAX_KEYS {
            self.folded += 1;
            return;
        }
        self.counts.insert((provider.to_string(), event_id), 1);
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn distinct_keys(&self) -> usize {
        self.counts.len()
    }

    pub fn folded(&self) -> u64 {
        self.folded
    }

    /// Most frequent first. Ties broken by provider name then event id so
    /// two runs over the same traffic render identically.
    pub fn top(&self, n: usize) -> Vec<(&str, u16, u64)> {
        let mut v: Vec<(&str, u16, u64)> = self
            .counts
            .iter()
            .map(|((p, id), c)| (p.as_str(), *id, *c))
            .collect();
        v.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then_with(|| a.0.cmp(b.0))
                .then_with(|| a.1.cmp(&b.1))
        });
        v.truncate(n);
        v
    }

    pub fn clear(&mut self) {
        self.counts.clear();
        self.folded = 0;
        self.total = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counting_the_same_pair_twice_keeps_one_key() {
        let mut h = UnrecognisedHistogram::default();
        h.note("p", 1);
        h.note("p", 1);
        h.note("p", 2);
        assert_eq!(h.distinct_keys(), 2);
        assert_eq!(h.total(), 3);
        let top = h.top(10);
        assert_eq!(top[0], ("p", 1, 2));
        assert_eq!(top[1], ("p", 2, 1));
    }

    #[test]
    fn ties_break_deterministically() {
        let mut h = UnrecognisedHistogram::default();
        h.note("b", 1);
        h.note("a", 2);
        h.note("a", 1);
        assert_eq!(h.top(10), vec![("a", 1, 1), ("a", 2, 1), ("b", 1, 1)]);
    }

    #[test]
    fn new_keys_fold_after_the_cap() {
        let mut h = UnrecognisedHistogram::default();
        for i in 0..MAX_KEYS as u16 + 50 {
            h.note("p", i);
        }
        assert_eq!(h.distinct_keys(), MAX_KEYS);
        assert_eq!(h.folded(), 50);
        assert_eq!(h.total(), MAX_KEYS as u64 + 50);
    }
}
