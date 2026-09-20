//! A breakdown of events the translator did not recognise.
//!
//! The `unrecognised` counter in [`super::ShapeCounts`] is a single
//! number: it says the translator is dropping events but not which. This
//! map answers the only question that matters when deciding whether to
//! widen [`super::shape_of`]: *what is actually inside the dropped
//! traffic*.
//!
//! # No allocation on the hot path
//!
//! The map is nested — `provider → event_id → count` — rather than keyed
//! by `(String, u16)` as a flat map. The difference is the fast path:
//!
//! * Flat: `counts.get_mut(&(provider.to_string(), event_id))` allocates
//!   a `String` on **every** call, whether or not the key exists. On a
//!   desktop that is ~12,000 allocations per second for a set of keys
//!   that does not change.
//! * Nested: `counts.get_mut(provider)` takes a `&str` (via `Borrow`),
//!   which does not allocate. The provider name is allocated once, on
//!   first sighting, and never again.
//!
//! # Bounded growth
//!
//! Once `MAX_KEYS` distinct providers are held, further new providers are
//! folded into a single count. An attacker who emits a million distinct
//! event ids under a new provider name per event would otherwise grow
//! this map without limit.

use std::collections::BTreeMap;

/// After this many distinct providers, new providers are folded into a
/// catch-all.
///
/// A busy Windows host produces about five. A host producing thousands is
/// doing something deliberate, and the map should not grow to match it.
const MAX_KEYS: usize = 512;

#[derive(Debug, Default, Clone)]
pub struct UnrecognisedHistogram {
    /// Provider name → (event id → count). Nested so the fast path takes
    /// a `&str` and never allocates.
    counts: BTreeMap<String, BTreeMap<u16, u64>>,
    /// Providers seen after the cap was reached. Counted but not named.
    folded: u64,
    /// Every call, whether it landed in `counts` or in `folded`.
    total: u64,
}

impl UnrecognisedHistogram {
    pub fn note(&mut self, provider: &str, event_id: u16) {
        self.total += 1;

        // Fast path: the provider is already known. `BTreeMap<String, _>`'s
        // `get_mut` accepts `&str` because `String: Borrow<str>`, so this
        // is one descent and no allocation.
        if let Some(inner) = self.counts.get_mut(provider) {
            *inner.entry(event_id).or_insert(0) += 1;
            return;
        }

        // Slow path: first time this provider has been seen. The
        // allocation happens once per provider, bounded by `MAX_KEYS`.
        if self.counts.len() >= MAX_KEYS {
            self.folded += 1;
            return;
        }
        let mut inner = BTreeMap::new();
        inner.insert(event_id, 1);
        self.counts.insert(provider.to_string(), inner);
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// Total distinct `(provider, event_id)` pairs.
    pub fn distinct_keys(&self) -> usize {
        self.counts.values().map(|inner| inner.len()).sum()
    }

    /// Providers folded after the cap.
    pub fn folded(&self) -> u64 {
        self.folded
    }

    /// Number of distinct providers seen before the cap was reached.
    pub fn distinct_providers(&self) -> usize {
        self.counts.len()
    }

    /// Most frequent first.
    ///
    /// Ties broken by provider name then event id so two runs over the
    /// same traffic render identically. The sort is on the *output*
    /// vector, not the map, so the map's iteration order does not matter.
    pub fn top(&self, n: usize) -> Vec<(&str, u16, u64)> {
        let mut v: Vec<(&str, u16, u64)> = self
            .counts
            .iter()
            .flat_map(|(p, inner)| inner.iter().map(move |(id, c)| (p.as_str(), *id, *c)))
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
    fn new_providers_fold_after_the_cap() {
        let mut h = UnrecognisedHistogram::default();
        for i in 0..MAX_KEYS + 50 {
            h.note(&format!("provider-{i}"), 1);
        }
        assert_eq!(h.distinct_providers(), MAX_KEYS);
        assert_eq!(h.folded(), 50);
        assert_eq!(h.total(), MAX_KEYS as u64 + 50);
    }

    #[test]
    fn event_ids_under_one_provider_do_not_fold() {
        // The cap is on providers, not on total keys. A single provider
        // emitting a wide range of event ids is normal and must not be
        // truncated by the fold.
        let mut h = UnrecognisedHistogram::default();
        h.note("only-provider", 1);
        for id in 2..2_000u16 {
            h.note("only-provider", id);
        }
        assert_eq!(h.distinct_keys(), 1_999);
        assert_eq!(h.distinct_providers(), 1);
        assert_eq!(h.folded(), 0);
    }

    #[test]
    fn clear_resets_every_counter() {
        let mut h = UnrecognisedHistogram::default();
        h.note("p", 1);
        h.note("q", 2);
        h.clear();
        assert_eq!(h.total(), 0);
        assert_eq!(h.distinct_keys(), 0);
        assert_eq!(h.folded(), 0);
    }

    #[test]
    fn top_returns_at_most_n() {
        let mut h = UnrecognisedHistogram::default();
        for id in 0..10u16 {
            h.note("p", id);
        }
        assert_eq!(h.top(3).len(), 3);
        assert_eq!(h.top(100).len(), 10);
    }
}
