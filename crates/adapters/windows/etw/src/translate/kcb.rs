//! Key Control Block correlation for `Microsoft-Windows-Kernel-Registry`.
//!
//! # Why this exists
//!
//! `SetValueKey` (id 5) fires inside the kernel at the moment of the write.
//! At that moment the kernel holds a **KCB** — a pointer to a key control
//! block — not a path. Resolving the pointer to
//! `\REGISTRY\MACHINE\SOFTWARE\...` requires walking the registry tree, and
//! the provider does not do that. So the manifest declares a `KeyName`
//! field, the field is empty at runtime, and no amount of renaming the field
//! chain will produce a path that isn't there.
//!
//! The events that *do* carry a path are the ones that name it at the point
//! the kernel already had to resolve it: `OpenKey`, `CreateKey`, `QueryKey`,
//! and the `KCBCreate` family. This module learns `KeyObject → KeyName` from
//! every such event the sensor already observes, and the decoder then looks
//! up the path for `SetValueKey`.
//!
//! # Bounds and correctness
//!
//! The cache is **bounded**: after [`DEFAULT_CAPACITY`] entries, the oldest
//! insertion is evicted. That is FIFO, not LRU, and the difference matters
//! only under a workload where a KCB is created once and referenced
//! continuously while thousands of other KCBs come and go — rare in
//! practice, and the failure mode is a cache miss (the event falls through
//! to the "no path" failure path), not a wrong answer.
//!
//! Staleness is possible in one direction: a KCB destroyed and its address
//! reused by a new KCB would produce a wrong path. The cache detects this
//! on the *next learn* for the same `KeyObject` — `learn` replaces the entry
//! when the path differs — so the window of incorrectness is bounded by how
//! long it takes the new KCB's owning event to arrive. In practice this is
//! microseconds; the KCB address is not reused until the tree walk that
//! created the first one has fully unwound.
//!
//! # Sharing
//!
//! `KeyCache` is `Arc<Mutex<Inner>>` internally, so `Clone` shares the
//! inner state. That matters for the observer, where N decode workers each
//! own a `Translator`: without sharing, a `KCBCreate` seen by worker 1 would
//! be invisible to worker 2, which would miss the correlation on its own
//! `SetValueKey` events. On a single-threaded translator it is a no-op.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

/// Default cap. 32,768 entries at roughly 80 bytes each is about 2.5 MB,
/// which is small enough to ignore on a desktop and large enough that a
/// week of normal activity does not exhaust it before the working set
/// turns over.
pub const DEFAULT_CAPACITY: usize = 32_768;

/// A pointer → path cache, shared cheaply.
#[derive(Debug, Clone)]
pub struct KeyCache {
    inner: Arc<Mutex<Inner>>,
    capacity: usize,
}

#[derive(Debug)]
struct Inner {
    map: HashMap<u64, Box<str>>,
    /// Insertion order, oldest first. `VecDeque` because eviction pops from
    /// the front and insertion pushes to the back, both O(1).
    order: VecDeque<u64>,
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl KeyCache {
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::with_capacity(capacity.min(4096)),
                order: VecDeque::with_capacity(capacity.min(4096)),
            })),
            capacity,
        }
    }

    /// Record that `key_object` maps to `path`.
    ///
    /// Zero and empty are refused rather than stored: a zero pointer is the
    /// "not present" sentinel in every kernel structure we read, and an empty
    /// path is TDH saying "declared but not populated". Neither is a fact
    /// worth keeping, and storing them would let a lookup find a wrong
    /// answer instead of falling through to the miss path.
    ///
    /// A path that differs from one already stored for the same pointer is
    /// treated as a replacement, not a conflict: the only way that happens is
    /// KCB address reuse, and the newer path is the true one.
    pub fn learn(&self, key_object: u64, path: &str) {
        if key_object == 0 || path.is_empty() {
            return;
        }
        let mut inner = self.lock();
        if let Some(existing) = inner.map.get_mut(&key_object) {
            if existing.as_ref() != path {
                *existing = path.into();
            }
            return;
        }
        if inner.map.len() >= self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
        inner.map.insert(key_object, path.into());
        inner.order.push_back(key_object);
    }

    /// Look up the path for a key object.
    ///
    /// Returns an owned `String` rather than a borrow, because the caller is
    /// in the middle of a decode and cannot hold the lock across TDH calls.
    /// The allocation is one per correlated `SetValueKey`; on a desktop that
    /// is tens per second, not thousands.
    pub fn lookup(&self, key_object: u64) -> Option<String> {
        if key_object == 0 {
            return None;
        }
        self.lock().map.get(&key_object).map(|s| s.to_string())
    }

    /// How many entries are held. For the run report.
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Recover from a poisoned lock rather than panic. A panic while
        // holding this lock means one decode aborted mid-insert; the cache
        // is still usable, and refusing every subsequent lookup would turn
        // a single bad event into a dead sensor.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learn_then_lookup_round_trips() {
        let cache = KeyCache::default();
        cache.learn(0xdead_beef, r"\REGISTRY\MACHINE\SOFTWARE\Example");
        assert_eq!(
            cache.lookup(0xdead_beef).as_deref(),
            Some(r"\REGISTRY\MACHINE\SOFTWARE\Example"),
        );
    }

    #[test]
    fn zero_and_empty_are_never_stored_or_found() {
        let cache = KeyCache::default();
        cache.learn(0, r"\REGISTRY\MACHINE");
        cache.learn(1, "");
        assert!(cache.is_empty());
        assert_eq!(cache.lookup(0), None);
        assert_eq!(cache.lookup(1), None);
    }

    #[test]
    fn learning_the_same_pointer_twice_does_not_grow_the_cache() {
        let cache = KeyCache::default();
        cache.learn(7, r"\REGISTRY\MACHINE");
        cache.learn(7, r"\REGISTRY\MACHINE");
        cache.learn(7, r"\REGISTRY\MACHINE");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_reused_pointer_is_replaced_rather_than_conflicting() {
        // The only way the same `KeyObject` yields two paths is address
        // reuse after the first KCB was destroyed. The newer path is the
        // true one; keeping the old one would answer confidently wrong.
        let cache = KeyCache::default();
        cache.learn(42, r"\REGISTRY\MACHINE\OLD");
        cache.learn(42, r"\REGISTRY\MACHINE\NEW");
        assert_eq!(cache.lookup(42).as_deref(), Some(r"\REGISTRY\MACHINE\NEW"),);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_capacity_is_respected_with_fifo_eviction() {
        let cache = KeyCache::with_capacity(4);
        for i in 0..4u64 {
            cache.learn(i + 1, &format!(r"\REGISTRY\KEY{i}"));
        }
        assert_eq!(cache.len(), 4);

        // The fifth insert evicts the first.
        cache.learn(5, r"\REGISTRY\KEY4");
        assert_eq!(cache.len(), 4);
        assert_eq!(cache.lookup(1), None, "the oldest entry was evicted");
        assert_eq!(
            cache.lookup(5).as_deref(),
            Some(r"\REGISTRY\KEY4"),
            "the newest entry is present",
        );
    }

    #[test]
    fn cloning_shares_the_inner_state() {
        // The property the observer depends on: a clone does not fork the
        // cache, it points at the same one.
        let a = KeyCache::default();
        let b = a.clone();
        a.learn(1, r"\REGISTRY\ONE");
        assert_eq!(b.lookup(1).as_deref(), Some(r"\REGISTRY\ONE"));
        b.learn(2, r"\REGISTRY\TWO");
        assert_eq!(a.lookup(2).as_deref(), Some(r"\REGISTRY\TWO"));
    }
}
