//! Implements A11 (Resource Constraints).
//!
//! The formal object is the resource-constrained action set: a budget, and a
//! triage order over candidate work. A11 says that the defender's action set is
//! not "everything that would help" but "everything that fits".
//!
//! This is the crate that keeps an XDR deployment honest about capacity. A
//! sensor that produces 40k events/s into a system sized for 10k does not
//! produce 40k events/s of coverage; it produces 10k and silently loses the
//! rest, which is why `overload` is reported alongside every throughput number
//! rather than buried in a log line.
#![forbid(unsafe_code)]

/// What the deployment can afford.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budget {
    pub events_per_sec: u64,
    pub analyst_minutes_per_hour: f64,
}

/// One candidate piece of work, with what it is worth and what it costs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TriageItem {
    pub id: u64,
    pub utility: f64,
    pub cost: f64,
}

/// A set of candidates competing for a fixed budget.
#[derive(Debug, Clone, Default)]
pub struct Triage {
    items: Vec<TriageItem>,
}

impl Triage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, item: TriageItem) {
        self.items.push(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Highest utility-per-unit-cost first, until the budget runs out.
    ///
    /// Greedy rather than optimal: the exact answer is a knapsack, and an
    /// analyst queue that re-solves a knapsack every time a new alert lands is
    /// not a queue anyone will keep running. Density ordering is stable,
    /// monotone in utility, and good enough — and it is the property an analyst
    /// can predict without being told.
    pub fn select(&self, budget: f64) -> Vec<u64> {
        let mut ranked: Vec<&TriageItem> = self.items.iter().collect();
        ranked.sort_by(|a, b| {
            density(b)
                .partial_cmp(&density(a))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.id.cmp(&b.id))
        });

        let mut remaining = budget.max(0.0);
        let mut chosen = Vec::new();
        for item in ranked {
            if item.cost <= 0.0 {
                chosen.push(item.id);
                continue;
            }
            if item.cost <= remaining {
                remaining -= item.cost;
                chosen.push(item.id);
            }
        }
        chosen
    }
}

fn density(item: &TriageItem) -> f64 {
    if item.cost <= 0.0 {
        f64::INFINITY
    } else {
        item.utility / item.cost
    }
}

/// Fraction of the budget consumed, clamped to `[0, 1]`.
pub fn utilization(used: f64, budget: f64) -> f64 {
    if budget <= 0.0 {
        return 1.0;
    }
    (used / budget).clamp(0.0, 1.0)
}

/// Offered load over capacity. `1.0` is exactly saturated; anything above it
/// means events are being dropped somewhere and the coverage numbers upstream
/// are optimistic.
pub fn overload(rate: f64, capacity: f64) -> f64 {
    if capacity <= 0.0 {
        return if rate <= 0.0 { 0.0 } else { f64::INFINITY };
    }
    rate / capacity
}

#[cfg(test)]
mod tests {
    use super::*;

    fn triage() -> Triage {
        let mut t = Triage::new();
        // density: 10/1 = 10, 1/1 = 1, 100/100 = 1, 6/3 = 2
        t.push(TriageItem {
            id: 1,
            utility: 10.0,
            cost: 1.0,
        });
        t.push(TriageItem {
            id: 2,
            utility: 1.0,
            cost: 1.0,
        });
        t.push(TriageItem {
            id: 3,
            utility: 100.0,
            cost: 100.0,
        });
        t.push(TriageItem {
            id: 4,
            utility: 6.0,
            cost: 3.0,
        });
        t
    }

    #[test]
    fn select_prefers_higher_density() {
        assert_eq!(triage().select(1.0), vec![1]);
        assert_eq!(triage().select(4.0), vec![1, 4]);
    }

    #[test]
    fn select_never_exceeds_the_budget() {
        let t = triage();
        // Densities are 10, 2, 1, 1. At a budget of 5 the greedy pass takes
        // item 1 (cost 1), item 4 (cost 3), then item 2 (cost 1) exactly fills
        // what is left; item 3 costs 100 and is never affordable.
        let chosen = t.select(5.0);
        assert_eq!(chosen, vec![1, 4, 2]);

        let spent: f64 = chosen
            .iter()
            .map(|id| t.items.iter().find(|i| i.id == *id).unwrap().cost)
            .sum();
        assert!(spent <= 5.0, "spent {spent} of a 5.0 budget");
        assert_eq!(spent, 5.0, "the budget should be spent exactly here");
    }

    #[test]
    fn zero_cost_items_are_always_taken_and_ties_break_by_id() {
        let mut t = Triage::new();
        t.push(TriageItem {
            id: 9,
            utility: 0.0,
            cost: 0.0,
        });
        t.push(TriageItem {
            id: 3,
            utility: 5.0,
            cost: 1.0,
        });
        t.push(TriageItem {
            id: 7,
            utility: 5.0,
            cost: 1.0,
        });
        // 3 and 7 have equal density, so ascending id wins.
        assert_eq!(t.select(1.0), vec![9, 3]);
    }

    #[test]
    fn empty_and_exhausted_budgets() {
        assert!(triage().select(0.0).is_empty());
        assert_eq!(Triage::new().select(100.0), Vec::<u64>::new());
        assert_eq!(triage().select(-5.0), Vec::<u64>::new());
    }

    #[test]
    fn utilization_clamps_and_handles_zero_budget() {
        assert_eq!(utilization(5.0, 10.0), 0.5);
        assert_eq!(utilization(20.0, 10.0), 1.0);
        assert_eq!(utilization(0.0, 0.0), 1.0);
        assert_eq!(utilization(0.0, 10.0), 0.0);
    }

    #[test]
    fn overload_marks_saturation_and_zero_capacity() {
        assert_eq!(overload(10_000.0, 10_000.0), 1.0);
        assert_eq!(overload(40_000.0, 10_000.0), 4.0);
        assert!(overload(1.0, 0.0).is_infinite());
        assert_eq!(overload(0.0, 0.0), 0.0);
    }
}
