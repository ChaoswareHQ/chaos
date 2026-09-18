//! Implements A23 (Structural Anomaly).
//!
//! The formal object is the observed graph — processes spawning processes,
//! processes touching files, processes opening sockets — and anomaly measured
//! against its *structure* rather than against any single value.
//!
//! This is the crate that catches a legitimate binary doing something it has
//! never done. A signed `svchost.exe` writing to `Documents` is not novel as a
//! binary (A22) and not high-severity as a single event, but the *edge* is one
//! this host has never drawn. An actor appearing for the first time is more
//! anomalous than a new relation between actors we already know, which is why
//! `score` weights the two cases differently.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// One directed relation: `from` acted on `to` under `label`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeKey {
    pub from: Box<str>,
    pub to: Box<str>,
    pub label: Box<str>,
}

impl EdgeKey {
    pub fn new(from: &str, to: &str, label: &str) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            label: label.into(),
        }
    }
}

/// The graph as seen so far.
#[derive(Debug, Clone, Default)]
pub struct StructuralProfile {
    known: BTreeSet<EdgeKey>,
    out_degree: BTreeMap<Box<str>, u32>,
    nodes: BTreeSet<Box<str>>,
}

impl StructuralProfile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Teach the profile an edge. Returns true when the edge itself was new,
    /// independent of whether its endpoints were.
    pub fn observe_edge(&mut self, e: EdgeKey) -> bool {
        self.nodes.insert(e.from.clone());
        self.nodes.insert(e.to.clone());
        *self.out_degree.entry(e.from.clone()).or_insert(0) += 1;
        self.known.insert(e)
    }

    pub fn knows_edge(&self, e: &EdgeKey) -> bool {
        self.known.contains(e)
    }

    pub fn knows_node(&self, node: &str) -> bool {
        self.nodes.contains(node)
    }

    pub fn out_degree(&self, node: &str) -> u32 {
        self.out_degree.get(node).copied().unwrap_or(0)
    }

    pub fn edges(&self) -> usize {
        self.known.len()
    }

    pub fn nodes(&self) -> usize {
        self.nodes.len()
    }

    /// How anomalous this edge is, evaluated *before* it is taught.
    ///
    /// - `0.0` — already known; a repeated behaviour tells you nothing.
    /// - `0.5` — a new relation between two actors we already know.
    /// - `1.0` — at least one endpoint is new, so we cannot even say which
    ///   actor this is; there is no baseline to compare against.
    pub fn score(&self, e: &EdgeKey) -> f64 {
        if self.knows_edge(e) {
            0.0
        } else if self.knows_node(&e.from) && self.knows_node(&e.to) {
            0.5
        } else {
            1.0
        }
    }

    /// This node's fan-out relative to the widest fan-out observed, in `[0, 1]`.
    /// A process spawning hundreds of children inside one window is the shape
    /// of process-injection and fork-bomb behaviour.
    pub fn fanout_ratio(&self, node: &str) -> f64 {
        let max = self.out_degree.values().copied().max().unwrap_or(0);
        if max == 0 {
            return 0.0;
        }
        f64::from(self.out_degree(node)) / f64::from(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from: &str, to: &str) -> EdgeKey {
        EdgeKey::new(from, to, "spawned")
    }

    #[test]
    fn score_is_evaluated_before_the_edge_is_taught() {
        let mut p = StructuralProfile::new();
        let e = edge("explorer.exe", "cmd.exe");

        assert!(p.knows_edge(&e) == false);
        assert_eq!(p.score(&e), 1.0, "both endpoints are new");

        assert!(
            p.observe_edge(e.clone()),
            "first sighting of the edge is new"
        );
        assert_eq!(p.score(&e), 0.0, "now it is known");

        // A second, different relation between the same two actors.
        let other = EdgeKey::new("explorer.exe", "cmd.exe", "wrote");
        assert_eq!(p.score(&other), 0.5, "new edge between known actors");
        assert!(p.observe_edge(other.clone()));
        assert!(!p.observe_edge(other), "re-teaching is not novel");
    }

    #[test]
    fn one_unknown_endpoint_is_as_anomalous_as_two() {
        let mut p = StructuralProfile::new();
        p.observe_edge(edge("a", "b"));
        // "a" is known, "z" is not.
        assert_eq!(p.score(&edge("a", "z")), 1.0);
        // both known
        assert_eq!(p.score(&edge("b", "a")), 0.5);
    }

    #[test]
    fn out_degree_and_node_bookkeeping() {
        let mut p = StructuralProfile::new();
        p.observe_edge(edge("a", "b"));
        p.observe_edge(edge("a", "c"));
        p.observe_edge(edge("b", "c"));
        assert_eq!(p.out_degree("a"), 2);
        assert_eq!(p.out_degree("b"), 1);
        assert_eq!(p.out_degree("c"), 0);
        assert_eq!(p.edges(), 3);
        assert_eq!(p.nodes(), 3);
        assert!(p.knows_node("b"));
        assert!(!p.knows_node("z"));
    }

    #[test]
    fn fanout_ratio_is_relative_and_bounded() {
        let mut p = StructuralProfile::new();
        p.observe_edge(edge("wide", "a"));
        p.observe_edge(edge("wide", "b"));
        p.observe_edge(edge("wide", "c"));
        p.observe_edge(edge("narrow", "a"));

        assert_eq!(p.fanout_ratio("wide"), 1.0);
        assert_eq!(p.fanout_ratio("narrow"), 1.0 / 3.0);
        assert_eq!(p.fanout_ratio("unknown"), 0.0);
    }

    #[test]
    fn fanout_of_an_empty_profile_is_zero_not_nan() {
        let p = StructuralProfile::new();
        assert_eq!(p.fanout_ratio("anything"), 0.0);
        assert_eq!(p.edges(), 0);
    }
}
