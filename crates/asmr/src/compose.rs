//! Implements A13 (Composition Algebra).
//!
//! The formal object is a graph of subsystems and the closure operators over
//! it: reachability, and the blast radius of a failure at a node.
//!
//! This is what turns an A6 action into a risk estimate. "Isolate host H" is
//! not one action in a composed system — it is an action whose consequences
//! follow the containment edges out of H, and the difference between a
//! workstation and the only domain controller with a replication link to every
//! site is entirely a question about the graph. Reachability is computed
//! iteratively so a dependency cycle (which real infrastructure always has)
//! terminates instead of overflowing the stack.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// The kind of relation between two subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKind {
    /// Failure follows the edge.
    Depends,
    /// Traffic follows the edge.
    Talks,
    /// The target is inside the source.
    Contains,
}

/// A directed graph of subsystems.
#[derive(Debug, Clone, Default)]
pub struct Composition {
    adjacency: BTreeMap<u32, Vec<(u32, EdgeKind)>>,
    nodes: BTreeSet<u32>,
}

impl Composition {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, from: u32, to: u32, kind: EdgeKind) {
        self.nodes.insert(from);
        self.nodes.insert(to);
        self.adjacency.entry(from).or_default().push((to, kind));
    }

    pub fn nodes(&self) -> Vec<u32> {
        self.nodes.iter().copied().collect()
    }

    pub fn edge_count(&self) -> usize {
        self.adjacency.values().map(Vec::len).sum()
    }

    /// Reflexive-transitive reachability, including `from` itself.
    ///
    /// Iterative on purpose: a cycle here is normal (service A calls B calls A
    /// through a queue), and a recursive version would abort the whole agent on
    /// input it cannot refuse.
    pub fn reachable(&self, from: u32) -> BTreeSet<u32> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![from];
        seen.insert(from);

        while let Some(node) = stack.pop() {
            if let Some(edges) = self.adjacency.get(&node) {
                for (next, _) in edges {
                    if seen.insert(*next) {
                        stack.push(*next);
                    }
                }
            }
        }
        seen
    }

    /// How many nodes a failure at `from` can propagate to, counting itself.
    /// `1` means fully contained.
    pub fn blast_radius(&self, from: u32) -> usize {
        self.reachable(from).len()
    }

    /// True when nothing in the graph has an edge into `from`.
    pub fn is_isolated(&self, from: u32) -> bool {
        !self
            .adjacency
            .values()
            .any(|edges| edges.iter().any(|(to, _)| *to == from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a -> b -> c, and c -> a (a cycle).
    fn chain() -> Composition {
        let mut g = Composition::new();
        g.add_edge(1, 2, EdgeKind::Depends);
        g.add_edge(2, 3, EdgeKind::Depends);
        g.add_edge(3, 1, EdgeKind::Depends);
        g
    }

    #[test]
    fn reachability_is_reflexive_even_at_a_leaf() {
        let mut g = Composition::new();
        g.add_edge(1, 2, EdgeKind::Talks);
        assert_eq!(g.reachable(2), BTreeSet::from([2]));
        assert_eq!(g.reachable(1), BTreeSet::from([1, 2]));
        assert_eq!(
            g.reachable(99),
            BTreeSet::from([99]),
            "unknown nodes are inert"
        );
    }

    #[test]
    fn cycles_terminate_and_reach_the_whole_cycle() {
        let g = chain();
        assert_eq!(g.reachable(1), BTreeSet::from([1, 2, 3]));
        assert_eq!(g.blast_radius(1), 3);
        assert_eq!(g.blast_radius(3), 3);
    }

    #[test]
    fn blast_radius_counts_the_origin() {
        let mut g = Composition::new();
        g.add_edge(1, 2, EdgeKind::Contains);
        assert_eq!(g.blast_radius(1), 2);
        assert_eq!(g.blast_radius(2), 1, "a leaf contains only itself");
    }

    #[test]
    fn isolation_is_about_incoming_edges_only() {
        let mut g = Composition::new();
        g.add_edge(1, 2, EdgeKind::Talks);
        assert!(g.is_isolated(1), "nothing points at 1");
        assert!(!g.is_isolated(2));
        assert!(g.is_isolated(99), "an unknown node has no in-edges");
    }

    #[test]
    fn diamond_does_not_double_count() {
        // 1 -> 2 -> 4, 1 -> 3 -> 4
        let mut g = Composition::new();
        g.add_edge(1, 2, EdgeKind::Depends);
        g.add_edge(1, 3, EdgeKind::Depends);
        g.add_edge(2, 4, EdgeKind::Depends);
        g.add_edge(3, 4, EdgeKind::Depends);
        assert_eq!(g.blast_radius(1), 4);
        assert_eq!(g.edge_count(), 4);
        assert_eq!(g.nodes(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn self_loop_is_handled() {
        let mut g = Composition::new();
        g.add_edge(7, 7, EdgeKind::Contains);
        assert_eq!(g.blast_radius(7), 1);
        assert!(!g.is_isolated(7));
    }
}
