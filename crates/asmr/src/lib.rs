//! Algebraic Security for Monitoring and Response — the axiom core.
//!
//! One module per axiom group, A1 through A30. The modules are deliberately
//! *independent*: each is `std`-only, has no I/O, no globals, no third-party
//! dependencies, and imports nothing from its siblings. Composition happens one
//! layer up, in the `pipeline` crate, which is the only place that knows both
//! this algebra and a telemetry wire format.
//!
//! # Why independence rather than a dependency chain
//!
//! The book builds the axioms in order — A1 state, then A2 events, and so on —
//! and each later axiom *presupposes* the ones before it. That is a statement
//! about the mathematics, not about the module graph. A crate that implements
//! Bayesian updating does not need to link against a crate that implements
//! channel models; it needs a `f64`.
//!
//! Keeping the modules flat buys three things that a chain of 18 crates did
//! not:
//!
//! * every module is testable from a literal, with no fixture pipeline;
//! * a change to one axiom cannot ripple into another's compile time;
//! * `cargo test -p asmr` covers the whole algebra.
//!
//! What it costs is the compiler-enforced dependency direction. That was the
//! one real benefit of the split, so [`tests::modules_do_not_depend_on_each_other`]
//! checks it instead: a module that reaches for a sibling fails the build.
//!
//! # Reading order
//!
//! Foundations A1–A12: [`state`] [`trace`] [`observe`] [`infer`] [`action`]
//! [`game`] [`decision`] [`trust`] [`resource`] [`governance`].
//!
//! Extensions A13–A20: [`compose`] [`decay`] [`deception`] [`scale`]
//! [`privacy`] [`recovery`].
//!
//! Zero-day A21–A30: [`state`] (open state space), [`novelty`], [`anomaly`],
//! [`infer`] (epistemic uncertainty), [`decision`] (minimax), [`decay`] (patch
//! latency), [`action`] (compensating controls, freeze and isolate), [`game`]
//! (transfer learning).

#![forbid(unsafe_code)]

/// A6 actions, A27 compensating controls, A30 freeze and isolate.
pub mod action;
/// A23 structural anomaly over the observed graph.
pub mod anomaly;
/// A13 composition algebra: reachability and blast radius.
pub mod compose;
/// A16 temporal decay and half-life, A26 patch latency.
pub mod decay;
/// A17 deception operator and deception gain.
pub mod deception;
/// A8 cost and utility, A25 minimax response: the alert threshold theorem.
pub mod decision;
/// A7 agents and games, A14 adversarial adaptation, A29 transfer learning.
pub mod game;
/// A12 autonomy levels, governed action space, auditable policy.
pub mod governance;
/// A5 uncertainty, A9 information sets, A24 epistemic uncertainty.
pub mod infer;
/// A22 novelty measurement and coverage estimation.
pub mod novelty;
/// A3 observation and partial observability, A15 channel capacity.
pub mod observe;
/// A19 differential privacy and utility loss.
pub mod privacy;
/// A20 recovery operator, MTTR, resilience, availability.
pub mod recovery;
/// A11 resource constraints: capacity, admissible actions, triage.
pub mod resource;
/// A18 abstraction, refinement, multi-scale fusion.
pub mod scale;
/// A1 state space and A21 open state space.
pub mod state;
/// A2 events and traces, A4 time and causality.
pub mod trace;
/// A10 trust lattice, propagation, trust-weighted likelihood.
pub mod trust;

#[cfg(test)]
mod tests {
    /// Every module in the crate, in the book's reading order.
    const MODULES: &[&str] = &[
        "state",
        "trace",
        "observe",
        "infer",
        "action",
        "game",
        "decision",
        "trust",
        "resource",
        "governance",
        "compose",
        "decay",
        "deception",
        "scale",
        "privacy",
        "recovery",
        "novelty",
        "anomaly",
    ];

    fn sources() -> Vec<(&'static str, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        MODULES
            .iter()
            .map(|name| {
                let path = dir.join(format!("{name}.rs"));
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
                (*name, source)
            })
            .collect()
    }

    /// The invariant that the single-crate layout would otherwise lose: the
    /// axioms compose in `pipeline`, never in here.
    #[test]
    fn modules_do_not_depend_on_each_other() {
        for (name, source) in sources() {
            for other in MODULES {
                if *other == name {
                    continue;
                }
                let path = format!("crate::{other}");
                assert!(
                    !source.contains(&path),
                    "`{name}` refers to `{path}`; axioms must stay independent and be \
                     composed by the pipeline instead"
                );
            }
        }
    }

    /// Each module must be self-contained enough to forbid its own unsafe code,
    /// so the guarantee survives someone adding a module to this file.
    #[test]
    fn every_module_forbids_unsafe_code() {
        for (name, source) in sources() {
            assert!(
                source.contains("#![forbid(unsafe_code)]"),
                "`{name}` does not forbid unsafe code"
            );
        }
    }

    /// The modules are pure mathematics: no I/O, no ambient state.
    #[test]
    fn modules_stay_free_of_io_and_third_party_crates() {
        const FORBIDDEN: &[&str] = &[
            "std::fs",
            "std::net",
            "std::process",
            "std::thread",
            "static mut",
            "use rand",
            "use serde",
            "use tokio",
        ];

        for (name, source) in sources() {
            for needle in FORBIDDEN {
                assert!(
                    !source.contains(needle),
                    "`{name}` contains `{needle}`; the algebra must stay pure and \
                     deterministic"
                );
            }
        }
    }

    /// Determinism needs ordered collections: `HashMap` iteration order would
    /// make the property tests in these modules flaky rather than wrong.
    #[test]
    fn modules_use_ordered_collections() {
        for (name, source) in sources() {
            // Sanctioned use is `std::collections::HashMap` in a doc example
            // only; flag any real import.
            assert!(
                !source.contains("use std::collections::HashMap"),
                "`{name}` imports HashMap; use BTreeMap so iteration is deterministic"
            );
            assert!(
                !source.contains("use std::collections::HashSet"),
                "`{name}` imports HashSet; use BTreeSet so iteration is deterministic"
            );
        }
    }

    #[test]
    fn the_module_list_matches_the_files_on_disk() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .expect("src directory")
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let name = path.file_stem()?.to_str()?.to_string();
                if name == "lib" {
                    return None;
                }
                Some(name)
            })
            .collect();
        on_disk.sort();

        let mut declared: Vec<String> = MODULES.iter().map(|m| (*m).to_string()).collect();
        declared.sort();

        assert_eq!(
            declared, on_disk,
            "every module file must be declared, and every declaration must exist"
        );
    }
}
