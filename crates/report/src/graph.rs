//! Call graph built from what actually executed.
//!
//! A call graph derived statically from a packed APK is mostly the stub. The
//! structure that matters only exists after the payload is decrypted, so the
//! graph is recorded during the run: an edge exists because control really
//! passed from one method to another.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use unhusk_vm::events::Event;

pub use graph_impl::CallGraph;

pub mod graph_impl {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Edge {
        pub caller: String,
        pub callee: String,
        pub first_seen_insn: u64,
        pub calls: u64,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct CallGraph {
        parents: BTreeMap<String, BTreeSet<String>>,
        children: BTreeMap<String, BTreeSet<String>>,
        pub edges: BTreeMap<(String, String), Edge>,
        pub roots: BTreeSet<String>,
        pub order: Vec<String>,
    }

    impl CallGraph {
        pub fn add_node(&mut self, method: &str) {
            self.children.entry(method.to_string()).or_default();
            self.parents.entry(method.to_string()).or_default();
            if !self.order.iter().any(|m| m == method) {
                self.order.push(method.to_string());
            }
        }

        pub fn add_edge(&mut self, caller: &str, callee: &str, insn: u64) {
            self.add_node(caller);
            self.add_node(callee);
            self.children
                .entry(caller.to_string())
                .or_default()
                .insert(callee.to_string());
            self.parents
                .entry(callee.to_string())
                .or_default()
                .insert(caller.to_string());
            let e = self
                .edges
                .entry((caller.to_string(), callee.to_string()))
                .or_insert_with(|| Edge {
                    caller: caller.to_string(),
                    callee: callee.to_string(),
                    first_seen_insn: insn,
                    calls: 0,
                });
            e.calls += 1;
        }

        pub fn callers(&self, method: &str) -> Vec<&str> {
            self.parents
                .get(method)
                .map(|s| s.iter().map(|x| x.as_str()).collect())
                .unwrap_or_default()
        }

        pub fn callees(&self, method: &str) -> Vec<&str> {
            self.children
                .get(method)
                .map(|s| s.iter().map(|x| x.as_str()).collect())
                .unwrap_or_default()
        }

        pub fn method_count(&self) -> usize {
            self.children.len()
        }

        pub fn edge_count(&self) -> usize {
            self.edges.len()
        }
    }
}

/// Build the graph from the executed-method record and the trace.
pub fn build(events: &[Event], executed: &[String]) -> CallGraph {
    let mut g = CallGraph::default();
    for m in executed {
        g.add_node(m);
        g.roots.insert(m.clone());
    }
    // MethodEnter events carry the caller→callee relation. Event ordering gives
    // us the instruction count at which each edge first ran.
    let mut depth_stack: Vec<(String, u64)> = Vec::new();
    for e in events {
        if e.kind != unhusk_vm::events::EventKind::MethodEnter {
            continue;
        }
        // Caller is in `caller`, callee in `subject`.
        if e.caller != e.subject {
            g.add_edge(&e.caller, &e.subject, e.insn);
        }
        depth_stack.push((e.subject.clone(), e.insn));
    }
    let _ = depth_stack;
    g
}
