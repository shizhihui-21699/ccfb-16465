//! 运行时调用图重建与关键路径分析。
//!
//! 静态调用图面对反射/JNI/动态加载基本失效，这里用 trace 里的真实调用事件
//! 构建**动态调用图**：
//! - 有 backtrace 时，调用栈相邻帧直接成边（最准确）；
//! - 没有 backtrace 时，同线程内相邻事件按时间顺序成边（保守近似）。
//!
//! 分析员最终需要的不是整张图，而是「外部入口 → 敏感 sink」的有限条路径，
//! 因此图构建后立即做 BFS 剪枝，只保留能到达 sink 的子图与路径。

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use droidunpack_protocol::{Event, EventKind, MethodRef};
use droidunpack_rules::builtin;
use serde::Serialize;

/// 图节点 id：方法的稳定文本键。
pub type NodeId = String;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub method: MethodDisplay,
    pub is_entry: bool,
    pub is_sink: bool,
    /// 该节点被调用的次数，频率异常（如定时轮询）可作为辅助信号
    pub hits: u64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MethodDisplay {
    pub class: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub thread: String,
    pub via_backtrace: bool,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SinkPath {
    /// 入口方法显示名
    pub entry: String,
    pub sink: String,
    pub path: Vec<String>,
    pub hops: usize,
    pub threads: Vec<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, Default)]
pub struct CallGraph {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: Vec<Edge>,
    /// 边索引：from -> (to -> edge 下标)
    #[serde(skip, default)]
    adjacency: HashMap<NodeId, Vec<usize>>,
}

impl CallGraph {
    fn node_id(m: &MethodRef) -> NodeId {
        m.node_key()
    }

    fn touch(&mut self, m: &MethodRef) -> NodeId {
        let id = Self::node_id(m);
        self.nodes.entry(id.clone()).or_insert_with(|| Node {
            id: id.clone(),
            method: MethodDisplay {
                class: m.dotted_class(),
                name: m.name.clone(),
            },
            is_entry: builtin::is_entry(&m.name),
            is_sink: builtin::is_sink(&m.name),
            hits: 0,
        });
        self.nodes.get_mut(&id).expect("刚插入").hits += 1;
        id
    }

    fn add_edge(&mut self, from: &NodeId, to: &NodeId, thread: &str, via_backtrace: bool) {
        let adj = self.adjacency.entry(from.clone()).or_default();
        if let Some(idx) = adj
            .iter()
            .find(|i| self.edges[**i].to == *to && self.edges[**i].thread == thread)
            .copied()
        {
            self.edges[idx].count += 1;
            return;
        }
        let idx = self.edges.len();
        self.edges.push(Edge {
            from: from.clone(),
            to: to.clone(),
            thread: thread.to_string(),
            via_backtrace,
            count: 1,
        });
        adj.push(idx);
    }

    /// 所有 sink 节点。
    pub fn sinks(&self) -> Vec<&NodeId> {
        self.nodes
            .values()
            .filter(|n| n.is_sink)
            .map(|n| &n.id)
            .collect()
    }

    /// 所有入口节点：命中入口回调名 **且入度为 0**（trace 内没有谁调用它，
    /// 即它是一条 observed 调用链的真正起点）。
    pub fn entries(&self) -> Vec<&NodeId> {
        let has_incoming: HashSet<&NodeId> = self.edges.iter().map(|e| &e.to).collect();
        self.nodes
            .values()
            .filter(|n| n.is_entry && !has_incoming.contains(&n.id))
            .map(|n| &n.id)
            .collect()
    }

    /// 重建边索引。反序列化或剪枝后 adjacency 可能为空，查询前惰性重建。
    fn ensure_index(&mut self) {
        if !self.adjacency.is_empty() || self.edges.is_empty() {
            return;
        }
        for (i, e) in self.edges.iter().enumerate() {
            self.adjacency.entry(e.from.clone()).or_default().push(i);
        }
    }

    /// BFS 求从指定入口到**最远可达 sink** 的最短路径（节点 id 序列）。
    /// 取最远 sink：路径上的中间节点本身也可能是 sink，但完整链路对分析员更有价值。
    fn bfs_to_any_sink(&self, start: &NodeId) -> Option<(Vec<NodeId>, NodeId, Vec<String>)> {
        let mut prev: HashMap<&NodeId, &NodeId> = HashMap::new();
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        seen.insert(start);
        queue.push_back(start);

        let mut best: Option<(Vec<NodeId>, NodeId)> = None;
        while let Some(cur) = queue.pop_front() {
            let node = self.nodes.get(cur)?;
            // 入口自身可能同时是 sink（如 onReceive 直接被标记），仍继续向下游找更远 sink；
            // 没有下游时 best 为空，交由调用方决定是否接受零跳路径
            if node.is_sink {
                let path = self.rebuild_path(cur, &prev);
                best = Some((path, cur.clone()));
            }
            if let Some(edge_idxs) = self.adjacency.get(cur) {
                for ei in edge_idxs {
                    let next = &self.edges[*ei].to;
                    if seen.insert(next) {
                        prev.insert(next, cur);
                        queue.push_back(next);
                    }
                }
            }
        }

        best.map(|(path, sink)| {
            let threads = self.threads_on_path(&path);
            (path, sink, threads)
        })
    }

    fn rebuild_path<'a>(
        &self,
        sink: &'a NodeId,
        prev: &HashMap<&'a NodeId, &'a NodeId>,
    ) -> Vec<NodeId> {
        let mut path = vec![sink.clone()];
        let mut p = sink;
        while let Some(up) = prev.get(p) {
            path.push((*up).clone());
            p = up;
        }
        path.reverse();
        path
    }

    fn threads_on_path(&self, path: &[NodeId]) -> Vec<String> {
        let mut threads = Vec::new();
        for pair in path.windows(2) {
            if let Some(edge_idxs) = self.adjacency.get(&pair[0]) {
                for ei in edge_idxs {
                    let e = &self.edges[*ei];
                    if e.to == pair[1] && !threads.contains(&e.thread) {
                        threads.push(e.thread.clone());
                    }
                }
            }
        }
        threads
    }

    /// 计算全部「入口 → sink」关键路径，按跳数升序，默认截断前 20 条。
    pub fn sink_paths(&mut self, limit: usize) -> Vec<SinkPath> {
        self.ensure_index();
        let mut out = Vec::new();
        for entry in self.entries() {
            if let Some((path, sink, threads)) = self.bfs_to_any_sink(entry) {
                out.push(SinkPath {
                    entry: entry.clone(),
                    sink,
                    hops: path.len().saturating_sub(1),
                    path,
                    threads,
                });
            }
        }
        out.sort_by_key(|p| p.hops);
        out.truncate(limit);
        out
    }

    /// 仅保留**能沿边到达某个 sink** 的节点与边（反向可达集），降低报告噪声。
    pub fn pruned_to_sinks(mut self) -> Self {
        // 反向图：to -> from 列表
        let mut reverse: HashMap<&NodeId, Vec<&NodeId>> = HashMap::new();
        for e in &self.edges {
            reverse.entry(&e.to).or_default().push(&e.from);
        }
        let mut keep: HashSet<NodeId> = HashSet::new();
        let mut stack: Vec<&NodeId> = self
            .nodes
            .values()
            .filter(|n| n.is_sink)
            .map(|n| &n.id)
            .collect();
        while let Some(id) = stack.pop() {
            if !keep.insert(id.clone()) {
                continue;
            }
            if let Some(ups) = reverse.get(id) {
                stack.extend(ups.iter().copied());
            }
        }

        if keep.is_empty() {
            self.nodes.clear();
            self.edges.clear();
            self.adjacency.clear();
            return self;
        }
        self.nodes.retain(|id, _| keep.contains(id));
        self.edges
            .retain(|e| keep.contains(&e.from) && keep.contains(&e.to));
        self.adjacency.clear();
        for (i, e) in self.edges.iter().enumerate() {
            self.adjacency.entry(e.from.clone()).or_default().push(i);
        }
        self
    }
}

/// 从 trace 事件构建动态调用图。
pub fn build(events: &[Event]) -> CallGraph {
    let mut graph = CallGraph::default();
    // 线程内上一个事件的方法 id，用于无栈近似成边
    let mut last_on_thread: HashMap<String, NodeId> = HashMap::new();

    for ev in events {
        let EventKind::Call(frame) = &ev.kind else {
            continue;
        };
        let callee = graph.touch(&frame.method);

        if !frame.backtrace.is_empty() {
            // ART/JVM 约定：backtrace[0] 是最近调用者（栈顶），尾元素是最外层入口。
            // reverse 后得到调用方向：入口 -> ... -> 直接调用者，再挂上当前事件方法。
            let mut chain: Vec<NodeId> = frame
                .backtrace
                .iter()
                .rev()
                .map(|m| graph.touch(m))
                .collect();
            chain.push(callee.clone());
            for pair in chain.windows(2) {
                graph.add_edge(&pair[0], &pair[1], &frame.thread, true);
            }
            last_on_thread.insert(frame.thread.clone(), callee);
        } else {
            if let Some(prev) = last_on_thread.get(&frame.thread) {
                if *prev != callee {
                    graph.add_edge(prev, &callee, &frame.thread, false);
                }
            }
            last_on_thread.insert(frame.thread.clone(), callee);
        }
    }

    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use droidunpack_core::SampleId;
    use droidunpack_protocol::{ArgValue, CallFrame, EventKind, MethodRef};

    fn ev(seq: u64, thread: &str, method: MethodRef, bt: Vec<MethodRef>) -> Event {
        Event {
            ts_ms: seq,
            sample: SampleId("g".into()),
            seq,
            kind: EventKind::Call(CallFrame {
                method,
                args: vec![ArgValue::Null],
                result: None,
                thread: thread.into(),
                backtrace: bt,
            }),
        }
    }

    fn m(class: &str, name: &str) -> MethodRef {
        MethodRef::from_dotted(class, name, "()V")
    }

    #[test]
    fn backtrace_edges_and_sink_path() {
        let events = vec![ev(
            1,
            "main",
            m("com.x.Sink", "sendTextMessage"),
            vec![m("com.x.Worker", "doSend"), m("com.x.Recv", "onReceive")],
        )];
        let mut graph = build(&events);
        // 3 个节点，2 条 backtrace 边
        assert_eq!(graph.nodes.len(), 3);
        assert!(graph.edges.iter().all(|e| e.via_backtrace));
        let paths = graph.sink_paths(10);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].entry.contains("onReceive"));
        assert!(paths[0].sink.contains("sendTextMessage"));
        assert_eq!(paths[0].hops, 2);
    }

    #[test]
    fn thread_local_sequential_edges() {
        let events = vec![
            ev(1, "main", m("com.x.A", "onCreate"), vec![]),
            ev(2, "main", m("com.x.B", "run"), vec![]),
            ev(3, "main", m("com.x.C", "exec"), vec![]),
            ev(4, "pool-1", m("com.x.D", "exec"), vec![]),
        ];
        let mut graph = build(&events);
        // pool-1 线程没有入口，main 线程有一条入口->sink 路径
        let paths = graph.sink_paths(10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path.len(), 3);
        assert_eq!(paths[0].threads, vec!["main".to_string()]);
    }

    #[test]
    fn pruning_keeps_only_sink_reachable_nodes() {
        let events = vec![
            // main 线程：入口直达 sink，两个节点都应保留
            ev(1, "main", m("com.x.Entry", "onCreate"), vec![]),
            ev(2, "main", m("com.x.Sink", "exec"), vec![]),
            // 独立线程上的孤立节点，无法到达任何 sink，剪枝时必须剔除
            ev(3, "pool-9", m("com.x.Orphan", "toString"), vec![]),
        ];
        let graph = build(&events).pruned_to_sinks();
        assert!(!graph
            .nodes
            .contains_key(&m("com.x.Orphan", "toString").display()));
        assert!(graph.nodes.len() <= 3);
    }
}
