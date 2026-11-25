use serde::Serialize;

use droidunpack_core::Severity;
use droidunpack_protocol::Event;

use crate::model::{Link, MatchOp, Matcher, Rule, RuleSet};

/// 一次规则命中。`evidence_events` 是支撑结论的事件序号，报告直接引用。
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub attack: Vec<String>,
    pub evidence_events: Vec<u64>,
    pub detail: String,
}

/// 对完整 trace 求值规则集，按严重级别降序返回命中。
pub fn evaluate(events: &[Event], set: &RuleSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in &set.rules {
        if let Some(detect) = &rule.detect {
            for ev in events {
                if matcher_matches(ev, detect) {
                    findings.push(single_finding(rule, ev));
                }
            }
        } else if !rule.sequence.is_empty() {
            for matched in match_sequence(events, rule) {
                findings.push(sequence_finding(rule, &matched));
            }
        }
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

fn single_finding(rule: &Rule, ev: &Event) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        attack: rule.attack.clone(),
        evidence_events: vec![ev.seq],
        detail: rule.description.clone(),
    }
}

fn sequence_finding(rule: &Rule, matched: &[&Event]) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        attack: rule.attack.clone(),
        evidence_events: matched.iter().map(|e| e.seq).collect(),
        detail: rule.description.clone(),
    }
}

/// 事件是否满足匹配器（kind + 全部条件）。
pub fn matcher_matches(ev: &Event, m: &Matcher) -> bool {
    if ev.kind_key() != m.kind {
        return false;
    }
    m.matches.iter().all(|op| op_matches(ev, op))
}

fn op_matches(ev: &Event, op: &MatchOp) -> bool {
    match op {
        MatchOp::Exists { field } => ev.field(field).map(|v| !v.is_empty()).unwrap_or(false),
        MatchOp::Eq { field, value } => ev.field(field).as_deref() == Some(value.as_str()),
        MatchOp::Contains { field, value } => ev
            .field(field)
            .map(|v| v.contains(value.as_str()))
            .unwrap_or(false),
        MatchOp::Regex { field, pattern } => {
            let Ok(re) = regex::Regex::new(pattern) else {
                return false; // validate() 已保证可编译，这里防御性处理
            };
            ev.field(field).map(|v| re.is_match(&v)).unwrap_or(false)
        }
    }
}

/// 贪心匹配有序序列：找到第一条满足时间窗与联动约束的事件链。
/// 采用「每步取最早可行事件」策略——恶意行为判定重召回，贪心足够且线性复杂度。
fn match_sequence<'a>(events: &'a [Event], rule: &Rule) -> Vec<Vec<&'a Event>> {
    let mut hits = Vec::new();
    let mut cursor = 0usize;

    'outer: while cursor < events.len() {
        let mut chain: Vec<&Event> = Vec::with_capacity(rule.sequence.len());
        let mut search_from = cursor;

        for step in &rule.sequence {
            let found = events[search_from..]
                .iter()
                .position(|ev| matcher_matches(ev, &step.matcher));
            let Some(rel) = found else { break 'outer };
            let idx = search_from + rel;
            chain.push(&events[idx]);
            search_from = idx + 1;
        }

        if chain.len() != rule.sequence.len() {
            break;
        }

        let first_ts = chain[0].ts_ms;
        let last_ts = chain[chain.len() - 1].ts_ms;
        let in_window = rule
            .window_ms
            .map(|w| last_ts.saturating_sub(first_ts) <= w)
            .unwrap_or(true);

        let links_ok = rule.links.iter().all(|link| link_holds(link, rule, &chain));

        if in_window && links_ok {
            // 去重：同一条事件链不重复报告（不同起点可能得到相同 seq 组合）
            let key: Vec<u64> = chain.iter().map(|e| e.seq).collect();
            if !hits.contains(&key) {
                hits.push(key);
            }
            // 从链尾之后继续寻找下一条链
            let last_seq = chain[chain.len() - 1].seq;
            cursor = events
                .iter()
                .position(|e| e.seq > last_seq)
                .unwrap_or(events.len());
        } else {
            // 窗口/联动不满足，从第一个匹配点之后重试
            cursor += 1;
        }
    }

    // 把 seq 键还原成事件引用
    hits.into_iter()
        .map(|seqs| {
            seqs.iter()
                .filter_map(|seq| events.iter().find(|e| e.seq == *seq))
                .collect()
        })
        .collect()
}

fn link_holds(link: &Link, rule: &Rule, chain: &[&Event]) -> bool {
    let step_index = |name: &str| {
        rule.sequence
            .iter()
            .position(|s| s.as_name.as_deref() == Some(name))
    };
    let (Some(i), Some(j)) = (step_index(&link.from_step), step_index(&link.to_step)) else {
        return false;
    };
    let (Some(a), Some(b)) = (chain.get(i), chain.get(j)) else {
        return false;
    };
    field_value(a, &link.from_field)
        .zip(field_value(b, &link.to_field))
        .map(|(x, y)| x == y && !x.is_empty())
        .unwrap_or(false)
}

/// 取事件字段或参数值；`argN` 走参数通道，其余走命名字段。
fn field_value(ev: &Event, field: &str) -> Option<String> {
    if let Some(rest) = field.strip_prefix("arg") {
        let idx: usize = rest.parse().ok()?;
        return ev.arg(idx).map(|a| a.comparable());
    }
    ev.field(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Step;
    use droidunpack_core::SampleId;
    use droidunpack_protocol::{ArgValue, CallFrame, EventKind, MethodRef};

    fn sample() -> SampleId {
        SampleId("t".into())
    }

    fn event(seq: u64, ts: u64, kind: EventKind) -> Event {
        Event {
            ts_ms: ts,
            sample: sample(),
            seq,
            kind,
        }
    }

    fn call_event(seq: u64, ts: u64, class: &str, name: &str, args: Vec<ArgValue>) -> Event {
        event(
            seq,
            ts,
            EventKind::Call(CallFrame {
                method: MethodRef::from_dotted(class, name, ""),
                args,
                result: None,
                thread: "main".into(),
                backtrace: vec![],
            }),
        )
    }

    #[test]
    fn single_event_eq_and_contains() {
        let events = vec![call_event(
            1,
            1,
            "java.lang.Runtime",
            "exec",
            vec![ArgValue::String("su -c id".into())],
        )];
        let set = RuleSet {
            name: "t".into(),
            rules: vec![Rule {
                id: "r1".into(),
                title: "su 执行".into(),
                severity: Severity::High,
                description: "".into(),
                attack: vec![],
                detect: Some(Matcher {
                    kind: "call".into(),
                    matches: vec![
                        MatchOp::Eq {
                            field: "name".into(),
                            value: "exec".into(),
                        },
                        MatchOp::Contains {
                            field: "arg0".into(),
                            value: "su".into(),
                        },
                    ],
                }),
                sequence: vec![],
                window_ms: None,
                links: vec![],
            }],
        };
        let findings = evaluate(&events, &set);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence_events, vec![1]);
    }

    #[test]
    fn ordered_sequence_with_window_and_data_link() {
        // 读短信 body=SECRET -> 加密 -> 把同一个 SECRET 发到 URL
        let events = vec![
            event(
                1,
                10,
                EventKind::Sms {
                    direction: "read".into(),
                    address: None,
                    body: "SECRET".into(),
                },
            ),
            event(
                2,
                20,
                EventKind::Crypto {
                    algorithm: "AES".into(),
                    key_sha1: None,
                    iv_sha1: None,
                },
            ),
            event(
                3,
                30,
                EventKind::Network {
                    url: "https://evil.example/x?d=SECRET".into(),
                    ip: "10.0.0.1".into(),
                    port: 443,
                    op: "connect".into(),
                },
            ),
        ];
        let rule = Rule {
            id: "exfil".into(),
            title: "短信外泄链".into(),
            severity: Severity::Critical,
            description: "".into(),
            attack: vec!["T1636.004".into()],
            detect: None,
            sequence: vec![
                Step {
                    matcher: Matcher {
                        kind: "sms".into(),
                        matches: vec![],
                    },
                    as_name: Some("sms".into()),
                },
                Step {
                    matcher: Matcher {
                        kind: "crypto".into(),
                        matches: vec![],
                    },
                    as_name: Some("enc".into()),
                },
                Step {
                    matcher: Matcher {
                        kind: "network".into(),
                        matches: vec![],
                    },
                    as_name: Some("net".into()),
                },
            ],
            window_ms: Some(500),
            links: vec![Link {
                from_step: "sms".into(),
                from_field: "body".into(),
                to_step: "net".into(),
                to_field: "url".into(),
            }],
        };
        // 联动要求严格相等；url 含 SECRET 但不等于 SECRET -> 不命中
        let set = RuleSet {
            name: "t".into(),
            rules: vec![clone_rule(&rule)],
        };
        assert!(evaluate(&events, &set).is_empty());

        // 改成 Contains 语义不可用于 link（link 是相等），把 url 换成恰好等于 body
        let mut events2 = events.clone();
        events2[2] = event(
            3,
            30,
            EventKind::Network {
                url: "SECRET".into(),
                ip: "10.0.0.1".into(),
                port: 443,
                op: "connect".into(),
            },
        );
        let set2 = RuleSet {
            name: "t".into(),
            rules: vec![rule],
        };
        let hits = evaluate(&events2, &set2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].evidence_events, vec![1, 2, 3]);
    }

    #[test]
    fn window_expiry_breaks_sequence() {
        let events = vec![
            event(
                1,
                0,
                EventKind::PrivacyRead {
                    source: "sms".into(),
                    detail: "x".into(),
                },
            ),
            event(
                2,
                9_000,
                EventKind::Network {
                    url: "u".into(),
                    ip: "i".into(),
                    port: 80,
                    op: "c".into(),
                },
            ),
        ];
        let rule = Rule {
            id: "w".into(),
            title: "t".into(),
            severity: Severity::High,
            description: "".into(),
            attack: vec![],
            detect: None,
            sequence: vec![
                Step {
                    matcher: Matcher {
                        kind: "privacy_read".into(),
                        matches: vec![],
                    },
                    as_name: Some("a".into()),
                },
                Step {
                    matcher: Matcher {
                        kind: "network".into(),
                        matches: vec![],
                    },
                    as_name: Some("b".into()),
                },
            ],
            window_ms: Some(1_000),
            links: vec![],
        };
        let set = RuleSet {
            name: "t".into(),
            rules: vec![rule],
        };
        assert!(evaluate(&events, &set).is_empty());
    }

    fn clone_rule(r: &Rule) -> Rule {
        serde_json::from_value(serde_json::to_value(r).unwrap()).unwrap()
    }
}
