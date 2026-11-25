use std::io::{BufRead, BufReader, Read};

use droidunpack_core::{Error, Result};

use crate::event::Event;

/// 读取 JSONL 事件流。遇到坏行返回错误并带上行号，方便分析员定位被截断的 trace
/// （模拟器被强制回收时最后一行经常不完整）。
pub fn read_jsonl<R: Read>(reader: R) -> Result<Vec<Event>> {
    let reader = BufReader::new(reader);
    let mut events = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(&line)
            .map_err(|e| Error::Format(format!("trace 第 {} 行 JSON 解析失败: {e}", i + 1)))?;
        events.push(event);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use droidunpack_core::SampleId;

    #[test]
    fn roundtrip_jsonl() {
        let input = r#"
{"ts_ms":1,"sample":"abc","seq":1,"kind":"process_start","pid":100,"package":"com.x"}
{"ts_ms":2,"sample":"abc","seq":2,"kind":"class_load","class":"Lcom/x/Y;"}
"#;
        let events = read_jsonl(input.as_bytes()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind_key(), "process_start");
        assert_eq!(events[1].sample, SampleId("abc".into()));
    }

    #[test]
    fn bad_line_reports_line_number() {
        // 第 1 行合法事件，第 2 行是截断的坏 JSON
        let input = "{\"ts_ms\":1,\"sample\":\"s\",\"seq\":1,\"kind\":\"class_load\",\"class\":\"Lx;\"}\n{broken\n";
        let err = read_jsonl(input.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("第 2 行"));
    }
}
