use std::sync::Arc;
use crate::snapshot_cache::SnapshotCache;
use crate::config::Config;

const HISTORY_TOOLS: &[&str] = &[
    "get_proxy_http_history",
    "get_proxy_http_history_regex",
];
const SCANNER_TOOLS: &[&str] = &["get_scanner_issues"];

/// Returns true if the tool is handled by the grouper.
pub fn is_groupable(tool_name: &str) -> bool {
    HISTORY_TOOLS.contains(&tool_name) || SCANNER_TOOLS.contains(&tool_name)
}

/// Process a tools/call response for a history or scanner tool.
/// Extracts raw_items from value["result"]["items"],
/// saves to cache, replaces value["result"] with a summary string.
/// Returns true if grouping was applied; false if response has no items array.
pub fn process(
    value: &mut serde_json::Value,
    tool_name: &str,
    cache: &Arc<SnapshotCache>,
    _config: &Config,
) -> bool {
    let items = match value.pointer("/result/items").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr.to_vec(),
        _ => return false,
    };

    let (prefix, summary) = if HISTORY_TOOLS.contains(&tool_name) {
        ("ph", summarize_history(&items))
    } else if SCANNER_TOOLS.contains(&tool_name) {
        ("sc", summarize_scanner(&items))
    } else {
        return false;
    };

    let snapshot_id = cache.insert(prefix, tool_name.to_string(), items.clone());

    let total = items.len();
    let page_size = 20;
    let header = if prefix == "sc" {
        format!("BTK scanner snapshot {snapshot_id} ({total} issues):\n{summary}")
    } else {
        format!("BTK proxy history snapshot {snapshot_id} ({total} items):\n{summary}")
    };
    let mut full_summary = header;
    if total > page_size {
        full_summary.push_str(&format!(
            "\nUse btk_next_page(snapshot=\"{snapshot_id}\", cursor={page_size}) for items {}-{}.",
            page_size + 1, total
        ));
    }
    let detail_hint = if prefix == "sc" {
        format!("\nUse btk_detail(snapshot=\"{snapshot_id}\", path=\"<issue_type>\") to expand an issue type.")
    } else {
        format!("\nUse btk_detail(snapshot=\"{snapshot_id}\", path=\"<METHOD /path>\") to expand a path.")
    };
    full_summary.push_str(&detail_hint);

    value["result"] = serde_json::json!({
        "content": [{"type": "text", "text": full_summary}],
        "isError": false
    });
    true
}

pub fn summarize_history(items: &[serde_json::Value]) -> String {
    use std::collections::HashMap;

    let mut groups: std::collections::BTreeMap<String, (Vec<String>, HashMap<u16, u32>)> =
        std::collections::BTreeMap::new();

    for item in items {
        let method = item["request"]["method"].as_str().unwrap_or("GET");
        let raw_path = item["request"]["path"].as_str().unwrap_or("/");
        let path = raw_path.split('?').next().unwrap_or(raw_path);
        let key = format!("{} {}", method, path);
        let status = item["response"]["statusCode"].as_u64().unwrap_or(0) as u16;
        let entry = groups.entry(key).or_default();
        *entry.1.entry(status).or_insert(0) += 1;
        if let Some(qs) = raw_path.split('?').nth(1) {
            for param in qs.split('&') {
                let name = param.split('=').next().unwrap_or("").to_string();
                if !name.is_empty() && !entry.0.contains(&name) {
                    entry.0.push(name);
                }
            }
        }
    }

    let mut lines = Vec::new();
    for (key, (params, statuses)) in &groups {
        let mut status_str: Vec<String> = statuses
            .iter()
            .map(|(s, c)| format!("{}:{}", s, c))
            .collect();
        status_str.sort();
        let mut line = format!("  {} (x{}) — {}", key, statuses.values().sum::<u32>(), status_str.join(", "));
        if !params.is_empty() {
            line.push_str(&format!(" — params: {}", params.join(", ")));
        }
        lines.push(line);
    }
    lines.join("\n")
}

pub fn summarize_scanner(items: &[serde_json::Value]) -> String {
    use std::collections::HashMap;

    let severity_order = ["critical", "high", "medium", "low", "info"];
    let mut by_severity: HashMap<String, HashMap<String, u32>> = HashMap::new();

    for item in items {
        let severity = item["severity"].as_str().unwrap_or("info").to_lowercase();
        let issue_type = item["issueName"].as_str()
            .or_else(|| item["name"].as_str())
            .unwrap_or("Unknown")
            .to_string();
        *by_severity.entry(severity).or_default().entry(issue_type).or_insert(0) += 1;
    }

    let mut lines = Vec::new();
    for sev in &severity_order {
        if let Some(types) = by_severity.get(*sev) {
            let total: u32 = types.values().sum();
            let mut type_str: Vec<String> = types.iter().map(|(t, c)| format!("{} (x{})", t, c)).collect();
            type_str.sort();
            lines.push(format!("  {} ({total}): {}", capitalize(sev), type_str.join(", ")));
        }
    }
    lines.join("\n")
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn make_config() -> Config {
        Config {
            burp_url: "http://127.0.0.1:9876".into(),
            reconnect_max_secs: 30,
            tools_config: None,
            tools: None,
            body_max_chars: 2000,
            snapshot_ttl_secs: 600,
            snapshot_max_mb: 50,
        }
    }

    fn make_history_response(items: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "items": items }
        })
    }

    fn make_history_item(method: &str, path: &str, status: u16) -> serde_json::Value {
        json!({
            "request": {
                "method": method,
                "path": path,
                "headers": [],
                "body": ""
            },
            "response": {
                "statusCode": status,
                "headers": [{"name": "Content-Type", "value": "text/html"}],
                "body": "response body here"
            }
        })
    }

    #[test]
    fn process_history_returns_summary_string() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![
            make_history_item("GET", "/api/users?id=1", 200),
            make_history_item("GET", "/api/users?id=2", 200),
            make_history_item("GET", "/api/users?id=3", 403),
            make_history_item("POST", "/api/login", 200),
        ]);
        let applied = process(&mut value, "get_proxy_http_history", &cache, &config);
        assert!(applied);
        let result = &value["result"];
        assert!(result["content"][0]["text"].is_string(), "expected MCP content text, got: {result}");
        let summary = result["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("ph_"), "no snapshot id: {summary}");
        assert!(summary.contains("GET /api/users"), "no path grouping: {summary}");
        assert!(summary.contains("POST /api/login"), "missing login: {summary}");
    }

    #[test]
    fn process_saves_snapshot_to_cache() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![
            make_history_item("GET", "/api/users", 200),
        ]);
        process(&mut value, "get_proxy_http_history", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        // The summary starts with "BTK proxy history snapshot ph_XXXXXXXX ("
        // Split on ' ' and find the token starting with "ph_"
        let snap_id = summary.split(' ')
            .find(|w| w.starts_with("ph_"))
            .unwrap_or("")
            .to_string();
        assert!(!snap_id.is_empty(), "no snapshot id found in: {summary}");
        assert!(cache.get(&snap_id, Duration::from_secs(600)).is_some(), "snapshot not in cache: {snap_id}");
    }

    fn make_scanner_item(severity: &str, issue_name: &str) -> serde_json::Value {
        json!({
            "severity": severity,
            "issueName": issue_name,
            "url": "https://example.com/api",
            "description": "Issue description"
        })
    }

    #[test]
    fn process_scanner_returns_severity_summary() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "items": [
                make_scanner_item("high", "SQL Injection"),
                make_scanner_item("high", "SQL Injection"),
                make_scanner_item("medium", "CSRF"),
                make_scanner_item("critical", "OS Command Injection"),
            ]}
        });
        let applied = process(&mut value, "get_scanner_issues", &cache, &config);
        assert!(applied);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("sc_"), "no scanner snapshot id: {summary}");
        assert!(summary.contains("BTK scanner snapshot"), "wrong header: {summary}");
        assert!(summary.contains("Critical"), "missing critical: {summary}");
        assert!(summary.contains("High"), "missing high: {summary}");
        assert!(summary.contains("SQL Injection"), "missing issue type: {summary}");
        assert!(summary.contains("CSRF"), "missing csrf: {summary}");
    }

    #[test]
    fn process_returns_false_for_non_items_response() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "fail"}});
        let original = value.clone();
        let applied = process(&mut value, "get_proxy_http_history", &cache, &config);
        assert!(!applied);
        assert_eq!(value, original);
    }

    #[test]
    fn status_codes_counted_correctly() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![
            make_history_item("GET", "/api/users", 200),
            make_history_item("GET", "/api/users", 200),
            make_history_item("GET", "/api/users", 403),
        ]);
        process(&mut value, "get_proxy_http_history", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("200:2"), "missing 200 count: {summary}");
        assert!(summary.contains("403:1"), "missing 403 count: {summary}");
    }

    // ── is_groupable ─────────────────────────────────────────────────────

    #[test]
    fn is_groupable_true_for_history_and_scanner_tools() {
        assert!(is_groupable("get_proxy_http_history"));
        assert!(is_groupable("get_proxy_http_history_regex"));
        assert!(is_groupable("get_scanner_issues"));
    }

    #[test]
    fn is_groupable_false_for_other_tools() {
        assert!(!is_groupable("send_http1_request"));
        assert!(!is_groupable("btk_detail"));
        assert!(!is_groupable(""));
    }

    // ── history summarization ─────────────────────────────────────────────

    #[test]
    fn query_params_are_extracted_in_history_summary() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![
            make_history_item("GET", "/search?q=foo&page=1", 200),
            make_history_item("GET", "/search?q=bar&page=2", 200),
        ]);
        process(&mut value, "get_proxy_http_history", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("params:"), "no params section: {summary}");
        assert!(summary.contains('q'), "param 'q' missing: {summary}");
        assert!(summary.contains("page"), "param 'page' missing: {summary}");
    }

    #[test]
    fn history_with_more_than_20_items_shows_pagination_hint() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let items: Vec<serde_json::Value> = (0..25)
            .map(|i| make_history_item("GET", &format!("/api/item/{i}"), 200))
            .collect();
        let mut value = make_history_response(items);
        process(&mut value, "get_proxy_http_history", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("btk_next_page"), "pagination hint missing: {summary}");
        assert!(summary.contains("cursor=20"), "cursor hint wrong: {summary}");
    }

    #[test]
    fn history_summary_includes_btk_detail_hint() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![
            make_history_item("GET", "/api/users", 200),
        ]);
        process(&mut value, "get_proxy_http_history", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("btk_detail"), "btk_detail hint missing: {summary}");
        assert!(summary.contains("METHOD /path"), "path hint wrong: {summary}");
    }

    #[test]
    fn get_proxy_http_history_regex_is_grouped() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![
            make_history_item("GET", "/api/users", 200),
        ]);
        let applied = process(&mut value, "get_proxy_http_history_regex", &cache, &config);
        assert!(applied, "get_proxy_http_history_regex should be groupable");
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("ph_"), "no snapshot id: {summary}");
    }

    #[test]
    fn process_returns_false_for_empty_items_array() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = make_history_response(vec![]);
        let original = value.clone();
        let applied = process(&mut value, "get_proxy_http_history", &cache, &config);
        assert!(!applied, "empty items should not be grouped");
        assert_eq!(value, original);
    }

    // ── scanner summarization ─────────────────────────────────────────────

    #[test]
    fn scanner_summary_includes_btk_detail_hint() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "items": [make_scanner_item("high", "SQL Injection")] }
        });
        process(&mut value, "get_scanner_issues", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("btk_detail"), "btk_detail hint missing: {summary}");
        assert!(summary.contains("issue_type"), "issue_type hint missing: {summary}");
    }

    #[test]
    fn scanner_with_more_than_20_items_shows_pagination_hint() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let items: Vec<serde_json::Value> = (0..25)
            .map(|_| make_scanner_item("high", "SQL Injection"))
            .collect();
        let mut value = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "items": items }
        });
        process(&mut value, "get_scanner_issues", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        assert!(summary.contains("btk_next_page"), "pagination hint missing for scanner: {summary}");
        assert!(summary.contains("cursor=20"), "cursor hint wrong: {summary}");
    }

    #[test]
    fn scanner_summary_orders_by_severity() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let config = make_config();
        let mut value = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "items": [
                make_scanner_item("low", "Info Disclosure"),
                make_scanner_item("critical", "RCE"),
                make_scanner_item("high", "SQLi"),
            ]}
        });
        process(&mut value, "get_scanner_issues", &cache, &config);
        let summary = value["result"]["content"][0]["text"].as_str().unwrap();
        let critical_pos = summary.find("Critical").unwrap_or(usize::MAX);
        let high_pos = summary.find("High").unwrap_or(usize::MAX);
        let low_pos = summary.find("Low").unwrap_or(usize::MAX);
        assert!(critical_pos < high_pos, "Critical should come before High");
        assert!(high_pos < low_pos, "High should come before Low");
    }
}
