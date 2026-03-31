use std::sync::Arc;
use std::time::Duration;
use crate::snapshot_cache::SnapshotCache;

const SYNTHETIC_TOOLS: &[&str] = &["btk_detail", "btk_next_page"];
const PAGE_SIZE: usize = 20;

pub fn is_synthetic(tool_name: &str) -> bool {
    SYNTHETIC_TOOLS.contains(&tool_name)
}

/// Inject btk_detail and btk_next_page into a tools/list result.
/// Call AFTER compressor::transform so synthetic tools are not compressed.
pub fn inject_tools(value: &mut serde_json::Value) {
    let tools = match value
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    {
        Some(arr) => arr,
        None => return,
    };

    tools.push(serde_json::json!({
        "name": "btk_detail",
        "description": "Get full entries from a BTK snapshot. For proxy history: filter by 'METHOD /path'. For scanner: filter by issue type name. Optionally filter by HTTP status code.",
        "inputSchema": {
            "type": "object",
            "required": ["snapshot", "path"],
            "properties": {
                "snapshot": {"type": "string", "description": "Snapshot ID from BTK summary"},
                "path": {"type": "string", "description": "For history: 'GET /api/users'. For scanner: issue type name"},
                "status": {"type": "integer", "description": "Filter by HTTP status code (history only, optional)"}
            }
        }
    }));

    tools.push(serde_json::json!({
        "name": "btk_next_page",
        "description": "Get next page of items from a BTK snapshot (page size: 20).",
        "inputSchema": {
            "type": "object",
            "required": ["snapshot", "cursor"],
            "properties": {
                "snapshot": {"type": "string", "description": "Snapshot ID from BTK summary"},
                "cursor": {"type": "integer", "description": "Item offset to start from"}
            }
        }
    }));
}

/// Handle a btk_detail or btk_next_page call. Returns a JSON-RPC response string.
pub fn handle(
    request: &serde_json::Value,
    cache: &Arc<SnapshotCache>,
    ttl: Duration,
    body_max_chars: usize,
) -> String {
    let id = request["id"].clone();
    let args = &request["params"]["arguments"];
    let tool_name = request["params"]["name"].as_str().unwrap_or("");
    let snapshot_id = args["snapshot"].as_str().unwrap_or("");

    let snapshot = match cache.get(snapshot_id, ttl) {
        Some(s) => s,
        None => {
            return json_rpc_error(&id, "snapshot expired or not found — call the original tool again to get a fresh snapshot");
        }
    };

    let result_text = match tool_name {
        "btk_detail" => {
            let path_filter = args["path"].as_str().unwrap_or("");
            let status_filter = args["status"].as_u64().map(|s| s as u16);
            let is_scanner = snapshot.tool_name.contains("scanner");

            let matched: Vec<serde_json::Value> = snapshot.raw_items.iter().filter(|item| {
                if is_scanner {
                    let issue = item["issueName"].as_str()
                        .or_else(|| item["name"].as_str())
                        .unwrap_or("");
                    issue.eq_ignore_ascii_case(path_filter)
                } else {
                    let method = item["request"]["method"].as_str().unwrap_or("");
                    let raw_path = item["request"]["path"].as_str().unwrap_or("/");
                    let path = raw_path.split('?').next().unwrap_or(raw_path);
                    let key = format!("{} {}", method, path);
                    let matches_path = key.eq_ignore_ascii_case(path_filter);
                    let matches_status = status_filter.map_or(true, |s| {
                        item["response"]["statusCode"].as_u64() == Some(s as u64)
                    });
                    matches_path && matches_status
                }
            }).map(|item| {
                let mut item = item.clone();
                crate::body_truncate::apply_to_item(&mut item, body_max_chars);
                item
            }).collect();

            format!("{} items matching '{}':\n{}", matched.len(), path_filter,
                serde_json::to_string_pretty(&serde_json::Value::Array(matched)).unwrap_or_default())
        }
        "btk_next_page" => {
            let cursor = args["cursor"].as_u64().unwrap_or(0) as usize;
            let total = snapshot.raw_items.len();
            let page: Vec<serde_json::Value> = snapshot.raw_items.iter()
                .skip(cursor)
                .take(PAGE_SIZE)
                .cloned()
                .collect();
            let page_end = cursor + page.len();
            let is_scanner = snapshot.tool_name.contains("scanner");
            let summary = if is_scanner {
                crate::grouper::summarize_scanner(&page)
            } else {
                crate::grouper::summarize_history(&page)
            };
            let mut text = format!("BTK snapshot {snapshot_id} items {}-{} of {total}:\n{summary}",
                cursor + 1, page_end);
            let remaining = total.saturating_sub(page_end);
            if remaining > 0 {
                text.push_str(&format!("\nUse btk_next_page(snapshot=\"{snapshot_id}\", cursor={page_end}) for items {}-{}.",
                    page_end + 1, total));
            }
            let detail_hint = if is_scanner {
                format!("\nUse btk_detail(snapshot=\"{snapshot_id}\", path=\"<issue_type>\") to expand an issue type.")
            } else {
                format!("\nUse btk_detail(snapshot=\"{snapshot_id}\", path=\"<METHOD /path>\") to expand a path.")
            };
            text.push_str(&detail_hint);
            text
        }
        _ => return json_rpc_error(&id, "unknown synthetic tool"),
    };

    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": result_text}]
        }
    }).to_string()
}

fn json_rpc_error(id: &serde_json::Value, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": message}],
            "isError": true
        }
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn make_cache_with_history() -> (Arc<SnapshotCache>, String) {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let items = vec![
            json!({"request": {"method": "GET", "path": "/api/users", "headers": [], "body": ""},
                   "response": {"statusCode": 200, "headers": [{"name": "Content-Type", "value": "text/plain"}], "body": "ok"}}),
            json!({"request": {"method": "GET", "path": "/api/users", "headers": [], "body": ""},
                   "response": {"statusCode": 403, "headers": [{"name": "Content-Type", "value": "text/plain"}], "body": "forbidden"}}),
            json!({"request": {"method": "POST", "path": "/api/login", "headers": [], "body": ""},
                   "response": {"statusCode": 200, "headers": [{"name": "Content-Type", "value": "text/plain"}], "body": "ok"}}),
        ];
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        (cache, id)
    }

    #[test]
    fn inject_tools_adds_btk_tools_to_list() {
        let mut value = json!({
            "result": {
                "tools": [{"name": "send_http1_request", "description": "short", "inputSchema": {}}]
            }
        });
        inject_tools(&mut value);
        let tools = value["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3, "expected 3 tools after injection");
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"btk_detail"));
        assert!(names.contains(&"btk_next_page"));
    }

    #[test]
    fn inject_tools_noop_if_no_tools_list() {
        let mut value = json!({"result": {"data": "not a tools list"}});
        let original = value.clone();
        inject_tools(&mut value);
        assert_eq!(value, original);
    }

    #[test]
    fn handle_btk_detail_filters_by_path() {
        let (cache, id) = make_cache_with_history();
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "GET /api/users"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        // Should return items matching GET /api/users (2 items: 200 and 403)
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("2 items"), "expected 2 items: {text}");
        assert!(text.contains("/api/users"), "path missing: {text}");
    }

    #[test]
    fn handle_btk_detail_expired_snapshot_returns_error() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": "ph_expired", "path": "GET /api/users"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response.to_string();
        assert!(text.contains("expired") || text.contains("not found"), "got: {text}");
    }

    #[test]
    fn handle_btk_detail_status_filter() {
        let (cache, id) = make_cache_with_history();
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "GET /api/users", "status": 403}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("1 items") || text.contains("forbidden"), "status filter not applied: {text}");
        assert!(!text.contains("\"statusCode\":200"), "200 items should be filtered out: {text}");
    }

    #[test]
    fn handle_btk_next_page_returns_slice() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let mk = |path: &str| json!({"request": {"method": "GET", "path": path, "headers": [], "body": ""},
                                     "response": {"statusCode": 200, "headers": [], "body": ""}});
        let mut items: Vec<serde_json::Value> = (0..20).map(|_| mk("/early")).collect();
        items.extend((0..5).map(|_| mk("/late")));
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "btk_next_page", "arguments": {"snapshot": id, "cursor": 20}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("items 21-25 of 25"), "cursor not applied: {text}");
        assert!(text.contains("/late"), "expected /late path in slice: {text}");
        assert!(!text.contains("/early"), "pre-cursor /early path present: {text}");
    }

    // ── is_synthetic ─────────────────────────────────────────────────────

    #[test]
    fn is_synthetic_true_for_btk_tools() {
        assert!(is_synthetic("btk_detail"));
        assert!(is_synthetic("btk_next_page"));
    }

    #[test]
    fn is_synthetic_false_for_burp_tools() {
        assert!(!is_synthetic("send_http1_request"));
        assert!(!is_synthetic("get_proxy_http_history"));
        assert!(!is_synthetic(""));
    }

    // ── btk_detail: additional scenarios ─────────────────────────────────

    #[test]
    fn handle_btk_detail_no_matches_returns_zero_items() {
        let (cache, id) = make_cache_with_history();
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "DELETE /nonexistent"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("0 items"), "expected 0 items: {text}");
    }

    #[test]
    fn handle_btk_detail_path_matching_is_case_insensitive() {
        let (cache, id) = make_cache_with_history();
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "get /API/USERS"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("2 items"), "case-insensitive match failed: {text}");
    }

    #[test]
    fn handle_btk_detail_scanner_mode_filters_by_issue_name() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let items = vec![
            json!({"issueName": "SQL Injection", "severity": "high", "host": "example.com"}),
            json!({"issueName": "SQL Injection", "severity": "high", "host": "other.com"}),
            json!({"issueName": "CSRF", "severity": "medium", "host": "example.com"}),
        ];
        let id = cache.insert("sc", "get_scanner_issues".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "SQL Injection"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("2 items"), "expected 2 SQL Injection items: {text}");
        assert!(!text.contains("CSRF"), "CSRF should be filtered out: {text}");
    }

    #[test]
    fn handle_btk_detail_body_truncation_applied() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let long_body = "x".repeat(5000);
        let items = vec![json!({
            "request": {"method": "GET", "path": "/api", "headers": [], "body": ""},
            "response": {
                "statusCode": 200,
                "headers": [{"name": "Content-Type", "value": "text/plain"}],
                "body": long_body
            }
        })];
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "GET /api"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        // Body in the JSON output should be truncated to <= 2000 chars
        let parsed: Vec<serde_json::Value> = serde_json::from_str(
            text.lines().skip(1).collect::<Vec<_>>().join("\n").trim()
        ).unwrap_or_default();
        if let Some(body) = parsed.first().and_then(|i| i.pointer("/response/body")).and_then(|v| v.as_str()) {
            assert!(body.len() <= 2000, "body not truncated: {} chars", body.len());
        }
    }

    // ── btk_next_page: additional scenarios ──────────────────────────────

    #[test]
    fn handle_btk_next_page_cursor_zero_returns_first_page() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let mk = |path: &str| json!({"request": {"method": "GET", "path": path, "headers": [], "body": ""},
                                     "response": {"statusCode": 200, "headers": [], "body": ""}});
        let mut items: Vec<serde_json::Value> = (0..20).map(|_| mk("/early")).collect();
        items.extend((0..5).map(|_| mk("/late")));
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_next_page", "arguments": {"snapshot": id, "cursor": 0}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("items 1-20 of 25"), "range header wrong: {text}");
        assert!(text.contains("/early"), "first page items missing: {text}");
        assert!(!text.contains("/late"), "item beyond page size present: {text}");
    }

    #[test]
    fn handle_btk_next_page_shows_remaining_hint_when_more_items() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let items: Vec<serde_json::Value> = (0..45).map(|i| json!({"index": i})).collect();
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_next_page", "arguments": {"snapshot": id, "cursor": 0}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("btk_next_page"), "pagination hint missing: {text}");
        assert!(text.contains("cursor=20"), "next cursor wrong: {text}");
    }

    #[test]
    fn handle_btk_next_page_expired_snapshot_returns_error() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_next_page", "arguments": {"snapshot": "ph_expired", "cursor": 0}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let is_error = response["result"]["isError"].as_bool().unwrap_or(false);
        assert!(is_error, "expected isError=true for expired snapshot: {response}");
    }

    #[test]
    fn handle_btk_next_page_scanner_snapshot_uses_scanner_summary() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let mk = |name: &str| json!({"issueName": name, "severity": "high", "url": "https://example.com"});
        let mut items: Vec<serde_json::Value> = (0..20).map(|_| mk("SQL Injection")).collect();
        items.extend((0..5).map(|_| mk("CSRF")));
        let id = cache.insert("sc", "get_scanner_issues".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_next_page", "arguments": {"snapshot": id, "cursor": 20}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("items 21-25 of 25"), "range header wrong: {text}");
        assert!(text.contains("CSRF"), "expected CSRF in scanner page: {text}");
        assert!(!text.contains("SQL Injection"), "pre-cursor issue present: {text}");
        assert!(text.contains("btk_detail"), "scanner detail hint missing: {text}");
        assert!(text.contains("issue_type"), "scanner detail hint wrong format: {text}");
    }

    #[test]
    fn handle_btk_next_page_last_page_no_continuation_hint() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let mk = |path: &str| json!({"request": {"method": "GET", "path": path, "headers": [], "body": ""},
                                     "response": {"statusCode": 200, "headers": [], "body": ""}});
        let items: Vec<serde_json::Value> = (0..5).map(|_| mk("/api")).collect();
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_next_page", "arguments": {"snapshot": id, "cursor": 0}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("items 1-5 of 5"), "range wrong: {text}");
        // Only the btk_detail hint should appear, not a next-page continuation
        let next_page_count = text.matches("cursor=").count();
        assert_eq!(next_page_count, 0, "no cursor hint expected on last page: {text}");
    }

    #[test]
    fn handle_btk_detail_query_string_stripped_in_path_match() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let items = vec![
            json!({"request": {"method": "GET", "path": "/api/users?id=1", "headers": [], "body": ""},
                   "response": {"statusCode": 200, "headers": [], "body": ""}}),
            json!({"request": {"method": "GET", "path": "/api/users?id=2", "headers": [], "body": ""},
                   "response": {"statusCode": 200, "headers": [], "body": ""}}),
        ];
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_detail", "arguments": {"snapshot": id, "path": "GET /api/users"}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("2 items"), "query string not stripped in path match: {text}");
    }

    #[test]
    fn handle_unknown_tool_returns_error() {
        let cache = Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)));
        let items = vec![json!({"x": 1})];
        let id = cache.insert("ph", "get_proxy_http_history".into(), items);
        let request = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "btk_unknown", "arguments": {"snapshot": id, "path": ""}}
        });
        let response_str = handle(&request, &cache, Duration::from_secs(600), 2000);
        let response: serde_json::Value = serde_json::from_str(&response_str).unwrap();
        let is_error = response["result"]["isError"].as_bool().unwrap_or(false);
        assert!(is_error, "expected isError=true for unknown tool: {response}");
    }
}
