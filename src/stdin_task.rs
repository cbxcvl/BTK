use std::sync::Arc;
use dashmap::DashMap;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use crate::config::Config;
use crate::snapshot_cache::SnapshotCache;

const HTTP_REQUEST_TOOLS: &[&str] = &[
    "create_repeater_tab",
    "send_to_intruder",
    "send_http1_request",
    "send_http2_request",
];

fn is_empty_line(line: &str) -> bool {
    line.trim().is_empty()
}

/// Normalize HTTP request line endings to CRLF.
/// Handles three cases:
///   - Lone LF (`\n`) → CRLF
///   - Literal backslash-r-backslash-n (4 chars, e.g. from Claude) → CRLF
///   - Already CRLF → unchanged (no doubling)
fn normalize_to_crlf(s: &str) -> String {
    // Step 1: interpret escaped \r\n sequences (literal 4-char \r\n text → actual CRLF)
    let s = s.replace("\\r\\n", "\r\n");
    // Step 2: collapse any existing CRLF to LF, then expand all LF to CRLF
    let s = s.replace("\r\n", "\n");
    s.replace('\n', "\r\n")
}

/// Normalize the `request` argument of HTTP-sending tools to use proper CRLF line endings.
/// Returns true if any modification was made.
fn normalize_http_request_args(value: &mut serde_json::Value) -> bool {
    let tool_name = value["params"]["name"].as_str().unwrap_or("");
    if !HTTP_REQUEST_TOOLS.contains(&tool_name) {
        return false;
    }
    let Some(args) = value["params"]["arguments"].as_object_mut() else {
        return false;
    };
    // Burp tools use either "request" or "content" as the HTTP request parameter name
    let field = if args.contains_key("request") { "request" } else { "content" };
    let Some(serde_json::Value::String(req_str)) = args.get_mut(field) else {
        return false;
    };
    let normalized = normalize_to_crlf(req_str);
    if normalized == *req_str {
        return false;
    }
    *req_str = normalized;
    true
}

/// Returns true if the request was a synthetic tool call and was handled locally (do not forward).
async fn handle_tools_call(
    request: &serde_json::Value,
    cache: &Arc<SnapshotCache>,
    inflight: &Arc<DashMap<u64, String>>,
    config: &Arc<Config>,
    stdout: &mut tokio::io::Stdout,
) -> anyhow::Result<bool> {
    let tool_name = request["params"]["name"].as_str().unwrap_or("").to_string();
    if crate::synthetic::is_synthetic(&tool_name) {
        let ttl = config.snapshot_ttl();
        let response = crate::synthetic::handle(request, cache, ttl, config.body_max_chars);
        let mut out = response.into_bytes();
        out.push(b'\n');
        stdout.write_all(&out).await?;
        stdout.flush().await?;
        return Ok(true);
    }
    if let Some(id) = request["id"].as_u64() {
        inflight.insert(id, tool_name);
    }
    Ok(false)
}

pub async fn run(
    client: Arc<reqwest::Client>,
    session_rx: tokio::sync::watch::Receiver<Option<String>>,
    cache: Arc<SnapshotCache>,
    inflight: Arc<DashMap<u64, String>>,
    config: Arc<Config>,
) -> anyhow::Result<()> {
    // Wait for the first session URL from the SSE handshake before processing stdin
    {
        let mut rx = session_rx.clone();
        while rx.borrow().is_none() {
            rx.changed()
                .await
                .map_err(|_| anyhow::anyhow!("session channel closed before handshake"))?;
        }
    }

    eprintln!("[btk] Session URL ready, forwarding stdin");

    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if is_empty_line(&line) {
            continue;
        }

        let mut normalized_line: Option<String> = None;

        // Check if this is a synthetic tool call (btk_detail, btk_next_page),
        // or a tool call that requires outgoing normalization (CRLF fix).
        if let Ok(mut request) = serde_json::from_str::<serde_json::Value>(&line) {
            if request["method"].as_str() == Some("tools/call") {
                if handle_tools_call(&request, &cache, &inflight, &config, &mut stdout).await? {
                    continue; // Do NOT forward to Burp
                }
                if normalize_http_request_args(&mut request) {
                    normalized_line = serde_json::to_string(&request).ok();
                }
            }
        }

        let body = normalized_line.unwrap_or(line);

        // Re-read the session URL on each iteration so reconnects are handled correctly
        let session_url = session_rx
            .borrow()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("session URL unexpectedly None"))?;
        match client
            .post(&session_url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(resp) if !resp.status().is_success() => {
                eprintln!("[btk] POST error: HTTP {}", resp.status());
            }
            Err(e) => { eprintln!("[btk] POST failed: {e}"); }
            Ok(_) => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_line_is_skipped() {
        assert!(is_empty_line(""));
    }

    #[test]
    fn whitespace_only_line_is_skipped() {
        assert!(is_empty_line("   "));
        assert!(is_empty_line("\t"));
        assert!(is_empty_line(" \t \n"));
    }

    #[test]
    fn non_empty_line_is_not_skipped() {
        assert!(!is_empty_line(r#"{"jsonrpc":"2.0","id":1}"#));
    }

    #[test]
    fn line_with_leading_whitespace_is_skipped() {
        assert!(is_empty_line("   \t  "));
    }

    #[test]
    fn line_with_content_and_whitespace_is_not_skipped() {
        assert!(!is_empty_line("  test  "));
    }

    // ── normalize_to_crlf ────────────────────────────────────────────────

    #[test]
    fn normalize_to_crlf_converts_lf_to_crlf() {
        let input = "GET / HTTP/1.1\nHost: example.com\n\n";
        let expected = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(normalize_to_crlf(input), expected);
    }

    #[test]
    fn normalize_to_crlf_leaves_crlf_unchanged() {
        let input = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(normalize_to_crlf(input), input);
    }

    #[test]
    fn normalize_to_crlf_interprets_escaped_sequences() {
        // Literal backslash-r-backslash-n (4 chars) → actual CRLF
        let input = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n";
        let expected = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(normalize_to_crlf(input), expected);
    }

    #[test]
    fn normalize_to_crlf_no_double_crlf() {
        // Already CRLF should not produce \r\r\n
        let input = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = normalize_to_crlf(input);
        assert!(!result.contains("\r\r\n"), "no double CR: {result:?}");
        assert_eq!(result, input);
    }

    // ── normalize_http_request_args ──────────────────────────────────────

    #[test]
    fn normalize_args_modifies_create_repeater_tab_request_field() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "create_repeater_tab",
                "arguments": {"request": "GET / HTTP/1.1\nHost: example.com\n\n"}
            }
        });
        assert!(normalize_http_request_args(&mut value));
        let req = value["params"]["arguments"]["request"].as_str().unwrap();
        assert_eq!(req, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn normalize_args_modifies_content_field() {
        // Burp's send_http1_request uses "content" not "request"
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "send_http1_request",
                "arguments": {"content": "GET / HTTP/1.1\nHost: example.com\n\n", "targetHostname": "example.com"}
            }
        });
        assert!(normalize_http_request_args(&mut value));
        let req = value["params"]["arguments"]["content"].as_str().unwrap();
        assert_eq!(req, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn normalize_args_escaped_crlf_via_content_field() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "send_http1_request",
                "arguments": {
                    "content": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\nAccept: */*\\r\\n\\r\\n",
                    "targetHostname": "example.com"
                }
            }
        });
        assert!(normalize_http_request_args(&mut value));
        let req = value["params"]["arguments"]["content"].as_str().unwrap();
        assert_eq!(req, "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n");
    }

    #[test]
    fn normalize_args_modifies_send_to_intruder() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "send_to_intruder",
                "arguments": {"request": "POST /login HTTP/1.1\nHost: x\n\nbody"}
            }
        });
        assert!(normalize_http_request_args(&mut value));
        let req = value["params"]["arguments"]["request"].as_str().unwrap();
        assert!(req.contains("\r\n"), "should have CRLF: {req:?}");
    }

    #[test]
    fn normalize_args_modifies_send_http1_request() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "send_http1_request",
                "arguments": {"request": "GET / HTTP/1.1\nHost: example.com\n\n"}
            }
        });
        assert!(normalize_http_request_args(&mut value));
    }

    #[test]
    fn normalize_args_modifies_send_http2_request() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "send_http2_request",
                "arguments": {"request": "GET / HTTP/2\nHost: example.com\n\n"}
            }
        });
        assert!(normalize_http_request_args(&mut value));
    }

    #[test]
    fn normalize_args_no_op_for_unrelated_tools() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "get_proxy_http_history",
                "arguments": {}
            }
        });
        assert!(!normalize_http_request_args(&mut value));
    }

    #[test]
    fn normalize_args_no_op_when_already_crlf() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "send_http1_request",
                "arguments": {"content": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}
            }
        });
        assert!(!normalize_http_request_args(&mut value), "no modification needed if already CRLF");
    }

    #[test]
    fn normalize_args_handles_escaped_crlf_request_field() {
        let mut value = serde_json::json!({
            "method": "tools/call",
            "params": {
                "name": "create_repeater_tab",
                "arguments": {"request": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"}
            }
        });
        assert!(normalize_http_request_args(&mut value));
        let req = value["params"]["arguments"]["request"].as_str().unwrap();
        assert_eq!(req, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }
}
