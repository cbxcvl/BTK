use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

const BURP_URL: &str = "http://127.0.0.1:9876";
const BTK_BIN: &str = env!("CARGO_BIN_EXE_btk");

/// Spawn a btk process connected to Burp and return its stdin/stdout/stderr handles.
async fn spawn_btk() -> (
    tokio::process::Child,
    tokio::process::ChildStdin,
    BufReader<tokio::process::ChildStdout>,
) {
    let mut child = Command::new(BTK_BIN)
        .arg("--burp-url")
        .arg(BURP_URL)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn btk");

    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdin, stdout)
}

/// Send one JSON-RPC request and read one response line from BTK's stdout.
async fn rpc(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut BufReader<tokio::process::ChildStdout>,
    request: serde_json::Value,
) -> serde_json::Value {
    let mut req_bytes = serde_json::to_vec(&request).unwrap();
    req_bytes.push(b'\n');
    stdin.write_all(&req_bytes).await.expect("write to btk stdin");
    stdin.flush().await.expect("flush btk stdin");

    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(15), stdout.read_line(&mut line))
        .await
        .expect("timed out waiting for btk response")
        .expect("read from btk stdout");

    serde_json::from_str(line.trim()).expect("btk response is not valid JSON")
}

/// End-to-end: tools/list through btk verifies descriptions are compressed
/// and synthetic btk_* tools are injected.
///
/// Run with: cargo test -- --include-ignored
#[tokio::test]
#[ignore]
async fn test_tools_list_compressed_via_btk() {
    let (_child, mut stdin, mut stdout) = spawn_btk().await;

    let resp = rpc(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }),
    )
    .await;

    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "expected result or error, got: {resp}"
    );

    if let Some(tools) = resp["result"]["tools"].as_array() {
        // Descriptions must be compressed to builtin short form
        let send_tool = tools.iter().find(|t| t["name"].as_str() == Some("send_http1_request"));
        if let Some(tool) = send_tool {
            assert_eq!(
                tool["description"].as_str().unwrap_or(""),
                "Send HTTP/1.1 request, return response.",
                "description not compressed"
            );
        }

        // BTK synthetic tools must be injected
        let has_btk_detail = tools.iter().any(|t| t["name"].as_str() == Some("btk_detail"));
        assert!(has_btk_detail, "btk_detail synthetic tool not found in tools list");

        // _meta must be stripped
        assert!(
            resp["result"]["_meta"].is_null() || resp["result"].get("_meta").is_none(),
            "_meta should be stripped"
        );
    }
}

/// End-to-end: get_proxy_http_history through btk returns a snapshot summary,
/// then btk_detail resolves the snapshot into actual items.
///
/// Run with: cargo test -- --include-ignored
#[tokio::test]
#[ignore]
async fn test_proxy_history_snapshot_and_detail_via_btk() {
    let (_child, mut stdin, mut stdout) = spawn_btk().await;

    // Step 1: call get_proxy_http_history — expect a BTK snapshot summary
    let resp = rpc(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "get_proxy_http_history",
                "arguments": { "count": 10, "offset": 0 }
            }
        }),
    )
    .await;

    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "expected result or error, got: {resp}"
    );

    // If Burp has proxy history, response should contain a snapshot ID
    let content_text = resp
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if content_text.is_empty() {
        eprintln!("[test] no proxy history available in Burp — skipping snapshot assertions");
        return;
    }

    // Extract snapshot ID (format: "ph_<hex>")
    let snapshot_id = content_text
        .split_whitespace()
        .find(|w| w.starts_with("ph_"))
        .expect("expected snapshot ID starting with ph_ in response");

    eprintln!("[test] got snapshot: {snapshot_id}");

    // Step 2: call btk_detail with the snapshot ID — handled locally by btk
    let detail_resp = rpc(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "btk_detail",
                "arguments": { "snapshot_id": snapshot_id }
            }
        }),
    )
    .await;

    assert!(
        detail_resp.get("result").is_some(),
        "btk_detail should return result, got: {detail_resp}"
    );

    let detail_text = detail_resp
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    assert!(
        !detail_text.is_empty(),
        "btk_detail returned empty content"
    );

    // Verify items have truncated bodies (BTK applied body_truncate)
    if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(detail_text) {
        for item in &items {
            if let Some(body) = item.pointer("/response/body").and_then(|v| v.as_str()) {
                assert!(
                    body.len() <= 2000 || body.starts_with('['),
                    "body should be truncated or replaced, got {} chars",
                    body.len()
                );
            }
        }
        eprintln!("[test] btk_detail returned {} items with truncated bodies", items.len());
    }
}

/// End-to-end: send_http1_request through btk returns a structured response.
///
/// Run with: cargo test -- --include-ignored
#[tokio::test]
#[ignore]
async fn test_send_http1_request_via_btk() {
    let (_child, mut stdin, mut stdout) = spawn_btk().await;

    let resp = rpc(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "send_http1_request",
                "arguments": {
                    "host": "http://127.0.0.1",
                    "port": 9876,
                    "request": "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                }
            }
        }),
    )
    .await;

    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "expected result or error, got: {resp}"
    );

    // If successful, response should have structured items (not raw text)
    if let Some(items) = resp.pointer("/result/items").and_then(|v| v.as_array()) {
        if let Some(first) = items.first() {
            assert!(
                first.get("response").is_some(),
                "expected structured response field in item"
            );
        }
    }
}
