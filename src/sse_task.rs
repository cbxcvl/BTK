use std::sync::Arc;
use std::time::Duration;
use futures::StreamExt;
use crate::compressor::CompressorConfig;
use crate::config::Config;
use crate::snapshot_cache::SnapshotCache;
use dashmap::DashMap;

struct SseContext<'a> {
    config: &'a Arc<Config>,
    compressor_config: &'a CompressorConfig,
    cache: &'a Arc<SnapshotCache>,
    inflight: &'a Arc<DashMap<u64, String>>,
    session_tx: &'a tokio::sync::watch::Sender<Option<String>>,
}

pub(crate) fn backoff_secs(consecutive_failures: u32, max_secs: u64) -> u64 {
    let exp = 2u64.saturating_pow(consecutive_failures.saturating_sub(1));
    exp.min(max_secs)
}

pub async fn run(
    client: Arc<reqwest::Client>,
    config: Arc<Config>,
    session_tx: tokio::sync::watch::Sender<Option<String>>,
    cache: Arc<SnapshotCache>,
    inflight: Arc<DashMap<u64, String>>,
) -> anyhow::Result<()> {
    const MAX_FAILURES: u32 = 5;
    let compressor_config = config.compressor_config()?;
    let mut failures = 0u32;

    loop {
        match stream_sse(&client, &config, &session_tx, &compressor_config, &cache, &inflight).await {
            Ok(()) => {
                // Stream ended cleanly (server closed connection) — reconnect immediately
                failures = 0;
                eprintln!("[btk] SSE stream ended, reconnecting...");
            }
            Err(e) => {
                failures += 1;
                eprintln!("[btk] SSE error ({failures}/{MAX_FAILURES}): {e}");
                if failures >= MAX_FAILURES {
                    anyhow::bail!("SSE failed {MAX_FAILURES} consecutive times, giving up");
                }
                let wait = backoff_secs(failures, config.reconnect_max_secs);
                eprintln!("[btk] Reconnecting in {wait}s...");
                tokio::time::sleep(Duration::from_secs(wait)).await;
            }
        }
    }
}

fn transform_message_data(data: &str, ctx: &SseContext<'_>) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) else {
        return data.to_string();
    };

    if value.pointer("/result/tools").and_then(|t| t.as_array()).is_some() {
        // tools/list response: compress descriptions + inject synthetic tools
        crate::lossless::strip(&mut value);
        crate::compressor::transform(&mut value, ctx.compressor_config);
        crate::synthetic::inject_tools(&mut value);
    } else {
        // Look up originating tool name from inflight map
        let tool_name = value["id"].as_u64()
            .and_then(|id| ctx.inflight.remove(&id).map(|(_, v)| v));

        // Normalize Burp's content[0].text → result.items (must precede lossless).
        // Only run for tools that actually benefit from normalization; all others pass
        // through unchanged so their original content[0].text reaches the MCP client.
        if let Some(ref tname) = tool_name {
            if crate::normalizer::needs_normalization(tname) {
                crate::normalizer::normalize_response(&mut value, tname);
            }
        }

        // Layer 1: lossless strip (now result.items exists if normalization ran)
        crate::lossless::strip(&mut value);

        let grouped = match tool_name.as_deref() {
            Some(tname) if crate::grouper::is_groupable(tname) => {
                crate::grouper::process(&mut value, tname, ctx.cache, ctx.config)
            }
            _ => false,
        };

        if !grouped {
            // Layer 2: body truncation on items array
            if let Some(items) = value.pointer_mut("/result/items").and_then(|v| v.as_array_mut()) {
                for item in items.iter_mut() {
                    crate::body_truncate::apply_to_item(item, ctx.config.body_max_chars);
                }
            }
            // Re-wrap result.items as content[0].text for MCP compliance.
            // This applies to normalizable-but-not-groupable tools (e.g. send_http1_request,
            // output_user_options) whose items array was built by the normalizer.
            if let Some(items) = value.pointer("/result/items").and_then(|v| v.as_array()) {
                if !items.is_empty() {
                    let text = if items.len() == 1 {
                        serde_json::to_string_pretty(&items[0]).unwrap_or_default()
                    } else {
                        serde_json::to_string_pretty(&serde_json::Value::Array(items.to_vec()))
                            .unwrap_or_default()
                    };
                    value["result"] = serde_json::json!({
                        "content": [{"type": "text", "text": text}]
                    });
                }
            }
        }
    }

    serde_json::to_string(&value).unwrap_or_else(|_| data.to_string())
}

fn process_data_line(data: &str, event_type: &Option<String>, ctx: &SseContext<'_>) -> Option<Vec<u8>> {
    match event_type.as_deref() {
        Some("endpoint") => {
            let session_url = format!("{}{}", ctx.config.burp_url, data);
            eprintln!("[btk] Got session URL: {session_url}");
            let _ = ctx.session_tx.send(Some(session_url));
            None
        }
        Some("message") | None => {
            // "message" is the explicit type, None means no event: line (default)
            let output = transform_message_data(data, ctx);
            let mut out = output.into_bytes();
            out.push(b'\n');
            Some(out)
        }
        Some(_) => None, // ignore other event types
    }
}

async fn process_line(
    line: &str,
    current_event_type: &mut Option<String>,
    ctx: &SseContext<'_>,
    out: &mut (impl tokio::io::AsyncWriteExt + Unpin),
) -> anyhow::Result<()> {
    if line.is_empty() {
        // blank line resets event state (standard SSE separator)
        *current_event_type = None;
        return Ok(());
    }

    if let Some(event_type) = line.strip_prefix("event: ") {
        *current_event_type = Some(event_type.to_string());
        return Ok(());
    }

    if let Some(data) = line.strip_prefix("data: ") {
        if let Some(bytes) = process_data_line(data, current_event_type, ctx) {
            out.write_all(&bytes).await?;
            out.flush().await?;
        }
        *current_event_type = None;
    }

    Ok(())
}

async fn stream_sse(
    client: &reqwest::Client,
    config: &Arc<Config>,
    session_tx: &tokio::sync::watch::Sender<Option<String>>,
    compressor_config: &CompressorConfig,
    cache: &Arc<SnapshotCache>,
    inflight: &Arc<DashMap<u64, String>>,
) -> anyhow::Result<()> {
    let url = format!("{}/", config.burp_url);
    let response = client
        .get(&url)
        .header("Accept", "text/event-stream")
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("SSE endpoint returned HTTP {}", response.status());
    }

    const MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MB hard cap per SSE line
    let mut stream = response.bytes_stream();
    let mut stdout = tokio::io::stdout();
    let mut buf = Vec::<u8>::new();
    let mut current_event_type: Option<String> = None;
    let ctx = SseContext { config, compressor_config, cache, inflight, session_tx };

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.extend_from_slice(&chunk);

        if buf.len() > MAX_LINE_BYTES && !buf.contains(&b'\n') {
            anyhow::bail!("SSE line exceeds {MAX_LINE_BYTES} bytes without newline — aborting");
        }

        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let raw_line = &buf[..pos];
            let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            // SSE protocol lines are UTF-8; drop lines that aren't valid UTF-8
            let line = match std::str::from_utf8(raw_line) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    buf.drain(..pos + 1);
                    continue;
                }
            };
            buf.drain(..pos + 1);
            process_line(&line, &mut current_event_type, &ctx, &mut stdout).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_ctx<'a>(
        config: &'a Arc<Config>,
        compressor_config: &'a CompressorConfig,
        cache: &'a Arc<SnapshotCache>,
        inflight: &'a Arc<DashMap<u64, String>>,
        session_tx: &'a tokio::sync::watch::Sender<Option<String>>,
    ) -> SseContext<'a> {
        SseContext { config, compressor_config, cache, inflight, session_tx }
    }

    fn default_config() -> Arc<Config> {
        Arc::new(Config {
            burp_url: "http://test.local".to_string(),
            reconnect_max_secs: 30,
            tools_config: None,
            tools: None,
            body_max_chars: 2000,
            snapshot_ttl_secs: 600,
            snapshot_max_mb: 50,
        })
    }

    fn default_cache() -> Arc<SnapshotCache> {
        Arc::new(SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600)))
    }

    // ── process_data_line ────────────────────────────────────────────────

    #[test]
    fn data_line_endpoint_sends_session_url_and_returns_none() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, session_rx) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let result = process_data_line("/sse/session-123", &Some("endpoint".to_string()), &ctx);

        assert!(result.is_none());
        assert_eq!(
            session_rx.borrow().as_deref(),
            Some("http://test.local/sse/session-123")
        );
    }

    #[test]
    fn data_line_message_event_returns_json_bytes_ending_with_newline() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let data = r#"{"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"hello","type":"text"}],"isError":false}}"#;
        let result = process_data_line(data, &Some("message".to_string()), &ctx);

        let bytes = result.expect("expected Some bytes");
        assert!(*bytes.last().unwrap() == b'\n');
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes[..bytes.len() - 1]).is_ok());
    }

    #[test]
    fn data_line_none_event_type_treated_as_message() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let data = r#"{"id":1,"jsonrpc":"2.0","result":{}}"#;
        let result = process_data_line(data, &None, &ctx);

        assert!(result.is_some());
    }

    #[test]
    fn data_line_unknown_event_type_returns_none() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let result = process_data_line("anything", &Some("ping".to_string()), &ctx);

        assert!(result.is_none());
    }

    // ── transform_message_data ───────────────────────────────────────────

    #[test]
    fn invalid_json_passes_through_unchanged() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let result = transform_message_data("not valid json", &ctx);
        assert_eq!(result, "not valid json");
    }

    #[test]
    fn tools_list_response_has_descriptions_compressed() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let data = r#"{"id":1,"jsonrpc":"2.0","result":{"tools":[{"name":"send_http1_request","description":"Some very long original description that should be replaced by the builtin short one"}]}}"#;
        let result = transform_message_data(data, &ctx);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        let desc = v.pointer("/result/tools/0/description").and_then(|d| d.as_str()).unwrap();
        assert!(desc.len() < 60, "description should be compressed, got: {desc}");
    }

    #[test]
    fn message_response_strips_null_fields_and_meta_at_result_level() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        // lossless::strip removes null fields and _meta at the result level
        let data = r#"{"id":1,"jsonrpc":"2.0","result":{"items":[],"_meta":null,"nullField":null,"keepMe":"value"}}"#;
        let result = transform_message_data(data, &ctx);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v.pointer("/result/_meta").is_none(), "_meta should be stripped");
        assert!(v.pointer("/result/nullField").is_none(), "null fields should be stripped from result");
        assert_eq!(v.pointer("/result/keepMe").and_then(|v| v.as_str()), Some("value"), "non-null fields should be preserved");
    }

    #[test]
    fn unknown_tool_content_passes_through_unchanged() {
        // Tools not in needs_normalization (e.g. base64_encode, url_encode) must preserve
        // the original content[0].text so the MCP client can display it.
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        inflight.insert(7, "base64_encode".to_string());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let data = r#"{"id":7,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"aGVsbG8="}],"isError":false}}"#;
        let result = transform_message_data(data, &ctx);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        let text = v.pointer("/result/content/0/text").and_then(|t| t.as_str())
            .expect("content[0].text should be preserved for unknown tools");
        assert_eq!(text, "aGVsbG8=", "base64 output should pass through verbatim");
        assert!(v.pointer("/result/items").is_none(), "result.items must not appear for unknown tools");
    }

    #[test]
    fn single_response_tool_items_rewrapped_as_content() {
        // send_http1_request is normalizable but not groupable: after normalization +
        // body_truncate the items should be re-wrapped as content[0].text.
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        inflight.insert(8, "send_http1_request".to_string());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let raw_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
        let data = format!(
            r#"{{"id":8,"jsonrpc":"2.0","result":{{"content":[{{"type":"text","text":"{raw_response}"}}],"isError":false}}}}"#,
            raw_response = raw_response.replace("\r\n", "\\r\\n")
        );
        let result = transform_message_data(&data, &ctx);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        let text = v.pointer("/result/content/0/text").and_then(|t| t.as_str())
            .expect("content[0].text should be present after re-wrap");
        assert!(text.contains("200"), "re-wrapped content should include status code: {text}");
        assert!(v.pointer("/result/items").is_none(), "result.items must not appear after re-wrap");
    }

    #[test]
    fn inflight_tool_name_is_consumed_on_response() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        inflight.insert(42, "get_proxy_http_history".to_string());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);

        let data = r#"{"id":42,"jsonrpc":"2.0","result":{"content":[{"text":"{}","type":"text"}],"isError":false}}"#;
        transform_message_data(data, &ctx);

        assert!(!inflight.contains_key(&42), "inflight entry should be consumed");
    }

    // ── process_line ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn blank_line_resets_event_type() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);
        let mut out = Vec::<u8>::new();
        let mut event_type = Some("message".to_string());

        process_line("", &mut event_type, &ctx, &mut out).await.unwrap();

        assert!(event_type.is_none());
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn event_line_sets_current_event_type() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);
        let mut out = Vec::<u8>::new();
        let mut event_type = None;

        process_line("event: message", &mut event_type, &ctx, &mut out).await.unwrap();

        assert_eq!(event_type.as_deref(), Some("message"));
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn data_line_writes_output_and_resets_event_type() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, _) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);
        let mut out = Vec::<u8>::new();
        let mut event_type = Some("message".to_string());

        let data = r#"data: {"id":1,"jsonrpc":"2.0","result":{}}"#;
        process_line(data, &mut event_type, &ctx, &mut out).await.unwrap();

        assert!(event_type.is_none(), "event type should be reset after data line");
        assert!(!out.is_empty(), "output should be written");
        assert_eq!(*out.last().unwrap(), b'\n');
    }

    #[tokio::test]
    async fn endpoint_data_line_sends_session_url_no_output() {
        let config = default_config();
        let compressor_config = CompressorConfig::default();
        let cache = default_cache();
        let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());
        let (session_tx, session_rx) = tokio::sync::watch::channel(None);
        let ctx = make_ctx(&config, &compressor_config, &cache, &inflight, &session_tx);
        let mut out = Vec::<u8>::new();
        let mut event_type = Some("endpoint".to_string());

        process_line("data: /sse/abc", &mut event_type, &ctx, &mut out).await.unwrap();

        assert!(out.is_empty(), "endpoint data should not be written to output");
        assert_eq!(session_rx.borrow().as_deref(), Some("http://test.local/sse/abc"));
    }

    // ── backoff_secs ─────────────────────────────────────────────────────

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        assert_eq!(backoff_secs(1, 30), 1);
        assert_eq!(backoff_secs(2, 30), 2);
        assert_eq!(backoff_secs(3, 30), 4);
        assert_eq!(backoff_secs(4, 30), 8);
        assert_eq!(backoff_secs(10, 30), 30); // capped
    }

    #[test]
    fn backoff_secs_zero_failures_returns_one() {
        // saturating_sub(1) on 0 → 0, so 2^0 = 1
        assert_eq!(backoff_secs(0, 30), 1);
    }
}
