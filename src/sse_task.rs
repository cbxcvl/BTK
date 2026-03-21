use std::sync::Arc;
use std::time::Duration;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use crate::compressor::CompressorConfig;
use crate::config::Config;
use crate::snapshot_cache::SnapshotCache;
use dashmap::DashMap;

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

fn transform_message_data(
    data: &str,
    config: &Arc<Config>,
    compressor_config: &CompressorConfig,
    cache: &Arc<SnapshotCache>,
    inflight: &Arc<DashMap<u64, String>>,
) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) else {
        return data.to_string();
    };

    if value.pointer("/result/tools").and_then(|t| t.as_array()).is_some() {
        // tools/list response: compress descriptions + inject synthetic tools
        crate::lossless::strip(&mut value);
        crate::compressor::transform(&mut value, compressor_config);
        crate::synthetic::inject_tools(&mut value);
    } else {
        // Look up originating tool name from inflight map
        let tool_name = value["id"].as_u64()
            .and_then(|id| inflight.remove(&id).map(|(_, v)| v));

        // Normalize Burp's content[0].text → result.items (must precede lossless)
        if let Some(ref tname) = tool_name {
            crate::normalizer::normalize_response(&mut value, tname);
        }

        // Layer 1: lossless strip (now result.items exists if normalization ran)
        crate::lossless::strip(&mut value);

        let grouped = match tool_name.as_deref() {
            Some(tname) if crate::grouper::is_groupable(tname) => {
                crate::grouper::process(&mut value, tname, cache, config)
            }
            _ => false,
        };

        if !grouped {
            // Layer 2: body truncation on items array
            if let Some(items) = value.pointer_mut("/result/items").and_then(|v| v.as_array_mut()) {
                for item in items.iter_mut() {
                    crate::body_truncate::apply_to_item(item, config.body_max_chars);
                }
            }
        }
    }

    serde_json::to_string(&value).unwrap_or_else(|_| data.to_string())
}

fn process_data_line(
    data: &str,
    event_type: &Option<String>,
    config: &Arc<Config>,
    compressor_config: &CompressorConfig,
    cache: &Arc<SnapshotCache>,
    inflight: &Arc<DashMap<u64, String>>,
    session_tx: &tokio::sync::watch::Sender<Option<String>>,
) -> Option<Vec<u8>> {
    match event_type.as_deref() {
        Some("endpoint") => {
            let session_url = format!("{}{}", config.burp_url, data);
            eprintln!("[btk] Got session URL: {session_url}");
            let _ = session_tx.send(Some(session_url));
            None
        }
        Some("message") | None => {
            // "message" is the explicit type, None means no event: line (default)
            let output = transform_message_data(data, config, compressor_config, cache, inflight);
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
    config: &Arc<Config>,
    compressor_config: &CompressorConfig,
    cache: &Arc<SnapshotCache>,
    inflight: &Arc<DashMap<u64, String>>,
    session_tx: &tokio::sync::watch::Sender<Option<String>>,
    stdout: &mut tokio::io::Stdout,
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
        if let Some(out) = process_data_line(data, current_event_type, config, compressor_config, cache, inflight, session_tx) {
            stdout.write_all(&out).await?;
            stdout.flush().await?;
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
            process_line(&line, &mut current_event_type, config, compressor_config, cache, inflight, session_tx, &mut stdout).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
