use std::sync::Arc;
use std::time::Duration;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use crate::compressor::{self, CompressorConfig};
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

    let mut stream = response.bytes_stream();
    let mut stdout = tokio::io::stdout();
    let mut buf = String::new();
    let mut current_event_type: Option<String> = None;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        while let Some(pos) = buf.find('\n') {
            let line = buf[..pos].trim_end_matches('\r').to_string();
            buf = buf[pos + 1..].to_string();

            if line.is_empty() {
                // blank line resets event state (standard SSE separator)
                current_event_type = None;
                continue;
            }

            if let Some(event_type) = line.strip_prefix("event: ") {
                current_event_type = Some(event_type.to_string());
                continue;
            }

            if let Some(data) = line.strip_prefix("data: ") {
                match current_event_type.as_deref() {
                    Some("endpoint") => {
                        let session_url = format!("{}{}", config.burp_url, data);
                        eprintln!("[btk] Got session URL: {session_url}");
                        let _ = session_tx.send(Some(session_url));
                        current_event_type = None;
                    }
                    Some("message") | None => {
                        // "message" is the explicit type, None means no event: line (default)
                        let output = if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) {
                            // Layer 1: lossless strip (always)
                            crate::lossless::strip(&mut value);

                            // tools/list response: compress descriptions + inject synthetic tools
                            if value.pointer("/result/tools").and_then(|t| t.as_array()).is_some() {
                                crate::compressor::transform(&mut value, compressor_config);
                                crate::synthetic::inject_tools(&mut value);
                            } else {
                                // Look up originating tool name from inflight map
                                let tool_name = value["id"].as_u64()
                                    .and_then(|id| inflight.remove(&id).map(|(_, v)| v));

                                let grouped = if let Some(ref tname) = tool_name {
                                    if crate::grouper::is_groupable(tname) {
                                        crate::grouper::process(&mut value, tname, cache, config)
                                    } else {
                                        false
                                    }
                                } else {
                                    false
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
                        } else {
                            data.to_string()
                        };
                        let mut out = output.into_bytes();
                        out.push(b'\n');
                        stdout.write_all(&out).await?;
                        stdout.flush().await?;
                        current_event_type = None;
                    }
                    Some(_) => {
                        // ignore other event types
                        current_event_type = None;
                    }
                }
            }
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
