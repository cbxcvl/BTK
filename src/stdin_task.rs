use std::sync::Arc;
use dashmap::DashMap;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use crate::config::Config;
use crate::snapshot_cache::SnapshotCache;

fn is_empty_line(line: &str) -> bool {
    line.trim().is_empty()
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

        // Check if this is a synthetic tool call (btk_detail, btk_next_page)
        if let Ok(request) = serde_json::from_str::<serde_json::Value>(&line) {
            if request["method"].as_str() == Some("tools/call") {
                let tool_name = request["params"]["name"].as_str().unwrap_or("").to_string();
                if crate::synthetic::is_synthetic(&tool_name) {
                    let ttl = config.snapshot_ttl();
                    let response = crate::synthetic::handle(&request, &cache, ttl, config.body_max_chars);
                    let mut out = response.into_bytes();
                    out.push(b'\n');
                    stdout.write_all(&out).await?;
                    stdout.flush().await?;
                    continue; // Do NOT forward to Burp
                }
                // Track non-synthetic tools/call in inflight map for sse_task correlation
                if let Some(id) = request["id"].as_u64() {
                    inflight.insert(id, tool_name);
                }
            }
        }

        // Re-read the session URL on each iteration so reconnects are handled correctly
        let session_url = session_rx
            .borrow()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("session URL unexpectedly None"))?;
        match client
            .post(&session_url)
            .header("Content-Type", "application/json")
            .body(line)
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
}
