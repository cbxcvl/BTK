use std::sync::Arc;
use std::time::Duration;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use crate::config::Config;

pub(crate) fn backoff_secs(consecutive_failures: u32, max_secs: u64) -> u64 {
    let exp = 2u64.saturating_pow(consecutive_failures - 1);
    exp.min(max_secs)
}

pub async fn run(client: Arc<reqwest::Client>, config: Arc<Config>) -> anyhow::Result<()> {
    const MAX_FAILURES: u32 = 5;
    let mut failures = 0u32;

    loop {
        match stream_sse(&client, &config).await {
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

async fn stream_sse(client: &reqwest::Client, config: &Config) -> anyhow::Result<()> {
    let url = format!("{}/sse", config.burp_url);
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

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        // Process all complete lines in the buffer
        while let Some(pos) = buf.find('\n') {
            let line = buf[..pos].trim_end_matches('\r').to_string();
            buf = buf[pos + 1..].to_string();

            if let Some(data) = parse_sse_data(&line) {
                stdout.write_all(data.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }
    }

    Ok(())
}

pub(crate) fn parse_sse_data(line: &str) -> Option<String> {
    line.strip_prefix("data: ").map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_data_field() {
        assert_eq!(
            parse_sse_data(r#"data: {"jsonrpc":"2.0","id":1}"#),
            Some(r#"{"jsonrpc":"2.0","id":1}"#.to_string())
        );
    }

    #[test]
    fn returns_none_for_event_line() {
        assert_eq!(parse_sse_data("event: message"), None);
    }

    #[test]
    fn returns_none_for_comment_line() {
        assert_eq!(parse_sse_data(": keep-alive"), None);
    }

    #[test]
    fn returns_none_for_blank_line() {
        assert_eq!(parse_sse_data(""), None);
    }

    #[test]
    fn returns_none_for_id_line() {
        assert_eq!(parse_sse_data("id: 42"), None);
    }

    #[test]
    fn returns_none_for_data_without_space() {
        // SSE spec allows "data:<value>" (no space) but we only handle "data: <value>"
        // Burp MCP server always sends the space, so this is intentionally not supported
        assert_eq!(parse_sse_data("data:{}"), None);
    }

    #[test]
    fn returns_some_empty_for_data_with_empty_value() {
        // "data: " (trailing space only) is a valid empty data field
        assert_eq!(parse_sse_data("data: "), Some("".to_string()));
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        assert_eq!(backoff_secs(1, 30), 1);
        assert_eq!(backoff_secs(2, 30), 2);
        assert_eq!(backoff_secs(3, 30), 4);
        assert_eq!(backoff_secs(4, 30), 8);
        assert_eq!(backoff_secs(10, 30), 30); // capped
    }
}
