use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use crate::config::Config;

fn is_empty_line(line: &str) -> bool {
    line.trim().is_empty()
}

pub async fn run(
    client: Arc<reqwest::Client>,
    _config: Arc<Config>,
    mut session_rx: tokio::sync::watch::Receiver<Option<String>>,
) -> anyhow::Result<()> {
    // Wait for the session URL from the SSE handshake before processing stdin
    let session_url = loop {
        {
            let url = session_rx.borrow();
            if url.is_some() {
                break url.clone().unwrap();
            }
        }
        session_rx
            .changed()
            .await
            .map_err(|_| anyhow::anyhow!("session channel closed before handshake"))?;
    };

    eprintln!("[btk] Session URL ready, forwarding stdin to {session_url}");

    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await? {
        if is_empty_line(&line) {
            continue;
        }
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
            Err(e) => {
                eprintln!("[btk] POST failed: {e}");
            }
            Ok(_) => {}
        }
    }

    // stdin closed — signal proxy to exit
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
