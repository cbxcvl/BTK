use tokio::io::AsyncBufReadExt;

fn is_empty_line(line: &str) -> bool {
    line.trim().is_empty()
}

pub async fn run(
    client: std::sync::Arc<reqwest::Client>,
    session_rx: tokio::sync::watch::Receiver<Option<String>>,
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

    while let Some(line) = lines.next_line().await? {
        if is_empty_line(&line) {
            continue;
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
