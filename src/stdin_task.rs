use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use crate::config::Config;

fn mcp_url(base: &str) -> String {
    format!("{}/mcp", base)
}

fn is_empty_line(line: &str) -> bool {
    line.trim().is_empty()
}

pub async fn run(client: Arc<reqwest::Client>, config: Arc<Config>) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();
    let url = mcp_url(&config.burp_url);

    while let Some(line) = lines.next_line().await? {
        if is_empty_line(&line) {
            continue;
        }
        match client
            .post(&url)
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
    fn mcp_url_appends_mcp_path() {
        assert_eq!(mcp_url("http://127.0.0.1:9876"), "http://127.0.0.1:9876/mcp");
    }

    #[test]
    fn mcp_url_with_trailing_slash() {
        assert_eq!(mcp_url("http://127.0.0.1:9876/"), "http://127.0.0.1:9876//mcp");
    }

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
