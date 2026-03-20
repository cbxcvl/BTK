use std::sync::Arc;
use crate::config::Config;

pub async fn run(client: Arc<reqwest::Client>, config: Arc<Config>) -> anyhow::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();
    let url = format!("{}/mcp", config.burp_url);

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
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
