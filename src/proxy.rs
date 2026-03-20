use std::sync::Arc;
use crate::config::Config;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let client = Arc::new(reqwest::Client::new());

    let stdin_handle = tokio::spawn(crate::stdin_task::run(client.clone(), config.clone()));
    let sse_handle = tokio::spawn(crate::sse_task::run(client.clone(), config.clone()));

    tokio::select! {
        res = stdin_handle => {
            match res {
                Ok(Ok(())) => {
                    eprintln!("[btk] stdin task finished (stdin closed)");
                    Ok(())
                }
                Ok(Err(e)) => {
                    eprintln!("[btk] stdin task error: {e}");
                    Err(e)
                }
                Err(e) => {
                    eprintln!("[btk] stdin task panicked: {e}");
                    Err(anyhow::anyhow!("stdin task panicked: {e}"))
                }
            }
        }
        res = sse_handle => {
            match res {
                Ok(Ok(())) => {
                    eprintln!("[btk] SSE task finished unexpectedly");
                    Err(anyhow::anyhow!("SSE task finished unexpectedly"))
                }
                Ok(Err(e)) => {
                    eprintln!("[btk] SSE task error: {e}");
                    Err(e)
                }
                Err(e) => {
                    eprintln!("[btk] SSE task panicked: {e}");
                    Err(anyhow::anyhow!("SSE task panicked: {e}"))
                }
            }
        }
    }
}
