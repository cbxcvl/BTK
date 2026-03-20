use std::sync::Arc;
use crate::config::Config;
use crate::snapshot_cache::SnapshotCache;
use dashmap::DashMap;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let client = Arc::new(reqwest::Client::new());
    let cache = Arc::new(SnapshotCache::new(
        config.snapshot_max_bytes(),
        config.snapshot_ttl(),
    ));
    let inflight: Arc<DashMap<u64, String>> = Arc::new(DashMap::new());

    let (session_tx, session_rx) = tokio::sync::watch::channel::<Option<String>>(None);

    let stdin_handle = tokio::spawn(crate::stdin_task::run(
        client.clone(),
        session_rx,
        cache.clone(),
        inflight.clone(),
        config.clone(),
    ));
    let sse_handle = tokio::spawn(crate::sse_task::run(
        client.clone(),
        config.clone(),
        session_tx,
        cache.clone(),
        inflight.clone(),
    ));

    tokio::select! {
        res = stdin_handle => {
            match res {
                Ok(Ok(())) => {
                    eprintln!("[btk] stdin task finished (stdin closed)");
                    Ok(())
                }
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow::anyhow!("stdin task panicked: {e}")),
            }
        }
        res = sse_handle => {
            match res {
                Ok(Ok(())) => {
                    eprintln!("[btk] SSE task finished unexpectedly");
                    Err(anyhow::anyhow!("SSE task finished unexpectedly"))
                }
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow::anyhow!("SSE task panicked: {e}")),
            }
        }
    }
}
