use clap::Parser;

mod body_truncate;
mod lossless;
mod snapshot_cache;
mod compressor;
mod config;
mod proxy;
mod stdin_task;
mod sse_task;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::parse();
    eprintln!("[btk] starting — burp: {}", config.burp_url);
    proxy::run(config).await
}
