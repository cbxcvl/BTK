use clap::Parser;

mod body_truncate;
mod grouper;
mod lossless;
mod snapshot_cache;
mod compressor;
mod synthetic;
mod config;
mod proxy;
mod stdin_task;
mod sse_task;
mod http_parse;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::parse();
    eprintln!("[btk] starting — burp: {}", config.burp_url);
    proxy::run(config).await
}
