use clap::Parser;

mod config;
mod proxy;
mod sse_task;
mod stdin_task;

fn main() {
    let config = config::Config::parse();
    eprintln!("btk starting — burp: {}", config.burp_url);
}
