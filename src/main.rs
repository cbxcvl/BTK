use clap::Parser;

mod config;
mod sse_task;

fn main() {
    let config = config::Config::parse();
    eprintln!("btk starting — burp: {}", config.burp_url);
}
