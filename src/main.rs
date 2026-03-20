use clap::Parser;

mod config;

fn main() {
    let config = config::Config::parse();
    eprintln!("btk starting — burp: {}", config.burp_url);
}
