use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "btk", about = "Burp Token Killer — MCP proxy for Burp Suite")]
pub struct Config {
    /// Base URL of the Burp MCP server
    #[arg(long, default_value = "http://127.0.0.1:9876")]
    pub burp_url: String,

    /// Maximum seconds to wait between SSE reconnect attempts
    #[arg(long, default_value_t = 30)]
    pub reconnect_max_secs: u64,
}
