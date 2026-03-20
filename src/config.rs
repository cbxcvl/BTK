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

    /// Path to TOML config file for tool compression settings
    #[arg(long)]
    pub tools_config: Option<std::path::PathBuf>,

    /// Comma-separated allowlist of tool names (overrides --tools-config allow list)
    /// Example: --tools send_http1_request,get_proxy_http_history
    #[arg(long)]
    pub tools: Option<String>,

    /// Maximum characters for response body truncation (0 = disabled)
    #[arg(long, default_value_t = 2000)]
    pub body_max_chars: usize,

    /// Snapshot TTL in seconds
    #[arg(long, default_value_t = 600)]
    pub snapshot_ttl_secs: u64,

    /// Maximum snapshot cache size in megabytes
    #[arg(long, default_value_t = 50)]
    pub snapshot_max_mb: usize,
}

#[derive(serde::Deserialize, Default)]
struct TomlConfig {
    tools: Option<TomlTools>,
    tool: Option<std::collections::HashMap<String, TomlToolEntry>>,
}

#[derive(serde::Deserialize, Default)]
struct TomlTools {
    allow: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default)]
struct TomlToolEntry {
    description: Option<String>,
}

impl Config {
    pub fn compressor_config(&self) -> anyhow::Result<crate::compressor::CompressorConfig> {
        let mut config = crate::compressor::CompressorConfig::default();

        if let Some(path) = &self.tools_config {
            let content = std::fs::read_to_string(path)?;
            let toml_cfg: TomlConfig = toml::from_str(&content)?;

            if let Some(tools) = toml_cfg.tools {
                if let Some(allow) = tools.allow {
                    config.allow = allow;
                }
            }

            if let Some(tool_map) = toml_cfg.tool {
                for (name, entry) in tool_map {
                    if let Some(desc) = entry.description {
                        config.overrides.insert(name, desc);
                    }
                }
            }
        }

        if let Some(names) = &self.tools {
            config.allow = names.split(',').map(|s| s.trim().to_string()).collect();
        }

        Ok(config)
    }

    pub fn snapshot_max_bytes(&self) -> usize {
        self.snapshot_max_mb * 1024 * 1024
    }

    pub fn snapshot_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.snapshot_ttl_secs)
    }
}
