<div align="center">

# BTK — Burp Token Killer

**A transparent MCP proxy between Claude Code and Burp Suite.**
Reduces 182 KB tool responses to ~4 KB. No config. No workflow changes. Just faster, cheaper security work.

[![Rust](https://img.shields.io/badge/built%20with-Rust-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
![Status: Production](https://img.shields.io/badge/status-production-brightgreen?style=flat-square)

</div>

---

## The Problem

Burp Suite's MCP extension is powerful — but its responses are enormous.
A single `get_proxy_http_history` call with 50 items returns **185 KB of raw HTTP wire format**.
That's ~46,000 tokens. Per call. For data you mostly don't need.

At that rate, your context window fills up after a few exchanges, and you're restarting sessions before finishing the job.

---

## The Solution

BTK sits between Claude Code and Burp, intercepting every response and compressing it before it reaches your context window.

```
Claude Code ──stdin──▶ BTK ──POST──▶ Burp MCP
                         ◀──SSE──────────────
                         │
                    normalize
                    lossless strip
                    group & summarize   ──▶ Claude Code
                    truncate bodies
```

No changes to your Burp setup. No changes to how Claude uses tools.
BTK is a drop-in replacement for the Burp MCP URL in your Claude config.

---

## Benchmark

Real measurements. Same Burp instance. Same proxy history. Both sides measured directly.

| Tool | Burp MCP Raw | BTK | Reduction | Ratio |
|---|---|---|---|---|
| `get_proxy_http_history` (10 items) | 42,379 B | 526 B | **98.8%** | 81× |
| `get_scanner_issues` (10 issues) | 230,343 B | 280 B | **99.9%** | 823× |
| `tools/list` | 6,837 B | 6,552 B | 4.2% | ~1× |

> Scanner issues achieve 823× because the grouper collapses repeated issue types into a single summary line.

---

## How Compression Works

**Three layers, all lossless at the information level:**

**1 — Lossless strip**
Removes empty fields, null headers, redundant metadata. Nothing useful is lost.

**2 — Grouper summary**
`GET /api/users` appearing 50 times with status 200 becomes one line:
```
GET /api/users (x50) — 200:50
```
The full data is cached in a snapshot. Claude expands any path on demand with `btk_detail`.

**3 — Body truncation**
Response bodies over 2000 chars are trimmed. Binary responses (images, fonts) are replaced with `[image/png, 4321B]`. Configurable.

---

## Synthetic Tools

BTK injects two extra tools into `tools/list` that Claude can use to navigate compressed data:

| Tool | What it does |
|---|---|
| `btk_detail(snapshot, path)` | Expand a specific path from a compressed snapshot — returns full request/response |
| `btk_next_page(snapshot, cursor)` | Paginate through large history sets |

---

## Usage with RTK

BTK pairs naturally with **[RTK (Real Token Killer)](https://github.com/rtk-ai/rtk)** — the CLI proxy that compresses `git`, `cargo`, `npm`, and other dev tool output before it reaches your LLM.

Together they cover the two sides of a security workflow:

```
┌──────────────────────────────────────────────────────┐
│                  Claude Code session                  │
├──────────────────────┬───────────────────────────────┤
│    Dev operations    │      Burp operations           │
│  git, cargo, files   │  proxy history, scanner,       │
│                      │  repeater, collaborator        │
│       RTK            │          BTK                   │
│  60-90% savings      │      97-99% savings            │
└──────────────────────┴───────────────────────────────┘
```

A full pentest session — recon, active scanning, manual testing, reporting — without burning through your context window.

---

## Installation

**Arch Linux (AUR):**

```bash
yay -S btk-bin
```

**Via Cargo:**

```bash
cargo install --git https://github.com/cbxcvl/BTK
```

Or build from source:

```bash
git clone https://github.com/cbxcvl/BTK
cd BTK
cargo build --release
./target/release/btk --help
```

---

## Configuration

### Claude Code (`~/.claude/settings.json`)

Replace your existing Burp MCP server entry:

```json
{
  "mcpServers": {
    "burp": {
      "command": "/path/to/btk",
      "args": ["--burp-url", "http://127.0.0.1:9876"]
    }
  }
}
```

### Options

```
--burp-url <URL>         Burp MCP endpoint (default: http://127.0.0.1:9876)
--body-max-chars <N>     Max response body chars before truncation (default: 2000)
--tools <names>          Comma-separated allowlist of Burp tools to expose
--tools-config <path>    TOML file with tool descriptions and allowlist
```

### Optional TOML config

```toml
[tools]
allow = ["send_http1_request", "get_proxy_http_history", "get_scanner_issues"]

[tool.send_http1_request]
description = "My custom description"
```

---

## What Claude Can Do With BTK

Every Burp tool works. Tested against a live Burp Pro instance:

| Category | Tools |
|---|---|
| **HTTP** | `send_http1_request`, `send_http2_request` |
| **Proxy** | `get_proxy_http_history`, `get_proxy_http_history_regex` |
| **WebSocket** | `get_proxy_websocket_history`, `get_proxy_websocket_history_regex` |
| **Scanner** | `get_scanner_issues` |
| **Repeater** | `create_repeater_tab` |
| **Intruder** | `send_to_intruder` |
| **Collaborator** | `generate_collaborator_payload`, `get_collaborator_interactions` |
| **Editor** | `get_active_editor_contents`, `set_active_editor_contents` |
| **Config** | `output_project_options`, `output_user_options`, `set_project_options`, `set_user_options` |
| **Proxy control** | `set_proxy_intercept_state`, `set_task_execution_engine_state` |
| **Encoding** | `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `generate_random_string` |
| **BTK synthetic** | `btk_detail`, `btk_next_page` |

---

## Example Session

```
Claude: I'll check the proxy history for authentication endpoints.

[calls get_proxy_http_history(count=50)]

BTK proxy history snapshot ph_a3f8 (50 items):
  POST /api/login (x12) — 200:8, 401:4
  GET /api/profile (x30) — 200:28, 403:2
  POST /api/password-reset (x4) — 200:4
  GET /api/admin (x4) — 403:4
Use btk_detail(snapshot="ph_a3f8", path="<METHOD /path>") to expand.

Claude: I see 4 login attempts returning 401. Let me expand those.

[calls btk_detail(snapshot="ph_a3f8", path="POST /api/login")]

Returns: full request/response for the 4 failed logins, with headers and bodies.

Claude: The 401 responses don't have account lockout — username enumeration is possible.
        I'll send a test to Repeater.

[calls create_repeater_tab(...)]
```

Total context used for 50-item history analysis: **~4 KB** instead of **~185 KB**.

---

## Architecture

```
src/
├── main.rs           — entry point, arg parsing
├── proxy.rs          — task orchestration (SSE + stdin tasks)
├── sse_task.rs       — SSE stream reader, compression pipeline
├── stdin_task.rs     — stdin reader, request forwarding
├── normalizer.rs     — Burp content[0].text → result.items
├── http_parse.rs     — raw HTTP wire format parser
├── lossless.rs       — field stripping (headers, cookies, empty fields)
├── grouper.rs        — history/scanner summary with snapshot cache
├── body_truncate.rs  — body size limiting, binary detection, HTML extraction
├── compressor.rs     — tool description compression for tools/list
├── synthetic.rs      — btk_detail / btk_next_page tool handlers
├── snapshot_cache.rs — in-memory TTL cache for compressed snapshots
└── config.rs         — CLI config, TOML loading
```

---

## Requirements

- Rust 1.75+
- Burp Suite Pro with the [MCP extension](https://github.com/PortSwigger/mcp-server) installed and running
- Claude Code

---

## License

MIT
