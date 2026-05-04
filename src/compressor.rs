use std::collections::HashMap;

pub struct CompressorConfig {
    pub allow: Vec<String>,
    pub overrides: HashMap<String, String>,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            overrides: HashMap::new(),
        }
    }
}

static BUILTIN: phf::Map<&str, &str> = phf::phf_map! {
    "send_http1_request"             => "Send HTTP/1.1 request, return response.",
    "send_http2_request"             => "Send HTTP/2 request (headers separate from body), return response.",
    "create_repeater_tab"            => "Create Repeater tab with request (use CRLF line endings).",
    "send_to_intruder"               => "Send request to Intruder (use CRLF line endings).",
    "url_encode"                     => "URL-encode a string.",
    "url_decode"                     => "URL-decode a string.",
    "base64_encode"                  => "Base64-encode a string.",
    "base64_decode"                  => "Base64-decode a string.",
    "generate_random_string"         => "Generate random string of given length and charset.",
    "output_project_options"         => "Get project config as JSON.",
    "output_user_options"            => "Get user config as JSON.",
    "set_project_options"            => "Merge JSON into project config (export first to see schema; top-level key: user_options).",
    "set_user_options"               => "Merge JSON into user config (export first; top-level key: project_options).",
    "get_scanner_issues"             => "Get scanner issues (paginated: count, offset).",
    "generate_collaborator_payload"  => "Generate OOB Collaborator payload; use get_collaborator_interactions to poll results.",
    "get_collaborator_interactions"  => "Poll Collaborator for OOB interactions (DNS/HTTP/SMTP); filter by payloadId.",
    "get_proxy_http_history"         => "Get proxy HTTP history (paginated).",
    "get_proxy_http_history_regex"   => "Get proxy HTTP history entries matching regex (paginated).",
    "get_proxy_websocket_history"    => "Get proxy WebSocket history (paginated).",
    "get_proxy_websocket_history_regex" => "Get proxy WebSocket history entries matching regex (paginated).",
    "set_task_execution_engine_state"=> "Set Burp task engine state (running: true=resume, false=pause).",
    "set_proxy_intercept_state"      => "Set Proxy intercept state (intercepting: true=on, false=off).",
    "get_active_editor_contents"     => "Get contents of active message editor.",
    "set_active_editor_contents"     => "Set contents of active message editor.",
};

pub fn transform(value: &mut serde_json::Value, config: &CompressorConfig) {
    // Must have result.tools as an array
    let tools = match value
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    {
        Some(arr) => arr,
        None => return,
    };

    // Build the filtered + description-replaced tool list
    let mut new_tools: Vec<serde_json::Value> = Vec::new();
    for tool in tools.drain(..) {
        let name = match tool.get("name").and_then(|n| n.as_str()) {
            Some(n) => n.to_string(),
            None => {
                new_tools.push(tool);
                continue;
            }
        };

        // Filter by allowlist
        if !config.allow.is_empty() && !config.allow.contains(&name) {
            continue;
        }

        let mut tool = tool;
        // Replace description
        let new_desc = config
            .overrides
            .get(&name)
            .map(|s| s.as_str())
            .or_else(|| BUILTIN.get(&*name).copied());
        if let Some(desc) = new_desc {
            tool["description"] = serde_json::Value::String(desc.to_string());
        }

        new_tools.push(tool);
    }

    // Write back
    if let Some(tools_slot) = value.get_mut("result").and_then(|r| r.get_mut("tools")) {
        *tools_slot = serde_json::Value::Array(new_tools);
    }

    // Strip _meta if present
    if let Some(result) = value.get_mut("result") {
        if let Some(obj) = result.as_object_mut() {
            obj.remove("_meta");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tools_list(tools: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": tools,
                "_meta": {}
            }
        })
    }

    fn make_tool(name: &str, desc: &str) -> serde_json::Value {
        json!({
            "name": name,
            "description": desc,
            "inputSchema": { "type": "object" }
        })
    }

    #[test]
    fn test_descriptions_replaced() {
        let mut value = make_tools_list(vec![
            make_tool("send_http1_request", "Some long verbose description"),
            make_tool("url_encode", "Another long description"),
        ]);
        transform(&mut value, &CompressorConfig::default());
        let tools = value["result"]["tools"].as_array().unwrap();
        assert_eq!(
            tools[0]["description"].as_str().unwrap(),
            "Send HTTP/1.1 request, return response."
        );
        assert_eq!(
            tools[1]["description"].as_str().unwrap(),
            "URL-encode a string."
        );
    }

    #[test]
    fn test_allowlist_filters() {
        let mut value = make_tools_list(vec![
            make_tool("send_http1_request", "desc"),
            make_tool("url_encode", "desc"),
            make_tool("get_proxy_http_history", "desc"),
        ]);
        let config = CompressorConfig {
            allow: vec!["send_http1_request".to_string()],
            overrides: Default::default(),
        };
        transform(&mut value, &config);
        let tools = value["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"].as_str().unwrap(), "send_http1_request");
    }

    #[test]
    fn test_override_wins() {
        let mut value = make_tools_list(vec![make_tool("send_http1_request", "original")]);
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(
            "send_http1_request".to_string(),
            "My custom description".to_string(),
        );
        let config = CompressorConfig {
            allow: vec![],
            overrides,
        };
        transform(&mut value, &config);
        let tools = value["result"]["tools"].as_array().unwrap();
        assert_eq!(
            tools[0]["description"].as_str().unwrap(),
            "My custom description"
        );
    }

    #[test]
    fn test_meta_stripped() {
        let mut value = make_tools_list(vec![make_tool("send_http1_request", "desc")]);
        transform(&mut value, &CompressorConfig::default());
        assert!(value["result"]["_meta"].is_null());
    }

    #[test]
    fn test_non_tools_list_unchanged() {
        let mut value = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": []}});
        let original = value.clone();
        transform(&mut value, &CompressorConfig::default());
        assert_eq!(value, original);
    }
}
