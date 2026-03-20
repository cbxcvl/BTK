use serde_json::{json, Value};
use crate::http_parse;

/// Convert Burp's result.content[0].text format to result.items.
/// If the value does not match Burp's content wrapper format, returns unchanged.
pub fn normalize_response(value: &mut Value, tool_name: &str) {
    // Pass through errors unchanged
    if value.pointer("/result/isError").and_then(|v| v.as_bool()).unwrap_or(false) {
        return;
    }

    // Only process content[0].text format
    let text = match value.pointer("/result/content/0/text").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return,
    };

    let items: Vec<Value> = if is_multi_item_history(tool_name) {
        build_history_items(&text)
    } else if is_single_response_tool(tool_name) {
        build_single_item(&text)
    } else if is_plain_json_tool(tool_name) {
        // Returns a single JSON blob (e.g. project config) — preserve as one item
        build_single_item(&text)
    } else {
        // Unknown tool: try multi if text has newlines with JSON objects, else single
        if text.trim_start().starts_with('{') && text.contains('\n') {
            build_history_items(&text)
        } else {
            build_single_item(&text)
        }
    };

    value["result"] = json!({ "items": items });
}

fn is_multi_item_history(tool: &str) -> bool {
    matches!(
        tool,
        "get_proxy_http_history"
            | "get_proxy_http_history_regex"
            | "get_proxy_websocket_history"
            | "get_proxy_websocket_history_regex"
            | "get_scanner_issues"
    )
}

fn is_single_response_tool(tool: &str) -> bool {
    matches!(
        tool,
        "send_http1_request" | "send_http2_request" | "get_active_editor_contents"
    )
}

fn is_plain_json_tool(tool: &str) -> bool {
    matches!(tool, "output_project_options" | "output_user_options")
}

fn build_history_items(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(parse_history_line)
        .collect()
}

fn parse_history_line(line: &str) -> Value {
    let Ok(parsed) = serde_json::from_str::<Value>(line) else {
        return json!({ "raw": line });
    };

    // Scanner items: structured JSON already (has issueName or severity, no raw HTTP)
    if parsed.get("issueName").is_some() || parsed.get("severity").is_some() {
        return parsed;
    }

    // req_raw/resp_raw contain JSON-decoded strings: Burp encodes CRLF as \r\n in JSON,
    // so these strings contain actual CR+LF bytes after serde_json decoding.
    let req_raw = parsed["request"].as_str().unwrap_or("");
    let resp_raw = parsed["response"].as_str().unwrap_or("");
    let notes = parsed["notes"].as_str().unwrap_or("").to_string();

    let request = match http_parse::parse_request(req_raw) {
        Some(req) => json!({
            "method": req.method,
            "path": req.path,
            "headers": headers_to_json(&req.headers),
            "body": req.body,
        }),
        None => json!({ "raw": req_raw }),
    };

    let response = match http_parse::parse_response(resp_raw) {
        Some(resp) => json!({
            "statusCode": resp.status_code,
            "headers": headers_to_json(&resp.headers),
            "body": resp.body,
        }),
        None => json!({ "raw": resp_raw }),
    };

    json!({
        "request": request,
        "response": response,
        "notes": notes,
    })
}

fn build_single_item(text: &str) -> Vec<Value> {
    // Try JSON first (scanner single item, get_active_editor_contents, config blobs, etc.)
    if let Ok(parsed) = serde_json::from_str::<Value>(text) {
        if parsed.get("request").is_some() || parsed.get("response").is_some() {
            return vec![parse_history_line(text)];
        }
        return vec![parsed];
    }

    // Try Burp's Java toString format: HttpRequestResponse{httpRequest=..., httpResponse=..., ...}
    if let Some(item) = try_parse_java_http_response_response(text) {
        return vec![item];
    }

    // Try as raw HTTP response string
    if let Some(resp) = http_parse::parse_response(text) {
        return vec![json!({
            "request": {},
            "response": {
                "statusCode": resp.status_code,
                "headers": headers_to_json(&resp.headers),
                "body": resp.body,
            }
        })];
    }

    // Fallback
    vec![json!({ "raw": text })]
}

/// Parse Burp's Java toString format:
/// `HttpRequestResponse{httpRequest=<raw HTTP>, httpResponse=<raw HTTP>, messageAnnotations=...}`
fn try_parse_java_http_response_response(text: &str) -> Option<Value> {
    let inner = text.strip_prefix("HttpRequestResponse{")?;
    let inner = inner.strip_suffix('}')?;

    // Strip messageAnnotations suffix to isolate the two HTTP fields
    let inner = if let Some(pos) = inner.rfind(", messageAnnotations=") {
        &inner[..pos]
    } else {
        inner
    };

    // inner is now "httpRequest=<REQ>, httpResponse=<RESP>"
    let inner = inner.strip_prefix("httpRequest=")?;
    let resp_pos = inner.find(", httpResponse=")?;
    let req_raw = &inner[..resp_pos];
    let resp_raw = &inner[resp_pos + ", httpResponse=".len()..];

    let request = match http_parse::parse_request(req_raw) {
        Some(req) => json!({
            "method": req.method,
            "path": req.path,
            "headers": headers_to_json(&req.headers),
            "body": req.body,
        }),
        None => json!({ "raw": req_raw }),
    };

    let response = match http_parse::parse_response(resp_raw) {
        Some(resp) => json!({
            "statusCode": resp.status_code,
            "headers": headers_to_json(&resp.headers),
            "body": resp.body,
        }),
        None => json!({ "raw": resp_raw }),
    };

    Some(json!({ "request": request, "response": response }))
}

fn headers_to_json(headers: &[http_parse::HttpHeader]) -> Vec<Value> {
    headers
        .iter()
        .map(|h| json!({"name": h.name, "value": h.value}))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_content_response(text: &str) -> Value {
        json!({
            "id": 1,
            "jsonrpc": "2.0",
            "result": {
                "content": [{"text": text, "type": "text"}],
                "isError": false
            }
        })
    }

    #[test]
    fn multi_item_history_normalizes_to_items() {
        let line1 = r#"{"request":"GET /a HTTP/1.1\r\nHost: x.com\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello","notes":""}"#;
        let line2 = r#"{"request":"POST /b HTTP/1.1\r\nHost: x.com\r\n\r\nbody","response":"HTTP/1.1 404 Not Found\r\n\r\n","notes":"interesting"}"#;
        let line3 = r#"{"request":"GET /c HTTP/1.1\r\nHost: x.com\r\n\r\n","response":"HTTP/2 302 Found\r\nLocation: /d\r\n\r\n","notes":""}"#;
        let text = format!("{}\n{}\n{}", line1, line2, line3);

        let mut value = make_content_response(&text);
        normalize_response(&mut value, "get_proxy_http_history");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).expect("items array");
        assert_eq!(items.len(), 3);

        assert_eq!(items[0]["request"]["method"].as_str().unwrap(), "GET");
        assert_eq!(items[0]["request"]["path"].as_str().unwrap(), "/a");
        assert_eq!(items[0]["response"]["statusCode"].as_u64().unwrap(), 200);
        assert_eq!(items[0]["response"]["body"].as_str().unwrap(), "hello");

        assert_eq!(items[1]["request"]["method"].as_str().unwrap(), "POST");
        assert_eq!(items[1]["request"]["body"].as_str().unwrap(), "body");
        assert_eq!(items[1]["response"]["statusCode"].as_u64().unwrap(), 404);
        assert_eq!(items[1]["notes"].as_str().unwrap(), "interesting");

        assert_eq!(items[2]["response"]["statusCode"].as_u64().unwrap(), 302);
    }

    #[test]
    fn request_headers_are_structured() {
        let line = r#"{"request":"GET /x HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer tok\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n","notes":""}"#;
        let mut value = make_content_response(line);
        normalize_response(&mut value, "get_proxy_http_history");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        let headers = items[0]["request"]["headers"].as_array().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0]["name"].as_str().unwrap(), "Host");
        assert_eq!(headers[1]["name"].as_str().unwrap(), "Authorization");
        assert_eq!(headers[1]["value"].as_str().unwrap(), "Bearer tok");
    }

    #[test]
    fn scanner_response_preserves_flat_fields() {
        let line = r#"{"issueName":"SQL Injection","severity":"High","confidence":"Certain","host":"example.com","path":"/login"}"#;
        let mut value = make_content_response(line);
        normalize_response(&mut value, "get_scanner_issues");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["issueName"].as_str().unwrap(), "SQL Injection");
        assert_eq!(items[0]["severity"].as_str().unwrap(), "High");
    }

    #[test]
    fn single_item_tool_wraps_in_items_array() {
        let text = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":1}";
        let mut value = make_content_response(text);
        normalize_response(&mut value, "send_http1_request");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["response"]["statusCode"].as_u64().unwrap(), 201);
        assert_eq!(items[0]["response"]["body"].as_str().unwrap(), "{\"id\":1}");
    }

    #[test]
    fn is_error_true_passes_through_unchanged() {
        let mut value = json!({
            "id": 1,
            "result": {
                "content": [{"text": "something", "type": "text"}],
                "isError": true
            }
        });
        let original = value.clone();
        normalize_response(&mut value, "get_proxy_http_history");
        assert_eq!(value, original);
    }

    #[test]
    fn non_content_response_passes_through_unchanged() {
        let mut value = json!({
            "id": 1,
            "result": {
                "items": [{"request": {"method": "GET"}, "response": {"statusCode": 200}}]
            }
        });
        let original = value.clone();
        normalize_response(&mut value, "get_proxy_http_history");
        assert_eq!(value, original);
    }

    #[test]
    fn malformed_json_line_falls_back_to_raw() {
        let text = "this is not json";
        let mut value = make_content_response(text);
        normalize_response(&mut value, "get_proxy_http_history");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].get("raw").is_some(), "expected raw fallback field");
    }

    #[test]
    fn empty_lines_are_skipped() {
        let line = format!(r#"{{"request":"GET /a HTTP/1.1\r\nHost: x.com\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n","notes":""}}"#);
        let text_with_blanks = format!("\n{}\n\n", line);
        let mut value = make_content_response(&text_with_blanks);
        normalize_response(&mut value, "get_proxy_http_history");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1, "blank lines should be filtered");
    }

    #[test]
    fn plain_json_tool_preserves_config_as_single_item() {
        let config = "{\"bambda\":{\"filter\":\"enabled\"},\"scope\":{\"include\":[]}}";
        let mut value = make_content_response(config);
        normalize_response(&mut value, "output_project_options");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1, "config JSON should be a single item, not split by lines");
        assert!(items[0].get("bambda").is_some(), "config fields should be preserved");
    }

    #[test]
    fn java_tostring_format_is_parsed_into_request_response() {
        let text = "HttpRequestResponse{httpRequest=GET / HTTP/1.1\r\nHost: example.com\r\n\r\n, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello, messageAnnotations=Annotations{comment='', highlightColor=NONE}}";
        let mut value = make_content_response(text);
        normalize_response(&mut value, "send_http1_request");

        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["request"]["method"].as_str().unwrap(), "GET");
        assert_eq!(items[0]["request"]["path"].as_str().unwrap(), "/");
        assert_eq!(items[0]["response"]["statusCode"].as_u64().unwrap(), 200);
        assert_eq!(items[0]["response"]["body"].as_str().unwrap(), "hello");
    }

    #[test]
    fn unknown_tool_with_multiline_json_uses_history_path() {
        let line1 = r#"{"request":"GET /a HTTP/1.1\r\nHost: x\r\n\r\n","response":"HTTP/1.1 200 OK\r\n\r\n","notes":""}"#;
        let line2 = r#"{"request":"GET /b HTTP/1.1\r\nHost: x\r\n\r\n","response":"HTTP/1.1 404 Not Found\r\n\r\n","notes":""}"#;
        let text = format!("{}\n{}", line1, line2);
        let mut value = json!({
            "id": 1,
            "result": {
                "content": [{"text": text, "type": "text"}],
                "isError": false
            }
        });
        normalize_response(&mut value, "some_unrecognized_tool");
        let items = value.pointer("/result/items").and_then(|v| v.as_array()).unwrap();
        assert_eq!(items.len(), 2, "unknown multi-line JSON tool should use history path");
        assert_eq!(items[0]["request"]["method"].as_str().unwrap(), "GET");
    }
}
