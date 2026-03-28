/// Apply body truncation to a Burp history item.
/// Reads content-type from item["response"]["headers"], truncates item["response"]["body"].
pub fn apply_to_item(item: &mut serde_json::Value, max_chars: usize) {
    if max_chars == 0 { return; }
    let content_type = get_content_type(item);
    if let Some(body) = item["response"]["body"].as_str() {
        let truncated = apply_to_body(body, &content_type, max_chars);
        if truncated != body {
            item["response"]["body"] = serde_json::Value::String(truncated);
        }
    }
}

fn get_content_type(item: &serde_json::Value) -> String {
    item["response"]["headers"]
        .as_array()
        .and_then(|headers| {
            headers.iter().find(|h| {
                h["name"].as_str().unwrap_or("").eq_ignore_ascii_case("content-type")
            })
        })
        .and_then(|h| h["value"].as_str())
        .unwrap_or("text/plain")
        .to_lowercase()
}

/// Truncate a body string given its content-type. Used for non-item contexts.
pub fn apply_to_body(body: &str, content_type: &str, max_chars: usize) -> String {
    // Binary types are always replaced with a descriptor regardless of size
    if content_type.starts_with("image/") || content_type.contains("octet-stream") {
        return format!("[{}, {}B]", content_type, body.len());
    }

    // JSON: always apply value-level truncation (catches long field values even in small bodies)
    if content_type.contains("application/json") {
        return truncate_json(body, max_chars);
    }

    // HTML: extract structure when body exceeds limit
    if content_type.contains("text/html") {
        if body.len() > max_chars {
            return extract_html(body);
        }
        return body.to_string();
    }

    // Plain text and everything else: byte-level truncation at a valid UTF-8 boundary
    if body.len() <= max_chars {
        return body.to_string();
    }
    let mut end = max_chars;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body[..end].to_string()
}

fn truncate_json(body: &str, max_chars: usize) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(mut v) => {
            truncate_json_value(&mut v, 100, 20);
            serde_json::to_string(&v).unwrap_or_else(|_| body.chars().take(max_chars).collect())
        }
        Err(_) => body.chars().take(max_chars).collect(),
    }
}

fn truncate_json_value(v: &mut serde_json::Value, str_max: usize, arr_max: usize) {
    match v {
        serde_json::Value::String(s) => {
            if s.chars().count() > str_max {
                let truncated: String = s.chars().take(str_max).collect();
                *s = format!("{truncated}…");
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                truncate_json_value(item, str_max, arr_max);
            }
            if arr.len() > arr_max {
                let n = arr.len();
                arr.truncate(arr_max);
                arr.push(serde_json::Value::String(format!("[…{} more]", n - arr_max)));
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                truncate_json_value(v, str_max, arr_max);
            }
        }
        _ => {}
    }
}

fn extract_html(body: &str) -> String {
    let mut out = String::new();

    // Extract <title>
    let lower_body = body.to_lowercase();
    if let Some(start) = lower_body.find("<title>") {
        if let Some(end_rel) = lower_body[start + 7..].find("</title>") {
            let title_start = start + 7;
            let title_end = title_start + end_rel;
            // Safe: <title> and </title> are ASCII so to_lowercase() preserves byte offsets;
            // guard with is_char_boundary for correctness on any valid UTF-8 content.
            if body.is_char_boundary(title_start) && body.is_char_boundary(title_end) {
                let title = &body[title_start..title_end];
                out.push_str(&format!("title: {}\n", title.trim()));
            }
        }
    }

    // Extract <form> elements
    let mut search = 0;
    while let Some(form_start) = lower_body[search..].find("<form") {
        let abs = search + form_start;
        let form_end = lower_body[abs..].find('>').map(|e| abs + e + 1).unwrap_or(abs + 6);
        let form_tag = &body[abs..form_end];
        let action = extract_attr(form_tag, "action").unwrap_or_default();
        let method = extract_attr(form_tag, "method").unwrap_or_else(|| "get".into());
        out.push_str(&format!("form: {} {}\n", method.to_uppercase(), action));

        // Find inputs inside this form
        let close = lower_body[form_end..].find("</form").map(|e| form_end + e).unwrap_or(body.len());
        let form_body = &body[form_end..close];
        let form_lower = form_body.to_lowercase();
        let mut isearch = 0;
        while let Some(inp) = form_lower[isearch..].find("<input") {
            let iabs = isearch + inp;
            let iend = form_lower[iabs..].find('>').map(|e| iabs + e + 1).unwrap_or(iabs + 6);
            let inp_tag = &form_body[iabs..iend];
            let name = extract_attr(inp_tag, "name").unwrap_or_default();
            let typ = extract_attr(inp_tag, "type").unwrap_or_else(|| "text".into());
            if !name.is_empty() {
                out.push_str(&format!("  input[{}]: {}\n", typ, name));
            }
            isearch = iend;
        }
        search = close;
    }

    if out.is_empty() {
        body.chars().take(500).collect()
    } else {
        out
    }
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let search = format!("{}=", attr);
    let pos = lower.find(&search)?;
    let rest = &tag[pos + search.len()..];
    let (quote, rest) = if rest.starts_with('"') {
        ('"', &rest[1..])
    } else if rest.starts_with('\'') {
        ('\'', &rest[1..])
    } else {
        return Some(rest.split_whitespace().next()?.to_string());
    };
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_body_unchanged() {
        let result = apply_to_body("hello", "text/plain", 2000);
        assert_eq!(result, "hello");
    }

    #[test]
    fn plain_text_truncated_at_max_chars() {
        let body = "a".repeat(3000);
        let result = apply_to_body(&body, "text/plain", 2000);
        assert_eq!(result.len(), 2000);
    }

    #[test]
    fn json_body_truncates_long_string_values() {
        let body = format!(r#"{{"key": "short", "long_key": "{}"}}"#, "a".repeat(110));
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["key"].as_str().unwrap(), "short");
        assert!(parsed["long_key"].as_str().unwrap().ends_with('…'));
    }

    #[test]
    fn html_body_extracts_title_and_forms() {
        let body = r#"<html><head><title>Login</title></head><body>
            <form action="/login" method="post">
              <input type="text" name="username"/>
              <input type="password" name="password"/>
            </form>
            <p>lots of content here...</p>
        </body></html>"#;
        // max_chars=50 forces extraction since body.len() > 50
        let result = apply_to_body(body, "text/html", 50);
        assert!(result.contains("Login"), "title missing: {result}");
        assert!(result.contains("/login"), "form action missing: {result}");
        assert!(result.contains("username"), "input missing: {result}");
    }

    #[test]
    fn binary_body_replaced_with_descriptor() {
        let result = apply_to_body("PNG binary data here", "image/png", 2000);
        assert!(result.starts_with("[image/png"), "got: {result}");
    }

    #[test]
    fn apply_to_item_reads_content_type_from_headers() {
        let mut item = serde_json::json!({
            "response": {
                "headers": [
                    {"name": "Content-Type", "value": "text/plain"}
                ],
                "body": "a".repeat(3000),
                "statusCode": 200
            }
        });
        apply_to_item(&mut item, 2000);
        let body = item["response"]["body"].as_str().unwrap();
        assert!(body.len() <= 2000, "body not truncated: len={}", body.len());
    }
}
