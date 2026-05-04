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
    // Binary types: try JSON parse first — some servers return JSON with wrong content-type
    if content_type.starts_with("image/") || content_type.contains("octet-stream") {
        let trimmed = body.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if serde_json::from_str::<serde_json::Value>(body).is_ok() {
                return truncate_json(body, max_chars);
            }
        }
        return format!("[{}, {}B]", content_type, body.len());
    }

    // JSON: always apply value-level truncation (catches long field values even in small bodies)
    // Matches application/json, application/vnd.api+json, application/problem+json, etc.
    if content_type.contains("json") {
        return truncate_json(body, max_chars);
    }

    // Form-encoded: truncate individual non-credential field values (OAuth uses this)
    if content_type.contains("application/x-www-form-urlencoded") {
        return truncate_form_encoded(body);
    }

    // XML: preserve in full — auth responses (SAML, AWS STS, SOAP, WS-Fed) must not be truncated
    if content_type.contains("text/xml") || content_type.contains("application/xml")
        || content_type.contains("application/saml")
    {
        return body.to_string();
    }

    // JSON probe: catches missing or wrong Content-Type (e.g. text/html, text/plain on a JSON body)
    // Must run before HTML extraction to prevent losing JSON credentials
    {
        let trimmed = body.trim_start();
        if (trimmed.starts_with('{') || trimmed.starts_with('['))
            && serde_json::from_str::<serde_json::Value>(body).is_ok()
        {
            return truncate_json(body, max_chars);
        }
    }

    // HTML: extract structure when body exceeds limit
    if content_type.contains("text/html") {
        if body.len() > max_chars {
            return extract_html(body);
        }
        return body.to_string();
    }

    // Plain text and everything else: truncate at word boundary to avoid splitting tokens
    if body.len() <= max_chars {
        return body.to_string();
    }
    let mut end = max_chars;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    // If we're mid-token (no whitespace at cut point), extend to next whitespace (up to 1000 chars)
    // so we don't split JWTs or API keys that straddle the boundary.
    if end < body.len() && !body[..end].ends_with(|c: char| c.is_whitespace()) {
        let scan_end = (end + 1000).min(body.len());
        if let Some(ws) = body[end..scan_end].find(|c: char| c.is_whitespace()) {
            end += ws;
        }
    }
    body[..end].to_string()
}

fn truncate_form_encoded(body: &str) -> String {
    const STR_MAX: usize = 100;
    body.split('&')
        .map(|pair| {
            let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
            if is_credential_key(key)
                || val.chars().count() <= STR_MAX
                || !val.contains(char::is_whitespace)
            {
                pair.to_string()
            } else {
                let truncated: String = val.chars().take(STR_MAX).collect();
                format!("{key}={truncated}…")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
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

pub(crate) fn is_credential_key(key: &str) -> bool {
    let k = key.to_lowercase();
    ["token", "secret", "password", "key", "hash", "signature",
     "jwt", "credential", "nonce", "cert", "auth", "code", "sess", "saml"]
        .iter()
        .any(|kw| k.contains(kw))
}

fn truncate_json_value(v: &mut serde_json::Value, str_max: usize, arr_max: usize) {
    match v {
        serde_json::Value::String(s) => {
            if s.chars().count() > str_max && s.contains(char::is_whitespace) {
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
            for (k, v) in map.iter_mut() {
                if !is_credential_key(k) {
                    truncate_json_value(v, str_max, arr_max);
                }
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
    fn is_credential_key_table() {
        let yes = [
            "access_token", "refresh_token", "id_token", "token", "bearer_token",
            "api_key", "private_key", "public_key", "signing_key",
            "client_secret", "secret", "password", "old_password",
            "authorization", "auth_header",
            "jwt", "certificate", "ssl_cert", "nonce",
            "signature", "hmac_signature", "hash", "password_hash",
            "credential", "credentials",
            "accessToken", "refreshToken", "apiKey", "clientSecret",
            "code", "code_verifier", "authorization_code",
            // session variants
            "session", "sess_id", "session_token",
            // saml variants
            "SAMLResponse", "saml_assertion",
        ];
        // token_type / status_code / zip_code contain "token"/"code" → treated as credential,
        // but their values are always short so there is no practical truncation impact.
        let no = [
            "description", "message", "title", "content", "name", "label",
            "error", "expires_in", "user_id", "email", "created_at", "scope",
            "grant_type",
        ];
        for k in yes { assert!(is_credential_key(k), "expected credential: {k}"); }
        for k in no  { assert!(!is_credential_key(k), "expected non-credential: {k}"); }
    }

    #[test]
    fn deeply_nested_credential_preserved() {
        let long_token = "x".repeat(200);
        let long_desc  = "word ".repeat(40);
        let body = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "access_token": long_token,
                        "description": long_desc,
                    }
                }
            }
        }).to_string();
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["level1"]["level2"]["level3"]["access_token"].as_str().unwrap(),
            long_token, "deeply nested token truncated"
        );
        assert!(
            parsed["level1"]["level2"]["level3"]["description"].as_str().unwrap().ends_with('…'),
            "deeply nested description must truncate"
        );
    }

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
        let body = format!(r#"{{"label": "short", "description": "{}"}}"#, "hello world ".repeat(10));
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["label"].as_str().unwrap(), "short");
        assert!(parsed["description"].as_str().unwrap().ends_with('…'));
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
    fn credential_key_names_never_truncated() {
        // Every key that contains a credential keyword must come through intact
        let long_val = "x".repeat(200);
        let cases = [
            // token variants
            "access_token", "refresh_token", "id_token", "token", "bearer_token",
            // key variants
            "api_key", "private_key", "public_key", "signing_key",
            // secret / password
            "client_secret", "secret", "password", "old_password", "new_password",
            // auth / authorization
            "authorization", "auth_header",
            // jwt / cert / nonce / hash / signature / credential
            "jwt", "certificate", "ssl_cert", "nonce",
            "signature", "hmac_signature", "hash", "password_hash",
            "credential", "credentials",
            // camelCase variants
            "accessToken", "refreshToken", "apiKey", "clientSecret", "passwordHash",
        ];
        for key in cases {
            let body = format!(r#"{{"{key}": "{long_val}"}}"#);
            let result = apply_to_body(&body, "application/json", 2000);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(
                parsed[key].as_str().unwrap(), long_val,
                "credential field '{key}' must not be truncated"
            );
        }
    }

    #[test]
    fn non_credential_fields_still_truncated() {
        let long_val = "word ".repeat(40);
        let cases = ["description", "message", "title", "content", "body", "name", "label", "error"];
        for key in cases {
            let body = format!(r#"{{"{key}": "{long_val}"}}"#);
            let result = apply_to_body(&body, "application/json", 2000);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert!(
                parsed[key].as_str().unwrap().ends_with('…'),
                "non-credential field '{key}' must be truncated"
            );
        }
    }

    #[test]
    fn nested_credential_fields_preserved() {
        let long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        let body = serde_json::json!({
            "data": {
                "access_token": long_token,
                "expires_in": 3600
            },
            "status": "ok"
        }).to_string();
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["data"]["access_token"].as_str().unwrap(), long_token);
        assert_eq!(parsed["status"].as_str().unwrap(), "ok");
    }

    #[test]
    fn short_credential_values_pass_through() {
        let body = r#"{"access_token": "short", "api_key": "abc123", "password": "hunter2"}"#;
        let result = apply_to_body(body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["access_token"].as_str().unwrap(), "short");
        assert_eq!(parsed["api_key"].as_str().unwrap(), "abc123");
        assert_eq!(parsed["password"].as_str().unwrap(), "hunter2");
    }

    #[test]
    fn mixed_response_credentials_intact_content_truncated() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        let long_desc = "word ".repeat(40);
        let body = serde_json::json!({
            "access_token": jwt,
            "token_type": "Bearer",
            "description": long_desc,
            "expires_in": 3600
        }).to_string();
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["access_token"].as_str().unwrap(), jwt, "token truncated");
        assert_eq!(parsed["token_type"].as_str().unwrap(), "Bearer", "token_type truncated");
        assert!(parsed["description"].as_str().unwrap().ends_with('…'), "description not truncated");
    }

    #[test]
    fn json_variant_content_types_use_field_level_truncation() {
        let jwt = "x".repeat(200);
        for ct in [
            "application/vnd.api+json",
            "application/problem+json",
            "application/hal+json",
            "application/ld+json",
            "application/json; charset=utf-8",
        ] {
            let body = format!(r#"{{"access_token":"{jwt}","description":"{}"}}"#, "word ".repeat(40));
            let result = apply_to_body(&body, ct, 2000);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(parsed["access_token"].as_str().unwrap(), jwt, "token truncated for {ct}");
            assert!(parsed["description"].as_str().unwrap().ends_with('…'), "description must truncate for {ct}");
        }
    }

    #[test]
    fn missing_content_type_json_body_credential_preserved() {
        // Server returns JSON without Content-Type header → BTK defaults to text/plain
        // JSON probe must fire and protect credential fields
        let jwt = "x".repeat(200);
        let body = format!(r#"{{"access_token":"{jwt}","description":"{}"}}"#, "y".repeat(200));
        let result = apply_to_body(&body, "text/plain", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["access_token"].as_str().unwrap(), jwt,
            "JSON probe must protect credentials even with text/plain content-type");
    }

    #[test]
    fn wrong_content_type_html_on_json_body_credential_preserved() {
        // Misconfigured server returns JSON with Content-Type: text/html
        // Without fix: extract_html() would destroy the JSON body entirely
        let jwt = "x".repeat(200);
        let body = format!(r#"{{"access_token":"{jwt}","scope":"read write"}}"#);
        let result = apply_to_body(&body, "text/html", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["access_token"].as_str().unwrap(), jwt,
            "JSON probe must fire before extract_html for text/html + JSON body");
    }

    #[test]
    fn wrong_content_type_html_large_body_credential_preserved() {
        // Same scenario but body > max_chars (would have triggered extract_html)
        let jwt = "x".repeat(200);
        let large_padding = "y".repeat(200);
        let body = format!(r#"{{"access_token":"{jwt}","description":"{large_padding}","noise":"{}"}}"#,
            "z".repeat(200));
        let result = apply_to_body(&body, "text/html", 100);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["access_token"].as_str().unwrap(), jwt,
            "large JSON body with text/html must still use JSON path");
    }

    #[test]
    fn octet_stream_with_json_content_uses_field_level_truncation() {
        // Some servers return JSON with Content-Type: application/octet-stream
        let jwt = "x".repeat(200);
        let body = format!(r#"{{"access_token":"{jwt}","description":"{}"}}"#, "word ".repeat(40));
        let result = apply_to_body(&body, "application/octet-stream", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["access_token"].as_str().unwrap(), jwt,
            "octet-stream with JSON body must protect credential fields");
        assert!(parsed["description"].as_str().unwrap().ends_with('…'),
            "non-credential fields must still truncate");
    }

    #[test]
    fn octet_stream_with_binary_content_replaced_by_descriptor() {
        let result = apply_to_body("\x00\x01\x02binary", "application/octet-stream", 2000);
        assert!(result.starts_with("[application/octet-stream"), "binary must be descriptor: {result}");
    }

    #[test]
    fn plain_text_truncation_does_not_split_tokens() {
        // If a JWT straddles the max_chars boundary, extend to next whitespace
        let prefix = "a ".repeat(999); // 1998 chars, ends with space
        let jwt    = "x".repeat(300);  // token starts at char 1998, no internal spaces
        let body   = format!("{prefix}{jwt} some trailing text");
        let result = apply_to_body(&body, "text/plain", 2000);
        assert!(result.contains(&jwt),
            "plain text truncation must not split a token straddling the boundary");
    }

    #[test]
    fn plain_text_hard_cut_when_no_whitespace_within_extension_window() {
        // If no whitespace within 1000 chars past the boundary, hard cut is acceptable
        let body = "x".repeat(4000); // no whitespace at all
        let result = apply_to_body(&body, "text/plain", 2000);
        assert!(result.len() <= 3000, "must still cut eventually: len={}", result.len());
    }

    #[test]
    fn xml_body_never_truncated() {
        // XML auth responses (SAML, AWS STS, SOAP) must be preserved in full
        let long_xml = format!(
            "<Root><AccessKeyId>ASIA{}</AccessKeyId></Root>",
            "x".repeat(3000)
        );
        for ct in ["text/xml", "application/xml", "application/saml+xml"] {
            let result = apply_to_body(&long_xml, ct, 2000);
            assert_eq!(result, long_xml, "XML must not be truncated for content-type: {ct}");
        }
    }

    #[test]
    fn aws_sts_xml_response_intact() {
        let session_token = "FwoGZXIvYXdzE".to_string() + &"A".repeat(300);
        let body = format!(
            r#"<AssumeRoleResponse><AssumeRoleResult><Credentials>
            <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
            <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
            <SessionToken>{session_token}</SessionToken>
            <Expiration>2023-01-01T00:00:00Z</Expiration>
            </Credentials></AssumeRoleResult></AssumeRoleResponse>"#
        );
        let result = apply_to_body(&body, "text/xml", 2000);
        assert_eq!(result, body, "AWS STS response must be intact");
        assert!(result.contains(&session_token), "SessionToken must be present");
    }

    #[test]
    fn saml_form_encoded_response_not_truncated() {
        // SAML POST binding: SAMLResponse field contains large base64 assertion
        let saml_blob = "PHNhbWxwOlJlc3BvbnNlIHhtbG5z".to_string() + &"A".repeat(3000);
        let body = format!("SAMLResponse={saml_blob}&RelayState=https%3A%2F%2Fexample.com");
        let result = apply_to_body(&body, "application/x-www-form-urlencoded", 2000);
        assert!(result.contains(&saml_blob), "SAMLResponse must not be truncated");
    }

    #[test]
    fn form_encoded_credential_fields_not_truncated() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        let body = format!("access_token={jwt}&token_type=Bearer&expires_in=3600");
        let result = apply_to_body(&body, "application/x-www-form-urlencoded", 2000);
        assert!(result.contains(&format!("access_token={jwt}")), "access_token truncated: {result}");
        assert!(result.contains("token_type=Bearer"));
    }

    #[test]
    fn form_encoded_non_credential_fields_truncated() {
        let long_desc = "word ".repeat(40);
        let body = format!("description={long_desc}&name=alice");
        let result = apply_to_body(&body, "application/x-www-form-urlencoded", 2000);
        let desc_val = result.split('&')
            .find(|p| p.starts_with("description="))
            .and_then(|p| p.split_once('=').map(|(_, v)| v))
            .unwrap();
        assert!(desc_val.ends_with('…'), "long non-credential value must truncate");
        assert!(result.contains("name=alice"));
    }

    #[test]
    fn form_encoded_oauth_response_both_tokens_intact() {
        // Full OAuth response: access_token + refresh_token both long JWTs
        let access = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access.".to_string() + &"a".repeat(200);
        let refresh = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh.".to_string() + &"r".repeat(200);
        let body = format!(
            "access_token={access}&refresh_token={refresh}&token_type=Bearer&expires_in=3600"
        );
        let result = apply_to_body(&body, "application/x-www-form-urlencoded", 2000);
        assert!(result.contains(&format!("access_token={access}")), "access_token truncated");
        assert!(result.contains(&format!("refresh_token={refresh}")), "refresh_token truncated");
    }

    #[test]
    fn form_encoded_short_values_unchanged() {
        let body = "grant_type=authorization_code&code=abc123&redirect_uri=https%3A%2F%2Fexample.com";
        let result = apply_to_body(body, "application/x-www-form-urlencoded", 2000);
        assert_eq!(result, body);
    }

    #[test]
    fn no_whitespace_value_preserved_regardless_of_key_name() {
        // Heuristic: any string value without whitespace looks like a token/key/hash
        // and must not be truncated even if the field name is generic
        let token = "x".repeat(200);
        for field in ["data", "value", "result", "payload", "body", "response", "blob", "raw"] {
            let body = format!(r#"{{"{field}": "{token}"}}"#);
            let result = apply_to_body(&body, "application/json", 2000);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert_eq!(
                parsed[field].as_str().unwrap(), token,
                "generic field '{field}' with no-whitespace value must not be truncated"
            );
        }
    }

    #[test]
    fn prose_value_still_truncated_despite_generic_key() {
        // Whitespace in value = prose content → truncate normally
        let prose = "word ".repeat(40);
        for field in ["data", "value", "result", "payload"] {
            let body = format!(r#"{{"{field}": "{prose}"}}"#);
            let result = apply_to_body(&body, "application/json", 2000);
            let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
            assert!(
                parsed[field].as_str().unwrap().ends_with('…'),
                "generic field '{field}' with prose value must still be truncated"
            );
        }
    }

    #[test]
    fn form_encoded_generic_field_with_token_preserved() {
        let token = "x".repeat(200);
        let body = format!("data={token}&name=alice");
        let result = apply_to_body(&body, "application/x-www-form-urlencoded", 2000);
        assert!(
            result.contains(&format!("data={token}")),
            "form-encoded generic field with no-whitespace value must not be truncated"
        );
    }

    #[test]
    fn array_of_credential_objects_preserved() {
        let long_token = "x".repeat(200);
        let body = serde_json::json!({
            "sessions": [
                {"token": long_token, "user": "alice"},
                {"token": long_token, "user": "bob"},
            ]
        }).to_string();
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["sessions"][0]["token"].as_str().unwrap(), long_token);
        assert_eq!(parsed["sessions"][1]["token"].as_str().unwrap(), long_token);
    }

    #[test]
    fn oauth_code_field_not_truncated() {
        let auth_code = "x".repeat(200);
        let body = format!(r#"{{"code": "{auth_code}", "state": "xyz"}}"#);
        let result = apply_to_body(&body, "application/json", 2000);
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["code"].as_str().unwrap(), auth_code, "OAuth code must not be truncated");
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

    #[test]
    fn apply_to_item_preserves_credential_fields_in_json_response() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        let body = serde_json::json!({
            "access_token": jwt,
            "token_type": "Bearer",
            "description": "word ".repeat(40),
        }).to_string();
        let mut item = serde_json::json!({
            "response": {
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "body": body,
                "statusCode": 200
            }
        });
        apply_to_item(&mut item, 2000);
        let result: serde_json::Value =
            serde_json::from_str(item["response"]["body"].as_str().unwrap()).unwrap();
        assert_eq!(result["access_token"].as_str().unwrap(), jwt,
            "apply_to_item must not truncate credential fields");
        assert!(result["description"].as_str().unwrap().ends_with('…'),
            "apply_to_item must still truncate non-credential fields");
    }
}
