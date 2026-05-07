/// Strip useless headers, collapse cookies, remove null fields.
/// Operates on a full Burp tool-call response (result array or single item).
pub fn strip(value: &mut serde_json::Value) {
    // Remove null fields and _meta at result level
    if let Some(result) = value.get_mut("result") {
        if let Some(obj) = result.as_object_mut() {
            obj.retain(|_, v| !v.is_null());
            obj.remove("_meta");
        }
    }

    // Strip items in result arrays (proxy history, scanner)
    if let Some(arr) = value.pointer_mut("/result/items").and_then(|v| v.as_array_mut()) {
        for item in arr.iter_mut() {
            strip_item(item);
        }
    }
}

const STRIP_HEADERS: &[&str] = &[
    "server", "x-powered-by", "via", "x-cache", "cf-ray",
    "x-request-id", "x-runtime",
];

pub(crate) fn strip_item(item: &mut serde_json::Value) {
    strip_headers_in(item, "response");
    strip_headers_in(item, "request");
    collapse_cookies(item, "request", "Cookie");
    collapse_cookies(item, "response", "Set-Cookie");
}

fn strip_headers_in(item: &mut serde_json::Value, side: &str) {
    if let Some(headers) = item[side]["headers"].as_array_mut() {
        headers.retain(|h| {
            let name = h["name"].as_str().unwrap_or("").to_lowercase();
            !STRIP_HEADERS.contains(&name.as_str())
        });
    }
}

fn is_known_session_cookie(name: &str) -> bool {
    matches!(name.to_lowercase().as_str(),
        "phpsessid" | "jsessionid" | "asp.net_sessionid" | "cfid" | "cftoken"
        | "connect.sid" | "rack.session" | "ci_session" | "laravel_session"
    )
}

fn collapse_cookies(item: &mut serde_json::Value, side: &str, header_name: &str) {
    let headers = match item[side]["headers"].as_array_mut() {
        Some(h) => h,
        None => return,
    };
    for header in headers.iter_mut() {
        if header["name"].as_str().unwrap_or("").eq_ignore_ascii_case(header_name) {
            let val = header["value"].as_str().unwrap_or("").to_string();
            let is_set_cookie = header_name.eq_ignore_ascii_case("Set-Cookie");
            let cookies: Vec<&str> = if is_set_cookie {
                val.split(';').next()
                    .map(|c| c.trim())
                    .filter(|c| !c.is_empty())
                    .into_iter().collect()
            } else {
                val.split(';').map(|c| c.trim()).filter(|c| !c.is_empty()).collect()
            };
            let count = cookies.len();
            let (creds, others): (Vec<&&str>, Vec<&&str>) = cookies.iter().partition(|c| {
                let name = c.split('=').next().unwrap_or("").to_lowercase();
                is_known_session_cookie(&name) || crate::body_truncate::is_credential_key(&name)
            });
            let mut parts: Vec<String> = Vec::new();
            for s in &creds {
                let (cname, cval) = s.split_once('=').unwrap_or((s, ""));
                parts.push(format!("{cname}={cval}"));
            }
            for s in &others {
                let cname = s.split('=').next().unwrap_or(s);
                parts.push(cname.to_string());
            }
            let collapsed = format!("[{count} cookies: {}]", parts.join(", "));
            header["value"] = serde_json::Value::String(collapsed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_item(resp_headers: serde_json::Value) -> serde_json::Value {
        json!({
            "request": { "headers": [], "body": "" },
            "response": {
                "statusCode": 200,
                "headers": resp_headers,
                "body": "hello"
            }
        })
    }

    #[test]
    fn strips_useless_response_headers() {
        let mut item = make_item(json!([
            {"name": "Server", "value": "nginx/1.24"},
            {"name": "Content-Type", "value": "text/html"},
            {"name": "X-Powered-By", "value": "PHP/8.1"},
            {"name": "CF-RAY", "value": "abc123"},
        ]));
        strip_item(&mut item);
        let headers = item["response"]["headers"].as_array().unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0]["name"].as_str().unwrap(), "Content-Type");
    }

    #[test]
    fn collapses_cookies_with_session() {
        let mut item = make_item(json!([
            {"name": "Content-Type", "value": "text/html"},
        ]));
        item["request"]["headers"] = json!([
            {"name": "Cookie", "value": "session=abc123def456; _ga=GA1; _gid=GA2; csrf=xyz"},
        ]);
        strip_item(&mut item);
        let req_headers = item["request"]["headers"].as_array().unwrap();
        let cookie = req_headers.iter().find(|h| h["name"] == "Cookie").unwrap();
        let val = cookie["value"].as_str().unwrap();
        assert!(val.starts_with("[4 cookies: "), "expected count: got {val}");
        assert!(val.contains("session=abc123def456"), "full session value must be preserved: got {val}");
        assert!(val.contains("_ga"), "non-credential names must appear: got {val}");
    }

    #[test]
    fn collapses_cookies_without_session() {
        let mut item = make_item(json!([]));
        item["request"]["headers"] = json!([
            {"name": "Cookie", "value": "_ga=GA1; _gid=GA2"},
        ]);
        strip_item(&mut item);
        let req_headers = item["request"]["headers"].as_array().unwrap();
        let cookie = req_headers.iter().find(|h| h["name"] == "Cookie").unwrap();
        let val = cookie["value"].as_str().unwrap();
        assert_eq!(val, "[2 cookies: _ga, _gid]");
    }

    #[test]
    fn credential_cookie_value_preserved_in_full() {
        let long_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        let mut item = make_item(json!([]));
        item["request"]["headers"] = json!([
            {"name": "Cookie", "value": format!("auth_token={long_jwt}; _ga=GA1")},
        ]);
        strip_item(&mut item);
        let req_headers = item["request"]["headers"].as_array().unwrap();
        let cookie = req_headers.iter().find(|h| h["name"] == "Cookie").unwrap();
        let val = cookie["value"].as_str().unwrap();
        assert!(val.contains(&long_jwt), "auth_token JWT must not be truncated: {val}");
    }

    #[test]
    fn set_cookie_credential_value_preserved_in_full() {
        let long_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        let mut item = make_item(json!([
            {"name": "Set-Cookie", "value": format!("access_token={long_jwt}; HttpOnly; Secure")},
        ]));
        strip_item(&mut item);
        let resp_headers = item["response"]["headers"].as_array().unwrap();
        let cookie = resp_headers.iter().find(|h| h["name"] == "Set-Cookie").unwrap();
        let val = cookie["value"].as_str().unwrap();
        assert!(val.contains(&long_jwt), "Set-Cookie access_token must not be truncated: {val}");
    }

    #[test]
    fn credential_named_cookie_not_caught_by_old_finder_preserved() {
        // jwt / secret are not "session"/"auth"/"token" — old finder missed them
        let long_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        for cookie_name in ["jwt", "secret", "private_key", "signature"] {
            let mut item = make_item(json!([]));
            item["request"]["headers"] = json!([
                {"name": "Cookie", "value": format!("{cookie_name}={long_jwt}; _ga=GA1")},
            ]);
            strip_item(&mut item);
            let req_headers = item["request"]["headers"].as_array().unwrap();
            let cookie = req_headers.iter().find(|h| h["name"] == "Cookie").unwrap();
            let val = cookie["value"].as_str().unwrap();
            assert!(
                val.contains(&long_jwt),
                "cookie '{cookie_name}' full value must be preserved: {val}"
            );
        }
    }

    #[test]
    fn non_credential_cookie_still_collapsed() {
        let mut item = make_item(json!([]));
        item["request"]["headers"] = json!([
            {"name": "Cookie", "value": "_ga=GA1; _gid=GA2; _fbp=FB1"},
        ]);
        strip_item(&mut item);
        let req_headers = item["request"]["headers"].as_array().unwrap();
        let cookie = req_headers.iter().find(|h| h["name"] == "Cookie").unwrap();
        let val = cookie["value"].as_str().unwrap();
        // tracker cookies only → no credential name found → collapsed to count only
        assert_eq!(val, "[3 cookies: _ga, _gid, _fbp]", "tracker-only cookies must list names: got {val}");
    }

    #[test]
    fn auth_response_headers_pass_through_intact() {
        let long_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.".to_string() + &"a".repeat(200);
        for header_name in ["Authorization", "X-Auth-Token", "X-Token", "X-API-Key", "X-Access-Token"] {
            let mut item = make_item(json!([
                {"name": "Content-Type",  "value": "application/json"},
                {"name": header_name,     "value": format!("Bearer {long_jwt}")},
            ]));
            strip_item(&mut item);
            let resp_headers = item["response"]["headers"].as_array().unwrap();
            let header = resp_headers.iter().find(|h| {
                h["name"].as_str().unwrap_or("").eq_ignore_ascii_case(header_name)
            }).unwrap_or_else(|| panic!("{header_name} must survive strip_item"));
            assert_eq!(
                header["value"].as_str().unwrap(),
                format!("Bearer {long_jwt}"),
                "{header_name} value must be preserved intact"
            );
        }
    }

    #[test]
    fn well_known_session_cookies_full_value_preserved() {
        let long_sid = "a".repeat(64);
        for name in ["PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "connect.sid", "laravel_session"] {
            let mut item = make_item(json!([]));
            item["request"]["headers"] = json!([
                {"name": "Cookie", "value": format!("{name}={long_sid}; _ga=GA1")},
            ]);
            strip_item(&mut item);
            let req_headers = item["request"]["headers"].as_array().unwrap();
            let cookie = req_headers.iter().find(|h| h["name"] == "Cookie").unwrap();
            let val = cookie["value"].as_str().unwrap();
            assert!(
                val.contains(&long_sid),
                "well-known session cookie '{name}' must preserve full value: {val}"
            );
        }
    }

    #[test]
    fn removes_null_fields() {
        let mut value = json!({"result": {"data": null, "items": [], "extra": null}});
        strip(&mut value);
        let result_obj = value["result"].as_object().unwrap();
        assert!(!result_obj.contains_key("data"), "null 'data' field should be removed");
        assert!(!result_obj.contains_key("extra"), "null 'extra' field should be removed");
    }

    #[test]
    fn strip_only_removes_nulls_at_result_level_not_recursively() {
        // Top-level result nulls ARE removed
        let mut value = json!({
            "result": {
                "status": "ok",
                "extra": null,
                "nested": {"deep_null": null}
            }
        });
        strip(&mut value);
        let result_obj = value["result"].as_object().unwrap();
        assert!(!result_obj.contains_key("extra"), "top-level null should be removed");
        // Nested nulls should NOT be removed (strip is shallow)
        assert!(result_obj["nested"]["deep_null"].is_null(), "nested null should survive");
    }
}
