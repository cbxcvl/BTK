#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<HttpHeader>,
    pub body: String,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HttpHeader>,
    pub body: String,
}

#[derive(Clone, Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

pub fn parse_request(raw: &str) -> Option<HttpRequest> {
    let (header_section, body) = split_headers_body(raw);
    let mut lines = header_section.lines();
    let first_line = lines.next()?;
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    // version (3rd part) is ignored
    let headers = parse_headers(lines);
    Some(HttpRequest { method, path, headers, body: body.to_string() })
}

pub fn parse_response(raw: &str) -> Option<HttpResponse> {
    let (header_section, body) = split_headers_body(raw);
    let mut lines = header_section.lines();
    let first_line = lines.next()?;
    let mut parts = first_line.splitn(3, ' ');
    parts.next()?; // HTTP/version — ignore
    let status_code: u16 = parts.next()?.parse().ok()?;
    let headers = parse_headers(lines);
    Some(HttpResponse { status_code, headers, body: body.to_string() })
}

fn split_headers_body(raw: &str) -> (&str, &str) {
    if let Some(pos) = raw.find("\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.find("\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw, "")
    }
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<HttpHeader> {
    lines
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some(HttpHeader {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_request_no_body() {
        let raw = "GET /api/users HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = parse_request(raw).expect("should parse");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/users");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].name, "Host");
        assert_eq!(req.headers[0].value, "example.com");
        assert_eq!(req.body, "");
    }

    #[test]
    fn parse_post_request_with_body() {
        let raw = "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"u\":\"x\"}";
        let req = parse_request(raw).expect("should parse");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/login");
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.body, "{\"u\":\"x\"}");
    }

    #[test]
    fn parse_request_lf_only_line_endings() {
        // Burp sometimes uses \n instead of \r\n
        let raw = "GET /foo HTTP/1.1\nHost: x.com\n\nbody";
        let req = parse_request(raw).expect("should parse lf-only");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo");
        assert_eq!(req.body, "body");
    }

    #[test]
    fn parse_http1_response_200() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse_response(raw).expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(resp.headers[0].name, "Content-Type");
        assert_eq!(resp.body, "hello");
    }

    #[test]
    fn parse_http2_response_304_no_body() {
        let raw = "HTTP/2 304 Not Modified\r\nETag: \"abc\"\r\n\r\n";
        let resp = parse_response(raw).expect("should parse");
        assert_eq!(resp.status_code, 304);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.body, "");
    }

    #[test]
    fn parse_request_empty_returns_none() {
        // Empty string → lines().next() returns None → ? propagates None
        assert!(parse_request("").is_none());
    }

    #[test]
    fn parse_response_malformed_status_returns_none() {
        let raw = "HTTP/1.1 abc OK\r\n\r\n";
        let result = parse_response(raw);
        assert!(result.is_none(), "non-numeric status should return None");
    }

    #[test]
    fn header_value_preserves_colons() {
        // Header values may contain colons (e.g. timestamps, URIs)
        let raw = "GET / HTTP/1.1\r\nDate: Mon, 20 Mar 2026 12:00:00 GMT\r\n\r\n";
        let req = parse_request(raw).expect("should parse");
        assert_eq!(req.headers[0].value, "Mon, 20 Mar 2026 12:00:00 GMT");
    }
}
