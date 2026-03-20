pub(crate) fn parse_sse_data(line: &str) -> Option<String> {
    line.strip_prefix("data: ").map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_data_field() {
        assert_eq!(
            parse_sse_data(r#"data: {"jsonrpc":"2.0","id":1}"#),
            Some(r#"{"jsonrpc":"2.0","id":1}"#.to_string())
        );
    }

    #[test]
    fn returns_none_for_event_line() {
        assert_eq!(parse_sse_data("event: message"), None);
    }

    #[test]
    fn returns_none_for_comment_line() {
        assert_eq!(parse_sse_data(": keep-alive"), None);
    }

    #[test]
    fn returns_none_for_blank_line() {
        assert_eq!(parse_sse_data(""), None);
    }

    #[test]
    fn returns_none_for_id_line() {
        assert_eq!(parse_sse_data("id: 42"), None);
    }
}
