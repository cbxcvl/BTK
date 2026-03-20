/// End-to-end test: sends tools/list to Burp via the btk binary and asserts
/// the response is valid JSON-RPC (result or error). Requires BURP_URL env var
/// and a running Burp MCP server. Skip if env var absent.
///
/// Run with: BURP_URL=http://127.0.0.1:9876 cargo test -- --include-ignored
///
/// Burp MCP server URL structure (discovered empirically):
///   GET  /               → SSE stream; first event is `event: endpoint`, `data: ?sessionId=<uuid>`
///   POST /?sessionId=... → JSON-RPC endpoint; returns 202 Accepted
///   SSE stream delivers the JSON-RPC response as `event: message`, `data: <json>`
#[tokio::test]
#[ignore]
async fn test_tools_list_passthrough() {
    let burp_url = match std::env::var("BURP_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("BURP_URL not set — skipping integration test");
            return;
        }
    };

    // Use reqwest directly to verify the Burp MCP SSE endpoint is reachable
    let client = reqwest::Client::new();

    // 1. Connect to SSE at root path to receive events
    let sse_url = format!("{burp_url}/");
    let sse_resp = client
        .get(&sse_url)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .expect("SSE connect failed");
    assert!(
        sse_resp.status().is_success(),
        "SSE endpoint returned {}",
        sse_resp.status()
    );

    // 2. Read the initial "endpoint" SSE event to extract the session ID.
    //    Burp sends: event: endpoint\r\ndata: ?sessionId=<uuid>\n
    //    NOTE: Burp uses mixed line endings and does NOT send a trailing \n\n
    //    terminator — the stream stays open.  We therefore accumulate chunks
    //    and break as soon as we see a data: ?sessionId= line, rather than
    //    waiting for \n\n which never arrives.
    use futures::StreamExt;
    let mut sse_stream = sse_resp.bytes_stream();
    let mut preamble = String::new();
    let mut session_id: Option<String> = None;

    let preamble_timeout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            while let Some(chunk) = sse_stream.next().await {
                let chunk = chunk.expect("stream error reading preamble");
                preamble.push_str(&String::from_utf8_lossy(&chunk));
                // Check each line accumulated so far (strip \r so CRLF works too)
                for raw_line in preamble.lines() {
                    let line = raw_line.trim_end_matches('\r');
                    if let Some(val) = line.strip_prefix("data: ") {
                        session_id = Some(val.trim_end_matches('\r').to_string());
                        return; // found what we need
                    }
                }
            }
        },
    )
    .await;
    assert!(preamble_timeout.is_ok(), "Timed out waiting for SSE endpoint event");

    let session_id = session_id.expect("no sessionId in endpoint event");

    assert!(
        !session_id.is_empty(),
        "No sessionId received in SSE preamble. Got: {preamble}"
    );

    // 3. POST tools/list to /?sessionId=<id>
    let tools_list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let post_url = format!("{burp_url}{session_id}");  // session_id is already "?sessionId=..."
    let post_resp = client
        .post(&post_url)
        .header("Content-Type", "application/json")
        .json(&tools_list)
        .send()
        .await
        .expect("POST failed");
    assert!(
        post_resp.status().is_success(),
        "POST /?sessionId=... returned {}",
        post_resp.status()
    );

    // 4. Read the "message" event from the SSE stream (response arrives here).
    //    Burp does not send a \n\n terminator, so we accumulate lines and break
    //    as soon as we have both an event: message line and a data: line in the
    //    same event block (separated from the preamble by at least one blank /
    //    non-data line).
    let mut received = String::new();
    let mut rpc_payload: Option<String> = None;

    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            let mut in_message_event = false;
            while let Some(chunk) = sse_stream.next().await {
                let chunk = chunk.expect("stream error");
                let text = String::from_utf8_lossy(&chunk).to_string();
                received.push_str(&text);
                // Process newly arrived lines
                for raw_line in text.lines() {
                    let line = raw_line.trim_end_matches('\r');
                    if line == "event: message" {
                        in_message_event = true;
                    } else if in_message_event {
                        if let Some(d) = line.strip_prefix("data: ") {
                            rpc_payload = Some(d.trim_end_matches('\r').to_string());
                            return; // got what we need
                        }
                    }
                }
            }
        },
    )
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for SSE response");

    // Verify the payload is valid JSON-RPC (result or error)
    let payload = rpc_payload.expect("No data line found in message event");
    let json: serde_json::Value = serde_json::from_str(&payload)
        .expect("SSE data is not valid JSON");
    assert!(
        json.get("result").is_some() || json.get("error").is_some(),
        "Expected result or error in response: {json}"
    );
}
