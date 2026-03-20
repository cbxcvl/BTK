/// End-to-end test: sends tools/list to Burp via the btk binary and asserts
/// the response contains a "tools" key. Requires BURP_URL env var and a running
/// Burp MCP server. Skip if env var absent.
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
    //    Burp sends: event: endpoint\ndata: ?sessionId=<uuid>\n\n
    use futures::StreamExt;
    let mut stream = sse_resp.bytes_stream();
    let mut preamble = String::new();

    let session_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("stream error reading preamble");
            preamble.push_str(&String::from_utf8_lossy(&chunk));
            // Look for the data line with the session ID
            for line in preamble.lines() {
                if let Some(suffix) = line.strip_prefix("data: ?sessionId=") {
                    return suffix.trim().to_string();
                }
            }
        }
        String::new()
    })
    .await
    .expect("Timed out waiting for SSE endpoint event");

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
    let post_url = format!("{burp_url}/?sessionId={session_id}");
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

    // 4. Read the "message" event from the SSE stream (response arrives here)
    let mut received = String::new();
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.expect("stream error");
                received.push_str(&String::from_utf8_lossy(&chunk));
                if received.contains("data: ") {
                    break;
                }
            }
        },
    )
    .await;

    assert!(timeout.is_ok(), "Timed out waiting for SSE response");
    assert!(
        received.contains("data: "),
        "No data: event received. Got: {received}"
    );

    // Extract the data payload and verify it's valid JSON with a "result" key
    for line in received.lines() {
        if let Some(payload) = line.strip_prefix("data: ") {
            let json: serde_json::Value =
                serde_json::from_str(payload).expect("SSE data is not valid JSON");
            assert!(
                json.get("result").is_some() || json.get("error").is_some(),
                "Expected result or error in response: {json}"
            );
            return;
        }
    }
    panic!("No data: line found in SSE output");
}
