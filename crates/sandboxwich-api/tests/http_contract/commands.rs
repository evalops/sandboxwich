use crate::common::*;
use sandboxwich_core::*;

#[tokio::test]
pub(crate) async fn small_body_route_rejects_oversized_json_but_upload_route_accepts_large_file() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-body-limit-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("body-limit-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // The global default body limit (1 MiB) applies to ordinary JSON routes: a body padded well
    // past that with an otherwise-valid JSON payload must be rejected before it is ever buffered
    // or parsed. Without `Expect: 100-continue`, the server can reject and close the connection
    // while the client is still writing the oversized body, which surfaces to the client as a
    // connection error rather than a clean response; either outcome proves the body was rejected.
    let oversized_name = "x".repeat(2 * 1024 * 1024);
    let oversized_body = format!(r#"{{"name":"{oversized_name}"}}"#);
    match client
        .post(format!("{}/sandboxes", server.base_url))
        .header("content-type", "application/json")
        .body(oversized_body)
        .send()
        .await
    {
        Ok(response) => {
            assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(error) => {
            assert!(
                error.is_request() || error.is_body() || error.is_connect(),
                "unexpected error sending oversized body: {error}"
            );
        }
    }

    // The file upload route opts into a much larger, explicit limit and must still accept a
    // payload far above the small default (well below the new MAX_SANDBOX_FILE_BYTES cap).
    // Use a fresh client: rejecting the oversized body above closes the connection mid-write,
    // which can poison a pooled connection and surface here as a spurious send error.
    let upload_client = server.client();
    let large_content = vec![b'a'; 8 * 1024 * 1024];
    let form = reqwest::multipart::Form::new()
        .text("path", "/workspace/large.bin")
        .part(
            "file",
            reqwest::multipart::Part::bytes(large_content.clone())
                .file_name("large.bin")
                .mime_str("application/octet-stream")
                .unwrap(),
        );
    let uploaded: FileResponse = upload_client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, created.sandbox.id
        ))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(uploaded.file.size_bytes, large_content.len() as u64);
}

#[tokio::test]
pub(crate) async fn list_commands_respect_limit_and_paginate_with_cursor() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-pagination-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("pagination-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let sandbox_id = created.sandbox.id;

    const TOTAL_COMMANDS: usize = 5;
    let mut created_ids = Vec::with_capacity(TOTAL_COMMANDS);
    for index in 0..TOTAL_COMMANDS {
        let command: QueueCommandResponse = client
            .post(format!(
                "{}/sandboxes/{}/commands",
                server.base_url, sandbox_id
            ))
            .json(&CommandRequest {
                argv: vec!["echo".to_string(), index.to_string()],
                cwd: None,
                env: Default::default(),
                timeout_secs: None,
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        created_ids.push(command.command.id);
    }

    // limit=0 is rejected rather than silently treated as "no limit".
    let zero_limit = client
        .get(format!(
            "{}/sandboxes/{}/commands?limit=0",
            server.base_url, sandbox_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(zero_limit.status(), reqwest::StatusCode::BAD_REQUEST);

    // Passing both before and after is rejected as ambiguous.
    let both_cursors = client
        .get(format!(
            "{}/sandboxes/{}/commands?before=a&after=b",
            server.base_url, sandbox_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(both_cursors.status(), reqwest::StatusCode::BAD_REQUEST);

    // Page through the full set two at a time and confirm we see every command exactly once, in
    // creation order, with the cursor chain terminating cleanly on the last page.
    let mut collected = Vec::with_capacity(TOTAL_COMMANDS);
    let mut cursor: Option<String> = None;
    loop {
        let mut url = format!(
            "{}/sandboxes/{}/commands?limit=2",
            server.base_url, sandbox_id
        );
        if let Some(after) = &cursor {
            url.push_str(&format!("&after={after}"));
        }
        let page: CommandListResponse = client
            .get(url)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(page.commands.len() <= 2);
        collected.extend(page.commands.iter().map(|command| command.id));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(
            collected.len() < TOTAL_COMMANDS * 2,
            "pagination did not terminate"
        );
    }

    assert_eq!(collected, created_ids);
}
