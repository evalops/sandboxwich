use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

#[tokio::test]
async fn v1_contract_exposes_operations_openapi_request_ids_and_honest_prompt_status() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("v1-contract.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let docs = client
        .get(format!("{}/v1/openapi.json", server.base_url))
        .header("x-request-id", "contract-request-id")
        .send()
        .await
        .unwrap();
    assert_eq!(docs.status(), StatusCode::OK);
    assert_eq!(docs.headers()["x-request-id"], "contract-request-id");
    let docs: serde_json::Value = docs.json().await.unwrap();
    assert_eq!(docs["info"]["version"], "1.0.0");
    assert!(docs["paths"]["/v1/operations/{operation_id}"].is_object());
    assert!(docs["components"]["schemas"]["Operation"].is_object());

    let malformed = client
        .post(format!("{}/v1/sandboxes", server.base_url))
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let malformed: ErrorEnvelope = malformed.json().await.unwrap();
    assert_eq!(malformed.code, "invalid_request");

    let created = client
        .post(format!("{}/v1/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("v1-contract".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    assert!(created.headers().contains_key("x-request-id"));
    let created: SandboxResponse = created.json().await.unwrap();

    let queued = client
        .post(format!(
            "{}/v1/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["echo".to_string(), "hello".to_string()],
            cwd: None,
            env: Default::default(),
            timeout_secs: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(queued.status(), StatusCode::ACCEPTED);
    let queued: QueueCommandResponse = queued.json().await.unwrap();
    assert_eq!(queued.operation.status, OperationStatus::Queued);
    assert_eq!(queued.operation.id, queued.queued_job.id.0);

    let operation: OperationResponse = client
        .get(format!(
            "{}/v1/operations/{}",
            server.base_url, queued.operation.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(operation.operation.status, OperationStatus::Queued);

    let cancelled: OperationResponse = client
        .post(format!(
            "{}/v1/operations/{}/cancel",
            server.base_url, queued.operation.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cancelled.operation.status, OperationStatus::Cancelled);

    let events = client
        .get(format!(
            "{}/v1/operations/{}/events",
            server.base_url, queued.operation.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(events.contains("event: operation"));
    assert!(events.contains("\"status\":\"cancelled\""));

    let prompt = client
        .post(format!(
            "{}/v1/sandboxes/{}/prompt",
            server.base_url, created.sandbox.id
        ))
        .json(&PromptRequest {
            instructions: "pretend".to_string(),
            engine: None,
            model: None,
            effort: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(prompt.status(), StatusCode::NOT_IMPLEMENTED);
    let error: ErrorEnvelope = prompt.json().await.unwrap();
    assert_eq!(error.code, "agent_prompt_unavailable");
}
