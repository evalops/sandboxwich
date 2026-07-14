use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;
use std::collections::BTreeSet;

#[tokio::test]
async fn openapi_covers_every_public_v1_operation() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("openapi-coverage.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let docs: serde_json::Value = server
        .client()
        .get(format!("{}/v1/openapi.json", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let actual: BTreeSet<(String, String)> = docs["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .unwrap()
                .keys()
                .filter(|method| {
                    matches!(method.as_str(), "get" | "post" | "put" | "delete" | "patch")
                })
                .map(move |method| (method.to_ascii_uppercase(), path.clone()))
        })
        .collect();
    let expected: BTreeSet<(String, String)> = [
        ("GET", "/v1/metrics"),
        ("GET", "/v1/sandboxes"),
        ("POST", "/v1/sandboxes"),
        ("GET", "/v1/sandboxes/{sandbox_id}"),
        ("GET", "/v1/sandboxes/{sandbox_id}/observed-state"),
        ("GET", "/v1/sandboxes/{sandbox_id}/files"),
        ("POST", "/v1/sandboxes/{sandbox_id}/files"),
        ("GET", "/v1/sandboxes/{sandbox_id}/files/{file_id}"),
        ("GET", "/v1/sandboxes/{sandbox_id}/runtime-resources"),
        ("POST", "/v1/sandboxes/{sandbox_id}/stop"),
        ("POST", "/v1/sandboxes/{sandbox_id}/resume"),
        ("POST", "/v1/sandboxes/{sandbox_id}/fork"),
        ("GET", "/v1/sandboxes/{sandbox_id}/snapshots"),
        ("POST", "/v1/sandboxes/{sandbox_id}/snapshots"),
        ("GET", "/v1/sandboxes/{sandbox_id}/desktop"),
        ("GET", "/v1/sandboxes/{sandbox_id}/desktop-sessions"),
        ("POST", "/v1/sandboxes/{sandbox_id}/desktop-sessions"),
        ("GET", "/v1/sandboxes/{sandbox_id}/commands"),
        ("POST", "/v1/sandboxes/{sandbox_id}/commands"),
        ("POST", "/v1/sandboxes/{sandbox_id}/prompt"),
        ("GET", "/v1/sandboxes/{sandbox_id}/events"),
        ("GET", "/v1/desktop-sessions/{desktop_session_id}"),
        ("POST", "/v1/desktop-sessions/{desktop_session_id}/status"),
        ("POST", "/v1/desktop-sessions/{desktop_session_id}/access"),
        ("POST", "/v1/snapshots/cleanup"),
        ("GET", "/v1/snapshots/{snapshot_id}"),
        ("POST", "/v1/snapshots/{snapshot_id}/fork"),
        ("GET", "/v1/commands/{command_id}"),
        ("GET", "/v1/commands/{command_id}/output"),
        ("GET", "/v1/workers"),
        ("POST", "/v1/workers/register"),
        ("GET", "/v1/capacity"),
        ("GET", "/v1/jobs"),
        ("POST", "/v1/jobs"),
        ("GET", "/v1/jobs/{job_id}"),
        ("POST", "/v1/divergence/reconcile"),
        ("POST", "/v1/sandboxes/{sandbox_id}/tool-call-ledger"),
        ("GET", "/v1/sandboxes/{sandbox_id}/divergence-findings"),
        ("GET", "/v1/operations/{operation_id}"),
        ("GET", "/v1/operations/{operation_id}/events"),
        ("POST", "/v1/operations/{operation_id}/cancel"),
        ("GET", "/v1/sandboxes/{sandbox_id}/guest-health"),
        ("POST", "/v1/sandboxes/{sandbox_id}/guest-health"),
        ("GET", "/v1/sandboxes/{sandbox_id}/ssh-keys"),
        ("POST", "/v1/sandboxes/{sandbox_id}/ssh-keys"),
        ("POST", "/v1/sandboxes/{sandbox_id}/ssh-access"),
        ("POST", "/v1/ssh-keys/{ssh_key_id}/status"),
        ("POST", "/v1/workers/{worker_id}/heartbeat"),
        ("POST", "/v1/workers/{worker_id}/drain"),
        (
            "POST",
            "/v1/workers/{worker_id}/sandboxes/{sandbox_id}/guest-token",
        ),
        (
            "POST",
            "/v1/workers/{worker_id}/runtime-resources/reconcile",
        ),
        ("POST", "/v1/workers/{worker_id}/leases/claim"),
        ("POST", "/v1/leases/{lease_id}/renew"),
        ("GET", "/v1/leases/{lease_id}/materialization"),
        ("POST", "/v1/leases/{lease_id}/output"),
        ("POST", "/v1/leases/{lease_id}/complete"),
        ("POST", "/v1/leases/{lease_id}/fail"),
        ("GET", "/v1/operator/tenant-policies/{tenant_id}"),
        ("PUT", "/v1/operator/tenant-policies/{tenant_id}"),
    ]
    .into_iter()
    .map(|(method, path)| (method.to_string(), path.to_string()))
    .collect();
    assert_eq!(actual, expected);
}

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
    assert!(docs["paths"]["/v1/leases/{lease_id}/materialization"]["get"].is_object());
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
            workspace_mode: None,
            runtime_profile: None,
            name: Some("v1-contract".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    assert!(created.headers().contains_key("x-request-id"));
    let created: SandboxResponse = created.json().await.unwrap();
    assert_eq!(
        created.operation.as_ref().unwrap().kind,
        OperationKind::ProvisionSandbox
    );

    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let command_key = uuid::Uuid::now_v7().to_string();
    let command_request = CommandRequest {
        argv: vec!["echo".to_string(), "hello".to_string()],
        cwd: None,
        env: Default::default(),
        stdin: None,
        timeout_secs: None,
    };
    let queued = client
        .post(format!(
            "{}/v1/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .header("idempotency-key", &command_key)
        .header("x-request-id", "platform-command-request")
        .header("traceparent", traceparent)
        .json(&command_request)
        .send()
        .await
        .unwrap();
    assert_eq!(queued.status(), StatusCode::ACCEPTED);
    assert_eq!(queued.headers()["x-request-id"], "platform-command-request");
    assert_eq!(queued.headers()["traceparent"], traceparent);
    let queued_body = queued.bytes().await.unwrap();
    let queued: QueueCommandResponse = serde_json::from_slice(&queued_body).unwrap();
    assert_eq!(queued.operation.status, OperationStatus::Queued);
    assert_eq!(queued.operation.id, queued.queued_job.id.0);

    let command_replay = client
        .post(format!(
            "{}/v1/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .header("idempotency-key", &command_key)
        .json(&command_request)
        .send()
        .await
        .unwrap();
    assert_eq!(command_replay.status(), StatusCode::ACCEPTED);
    assert_eq!(command_replay.bytes().await.unwrap(), queued_body);

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

#[tokio::test]
async fn platform_provider_lifecycle_contract_is_tenant_bound_idempotent_and_correlated() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("platform-provider-contract.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let create_url = format!("{}/v1/sandboxes", server.base_url);

    let unauthorized = reqwest::Client::new()
        .post(&create_url)
        .json(&CreateSandboxRequest {
            workspace_mode: None,
            runtime_profile: None,
            name: Some("missing-tenant-identity".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let idempotency_key = uuid::Uuid::now_v7().to_string();
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let request = CreateSandboxRequest {
        workspace_mode: None,
        runtime_profile: None,
        name: Some("platform-provider-contract".to_string()),
        template: None,
        memory_limit: None,
        network_egress: None,
        ttl_seconds: Some(120),
    };
    let first = client
        .post(&create_url)
        .header("idempotency-key", &idempotency_key)
        .header("x-request-id", "platform-create-request")
        .header("traceparent", traceparent)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(first.headers()["x-request-id"], "platform-create-request");
    assert_eq!(first.headers()["traceparent"], traceparent);
    let first_body = first.bytes().await.unwrap();
    let created: SandboxResponse = serde_json::from_slice(&first_body).unwrap();

    let replay = client
        .post(&create_url)
        .header("idempotency-key", &idempotency_key)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(replay.bytes().await.unwrap(), first_body);

    let observed = client
        .get(format!(
            "{}/v1/sandboxes/{}/observed-state",
            server.base_url, created.sandbox.id
        ))
        .header("x-request-id", "platform-observe-request")
        .header("traceparent", traceparent)
        .send()
        .await
        .unwrap();
    assert_eq!(observed.status(), StatusCode::OK);
    assert_eq!(
        observed.headers()["x-request-id"],
        "platform-observe-request"
    );
    assert_eq!(observed.headers()["traceparent"], traceparent);
    let observed: serde_json::Value = observed.json().await.unwrap();
    assert_eq!(observed["sandboxId"], created.sandbox.id.to_string());
    assert_eq!(observed["tenantId"], "default");
    assert_eq!(observed["state"], "planning");
    assert!(observed["observedAt"].is_string());

    let snapshot: SnapshotResponse = client
        .post(format!(
            "{}/v1/sandboxes/{}/snapshots",
            server.base_url, created.sandbox.id
        ))
        .header("idempotency-key", uuid::Uuid::now_v7().to_string())
        .json(&CreateSnapshotRequest {
            label: Some("platform-restore-source".to_string()),
            inventory: None,
            provider_metadata: None,
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
    let pending_restore = client
        .post(format!(
            "{}/v1/snapshots/{}/fork",
            server.base_url, snapshot.snapshot.id
        ))
        .header("idempotency-key", uuid::Uuid::now_v7().to_string())
        .json(&ForkSnapshotRequest {
            name: Some("must-not-restore-pending".to_string()),
            template: "ubuntu-dev".to_string(),
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::DenyAll,
            runtime_profile: SandboxRuntimeProfile::Unprivileged,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(pending_restore.status(), StatusCode::CONFLICT);
    let pending_error: ErrorEnvelope = pending_restore.json().await.unwrap();
    assert_eq!(pending_error.code, "conflict");
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query(
        "update snapshots set status = 'ready', ready_at = '2026-07-09T00:00:00Z' where id = ?",
    )
    .bind(snapshot.snapshot.id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("update snapshot_restore_sources set status = 'ready' where snapshot_id = ?")
        .bind(snapshot.snapshot.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("delete from sandboxes where id = ?")
        .bind(created.sandbox.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let source_is_gone = client
        .get(format!(
            "{}/v1/sandboxes/{}",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(source_is_gone.status(), StatusCode::NOT_FOUND);

    let restore_request = ForkSnapshotRequest {
        name: Some("platform-restored-child".to_string()),
        template: "ubuntu-dev".to_string(),
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: SandboxRuntimeProfile::Unprivileged,
        ttl_seconds: Some(120),
    };
    let restore_key = uuid::Uuid::now_v7().to_string();
    let restore_url = format!(
        "{}/v1/snapshots/{}/fork",
        server.base_url, snapshot.snapshot.id
    );
    let forbidden = reqwest::Client::new()
        .post(&restore_url)
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .header("idempotency-key", uuid::Uuid::now_v7().to_string())
        .json(&restore_request)
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);

    let restored = client
        .post(&restore_url)
        .header("idempotency-key", &restore_key)
        .header("x-request-id", "platform-snapshot-fork-request")
        .header("traceparent", traceparent)
        .json(&restore_request)
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::ACCEPTED);
    assert_eq!(
        restored.headers()["x-request-id"],
        "platform-snapshot-fork-request"
    );
    assert_eq!(restored.headers()["traceparent"], traceparent);
    let restored_body = restored.bytes().await.unwrap();
    let restored: SandboxResponse = serde_json::from_slice(&restored_body).unwrap();
    assert_eq!(
        restored.sandbox.parent_snapshot_id,
        Some(snapshot.snapshot.id)
    );
    assert_eq!(restored.sandbox.state, SandboxState::Planning);
    assert_eq!(
        restored.operation.as_ref().map(|operation| &operation.kind),
        Some(&OperationKind::ForkSandbox)
    );

    let restore_replay = client
        .post(&restore_url)
        .header("idempotency-key", &restore_key)
        .json(&restore_request)
        .send()
        .await
        .unwrap();
    assert_eq!(restore_replay.status(), StatusCode::ACCEPTED);
    assert_eq!(restore_replay.bytes().await.unwrap(), restored_body);

    let stopped = client
        .post(format!(
            "{}/v1/sandboxes/{}/stop",
            server.base_url, restored.sandbox.id
        ))
        .header("idempotency-key", uuid::Uuid::now_v7().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stopped.status(), StatusCode::ACCEPTED);
    let stopped: SandboxResponse = stopped.json().await.unwrap();
    assert_eq!(stopped.sandbox.state, SandboxState::Archiving);

    let docs: serde_json::Value = client
        .get(format!("{}/v1/openapi.json", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(docs["paths"]["/v1/sandboxes/{sandbox_id}/observed-state"].is_object());
    assert!(docs["components"]["schemas"]["SandboxObservedState"].is_object());
    assert!(docs["paths"]["/v1/snapshots/{snapshot_id}/fork"].is_object());
    assert!(docs["components"]["schemas"]["ForkSnapshotRequest"].is_object());

    for path in [
        "/v1/sandboxes/{sandbox_id}/commands",
        "/v1/commands/{command_id}",
        "/v1/commands/{command_id}/output",
        "/v1/sandboxes/{sandbox_id}/snapshots",
        "/v1/snapshots/{snapshot_id}",
        "/v1/sandboxes/{sandbox_id}/fork",
    ] {
        assert!(
            docs["paths"][path].is_object(),
            "missing provider path {path}"
        );
    }
    for schema in [
        "QueueCommandResponse",
        "CommandResponse",
        "CommandOutputListResponse",
        "SnapshotResponse",
        "CreateSnapshotRequest",
        "SandboxResponse",
    ] {
        assert!(
            docs["components"]["schemas"][schema].is_object(),
            "missing provider schema {schema}"
        );
    }
}
