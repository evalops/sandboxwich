use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;

#[tokio::test]
async fn idempotency_is_concurrent_safe_and_tenant_scoped_on_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("idempotency.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    assert_idempotency_contract(server).await;
}

#[tokio::test]
async fn idempotency_is_concurrent_safe_and_tenant_scoped_on_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start_with_expiry_sweeper(database_url, None).await;
    assert_idempotency_contract(server).await;
}

async fn assert_idempotency_contract(server: TestServer) {
    let client = server.client();
    let key = uuid::Uuid::now_v7().to_string();
    let url = format!("{}/v1/sandboxes", server.base_url);
    let request = CreateSandboxRequest {
        workspace_mode: None,
        runtime_profile: None,
        name: Some("idempotent-sandbox".to_string()),
        template: None,
        memory_limit: None,
        network_egress: None,
        ttl_seconds: Some(120),
    };

    let first = client
        .post(&url)
        .header("idempotency-key", &key)
        .json(&request)
        .send();
    let second = client
        .post(&url)
        .header("idempotency-key", &key)
        .json(&request)
        .send();
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    let first_body = first.bytes().await.unwrap();
    let second_body = second.bytes().await.unwrap();
    assert_eq!(first_body, second_body);
    let accepted: SandboxResponse = serde_json::from_slice(&first_body).unwrap();
    assert_eq!(
        accepted.operation.as_ref().unwrap().id,
        serde_json::from_slice::<SandboxResponse>(&second_body)
            .unwrap()
            .operation
            .unwrap()
            .id
    );

    let mismatch = client
        .post(&url)
        .header("idempotency-key", &key)
        .json(&CreateSandboxRequest {
            workspace_mode: None,
            runtime_profile: None,
            name: Some("different".to_string()),
            ..request.clone()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let mismatch: ErrorEnvelope = mismatch.json().await.unwrap();
    assert_eq!(mismatch.code, "idempotency_key_reused");

    let tenant_b = reqwest::Client::new()
        .post(&url)
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .header("idempotency-key", &key)
        .json(&CreateSandboxRequest {
            workspace_mode: None,
            runtime_profile: None,
            name: Some("tenant-b-idempotent".to_string()),
            ..request
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_b.status(), StatusCode::ACCEPTED);

    let registration_key = uuid::Uuid::now_v7().to_string();
    let registered: WorkerResponse = client
        .post(format!("{}/v1/workers/register", server.base_url))
        .header("idempotency-key", &registration_key)
        .json(&RegisterWorkerRequest {
            name: "idempotency-secret-boundary".to_string(),
            provider: "test".to_string(),
            capabilities: vec![WorkerCapability::ProvisionSandbox],
            max_concurrent_jobs: Some(1),
            labels: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(registered.worker_token.is_some());

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();
    let sandbox_count: i64 = sqlx::query(
        "select count(*) as count from sandboxes where tenant_id = 'default' and name = 'idempotent-sandbox'",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(sandbox_count, 1);
    let key_placeholder = if server.database_url.starts_with("postgres") {
        "$1"
    } else {
        "?"
    };
    let secret_record_count: i64 = sqlx::query(&format!(
        "select count(*) as count from idempotency_records where idempotency_key = {key_placeholder}"
    ))
    .bind(&registration_key)
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(
        secret_record_count, 0,
        "raw worker tokens must never enter replay storage"
    );

    sqlx::query("update idempotency_records set expires_at = '1970-01-01T00:00:00Z' where tenant_id = 'default'")
        .execute(&pool)
        .await
        .unwrap();
    let expired = poll_until(|| async {
        let count: i64 = sqlx::query(
            "select count(*) as count from idempotency_records where tenant_id = 'default'",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        (count == 0).then_some(count)
    })
    .await;
    assert_eq!(expired, Some(0));
}
