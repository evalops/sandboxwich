use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::{CreateSandboxRequest, ErrorEnvelope};
use serde_json::json;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;

#[tokio::test]
async fn tenant_limits_are_atomic_and_refill_on_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("limits.db").display());
    assert_limit_contract(
        TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await,
    )
    .await;
}

#[tokio::test]
async fn tenant_limits_are_atomic_and_refill_on_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    assert_limit_contract(TestServer::start_with_expiry_sweeper(database_url, None).await).await;
}

async fn assert_limit_contract(server: TestServer) {
    let policy_url = format!("{}/v1/operator/tenant-policies/default", server.base_url);
    let operator = reqwest::Client::new();
    let configured = operator
        .put(&policy_url)
        .bearer_auth(TEST_DEFAULT_TENANT_TOKEN)
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .json(&json!({"requestLimit": 1, "mutationLimit": 1, "windowSeconds": 60}))
        .send()
        .await
        .unwrap();
    assert_eq!(configured.status(), StatusCode::OK);
    let loaded = operator
        .get(&policy_url)
        .bearer_auth(TEST_DEFAULT_TENANT_TOKEN)
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(loaded.status(), StatusCode::OK);
    assert_eq!(
        loaded.json::<serde_json::Value>().await.unwrap()["requestLimit"],
        1
    );

    let client = server.client();
    let url = format!("{}/v1/sandboxes", server.base_url);
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let client = client.clone();
        let url = url.clone();
        attempts.spawn(async move { client.get(url).send().await });
    }
    let mut responses = Vec::new();
    while let Some(response) = attempts.join_next().await {
        responses.push(response.unwrap());
    }
    let mut accepted = 0;
    let mut limited = 0;
    for response in responses {
        let response = response.unwrap();
        if response.status() == StatusCode::OK {
            accepted += 1;
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(response.headers().get("retry-after").is_some());
            let error: ErrorEnvelope = response.json().await.unwrap();
            assert_eq!(error.code, "tenant_rate_limit_exceeded");
            limited += 1;
        }
    }
    assert_eq!((accepted, limited), (1, 7));
    assert_eq!(
        reqwest::Client::new()
            .get(&url)
            .bearer_auth(TEST_TENANT_B_TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "a default-tenant policy must not affect another tenant"
    );

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query("update tenant_limit_counters set window_expires_at = '1970-01-01T00:00:00Z'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::OK,
        "an expired window must refill"
    );

    operator
        .put(&policy_url)
        .bearer_auth(TEST_DEFAULT_TENANT_TOKEN)
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .json(&json!({"requestLimit": 100, "mutationLimit": 1, "windowSeconds": 60}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    sqlx::query("delete from tenant_limit_counters")
        .execute(&pool)
        .await
        .unwrap();
    let body = CreateSandboxRequest {
        workspace_mode: None,
        runtime_profile: None,
        name: Some("quota-race".into()),
        template: None,
        memory_limit: None,
        network_egress: None,
        ttl_seconds: Some(120),
    };
    let first_key = uuid::Uuid::now_v7().to_string();
    let second_key = uuid::Uuid::now_v7().to_string();
    let first = client
        .post(&url)
        .header("idempotency-key", &first_key)
        .json(&body)
        .send();
    let second = client
        .post(&url)
        .header("idempotency-key", &second_key)
        .json(&body)
        .send();
    let (first, second) = tokio::join!(first, second);
    let responses = [first, second];
    let accepted_key = if responses[0].as_ref().unwrap().status() == StatusCode::ACCEPTED {
        &first_key
    } else {
        &second_key
    };
    let limited_key = if accepted_key == &first_key {
        &second_key
    } else {
        &first_key
    };
    let statuses: Vec<_> = responses
        .iter()
        .map(|r| r.as_ref().unwrap().status())
        .collect();
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::ACCEPTED)
            .count(),
        1
    );
    let limited = responses
        .into_iter()
        .find_map(|r| {
            let r = r.unwrap();
            (r.status() == StatusCode::TOO_MANY_REQUESTS).then_some(r)
        })
        .unwrap();
    assert!(limited.headers().get("retry-after").is_some());
    assert_eq!(
        limited.json::<ErrorEnvelope>().await.unwrap().code,
        "tenant_mutation_quota_exceeded"
    );
    assert_eq!(
        client
            .post(&url)
            .header("idempotency-key", accepted_key)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED,
        "an idempotent replay must not consume the mutation quota twice"
    );

    sqlx::query("update tenant_limit_counters set window_expires_at = '1970-01-01T00:00:00Z'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        client
            .post(&url)
            .header("idempotency-key", limited_key)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED,
        "a throttled key must be executable after the quota window refills"
    );
    sqlx::query("update tenant_limit_counters set window_expires_at = '1970-01-01T00:00:00Z'")
        .execute(&pool)
        .await
        .unwrap();
    let removed = poll_until(|| async {
        let count: i64 = sqlx::query("select count(*) as count from tenant_limit_counters")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
        (count == 0).then_some(count)
    })
    .await;
    assert_eq!(
        removed,
        Some(0),
        "expired counter retention sweep must remove durable state"
    );
}
