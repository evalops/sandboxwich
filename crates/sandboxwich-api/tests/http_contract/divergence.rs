use crate::common::*;
use chrono::{Duration, Utc};
use sandboxwich_core::*;

#[tokio::test]
async fn divergence_contract_works_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("divergence.db").display()
    );
    run_divergence_contract(TestServer::start(database_url, Some(data_dir)).await).await;
}

#[tokio::test]
async fn divergence_contract_works_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    run_divergence_contract(TestServer::start(database_url, None).await).await;
}

async fn run_divergence_contract(server: TestServer) {
    let client = server.client();
    let sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("divergence-contract".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let now = Utc::now();
    client
        .post(format!(
            "{}/sandboxes/{}/tool-call-ledger",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&ToolCallLedgerEntryRequest {
            external_id: "ledger-1".to_string(),
            session_id: "session-1".to_string(),
            receipt_id: "receipt-1".to_string(),
            started_at: now - Duration::seconds(5),
            ended_at: now + Duration::seconds(5),
            scopes: vec![ReceiptScope {
                activity_class: ActivityClass::FileWrite,
                resource_prefix: "/workspace/".to_string(),
            }],
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(format!(
            "{}/sandboxes/{}/tool-call-ledger",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&ToolCallLedgerEntryRequest {
            external_id: "ledger-literal-prefix".to_string(),
            session_id: "session-literal-prefix".to_string(),
            receipt_id: "receipt-literal-prefix".to_string(),
            started_at: now - Duration::seconds(5),
            ended_at: now + Duration::seconds(5),
            scopes: vec![ReceiptScope {
                activity_class: ActivityClass::FileWrite,
                resource_prefix: "/workspace/file_v2/".to_string(),
            }],
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let observations = vec![
        SensorObservation {
            external_id: "matched".to_string(),
            sandbox_id: sandbox.sandbox.id,
            session_id: "session-1".to_string(),
            activity_class: ActivityClass::FileWrite,
            resource: "/workspace/main.rs".to_string(),
            observed_at: now,
        },
        SensorObservation {
            external_id: "literal-prefix-mismatch".to_string(),
            sandbox_id: sandbox.sandbox.id,
            session_id: "session-literal-prefix".to_string(),
            activity_class: ActivityClass::FileWrite,
            resource: "/workspace/fileXv2/secret".to_string(),
            observed_at: now,
        },
        SensorObservation {
            external_id: "scope-mismatch".to_string(),
            sandbox_id: sandbox.sandbox.id,
            session_id: "session-1".to_string(),
            activity_class: ActivityClass::NetworkConnect,
            resource: "203.0.113.9:443".to_string(),
            observed_at: now,
        },
        SensorObservation {
            external_id: "unaccounted".to_string(),
            sandbox_id: sandbox.sandbox.id,
            session_id: "unknown-session".to_string(),
            activity_class: ActivityClass::ProcessSpawn,
            resource: "/usr/bin/curl".to_string(),
            observed_at: now,
        },
    ];
    let reconciled: DivergenceReconcileResponse = client
        .post(format!("{}/divergence/reconcile", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .json(&DivergenceReconcileRequest {
            source: "limacharlie".to_string(),
            observations: observations.clone(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(reconciled.ok);
    assert_eq!(reconciled.observations_matched, 1);
    assert_eq!(reconciled.findings_created.len(), 3);
    assert!(
        reconciled
            .findings_created
            .iter()
            .any(|f| f.kind == DivergenceKind::ReceiptScopeMismatch
                && f.receipt_id.as_deref() == Some("receipt-1"))
    );
    assert!(
        reconciled
            .findings_created
            .iter()
            .any(|f| f.kind == DivergenceKind::UnaccountedActivity && f.receipt_id.is_none())
    );
    let stopped: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stopped.sandbox.state, SandboxState::Archiving);
    let jobs: JobListResponse = client
        .get(format!("{}/jobs?limit=100", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        jobs.jobs
            .iter()
            .filter(|job| job.kind == JobKind::StopSandbox)
            .count(),
        1
    );
    let events: EventListResponse = client
        .get(format!(
            "{}/sandboxes/{}/events",
            server.base_url, sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.kind == SandboxEventKind::DivergenceDetected)
            .count(),
        3
    );

    // Replaying a vendor batch is idempotent at every durable boundary.
    let replayed: DivergenceReconcileResponse = client
        .post(format!("{}/divergence/reconcile", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .json(&DivergenceReconcileRequest {
            source: "limacharlie".to_string(),
            observations,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(replayed.findings_created.is_empty());
    let listed: DivergenceFindingListResponse = client
        .get(format!(
            "{}/sandboxes/{}/divergence-findings",
            server.base_url, sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed.findings.len(), 3);
}
