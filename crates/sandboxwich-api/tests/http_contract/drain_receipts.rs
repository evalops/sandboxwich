use crate::common::*;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sandboxwich_core::*;
use serde::{Deserialize, Serialize};
use sqlx::{Row, any::AnyPoolOptions};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DrainWorkerRequest {
    shutdown_id: Uuid,
    hard_deadline: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DrainWorkerResponse {
    worker: Worker,
    drain_receipt: DrainReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DrainReceipt {
    shutdown_id: Uuid,
    worker_id: WorkerId,
    hard_deadline: DateTime<Utc>,
    leases: Vec<DrainLeaseFence>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DrainLeaseFence {
    lease_id: LeaseId,
    job_id: JobId,
    attempt: i64,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    resolved_at: Option<DateTime<Utc>>,
}

async fn register_worker(server: &TestServer, name: &str) -> WorkerResponse {
    server
        .client()
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: name.to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::ProvisionSandbox],
            max_concurrent_jobs: Some(2),
            labels: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn create_provision_job(server: &TestServer, name: &str) -> SandboxResponse {
    server
        .client()
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            secret_ref_ids: Vec::new(),
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some(name.to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            provider_preference: None,
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
        .unwrap()
}

async fn claim_provision_job(
    server: &TestServer,
    worker: &WorkerResponse,
    sandbox_id: SandboxId,
) -> Option<JobLease> {
    worker_client(worker)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(300),
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::ProvisionSandbox]),
            wait_ms: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimLeaseResponse>()
        .await
        .unwrap()
        .lease
}

async fn drain(
    server: &TestServer,
    worker: &WorkerResponse,
    request: &DrainWorkerRequest,
) -> DrainWorkerResponse {
    worker_client(worker)
        .post(format!(
            "{}/workers/{}/drain",
            server.base_url, worker.worker.id
        ))
        .json(request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn connect_database(database_url: &str) -> sqlx::AnyPool {
    sqlx::any::install_default_drivers();
    AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap()
}

#[tokio::test]
async fn legacy_bodyless_drain_remains_rollout_compatible() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("legacy-drain.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "legacy-drain-worker").await;

    let response: WorkerResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/drain",
            server.base_url, worker.worker.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(response.worker.status, WorkerStatus::Draining);
}

#[tokio::test]
async fn drain_receipt_is_idempotent_and_captures_exact_active_leases() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("receipt.db").display());
    let server = TestServer::start(database_url.clone(), Some(data_dir)).await;
    let worker = register_worker(&server, "receipt-worker").await;
    let sandbox = create_provision_job(&server, "receipt-sandbox").await;
    let lease = claim_provision_job(&server, &worker, sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };

    let first = drain(&server, &worker, &request).await;
    let replay = drain(&server, &worker, &request).await;

    assert_eq!(first.worker.status, WorkerStatus::Draining);
    assert_eq!(first.drain_receipt.shutdown_id, request.shutdown_id);
    assert_eq!(first.drain_receipt.worker_id, worker.worker.id);
    assert_eq!(first.drain_receipt.hard_deadline, request.hard_deadline);
    assert_eq!(first.drain_receipt.leases.len(), 1);
    assert_eq!(first.drain_receipt.leases[0].lease_id, lease.id);
    assert_eq!(first.drain_receipt.leases[0].job_id, lease.job.id);
    assert_eq!(first.drain_receipt.leases[0].attempt, lease.attempt);
    assert_eq!(
        replay.drain_receipt.shutdown_id,
        first.drain_receipt.shutdown_id
    );
    assert_eq!(replay.drain_receipt.leases[0].lease_id, lease.id);

    let pool = connect_database(&database_url).await;
    let expires_at: String = sqlx::query("select expires_at from job_leases where id = ?")
        .bind(lease.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("expires_at")
        .unwrap();
    let expires_at = DateTime::parse_from_rfc3339(&expires_at)
        .unwrap()
        .with_timezone(&Utc);
    assert!(expires_at <= request.hard_deadline);
}

#[tokio::test]
async fn drain_receipt_replay_remains_available_after_the_hard_deadline() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("late-replay.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "late-replay-worker").await;
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(1),
    };
    let first = drain(&server, &worker, &request).await;

    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let replay = drain(&server, &worker, &request).await;
    assert_eq!(
        replay.drain_receipt.shutdown_id,
        first.drain_receipt.shutdown_id
    );
    assert_eq!(replay.drain_receipt.hard_deadline, request.hard_deadline);
}

#[tokio::test]
async fn concurrent_exact_drain_retries_return_one_receipt() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("concurrent-replay.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "concurrent-replay-worker").await;
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };

    let (first, second) = tokio::join!(
        drain(&server, &worker, &request),
        drain(&server, &worker, &request)
    );

    assert_eq!(first.drain_receipt.shutdown_id, request.shutdown_id);
    assert_eq!(second.drain_receipt.shutdown_id, request.shutdown_id);
    assert_eq!(
        first.drain_receipt.hard_deadline,
        second.drain_receipt.hard_deadline
    );
}

#[tokio::test]
async fn draining_worker_cannot_claim_jobs_created_after_admission_closes() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("claim-fence.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "claim-fence-worker").await;
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };
    drain(&server, &worker, &request).await;
    let heartbeat: WorkerResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/heartbeat",
            server.base_url, worker.worker.id
        ))
        .json(&WorkerHeartbeatRequest::default())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(heartbeat.worker.status, WorkerStatus::Draining);
    let sandbox = create_provision_job(&server, "post-drain-sandbox").await;

    assert!(
        claim_provision_job(&server, &worker, sandbox.sandbox.id)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn draining_worker_renewal_is_capped_at_the_receipt_deadline() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("renew-cap.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "renew-cap-worker").await;
    let sandbox = create_provision_job(&server, "renew-cap-sandbox").await;
    let lease = claim_provision_job(&server, &worker, sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };
    drain(&server, &worker, &request).await;

    let renewed: LeaseResponse = worker_client(&worker)
        .post(format!("{}/leases/{}/renew", server.base_url, lease.id))
        .json(&RenewLeaseRequest {
            lease_seconds: Some(3_600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(renewed.lease.expires_at <= request.hard_deadline);
}

#[tokio::test]
async fn reregister_during_drain_keeps_admission_closed_and_exact_renewal_capped() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("reregister-fence.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "reregister-worker").await;
    let sandbox = create_provision_job(&server, "reregister-sandbox").await;
    let lease = claim_provision_job(&server, &worker, sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };
    drain(&server, &worker, &request).await;

    let restarted = register_worker(&server, "reregister-worker").await;
    assert_eq!(restarted.worker.id, worker.worker.id);
    assert_eq!(restarted.worker.status, WorkerStatus::Draining);
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query("update workers set status = 'offline' where id = ?")
        .bind(restarted.worker.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let renewed: LeaseResponse = worker_client(&restarted)
        .post(format!("{}/leases/{}/renew", server.base_url, lease.id))
        .json(&RenewLeaseRequest {
            lease_seconds: Some(3_600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(renewed.lease.expires_at <= request.hard_deadline);

    let heartbeat: WorkerResponse = worker_client(&restarted)
        .post(format!(
            "{}/workers/{}/heartbeat",
            server.base_url, restarted.worker.id
        ))
        .json(&WorkerHeartbeatRequest::default())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(heartbeat.worker.status, WorkerStatus::Draining);

    let another = create_provision_job(&server, "reregister-claim-sandbox").await;
    assert!(
        claim_provision_job(&server, &restarted, another.sandbox.id)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn postgres_terminalization_waits_for_drain_fence_publication() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start(database_url, None).await;
    let worker = register_worker(&server, "terminal-drain-race-worker").await;
    let sandbox = create_provision_job(&server, "terminal-drain-race-sandbox").await;
    let lease = claim_provision_job(&server, &worker, sandbox.sandbox.id)
        .await
        .unwrap();
    let shutdown_id = Uuid::new_v4();
    let hard_deadline = Utc::now() + ChronoDuration::seconds(30);
    let pool = AnyPoolOptions::new()
        .connect(&server.database_url)
        .await
        .unwrap();
    let mut drain_tx = pool.begin().await.unwrap();
    sqlx::query("update workers set status = 'draining' where id = $1")
        .bind(worker.worker.id.to_string())
        .execute(&mut *drain_tx)
        .await
        .unwrap();

    let terminal_client = worker_client(&worker);
    let terminal_url = format!("{}/leases/{}/complete", server.base_url, lease.id);
    let sandbox_id = sandbox.sandbox.id;
    let terminal = tokio::spawn(async move {
        terminal_client
            .post(terminal_url)
            .json(&CompleteLeaseRequest {
                result: Some(WorkerJobResult::ProvisionSandbox {
                    handle: ProviderSandboxHandle {
                        provider: "kubernetes".to_string(),
                        sandbox_id,
                        resources: provision_resources(sandbox_id),
                        metadata: serde_json::json!({}),
                    },
                }),
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !terminal.is_finished(),
        "terminal transition escaped the worker-row drain serialization lock"
    );

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "insert into worker_drain_receipts
         (shutdown_id, worker_id, tenant_id, hard_deadline, created_at)
         values ($1, $2, 'default', $3, $4)",
    )
    .bind(shutdown_id.to_string())
    .bind(worker.worker.id.to_string())
    .bind(hard_deadline.to_rfc3339())
    .bind(&now)
    .execute(&mut *drain_tx)
    .await
    .unwrap();
    sqlx::query(
        "insert into worker_drain_lease_fences
         (shutdown_id, lease_id, worker_id, job_id, attempt, hard_deadline)
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(shutdown_id.to_string())
    .bind(lease.id.to_string())
    .bind(worker.worker.id.to_string())
    .bind(lease.job_id.to_string())
    .bind(lease.attempt)
    .bind(hard_deadline.to_rfc3339())
    .execute(&mut *drain_tx)
    .await
    .unwrap();
    drain_tx.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), terminal)
        .await
        .expect("terminal transition remained blocked after drain commit")
        .unwrap();

    let row = sqlx::query(
        "select outcome, resolved_at from worker_drain_lease_fences
         where shutdown_id = $1 and lease_id = $2",
    )
    .bind(shutdown_id.to_string())
    .bind(lease.id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row.try_get::<Option<String>, _>("outcome")
            .unwrap()
            .as_deref(),
        Some("completed")
    );
    assert!(
        row.try_get::<Option<String>, _>("resolved_at")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn captured_leases_resolve_receipt_progress_when_they_finish_before_deadline() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("early-terminal.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let worker = register_worker(&server, "early-terminal-worker").await;
    let completed_sandbox = create_provision_job(&server, "completed-sandbox").await;
    let failed_sandbox = create_provision_job(&server, "failed-sandbox").await;
    let completed_lease = claim_provision_job(&server, &worker, completed_sandbox.sandbox.id)
        .await
        .unwrap();
    let failed_lease = claim_provision_job(&server, &worker, failed_sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };
    drain(&server, &worker, &request).await;

    worker_client(&worker)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, completed_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: completed_sandbox.sandbox.id,
                    resources: provision_resources(completed_sandbox.sandbox.id),
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    worker_client(&worker)
        .post(format!(
            "{}/leases/{}/fail",
            server.base_url, failed_lease.id
        ))
        .json(&FailLeaseRequest {
            error: "provider unavailable".to_string(),
            retry: true,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let replay = drain(&server, &worker, &request).await;
    let completed = replay
        .drain_receipt
        .leases
        .iter()
        .find(|fence| fence.lease_id == completed_lease.id)
        .unwrap();
    assert_eq!(completed.outcome.as_deref(), Some("completed"));
    assert!(completed.resolved_at.is_some());
    let failed = replay
        .drain_receipt
        .leases
        .iter()
        .find(|fence| fence.lease_id == failed_lease.id)
        .unwrap();
    assert_eq!(failed.outcome.as_deref(), Some("failed"));
    assert!(failed.resolved_at.is_some());
}

#[tokio::test]
async fn terminalizing_a_noncaptured_lease_does_not_resolve_the_receipt() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("noncaptured-terminal.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let draining_worker = register_worker(&server, "draining-worker").await;
    let other_worker = register_worker(&server, "other-worker").await;
    let captured_sandbox = create_provision_job(&server, "captured-sandbox").await;
    let other_sandbox = create_provision_job(&server, "other-sandbox").await;
    let captured = claim_provision_job(&server, &draining_worker, captured_sandbox.sandbox.id)
        .await
        .unwrap();
    let noncaptured = claim_provision_job(&server, &other_worker, other_sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(30),
    };
    drain(&server, &draining_worker, &request).await;

    worker_client(&other_worker)
        .post(format!(
            "{}/leases/{}/fail",
            server.base_url, noncaptured.id
        ))
        .json(&FailLeaseRequest {
            error: "unrelated failure".to_string(),
            retry: false,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let replay = drain(&server, &draining_worker, &request).await;
    let captured = replay
        .drain_receipt
        .leases
        .iter()
        .find(|fence| fence.lease_id == captured.id)
        .unwrap();
    assert!(captured.outcome.is_none());
    assert!(captured.resolved_at.is_none());
}

#[tokio::test]
async fn deadline_sweeper_resolves_the_exact_fenced_lease_and_records_receipt_progress() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("sweep.db").display());
    let server = TestServer::start_with_expiry_sweeper(database_url.clone(), Some(data_dir)).await;
    let worker = register_worker(&server, "sweep-worker").await;
    let sandbox = create_provision_job(&server, "sweep-sandbox").await;
    let lease = claim_provision_job(&server, &worker, sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(1),
    };
    drain(&server, &worker, &request).await;

    tokio::time::sleep(Duration::from_millis(2_500)).await;

    let pool = connect_database(&database_url).await;
    let lease_status: String = sqlx::query("select status from job_leases where id = ?")
        .bind(lease.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("status")
        .unwrap();
    assert_eq!(lease_status, "expired");
    let fence = sqlx::query(
        "select outcome, resolved_at from worker_drain_lease_fences where shutdown_id = ? and lease_id = ?",
    )
    .bind(request.shutdown_id.to_string())
    .bind(lease.id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fence.try_get::<String, _>("outcome").unwrap(), "expired");
    assert!(
        fence
            .try_get::<Option<String>, _>("resolved_at")
            .unwrap()
            .is_some()
    );
    let replay = drain(&server, &worker, &request).await;
    assert_eq!(
        replay.drain_receipt.leases[0].outcome.as_deref(),
        Some("expired")
    );
    assert!(replay.drain_receipt.leases[0].resolved_at.is_some());
}

#[tokio::test]
async fn deadline_sweeper_marks_a_stale_fence_without_mutating_different_authority() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("stale-fence.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url.clone(), Some(data_dir)).await;
    let worker = register_worker(&server, "stale-fence-worker").await;
    let sandbox = create_provision_job(&server, "stale-fence-sandbox").await;
    let lease = claim_provision_job(&server, &worker, sandbox.sandbox.id)
        .await
        .unwrap();
    let request = DrainWorkerRequest {
        shutdown_id: Uuid::new_v4(),
        hard_deadline: Utc::now() + ChronoDuration::seconds(1),
    };
    drain(&server, &worker, &request).await;

    // Model successor authority occupying the durable row after the receipt
    // was captured. The stale receipt must not expire this different tuple.
    let pool = connect_database(&database_url).await;
    sqlx::query("update job_leases set attempt = ?, expires_at = ? where id = ?")
        .bind(lease.attempt + 1)
        .bind((Utc::now() + ChronoDuration::minutes(5)).to_rfc3339())
        .bind(lease.id.to_string())
        .execute(&pool)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(2_500)).await;

    let row = sqlx::query(
        "select l.status, f.outcome from job_leases l
         join worker_drain_lease_fences f on f.lease_id = l.id
         where f.shutdown_id = ? and f.lease_id = ?",
    )
    .bind(request.shutdown_id.to_string())
    .bind(lease.id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "active");
    assert_eq!(row.try_get::<String, _>("outcome").unwrap(), "stale_fence");
}
