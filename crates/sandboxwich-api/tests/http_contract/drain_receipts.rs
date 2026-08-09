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
