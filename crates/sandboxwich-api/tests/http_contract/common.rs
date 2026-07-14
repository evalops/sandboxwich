use crate::auth::*;
use crate::desktop::*;
use crate::jobs::*;
use crate::metrics::*;
use crate::sandboxes::*;
use crate::snapshots::*;
use crate::types::*;
use crate::workers::*;
use reqwest::StatusCode;
use sandboxwich_core::*;
use sqlx::any::AnyPoolOptions;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

/// Default-tenant bearer token used by `TestServer::start*` helpers when no
/// explicit auth token is requested. The server is always started with real
/// authentication configured (SANDBOXWICH_TENANT_TOKENS covering this tenant
/// and `TEST_TENANT_B_TOKEN`) so that tests exercise the fail-closed auth
/// path rather than the removed "trust the client header" fallback.
pub(crate) const TEST_DEFAULT_TENANT_TOKEN: &str = "sandboxwich-test-default-tenant-token";
/// Bearer token for a second tenant ("tenant-b"), used to prove tenant
/// isolation via real credentials instead of a spoofable header.
pub(crate) const TEST_TENANT_B_TOKEN: &str = "sandboxwich-test-tenant-b-token";
/// Dedicated operator credential for `/snapshots/cleanup`, distinct from any
/// tenant token.
pub(crate) const TEST_OPERATOR_TOKEN: &str = "sandboxwich-test-operator-token";
/// Must match `OPERATOR_TOKEN_HEADER` in `sandboxwich-api::main`.
pub(crate) const OPERATOR_TOKEN_HEADER: &str = "x-sandboxwich-operator-token";

pub(crate) struct TestServer {
    pub(crate) base_url: String,
    /// The URL the spawned server process is actually connected to. For
    /// Postgres this is the uniquely named per-test database created by
    /// `isolate_postgres_test_database`, not the shared admin URL from
    /// `SANDBOXWICH_TEST_POSTGRES_URL`.
    pub(crate) database_url: String,
    pub(crate) child: Child,
    /// Bearer token that authenticates as the default tenant, if any auth is
    /// configured at all. `None` only for servers started with
    /// `start_with_no_auth_configured`, which deliberately leave both
    /// SANDBOXWICH_API_TOKEN and SANDBOXWICH_TENANT_TOKENS unset.
    pub(crate) auth_token: Option<String>,
    pub(crate) _data_dir: Option<TempDir>,
    /// Drops the uniquely named per-test Postgres database (best-effort) when
    /// the `TestServer` goes out of scope. `None` for SQLite-backed servers.
    pub(crate) _postgres_guard: Option<PostgresTestDatabaseGuard>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
pub(crate) async fn lifecycle_command_and_event_contracts_work_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-test.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    run_contract(server).await;
}

#[tokio::test]
pub(crate) async fn lifecycle_command_and_event_contracts_work_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };

    // `TestServer` transparently isolates this into its own uniquely named
    // database (see `isolate_postgres_test_database`) so this test can run
    // concurrently with any other Postgres-backed test without racing on
    // shared rows.
    let server = TestServer::start_with_expiry_sweeper(database_url, None).await;
    run_contract(server).await;
}

#[tokio::test]
pub(crate) async fn migrate_command_prepares_database_for_no_auto_migrate_server() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-migrate-test.db")
            .display()
    );

    let status = Command::new(env!("CARGO_BIN_EXE_sandboxwich-api"))
        .arg("migrate")
        .env("SANDBOXWICH_DATABASE_URL", &database_url)
        .status()
        .unwrap();
    assert!(status.success(), "migrate command failed: {status}");

    let server = TestServer::start_with_auto_migrate(database_url, Some(data_dir), false).await;
    let readiness: HealthResponse = reqwest::Client::new()
        .get(format!("{}/readyz", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(readiness.ok);
}

pub(crate) async fn run_contract(server: TestServer) {
    let client = server.client();

    let health: HealthResponse = client
        .get(format!("{}/healthz", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(health.ok);
    assert!(health.database.is_none());

    let readiness: HealthResponse = client
        .get(format!("{}/readyz", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(readiness.ok);
    assert!(readiness.database.unwrap().ok);

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            workspace_mode: None,
            name: Some("contract-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.sandbox.name, "contract-test");
    assert_eq!(created.sandbox.memory_limit, MemoryLimit::OneG);
    assert_eq!(created.sandbox.network_egress, NetworkEgress::DenyAll);
    assert_database_rejects_invalid_typed_values(
        &server.database_url,
        &created.sandbox.id.to_string(),
    )
    .await;
    assert_eq!(created.sandbox.tenant_id, "default");
    assert_tenant_boundaries_are_enforced(&client, &server, &created).await;
    let uploaded_file = assert_resource_tiers_and_file_contracts(&client, &server, &created).await;
    assert_metrics_are_exposed(&client, &server).await;

    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "k3s-worker-a".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::K8sPod,
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
            ],
            max_concurrent_jobs: Some(1),
            labels: [("cluster".to_string(), "k3s-dev".to_string())].into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(worker.worker.name, "k3s-worker-a");
    // GH-64: lease claim/renew/complete/fail/output and guest-health are
    // guest-facing and now reject tenant-wide tokens, so every call to one
    // of those routes on this worker's behalf below uses this instead of
    // `client`.
    let worker_client = worker_client(&worker);

    let heartbeat: WorkerResponse = worker_client
        .post(format!(
            "{}/workers/{}/heartbeat",
            server.base_url, worker.worker.id
        ))
        .json(&WorkerHeartbeatRequest {
            max_concurrent_jobs: None,
            labels: [("node".to_string(), "k3s-node-1".to_string())].into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(heartbeat.worker.last_heartbeat_at.is_some());

    let workers: WorkerListResponse = client
        .get(format!("{}/workers", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        workers
            .workers
            .iter()
            .any(|seen| seen.id == worker.worker.id)
    );
    assert_provision_job_persists_runtime_resources(&client, &server, &created, &worker).await;
    // Must run after the ProvisionSandbox lease above completes: guest-health
    // is guest-facing (GH-64) and now requires a worker-scoped token from a
    // worker that has actually completed a provision/fork lease for this
    // sandbox, which is what the call above just did.
    assert_guest_health_and_ssh_key_lifecycle(&client, &server, &created, &worker).await;
    assert_runtime_resource_reconcile_marks_missing_resources_deleted(
        &client, &server, &created, &worker,
    )
    .await;
    assert_failed_completion_rolls_back_lease_state(&client, &server, &created, &worker).await;

    // Tenant-boundary coverage creates another default-tenant sandbox before the worker exists.
    // Drain its automatically queued provision operation so later assertions can target their
    // own jobs deterministically.
    let pending: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    if let Some(lease) = pending.lease {
        assert_eq!(lease.job.kind, JobKind::ProvisionSandbox);
        let sandbox_id: SandboxId =
            serde_json::from_value(lease.job.payload["sandboxId"].clone()).unwrap();
        worker_client
            .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
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
    }

    let listed: SandboxListResponse = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.id == created.sandbox.id)
    );

    let command: QueueCommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["echo".to_string(), "hello".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: None,
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
    assert_eq!(command.command.argv, ["echo", "hello"]);
    assert_eq!(command.command.status, CommandStatus::Queued);
    let command_job = &command.queued_job;
    assert_eq!(command_job.sandbox_id, created.sandbox.id);
    assert_eq!(command_job.command_id, command.command.id);
    assert_eq!(command_job.kind, JobKind::RunCommand);
    assert_eq!(command_job.status, JobStatus::Queued);
    assert_eq!(
        command_job.required_capability,
        WorkerCapability::RunCommand
    );

    let jobs: JobListResponse = client
        .get(format!("{}/jobs", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let queued_job = job_for_command(&jobs.jobs, command.command.id);
    assert_eq!(queued_job.id, command_job.id);
    assert_eq!(queued_job.status, JobStatus::Queued);
    assert_eq!(
        queued_job.payload["provisionSpec"]["memory_limit"],
        serde_json::json!("1g")
    );
    assert_eq!(
        queued_job.payload["provisionSpec"]["network_egress"]["mode"],
        serde_json::json!("deny_all")
    );

    let claimed: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed.lease.expect("expected worker to claim command job");
    assert_eq!(lease.job.id, queued_job.id);
    assert_eq!(lease.job.status, JobStatus::Leased);

    let running_command: CommandResponse = client
        .get(format!(
            "{}/commands/{}",
            server.base_url, command.command.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(running_command.command.status, CommandStatus::Running);

    let output_operation_id = uuid::Uuid::now_v7();
    let first_chunk: sandboxwich_core::CommandOutputChunkResponse = worker_client
        .post(format!("{}/leases/{}/output", server.base_url, lease.id))
        .header("idempotency-key", output_operation_id.to_string())
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "hel".to_string(),
            annotations: vec![CommandOutputAnnotation::ContainerFileCitation {
                file_id: uploaded_file.file.id,
                path: uploaded_file.file.path.clone(),
                start_index: Some(0),
                end_index: Some(3),
            }],
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first_chunk.chunk.sequence, 1);
    assert_eq!(first_chunk.chunk.annotations.len(), 1);
    let replayed_chunk: sandboxwich_core::CommandOutputChunkResponse = worker_client
        .post(format!("{}/leases/{}/output", server.base_url, lease.id))
        .header("idempotency-key", output_operation_id.to_string())
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "hel".to_string(),
            annotations: Vec::new(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replayed_chunk.chunk.id, first_chunk.chunk.id);
    let second_chunk: sandboxwich_core::CommandOutputChunkResponse = worker_client
        .post(format!("{}/leases/{}/output", server.base_url, lease.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "lo\n".to_string(),
            annotations: Vec::new(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second_chunk.chunk.sequence, 2);
    let output_chunks: CommandOutputListResponse = client
        .get(format!(
            "{}/commands/{}/output",
            server.base_url, command.command.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(output_chunks.chunks.len(), 2);
    assert_eq!(output_chunks.chunks[0].chunk, "hel");
    assert_eq!(output_chunks.chunks[0].annotations.len(), 1);
    assert_eq!(output_chunks.chunks[1].chunk, "lo\n");

    let second_command: CommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["echo".to_string(), "second".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: None,
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
    assert_eq!(second_command.command.status, CommandStatus::Queued);

    let saturated_capacity: CapacityResponse = client
        .get(format!("{}/capacity", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let saturated_worker = saturated_capacity
        .workers
        .iter()
        .find(|capacity| capacity.worker_id == worker.worker.id)
        .expect("worker should have capacity row");
    assert_eq!(saturated_worker.max_concurrent_jobs, 1);
    assert_eq!(saturated_worker.active_leases, 1);
    assert_eq!(saturated_worker.available_slots, 0);

    let saturated_claim: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(saturated_claim.lease.is_none());

    let completed: LeaseResponse = worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(command_result("hello\n", "", 0)),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(completed.lease.job.status, JobStatus::Succeeded);

    let second_claimed: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_lease = second_claimed
        .lease
        .expect("worker should claim queued command after capacity frees");
    let second_completed: LeaseResponse = worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, second_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(command_result("second\n", "", 0)),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(second_completed.lease.job.status, JobStatus::Succeeded);

    let finished_command: CommandResponse = client
        .get(format!(
            "{}/commands/{}",
            server.base_url, command.command.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(finished_command.command.status, CommandStatus::Finished);
    assert_eq!(finished_command.command.stdout, "hello\n");
    let output_after_completion: CommandOutputListResponse = client
        .get(format!(
            "{}/commands/{}/output",
            server.base_url, command.command.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(output_after_completion.chunks.len(), 2);
    assert_eq!(output_after_completion.chunks[0].chunk, "hel");
    assert_eq!(output_after_completion.chunks[1].chunk, "lo\n");

    let commands: CommandListResponse = client
        .get(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        commands
            .commands
            .iter()
            .any(|seen| seen.id == command.command.id)
    );
    assert!(
        commands
            .commands
            .iter()
            .any(|seen| seen.id == second_command.command.id)
    );

    let fetched_command: CommandResponse = client
        .get(format!(
            "{}/commands/{}",
            server.base_url, command.command.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched_command.command.id, command.command.id);
    assert_eq!(fetched_command.command.status, CommandStatus::Finished);

    assert_retryable_failure_requeues_command(&client, &server, &created, &worker).await;
    assert_command_status_is_derived_from_exit_code(&client, &server, &created, &worker).await;
    assert_expired_lease_requeues_command(&client, &server, &created, &worker).await;
    assert_prompt_job_lifecycle(&client, &server, &created).await;
    assert_desktop_session_lifecycle(&client, &server, &created).await;
    assert_snapshot_fork_and_cleanup_lifecycle(&client, &server, &created, &worker).await;

    let stopped: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/stop",
            server.base_url, created.sandbox.id
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
        serde_json::to_value(stopped.sandbox.state).unwrap(),
        "archiving"
    );

    let stop_claim: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let stop_lease = stop_claim.lease.expect("stop must queue provider teardown");
    assert_eq!(stop_lease.job.kind, JobKind::StopSandbox);
    assert_eq!(stop_lease.job.payload["deleteGkeFqdnPolicy"], true);
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, stop_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                sandbox_id: created.sandbox.id,
                provider: "kubernetes".to_string(),
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let archived: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(archived.sandbox.state, SandboxState::Archived);

    let resumed = client
        .post(format!(
            "{}/sandboxes/{}/resume",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resumed.status(), StatusCode::NOT_IMPLEMENTED);

    assert_job_completion_does_not_resurrect_concurrently_archived_sandbox(
        &client, &server, &created,
    )
    .await;

    let events: EventListResponse = client
        .get(format!(
            "{}/sandboxes/{}/events",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(events.events.len() >= 5);
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::CommandOutput
            && event.data.get("commandId").and_then(|value| value.as_str())
                == Some(&command.command.id.to_string())
    }));

    let missing = client
        .get(format!(
            "{}/commands/00000000-0000-0000-0000-000000000000",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_slo_metrics_have_bounded_observations(&client, &server).await;
}

/// Polls `check` until it returns `Some`, or panics after a bounded wait. Used
/// for assertions on state produced by the background expiry sweeper, which is
/// no longer synchronous with any single request.
pub(crate) async fn poll_until<F, Fut, T>(mut check: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..100 {
        if let Some(value) = check().await {
            return Some(value);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

pub(crate) fn job_for_command(jobs: &[Job], command_id: CommandId) -> Job {
    jobs.iter()
        .find(|job| {
            job.kind == JobKind::RunCommand
                && job
                    .payload
                    .get("commandId")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<CommandId>(value).ok())
                    == Some(command_id)
        })
        .cloned()
        .expect("expected command job")
}

pub(crate) fn job_for_child_sandbox(jobs: &[Job], child_sandbox_id: &str) -> Job {
    jobs.iter()
        .find(|job| {
            job.payload
                .get("childSandboxId")
                .and_then(|value| value.as_str())
                == Some(child_sandbox_id)
        })
        .cloned()
        .expect("expected fork job")
}

pub(crate) fn job_for_snapshot(jobs: &[Job], snapshot_id: &str) -> Job {
    jobs.iter()
        .find(|job| {
            job.payload
                .get("snapshotId")
                .and_then(|value| value.as_str())
                == Some(snapshot_id)
                && job.kind == JobKind::CreateSnapshot
        })
        .cloned()
        .expect("expected snapshot job")
}

pub(crate) fn assert_no_access_url(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            assert!(
                !map.contains_key("access_url") && !map.contains_key("accessUrl"),
                "secret-bearing access URL leaked into durable metadata: {value}"
            );
            for value in map.values() {
                assert_no_access_url(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                assert_no_access_url(value);
            }
        }
        _ => {}
    }
}

pub(crate) fn command_result(stdout: &str, stderr: &str, exit_code: i32) -> WorkerJobResult {
    let now = chrono::Utc::now();
    WorkerJobResult::RunCommand {
        result: AgentCommandResult {
            exit_code: Some(exit_code),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            started_at: now,
            finished_at: now,
        },
    }
}

pub(crate) fn provision_resources(
    sandbox_id: sandboxwich_core::SandboxId,
) -> Vec<ProviderRuntimeResource> {
    vec![
        provider_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::PersistentVolumeClaim,
            RuntimeResourcePurpose::Workspace,
            format!("sandboxwich-pvc-{sandbox_id}"),
        ),
        provider_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Pod,
            RuntimeResourcePurpose::Runtime,
            format!("sandboxwich-{sandbox_id}"),
        ),
        provider_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Service,
            RuntimeResourcePurpose::Ssh,
            format!("sandboxwich-ssh-{sandbox_id}"),
        ),
        provider_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Service,
            RuntimeResourcePurpose::Desktop,
            format!("sandboxwich-desktop-{sandbox_id}"),
        ),
        provider_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::NetworkPolicy,
            RuntimeResourcePurpose::Network,
            format!("sandboxwich-egress-{sandbox_id}"),
        ),
    ]
}

pub(crate) fn fork_resources(
    sandbox_id: sandboxwich_core::SandboxId,
    source_snapshot_id: SnapshotId,
) -> Vec<ProviderRuntimeResource> {
    provision_resources(sandbox_id)
        .into_iter()
        .map(|mut resource| {
            if resource.resource_kind == RuntimeResourceKind::PersistentVolumeClaim {
                resource.source_snapshot_id = Some(source_snapshot_id);
            }
            resource
        })
        .collect()
}

pub(crate) fn snapshot_resources(
    sandbox_id: sandboxwich_core::SandboxId,
    snapshot_id: SnapshotId,
) -> Vec<ProviderRuntimeResource> {
    vec![provider_resource(
        sandbox_id,
        Some(snapshot_id),
        RuntimeResourceKind::VolumeSnapshot,
        RuntimeResourcePurpose::Snapshot,
        format!("sandboxwich-snapshot-{snapshot_id}"),
    )]
}

pub(crate) fn provider_resource(
    sandbox_id: sandboxwich_core::SandboxId,
    snapshot_id: Option<SnapshotId>,
    resource_kind: RuntimeResourceKind,
    purpose: RuntimeResourcePurpose,
    resource_name: String,
) -> ProviderRuntimeResource {
    let mut resource = ProviderRuntimeResource {
        sandbox_id,
        snapshot_id,
        provider: "kubernetes".to_string(),
        resource_kind,
        purpose,
        resource_name,
        namespace: "sandboxwich-contract".to_string(),
        status: RuntimeResourceStatus::Ready,
        cluster: Some("k3s-dev".to_string()),
        storage_class: Some("local-path".to_string()),
        snapshot_class: Some("local-path-snapshot".to_string()),
        storage_size: None,
        runtime_image: None,
        service_port: None,
        target_port: None,
        source_snapshot_id: None,
        ready_at: Some(chrono::Utc::now()),
        error: None,
    };

    match &resource.purpose {
        RuntimeResourcePurpose::Workspace => {
            resource.storage_size = Some("2Gi".to_string());
        }
        RuntimeResourcePurpose::Runtime => {
            resource.runtime_image =
                Some("ghcr.io/evalops/sandboxwich-ubuntu-dev:test".to_string());
        }
        RuntimeResourcePurpose::Ssh => {
            resource.service_port = Some(22);
            resource.target_port = Some("ssh".to_string());
        }
        RuntimeResourcePurpose::Desktop => {
            resource.service_port = Some(6080);
            resource.target_port = Some("desktop".to_string());
        }
        RuntimeResourcePurpose::Network => {}
        RuntimeResourcePurpose::Snapshot => {}
    }

    resource
}

/// Outcome of one bind-drop-spawn cycle in `try_spawn_once`.
pub(crate) enum SpawnAttempt {
    Healthy {
        base_url: String,
        child: Child,
    },
    /// The child exited early because another process won the race for the
    /// ephemeral port `try_spawn_once` picked, between our `drop(listener)`
    /// and the child's own bind a moment later. Retryable with a fresh port.
    LostBindRace(String),
    /// The child exited early, or never became healthy, for any other
    /// reason. Not retried -- surfaced immediately so a real startup bug
    /// fails fast instead of being masked behind retries.
    Failed(String),
}

/// The signature a bind failure leaves in the child's stderr when it loses
/// the ephemeral-port race `try_spawn_once` describes. Matched loosely
/// (case-insensitive substring, not an exact OS-error code) because the
/// exact wording differs slightly between Linux and macOS.
pub(crate) fn is_lost_bind_race(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("already in use")
}

/// Binds a fresh ephemeral port, drops the listener, and spawns the API
/// server process pointed at that port via `SANDBOXWICH_BIND`, then polls
/// `/healthz` until the server is up (or gives up).
///
/// This bind-then-drop-then-rebind sequence is an inherent TOCTOU: another
/// process on the machine can steal the port in the window between our
/// `drop(listener)` and the child's own bind. The usual fix -- bind once and
/// hand the already-bound `TcpListener` straight to the server, which
/// `axum::serve` accepts directly -- isn't available here, because
/// `TestServer` starts the API as a genuine child *process*
/// (`CARGO_BIN_EXE_sandboxwich-api`), not an in-process `axum::serve` task:
///
///   - Handing a bound socket across an `exec()` boundary means passing its
///     raw file descriptor (`from_raw_fd`/`fcntl`), which requires `unsafe`.
///     This workspace forbids `unsafe_code` outright
///     (`[workspace.lints.rust] unsafe_code = "forbid"` at the repo root,
///     with no existing `unsafe` anywhere to build on), so fd-passing isn't
///     an option.
///   - Running the server in-process instead would mean tearing out its
///     env-var-based bootstrap (`SANDBOXWICH_BIND`,
///     `SANDBOXWICH_DATABASE_URL`, ...), since concurrent `TestServer`s
///     inside the same test-binary process can't each set process-global
///     env vars without racing each other. That's a real redesign of the
///     server's startup, not a test-harness fix, and out of scope here.
///
/// So `spawn` below retries this whole cycle with a fresh port instead, but
/// only on the specific failure signature of a lost bind race -- see
/// `is_lost_bind_race`.
pub(crate) async fn try_spawn_once(
    database_url: &str,
    auto_migrate: bool,
    enable_sweeper: bool,
    configure: &impl Fn(&mut Command),
) -> SpawnAttempt {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = listener.local_addr().unwrap();
    drop(listener);

    let mut command = Command::new(env!("CARGO_BIN_EXE_sandboxwich-api"));
    command
        .env("SANDBOXWICH_DATABASE_URL", database_url)
        .env("SANDBOXWICH_BIND", bind.to_string())
        // Expiry sweeps (leases, snapshots, desktop sessions) now run on a
        // background interval instead of inline on every read request; run
        // it fast in tests so assertions that expect prompt expiry don't
        // need long sleeps, for the tests that opt into the sweeper below.
        .env("SANDBOXWICH_SWEEP_INTERVAL_MS", "25")
        // Disabled by default: most tests assert on synchronous
        // request/response behavior and don't want a background sweeper
        // mutating rows underneath them. Only `run_contract` (via
        // `start_with_expiry_sweeper`) asserts on sweep-driven expiry and
        // opts back in.
        .env(
            "SANDBOXWICH_DISABLE_EXPIRY_SWEEPER",
            if enable_sweeper { "false" } else { "true" },
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if !auto_migrate {
        command.env("SANDBOXWICH_AUTO_MIGRATE", "false");
    }
    configure(&mut command);
    let mut child = command.spawn().unwrap();

    // Drain stderr on a background thread as it's produced, so a failure
    // that writes more than the pipe buffer can't deadlock the child before
    // we get around to reading it.
    let stderr_reader = child.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            buf
        })
    });

    let base_url = format!("http://{bind}");
    // /healthz is a probe path exempt from auth in every mode, so no
    // credential is needed here regardless of how the server was
    // configured above.
    let health_client = reqwest::Client::new();
    for _ in 0..100 {
        if let Ok(response) = health_client
            .get(format!("{base_url}/healthz"))
            .send()
            .await
            && response.status().is_success()
        {
            return SpawnAttempt::Healthy { base_url, child };
        }
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = stderr_reader
                .and_then(|handle| handle.join().ok())
                .unwrap_or_default();
            return if is_lost_bind_race(&stderr) {
                SpawnAttempt::LostBindRace(format!(
                    "child exited with {status} after losing the ephemeral-port bind race \
                     for {bind}\nstderr:\n{stderr}"
                ))
            } else {
                SpawnAttempt::Failed(format!(
                    "server exited before becoming healthy: {status}\nstderr:\n{stderr}"
                ))
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = child.kill();
    let _ = child.wait();
    let stderr = stderr_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    SpawnAttempt::Failed(format!("server did not become healthy\nstderr:\n{stderr}"))
}

impl TestServer {
    /// Starts a server with real multi-tenant auth configured (the default
    /// tenant plus "tenant-b"), so every existing behavioral test continues
    /// to exercise an authenticated deployment rather than the removed
    /// header-trust fallback.
    pub(crate) async fn start(database_url: String, data_dir: Option<TempDir>) -> Self {
        Self::start_with_auth(database_url, data_dir, None).await
    }

    /// Like `start`, but leaves the background expiry sweeper running (see
    /// `SANDBOXWICH_DISABLE_EXPIRY_SWEEPER` in `spawn`) instead of the
    /// disabled-by-default test posture. `run_contract` exercises lease and
    /// desktop-session expiry that only happens via that background sweep;
    /// every other test asserts on synchronous request/response behavior and
    /// is better off with no background task mutating rows underneath it.
    pub(crate) async fn start_with_expiry_sweeper(
        database_url: String,
        data_dir: Option<TempDir>,
    ) -> Self {
        Self::start_with_auth_and_auto_migrate_and_sweeper(database_url, data_dir, None, true, true)
            .await
    }

    pub(crate) async fn start_with_auto_migrate(
        database_url: String,
        data_dir: Option<TempDir>,
        auto_migrate: bool,
    ) -> Self {
        Self::start_with_auth_and_auto_migrate(database_url, data_dir, None, auto_migrate).await
    }

    /// `auth_token: Some(token)` configures `SANDBOXWICH_API_TOKEN` (shared,
    /// single-tenant) mode with that exact token. `auth_token: None`
    /// configures `SANDBOXWICH_TENANT_TOKENS` (multi-tenant) mode with
    /// `TEST_DEFAULT_TENANT_TOKEN` and `TEST_TENANT_B_TOKEN`.
    pub(crate) async fn start_with_auth(
        database_url: String,
        data_dir: Option<TempDir>,
        auth_token: Option<&str>,
    ) -> Self {
        Self::start_with_auth_and_auto_migrate(database_url, data_dir, auth_token, true).await
    }

    pub(crate) async fn start_with_auth_and_auto_migrate(
        database_url: String,
        data_dir: Option<TempDir>,
        auth_token: Option<&str>,
        auto_migrate: bool,
    ) -> Self {
        Self::start_with_auth_and_auto_migrate_and_sweeper(
            database_url,
            data_dir,
            auth_token,
            auto_migrate,
            false,
        )
        .await
    }

    pub(crate) async fn start_with_auth_and_auto_migrate_and_sweeper(
        database_url: String,
        data_dir: Option<TempDir>,
        auth_token: Option<&str>,
        auto_migrate: bool,
        enable_sweeper: bool,
    ) -> Self {
        let default_tenant_token = auth_token
            .map(str::to_string)
            .unwrap_or_else(|| TEST_DEFAULT_TENANT_TOKEN.to_string());
        let resolved_auth_token = default_tenant_token.clone();
        Self::spawn(
            database_url,
            data_dir,
            auto_migrate,
            enable_sweeper,
            move |command| {
                if let Some(auth_token) = auth_token {
                    command.env("SANDBOXWICH_API_TOKEN", auth_token);
                } else {
                    command.env(
                        "SANDBOXWICH_TENANT_TOKENS",
                        format!("default={default_tenant_token},tenant-b={TEST_TENANT_B_TOKEN}"),
                    );
                }
                command.env("SANDBOXWICH_OPERATOR_TOKEN", TEST_OPERATOR_TOKEN);
            },
        )
        .await
        .with_auth_token(Some(resolved_auth_token))
    }

    /// Starts a server with neither `SANDBOXWICH_API_TOKEN` nor
    /// `SANDBOXWICH_TENANT_TOKENS` set, to prove the fail-closed behavior
    /// from issue #63: with no auth configured, the server must refuse every
    /// non-probe request rather than trusting a client-supplied
    /// `x-sandboxwich-tenant` header.
    pub(crate) async fn start_with_no_auth_configured(
        database_url: String,
        data_dir: Option<TempDir>,
    ) -> Self {
        Self::spawn(database_url, data_dir, true, false, |_command| {})
            .await
            .with_auth_token(None)
    }

    pub(crate) fn with_auth_token(mut self, auth_token: Option<String>) -> Self {
        self.auth_token = auth_token;
        self
    }

    pub(crate) async fn spawn(
        database_url: String,
        data_dir: Option<TempDir>,
        auto_migrate: bool,
        enable_sweeper: bool,
        configure: impl Fn(&mut Command),
    ) -> Self {
        // Transparent for SQLite (returns the URL unchanged, no guard). For
        // Postgres, carves out a uniquely named database on the same server
        // so this server's rows can never collide with another test's rows,
        // regardless of how many Postgres-backed `TestServer`s run
        // concurrently against the same `SANDBOXWICH_TEST_POSTGRES_URL`.
        let (database_url, postgres_guard) = isolate_postgres_test_database(database_url).await;

        // See `try_spawn_once` for why this retries on a lost bind race
        // instead of eliminating the TOCTOU window outright.
        const MAX_SPAWN_ATTEMPTS: u32 = 5;
        let mut last_bind_race: Option<String> = None;
        for _ in 0..MAX_SPAWN_ATTEMPTS {
            match try_spawn_once(&database_url, auto_migrate, enable_sweeper, &configure).await {
                SpawnAttempt::Healthy { base_url, child } => {
                    return Self {
                        base_url,
                        database_url,
                        child,
                        auth_token: None,
                        _data_dir: data_dir,
                        _postgres_guard: postgres_guard,
                    };
                }
                SpawnAttempt::LostBindRace(detail) => {
                    last_bind_race = Some(detail);
                }
                SpawnAttempt::Failed(detail) => panic!("{detail}"),
            }
        }

        panic!(
            "server never became healthy after {MAX_SPAWN_ATTEMPTS} attempts, each time losing \
             the ephemeral-port bind race: {}",
            last_bind_race.unwrap_or_else(|| "<no attempts recorded>".to_string())
        );
    }

    /// A client that authenticates as the default tenant when the server has
    /// auth configured (i.e. wasn't started via
    /// `start_with_no_auth_configured`), and an unauthenticated client
    /// otherwise.
    pub(crate) fn client(&self) -> reqwest::Client {
        match &self.auth_token {
            Some(token) => {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {token}").parse().unwrap(),
                );
                reqwest::Client::builder()
                    .default_headers(headers)
                    .build()
                    .unwrap()
            }
            None => reqwest::Client::new(),
        }
    }
}

/// A client authenticated with `worker`'s scoped credential (see GH-64),
/// returned once by `POST /workers/register`. Guest-facing routes -- lease
/// claim/renew/complete/fail/output and guest-health -- now reject
/// tenant-wide tokens outright, so every test that exercises those routes on
/// behalf of a specific worker must use this instead of `TestServer::client`.
pub(crate) fn worker_client(worker: &WorkerResponse) -> reqwest::Client {
    let token = worker
        .worker_token
        .as_deref()
        .expect("register_worker response must include a worker-scoped token (see GH-64)");
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

/// Drops the uniquely named per-test Postgres database created by
/// `isolate_postgres_test_database` when the owning `TestServer` goes out of
/// scope.
///
/// Best-effort only: `Drop` can't be async, and this is the difference
/// between a passing test suite with a handful of leftover empty databases in
/// a throwaway CI Postgres container versus a hang, so failures here are
/// swallowed rather than propagated.
pub(crate) struct PostgresTestDatabaseGuard {
    /// The original `SANDBOXWICH_TEST_POSTGRES_URL`-style URL, used to open
    /// an admin connection capable of dropping the per-test database.
    pub(crate) admin_url: String,
    pub(crate) database_name: String,
}

impl Drop for PostgresTestDatabaseGuard {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let database_name = self.database_name.clone();
        // Run the teardown on a dedicated OS thread with its own throwaway
        // Tokio runtime. We can't `.await` inside `Drop`, and blocking on the
        // runtime that's already driving the current test (e.g. via
        // `Handle::current().block_on`) panics because it would nest
        // runtimes. A brand new runtime on a brand new thread sidesteps both
        // problems; joining it keeps cleanup synchronous with the rest of
        // `Drop` without leaking a dangling thread.
        let teardown = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok(pool) = sqlx::any::AnyPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                else {
                    return;
                };
                // `WITH (FORCE)` (Postgres 13+; the CI service runs 17) drops
                // the database even if the just-killed server process hasn't
                // finished tearing down its connections yet.
                let _ = sqlx::query(&format!(
                    r#"drop database if exists "{database_name}" with (force)"#
                ))
                .execute(&pool)
                .await;
            });
        });
        let _ = teardown.join();
    }
}

/// If `database_url` looks like a Postgres URL, provisions a uniquely named
/// database on the same server and returns a URL pointing at it, plus a
/// guard that drops that database (best-effort) on teardown.
///
/// `SANDBOXWICH_TEST_POSTGRES_URL` points every Postgres-backed test at one
/// shared, already-existing admin database. If every `TestServer` connected
/// its spawned API process directly to that URL, concurrent
/// Postgres-backed tests (and each server's own background expiry sweeper,
/// see `SANDBOXWICH_DISABLE_EXPIRY_SWEEPER`) would mutate the same rows.
/// Instead, connect to the admin URL (any existing database on a Postgres
/// cluster can issue `CREATE DATABASE`) to create a fresh, empty database
/// per `TestServer`, and point the spawned process at that instead; it runs
/// its own migrations at startup exactly as it would against any other empty
/// database.
///
/// SQLite URLs pass through unchanged with no guard, so SQLite-backed tests
/// are unaffected.
pub(crate) async fn isolate_postgres_test_database(
    database_url: String,
) -> (String, Option<PostgresTestDatabaseGuard>) {
    if !database_url.starts_with("postgres:") && !database_url.starts_with("postgresql:") {
        return (database_url, None);
    }

    sqlx::any::install_default_drivers();
    let admin_pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to SANDBOXWICH_TEST_POSTGRES_URL to provision a per-test database");

    // `Uuid::now_v7().simple()` renders as 32 lowercase hex characters with no
    // hyphens, so the resulting identifier needs no quoting concerns beyond
    // wrapping it in double quotes defensively.
    let database_name = format!("sandboxwich_test_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(r#"create database "{database_name}""#))
        .execute(&admin_pool)
        .await
        .expect("create per-test Postgres database");
    drop(admin_pool);

    let per_test_url = replace_postgres_database_name(&database_url, &database_name);
    (
        per_test_url,
        Some(PostgresTestDatabaseGuard {
            admin_url: database_url,
            database_name,
        }),
    )
}

/// Swaps the path segment (database name) of a Postgres connection URL,
/// preserving any query string (e.g. `?sslmode=disable`).
pub(crate) fn replace_postgres_database_name(database_url: &str, database_name: &str) -> String {
    let (base, query) = match database_url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (database_url, None),
    };
    let last_slash = base
        .rfind('/')
        .expect("Postgres URL is expected to contain a path segment (database name)");
    let mut url = format!("{}/{database_name}", &base[..last_slash]);
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    url
}
