use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::StatusCode;
use sandboxwich_core::{
    AgentCommandResult, AppendCommandOutputRequest, CapacityResponse, ClaimLeaseRequest,
    ClaimLeaseResponse, CleanupRunStatus, CommandListResponse, CommandOutputListResponse,
    CommandOutputStream, CommandRequest, CommandResponse, CommandStatus, CompleteLeaseRequest,
    CreateDesktopSessionRequest, CreateJobRequest, CreateSandboxRequest, CreateSnapshotRequest,
    DesktopAccessMode, DesktopAccessRequest, DesktopAccessResponse, DesktopSessionListResponse,
    DesktopSessionResponse, DesktopSessionStatus, EventListResponse, FailLeaseRequest,
    GuestHealthResponse, GuestStatus, HealthResponse, Job, JobKind, JobListResponse, JobResponse,
    JobStatus, LeaseResponse, PromptQueuedResponse, PromptRequest, ProviderForkHandle,
    ProviderRuntimeResource, ProviderSandboxHandle, ProviderSnapshotHandle,
    ReconcileRuntimeResourcesRequest, ReconcileRuntimeResourcesResponse, RegisterWorkerRequest,
    RequestSshKeyRequest, RuntimeResourceKind, RuntimeResourceListResponse, RuntimeResourcePurpose,
    RuntimeResourceStatus, SandboxEventKind, SandboxListResponse, SandboxResponse, SandboxState,
    SnapshotCleanupResponse, SnapshotId, SnapshotListResponse, SnapshotResponse, SnapshotStatus,
    SshAccessRequest, SshAccessResponse, SshKeyListResponse, SshKeyResponse, SshKeyStatus,
    UpdateDesktopSessionRequest, UpdateGuestHealthRequest, UpdateSshKeyStatusRequest,
    WorkerCapability, WorkerHeartbeatRequest, WorkerJobResult, WorkerListResponse, WorkerResponse,
};
use sqlx::any::AnyPoolOptions;
use tempfile::TempDir;
use uuid::Uuid;

struct TestServer {
    base_url: String,
    database_url: String,
    child: Child,
    _data_dir: Option<TempDir>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn lifecycle_command_and_event_contracts_work_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-test.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    run_contract(server).await;
}

#[tokio::test]
async fn lifecycle_command_and_event_contracts_work_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };

    let server = TestServer::start(database_url, None).await;
    run_contract(server).await;
}

#[tokio::test]
async fn api_token_is_required_when_configured() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-auth-test.db").display()
    );
    let server =
        TestServer::start_with_auth(database_url, Some(data_dir), Some("test-token")).await;
    let client = reqwest::Client::new();

    let missing = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let ready_without_token: HealthResponse = client
        .get(format!("{}/readyz", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ready_without_token.ok);

    let metrics_without_token = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics_without_token.status(), StatusCode::UNAUTHORIZED);

    let authorized: SandboxListResponse = client
        .get(format!("{}/sandboxes", server.base_url))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(authorized.ok);
}

async fn run_contract(server: TestServer) {
    let client = reqwest::Client::new();

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
            name: Some("contract-test".to_string()),
            template: None,
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
    assert_database_rejects_invalid_typed_values(
        &server.database_url,
        &created.sandbox.id.to_string(),
    )
    .await;
    assert_eq!(created.sandbox.tenant_id, "default");
    assert_tenant_boundaries_are_enforced(&client, &server, &created).await;
    assert_metrics_are_exposed(&client, &server).await;
    assert_guest_health_and_ssh_key_lifecycle(&client, &server, &created).await;

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

    let heartbeat: WorkerResponse = client
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
    assert_runtime_resource_reconcile_marks_missing_resources_deleted(
        &client, &server, &created, &worker,
    )
    .await;
    assert_failed_completion_rolls_back_lease_state(&client, &server, &created, &worker).await;

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

    let command: CommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["echo".to_string(), "hello".to_string()],
            cwd: None,
            env: Default::default(),
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
    let queued_job = job_for_command(&jobs.jobs, &command.command.id.to_string());
    assert_eq!(queued_job.status, JobStatus::Queued);

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
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

    let first_chunk: sandboxwich_core::CommandOutputChunkResponse = client
        .post(format!("{}/leases/{}/output", server.base_url, lease.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "hel".to_string(),
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
    let second_chunk: sandboxwich_core::CommandOutputChunkResponse = client
        .post(format!("{}/leases/{}/output", server.base_url, lease.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "lo\n".to_string(),
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

    let saturated_claim: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
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

    let completed: LeaseResponse = client
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

    let second_claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
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
    let second_completed: LeaseResponse = client
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
        "archived"
    );

    let resumed: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/resume",
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
        serde_json::to_value(resumed.sandbox.state).unwrap(),
        "ready"
    );

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
}

async fn assert_tenant_boundaries_are_enforced(
    client: &reqwest::Client,
    server: &TestServer,
    default_sandbox: &SandboxResponse,
) {
    let tenant_sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .header("x-sandboxwich-tenant", "tenant-b")
        .json(&CreateSandboxRequest {
            name: Some("tenant-b-sandbox".to_string()),
            template: None,
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
    assert_eq!(tenant_sandbox.sandbox.tenant_id, "tenant-b");

    let default_list: SandboxListResponse = client
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
        default_list
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.id == default_sandbox.sandbox.id)
    );
    assert!(
        default_list
            .sandboxes
            .iter()
            .all(|sandbox| sandbox.id != tenant_sandbox.sandbox.id)
    );

    let hidden = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, tenant_sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

    let tenant_list: SandboxListResponse = client
        .get(format!("{}/sandboxes", server.base_url))
        .header("x-sandboxwich-tenant", "tenant-b")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        tenant_list
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.id == tenant_sandbox.sandbox.id)
    );
    assert!(
        tenant_list
            .sandboxes
            .iter()
            .all(|sandbox| sandbox.id != default_sandbox.sandbox.id)
    );
}

async fn assert_metrics_are_exposed(client: &reqwest::Client, server: &TestServer) {
    let metrics = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("# TYPE sandboxwich_sandboxes_total gauge"));
    assert!(metrics.contains("sandboxwich_sandboxes_total{state=\"ready\"}"));
    assert!(metrics.contains("sandboxwich_worker_capacity_slots"));
}

async fn assert_guest_health_and_ssh_key_lifecycle(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
) {
    let default_health: GuestHealthResponse = client
        .get(format!(
            "{}/sandboxes/{}/guest-health",
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
    assert_eq!(default_health.guest_health.status, GuestStatus::Pending);

    let ready_health: GuestHealthResponse = client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/test".to_string()),
            checks: Some(serde_json::json!({
                "exec": {"status": "ok"},
                "ssh": {
                    "host": "127.0.0.1",
                    "port": 2222,
                    "username": "ubuntu"
                }
            })),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ready_health.guest_health.status, GuestStatus::Ready);

    let requested_key: SshKeyResponse = client
        .post(format!(
            "{}/sandboxes/{}/ssh-keys",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&RequestSshKeyRequest {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest sandboxwich".to_string(),
            principal: Some("tester".to_string()),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(requested_key.ssh_key.status, SshKeyStatus::Requested);

    let applied_key: SshKeyResponse = client
        .post(format!(
            "{}/ssh-keys/{}/status",
            server.base_url, requested_key.ssh_key.id
        ))
        .json(&UpdateSshKeyStatusRequest {
            status: SshKeyStatus::Applied,
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(applied_key.ssh_key.status, SshKeyStatus::Applied);
    assert!(applied_key.ssh_key.applied_at.is_some());

    let keys: SshKeyListResponse = client
        .get(format!(
            "{}/sandboxes/{}/ssh-keys",
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
    assert!(
        keys.ssh_keys
            .iter()
            .any(|seen| seen.id == requested_key.ssh_key.id)
    );

    let ssh_access: SshAccessResponse = client
        .post(format!(
            "{}/sandboxes/{}/ssh-access",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&SshAccessRequest {
            principal: Some("tester".to_string()),
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ssh_access.ssh_access.host, "127.0.0.1");
    assert_eq!(ssh_access.ssh_access.port, 2222);
    assert_eq!(ssh_access.ssh_access.username, "ubuntu");
    assert_eq!(
        ssh_access.ssh_access.command,
        "ssh -p 2222 ubuntu@127.0.0.1"
    );
    assert_eq!(ssh_access.ssh_access.scp_command_prefix, "scp -P 2222");
}

async fn assert_provision_job_persists_runtime_resources(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let queued: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::ProvisionSandbox,
            payload: serde_json::json!({
                "sandboxId": sandbox.sandbox.id
            }),
            required_capability: WorkerCapability::ProvisionSandbox,
            priority: Some(10),
            max_attempts: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(queued.job.status, JobStatus::Queued);

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed
        .lease
        .expect("expected worker to claim provision job");
    assert_eq!(lease.job.id, queued.job.id);

    let completed: LeaseResponse = client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sandbox.sandbox.id,
                    resources: provision_resources(sandbox.sandbox.id),
                    metadata: serde_json::json!({
                        "diagnostic": "provider metadata is not the durable runtime source"
                    }),
                },
            }),
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

    let resources: RuntimeResourceListResponse = client
        .get(format!(
            "{}/sandboxes/{}/runtime-resources",
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
    assert!(resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Pod
            && resource.purpose == RuntimeResourcePurpose::Runtime
            && resource.runtime_image.as_deref()
                == Some("ghcr.io/evalops/sandboxwich-ubuntu-dev:test")
    }));
    assert!(resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::PersistentVolumeClaim
            && resource.purpose == RuntimeResourcePurpose::Workspace
            && resource.storage_size.as_deref() == Some("2Gi")
    }));
    assert!(resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Service
            && resource.purpose == RuntimeResourcePurpose::Ssh
            && resource.service_port == Some(22)
    }));
}

async fn assert_failed_completion_rolls_back_lease_state(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let queued: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::ProvisionSandbox,
            payload: serde_json::json!({
                "sandboxId": sandbox.sandbox.id
            }),
            required_capability: WorkerCapability::ProvisionSandbox,
            priority: Some(9),
            max_attempts: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed
        .lease
        .expect("expected worker to claim rollback probe job");
    assert_eq!(lease.job.id, queued.job.id);

    let mut resources = provision_resources(sandbox.sandbox.id);
    resources[0].provider = String::new();
    let rejected = client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sandbox.sandbox.id,
                    resources,
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let failed: LeaseResponse = client
        .post(format!("{}/leases/{}/fail", server.base_url, lease.id))
        .json(&FailLeaseRequest {
            error: "rollback probe".to_string(),
            retry: false,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(failed.lease.job.status, JobStatus::Failed);
}

async fn assert_runtime_resource_reconcile_marks_missing_resources_deleted(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let mut observed = provision_resources(sandbox.sandbox.id);
    observed.retain(|resource| {
        resource.resource_kind != RuntimeResourceKind::Service
            || resource.purpose == RuntimeResourcePurpose::Ssh
    });
    let reconciled: ReconcileRuntimeResourcesResponse = client
        .post(format!(
            "{}/workers/{}/runtime-resources/reconcile",
            server.base_url, worker.worker.id
        ))
        .json(&ReconcileRuntimeResourcesRequest {
            provider: "kubernetes".to_string(),
            namespace: "sandboxwich-contract".to_string(),
            cluster: Some("k3s-dev".to_string()),
            resources: observed,
            mark_missing_deleted: true,
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
    assert_eq!(reconciled.upserted.len(), 3);
    assert!(reconciled.upserted.iter().all(|resource| {
        resource.observed_at.is_some() && resource.last_reconciled_at.is_some()
    }));
    assert!(reconciled.deleted.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Service
            && resource.purpose == RuntimeResourcePurpose::Desktop
            && resource.status == RuntimeResourceStatus::Deleted
            && resource.deleted_at.is_some()
    }));

    let resources: RuntimeResourceListResponse = client
        .get(format!(
            "{}/sandboxes/{}/runtime-resources",
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
    assert!(resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Service
            && resource.purpose == RuntimeResourcePurpose::Desktop
            && resource.status == RuntimeResourceStatus::Deleted
    }));

    let mut edge_observed = provision_resources(sandbox.sandbox.id);
    for resource in &mut edge_observed {
        resource.cluster = Some("k3s-edge".to_string());
    }
    let edge_reconciled: ReconcileRuntimeResourcesResponse = client
        .post(format!(
            "{}/workers/{}/runtime-resources/reconcile",
            server.base_url, worker.worker.id
        ))
        .json(&ReconcileRuntimeResourcesRequest {
            provider: "kubernetes".to_string(),
            namespace: "sandboxwich-contract".to_string(),
            cluster: Some("k3s-edge".to_string()),
            resources: edge_observed,
            mark_missing_deleted: false,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(edge_reconciled.upserted.len(), 4);
    assert!(
        edge_reconciled
            .upserted
            .iter()
            .all(|resource| resource.cluster.as_deref() == Some("k3s-edge"))
    );

    let resources: RuntimeResourceListResponse = client
        .get(format!(
            "{}/sandboxes/{}/runtime-resources",
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
    assert!(resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Pod
            && resource.cluster.as_deref() == Some("k3s-dev")
            && resource.status == RuntimeResourceStatus::Ready
    }));
    assert!(resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Pod
            && resource.cluster.as_deref() == Some("k3s-edge")
            && resource.status == RuntimeResourceStatus::Ready
    }));
}

async fn assert_retryable_failure_requeues_command(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let command: CommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["false".to_string()],
            cwd: None,
            env: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed.lease.expect("expected retry test lease");
    let failed: LeaseResponse = client
        .post(format!("{}/leases/{}/fail", server.base_url, lease.id))
        .json(&FailLeaseRequest {
            error: "temporary failure".to_string(),
            retry: true,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(failed.lease.job.status, JobStatus::Queued);

    let fetched: CommandResponse = client
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
    assert_eq!(fetched.command.status, CommandStatus::Queued);

    let claimed_again: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let retry_lease = claimed_again.lease.expect("expected retry lease");
    assert_eq!(retry_lease.job.id, lease.job.id);
    let completed: LeaseResponse = client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, retry_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(command_result("retried\n", "", 0)),
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
}

async fn assert_expired_lease_requeues_command(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let command: CommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["sleep".to_string(), "1".to_string()],
            cwd: None,
            env: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(0),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(claimed.lease.is_some());

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
    let expired_job = job_for_command(&jobs.jobs, &command.command.id.to_string());
    assert_eq!(expired_job.status, JobStatus::Queued);

    let fetched: CommandResponse = client
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
    assert_eq!(fetched.command.status, CommandStatus::Queued);
}

async fn assert_prompt_job_lifecycle(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
) {
    let prompt_worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "prompt-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::AgentPrompt],
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

    let prompt: PromptQueuedResponse = client
        .post(format!(
            "{}/sandboxes/{}/prompt",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&PromptRequest {
            instructions: "summarize the workspace".to_string(),
            engine: Some("dry-run".to_string()),
            model: None,
            effort: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prompt.event.kind, SandboxEventKind::PromptQueued);

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
    let prompt_job = job_for_prompt(&jobs.jobs, &prompt.event.id.to_string());
    assert_eq!(prompt_job.status, JobStatus::Queued);

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, prompt_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed
        .lease
        .expect("expected prompt worker to claim prompt job");
    assert_eq!(lease.job.id, prompt_job.id);

    let completed: LeaseResponse = client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::RunPrompt {
                output: "workspace summary".to_string(),
            }),
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
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::PromptStarted
            && event
                .data
                .get("promptEventId")
                .and_then(|value| value.as_str())
                == Some(&prompt.event.id.to_string())
    }));
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::PromptFinished
            && event
                .data
                .get("promptEventId")
                .and_then(|value| value.as_str())
                == Some(&prompt.event.id.to_string())
    }));
}

async fn assert_desktop_session_lifecycle(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
) {
    let rejected_secret_url = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: Some("https://broker.example.test/connect?token=secret".to_string()),
            access_mode: Some(DesktopAccessMode::Browser),
            connection_metadata: None,
            ttl_seconds: Some(300),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(rejected_secret_url.status(), StatusCode::BAD_REQUEST);

    let desktop: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: Some("https://broker.example.test".to_string()),
            access_mode: Some(DesktopAccessMode::Browser),
            connection_metadata: Some(serde_json::json!({
                "cluster": "k3s-dev",
                "namespace": "sandboxwich-contract",
                "service": "novnc"
            })),
            ttl_seconds: Some(600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        desktop.desktop_session.status,
        DesktopSessionStatus::Pending
    );
    assert_eq!(desktop.desktop_session.sandbox_id, sandbox.sandbox.id);

    let discovery: DesktopSessionListResponse = client
        .get(format!(
            "{}/sandboxes/{}/desktop",
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
    assert!(discovery.desktop_sessions.iter().any(|seen| {
        seen.id == desktop.desktop_session.id && seen.status == DesktopSessionStatus::Pending
    }));
    assert_no_access_url(&serde_json::to_value(&discovery).unwrap());

    let not_ready = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(not_ready.status(), StatusCode::BAD_REQUEST);

    let ready: DesktopSessionResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/status",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&UpdateDesktopSessionRequest {
            status: DesktopSessionStatus::Ready,
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: Some(serde_json::json!({
                "cluster": "k3s-dev",
                "namespace": "sandboxwich-contract",
                "service": "novnc",
                "pod": "desktop-a"
            })),
            ttl_seconds: Some(600),
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ready.desktop_session.status, DesktopSessionStatus::Ready);

    let fetched: DesktopSessionResponse = client
        .get(format!(
            "{}/desktop-sessions/{}",
            server.base_url, desktop.desktop_session.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched.desktop_session.id, desktop.desktop_session.id);
    assert_no_access_url(&serde_json::to_value(&fetched).unwrap());

    let access: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(access.access.session_id, desktop.desktop_session.id);
    assert_eq!(access.access.access_mode, DesktopAccessMode::Browser);
    assert!(
        access
            .access
            .access_url
            .starts_with("https://broker.example.test/sessions/")
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
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::DesktopRequested
            && event
                .data
                .get("desktopSessionId")
                .and_then(|value| value.as_str())
                == Some(&desktop.desktop_session.id.to_string())
    }));
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::DesktopReady
            && event
                .data
                .get("desktopSessionId")
                .and_then(|value| value.as_str())
                == Some(&desktop.desktop_session.id.to_string())
    }));
    for event in &events.events {
        assert_no_access_url(&event.data);
    }

    let expiring: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: None,
            access_mode: Some(DesktopAccessMode::Vnc),
            connection_metadata: None,
            ttl_seconds: Some(0),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let discovered: DesktopSessionListResponse = client
        .get(format!(
            "{}/sandboxes/{}/desktop-sessions",
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
    assert!(discovered.desktop_sessions.iter().any(|seen| {
        seen.id == expiring.desktop_session.id && seen.status == DesktopSessionStatus::Expired
    }));
}

async fn assert_snapshot_fork_and_cleanup_lifecycle(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let snapshot_worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "k3s-snapshot-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::Snapshot],
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

    let snapshot: SnapshotResponse = client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateSnapshotRequest {
            label: Some("contract-snapshot".to_string()),
            inventory: Some(serde_json::json!({"paths": []})),
            provider_metadata: Some(serde_json::json!({"provider": "contract"})),
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
    assert_eq!(snapshot.snapshot.status, SnapshotStatus::Pending);
    assert_eq!(snapshot.snapshot.sandbox_id, sandbox.sandbox.id);

    let snapshot_claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let snapshot_lease = snapshot_claimed
        .lease
        .expect("expected snapshot worker to claim manual snapshot job");
    assert_eq!(snapshot_lease.job.kind, JobKind::CreateSnapshot);
    let snapshot_id = snapshot.snapshot.id.to_string();
    assert_eq!(
        snapshot_lease
            .job
            .payload
            .get("snapshotId")
            .and_then(|value| value.as_str()),
        Some(snapshot_id.as_str())
    );
    let completed_snapshot: LeaseResponse = client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, snapshot_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::CreateSnapshot {
                handle: ProviderSnapshotHandle {
                    provider: "kubernetes".to_string(),
                    snapshot_id: snapshot.snapshot.id,
                    resources: snapshot_resources(sandbox.sandbox.id, snapshot.snapshot.id),
                    metadata: serde_json::json!({
                        "cluster": "k3s-dev",
                        "namespace": "sandboxwich-contract"
                    }),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(completed_snapshot.lease.job.status, JobStatus::Succeeded);

    let fetched_snapshot: SnapshotResponse = client
        .get(format!(
            "{}/snapshots/{}",
            server.base_url, snapshot.snapshot.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched_snapshot.snapshot.id, snapshot.snapshot.id);
    assert_eq!(fetched_snapshot.snapshot.status, SnapshotStatus::Ready);

    let snapshots: SnapshotListResponse = client
        .get(format!(
            "{}/sandboxes/{}/snapshots",
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
    assert!(
        snapshots
            .snapshots
            .iter()
            .any(|seen| seen.id == snapshot.snapshot.id)
    );

    let expiring: SnapshotResponse = client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateSnapshotRequest {
            label: Some("expires-now".to_string()),
            inventory: None,
            provider_metadata: None,
            ttl_seconds: Some(0),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let cleanup: SnapshotCleanupResponse = client
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        cleanup
            .expired
            .iter()
            .any(|seen| seen.id == expiring.snapshot.id)
    );
    assert_eq!(cleanup.cleanup_run.status, CleanupRunStatus::Succeeded);
    assert!(cleanup.cleanup_run.finished_at.is_some());
    assert!(cleanup.cleanup_run.expired_snapshots >= 1);

    let archived: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("cleanup-me".to_string()),
            template: None,
            ttl_seconds: Some(0),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_provision_job_persists_runtime_resources(client, server, &archived, worker).await;
    client
        .post(format!(
            "{}/sandboxes/{}/stop",
            server.base_url, archived.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let cleanup: SnapshotCleanupResponse = client
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(cleanup.archived_sandboxes_deleted >= 1);
    assert!(cleanup.cleanup_run.archived_sandboxes_deleted >= 1);
    assert!(
        cleanup
            .archived_sandboxes
            .iter()
            .any(|seen| seen.id == archived.sandbox.id)
    );
    assert!(cleanup.runtime_resources_deleted.iter().any(|resource| {
        resource.sandbox_id == archived.sandbox.id
            && resource.status == RuntimeResourceStatus::Deleted
    }));
    assert!(cleanup.cleanup_run.runtime_resources_deleted >= 1);
    let missing_archived = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, archived.sandbox.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_archived.status(), StatusCode::NOT_FOUND);

    let forked: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/fork",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateSandboxRequest {
            name: Some("contract-child".to_string()),
            template: None,
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
    assert_eq!(forked.sandbox.state, SandboxState::Planning);
    let fork_snapshot_id = forked
        .sandbox
        .parent_snapshot_id
        .expect("fork should point at a real snapshot");

    let parent_snapshots: SnapshotListResponse = client
        .get(format!(
            "{}/sandboxes/{}/snapshots",
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
    assert!(
        parent_snapshots
            .snapshots
            .iter()
            .any(|seen| { seen.id == fork_snapshot_id && seen.status == SnapshotStatus::Pending })
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
    let fork_snapshot_job = job_for_snapshot(&jobs.jobs, &fork_snapshot_id.to_string());
    assert_eq!(fork_snapshot_job.kind, JobKind::CreateSnapshot);
    assert_eq!(fork_snapshot_job.status, JobStatus::Queued);

    let claimed_snapshot: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let snapshot_lease = claimed_snapshot
        .lease
        .expect("expected snapshot worker to claim fork snapshot job");
    assert_eq!(snapshot_lease.job.id, fork_snapshot_job.id);

    let completed_fork_snapshot: LeaseResponse = client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, snapshot_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::CreateSnapshot {
                handle: ProviderSnapshotHandle {
                    provider: "kubernetes".to_string(),
                    snapshot_id: fork_snapshot_id,
                    resources: snapshot_resources(sandbox.sandbox.id, fork_snapshot_id),
                    metadata: serde_json::json!({
                        "cluster": "k3s-dev",
                        "namespace": "sandboxwich-contract"
                    }),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        completed_fork_snapshot.lease.job.status,
        JobStatus::Succeeded
    );

    let parent_snapshots: SnapshotListResponse = client
        .get(format!(
            "{}/sandboxes/{}/snapshots",
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
    assert!(
        parent_snapshots
            .snapshots
            .iter()
            .any(|seen| { seen.id == fork_snapshot_id && seen.status == SnapshotStatus::Ready })
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
    let fork_job = job_for_child_sandbox(&jobs.jobs, &forked.sandbox.id.to_string());
    assert_eq!(fork_job.status, JobStatus::Queued);

    let claimed: ClaimLeaseResponse = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed
        .lease
        .expect("expected snapshot worker to claim fork job");
    assert_eq!(lease.job.id, fork_job.id);

    let provisioning_child: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, forked.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(provisioning_child.sandbox.state, SandboxState::Provisioning);

    let completed: LeaseResponse = client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ForkSandbox {
                handle: ProviderForkHandle {
                    provider: "kubernetes".to_string(),
                    parent_sandbox_id: sandbox.sandbox.id,
                    child_sandbox_id: forked.sandbox.id,
                    snapshot_id: fork_snapshot_id,
                    resources: fork_resources(forked.sandbox.id, fork_snapshot_id),
                    metadata: serde_json::json!({
                        "cluster": "k3s-dev",
                        "namespace": "sandboxwich-contract"
                    }),
                },
            }),
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

    let ready_child: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, forked.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ready_child.sandbox.state, SandboxState::Ready);

    let child_resources: RuntimeResourceListResponse = client
        .get(format!(
            "{}/sandboxes/{}/runtime-resources",
            server.base_url, forked.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(child_resources.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::PersistentVolumeClaim
            && resource.purpose == RuntimeResourcePurpose::Workspace
            && resource.source_snapshot_id == Some(fork_snapshot_id)
    }));
}

fn job_for_command(jobs: &[Job], command_id: &str) -> Job {
    jobs.iter()
        .find(|job| {
            job.payload
                .get("commandId")
                .and_then(|value| value.as_str())
                == Some(command_id)
        })
        .cloned()
        .expect("expected command job")
}

fn job_for_child_sandbox(jobs: &[Job], child_sandbox_id: &str) -> Job {
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

fn job_for_snapshot(jobs: &[Job], snapshot_id: &str) -> Job {
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

fn job_for_prompt(jobs: &[Job], prompt_event_id: &str) -> Job {
    jobs.iter()
        .find(|job| {
            job.payload
                .get("promptEventId")
                .and_then(|value| value.as_str())
                == Some(prompt_event_id)
        })
        .cloned()
        .expect("expected prompt job")
}

fn assert_no_access_url(value: &serde_json::Value) {
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

fn command_result(stdout: &str, stderr: &str, exit_code: i32) -> WorkerJobResult {
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

fn provision_resources(sandbox_id: sandboxwich_core::SandboxId) -> Vec<ProviderRuntimeResource> {
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
    ]
}

fn fork_resources(
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

fn snapshot_resources(
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

fn provider_resource(
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
        RuntimeResourcePurpose::Snapshot => {}
    }

    resource
}

impl TestServer {
    async fn start(database_url: String, data_dir: Option<TempDir>) -> Self {
        Self::start_with_auth(database_url, data_dir, None).await
    }

    async fn start_with_auth(
        database_url: String,
        data_dir: Option<TempDir>,
        auth_token: Option<&str>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bind = listener.local_addr().unwrap();
        drop(listener);

        let mut command = Command::new(env!("CARGO_BIN_EXE_sandboxwich-api"));
        command
            .env("SANDBOXWICH_DATABASE_URL", &database_url)
            .env("SANDBOXWICH_BIND", bind.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(auth_token) = auth_token {
            command.env("SANDBOXWICH_API_TOKEN", auth_token);
        }
        let mut child = command.spawn().unwrap();

        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();
        for _ in 0..100 {
            let mut health_request = client.get(format!("{base_url}/healthz"));
            if let Some(auth_token) = auth_token {
                health_request = health_request.bearer_auth(auth_token);
            }
            if let Ok(response) = health_request.send().await {
                if response.status().is_success() {
                    return Self {
                        base_url,
                        database_url,
                        child,
                        _data_dir: data_dir,
                    };
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited before becoming healthy: {status}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = child.kill();
        let _ = child.wait();
        panic!("server did not become healthy");
    }
}

async fn assert_database_rejects_invalid_typed_values(database_url: &str, sandbox_id: &str) {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap();

    let invalid_sandbox_id = Uuid::now_v7().to_string();
    let invalid_snapshot_id = Uuid::now_v7().to_string();
    let invalid_desktop_status_id = Uuid::now_v7().to_string();
    let invalid_desktop_access_mode_id = Uuid::now_v7().to_string();
    let invalid_command_id = Uuid::now_v7().to_string();
    let invalid_event_id = Uuid::now_v7().to_string();
    let invalid_runtime_kind_id = Uuid::now_v7().to_string();
    let invalid_runtime_purpose_id = Uuid::now_v7().to_string();
    let invalid_runtime_status_id = Uuid::now_v7().to_string();
    let now = "2026-07-04T00:00:00Z";

    let sandbox_result = sqlx::query(&insert_sandbox_sql(database_url))
        .bind(invalid_sandbox_id)
        .bind("invalid")
        .bind("not_real")
        .bind("ubuntu-dev")
        .bind(now)
        .bind(now)
        .bind(120_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        sandbox_result.is_err(),
        "invalid sandbox state was accepted"
    );

    let command_result = sqlx::query(&insert_command_sql(database_url))
        .bind(invalid_command_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind(r#"["echo","nope"]"#)
        .bind(Option::<String>::None)
        .bind(Option::<i32>::None)
        .bind("")
        .bind("")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        command_result.is_err(),
        "invalid command status was accepted"
    );

    let snapshot_result = sqlx::query(&insert_snapshot_sql(database_url))
        .bind(invalid_snapshot_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("invalid")
        .bind("{}")
        .bind("{}")
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        snapshot_result.is_err(),
        "invalid snapshot status was accepted"
    );

    let desktop_status_result = sqlx::query(&insert_desktop_session_sql(database_url))
        .bind(invalid_desktop_status_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("k3s-broker")
        .bind(Option::<String>::None)
        .bind("browser")
        .bind("{}")
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        desktop_status_result.is_err(),
        "invalid desktop session status was accepted"
    );

    let desktop_access_mode_result = sqlx::query(&insert_desktop_session_sql(database_url))
        .bind(invalid_desktop_access_mode_id)
        .bind(sandbox_id)
        .bind("ready")
        .bind("k3s-broker")
        .bind(Option::<String>::None)
        .bind("not_real")
        .bind("{}")
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        desktop_access_mode_result.is_err(),
        "invalid desktop access mode was accepted"
    );

    let event_result = sqlx::query(&insert_event_sql(database_url))
        .bind(invalid_event_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("{}")
        .bind(now)
        .execute(&pool)
        .await;
    assert!(event_result.is_err(), "invalid event kind was accepted");

    let worker_result = sqlx::query(&insert_worker_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind("invalid-worker")
        .bind("not_real")
        .bind("kubernetes")
        .bind(r#"["k8s_pod"]"#)
        .bind("{}")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(worker_result.is_err(), "invalid worker status was accepted");

    let guest_health_result = sqlx::query(&insert_guest_health_sql(database_url))
        .bind(sandbox_id)
        .bind("not_real")
        .bind(now)
        .bind(Option::<String>::None)
        .bind("{}")
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        guest_health_result.is_err(),
        "invalid guest status was accepted"
    );

    let ssh_key_result = sqlx::query(&insert_ssh_key_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind(sandbox_id)
        .bind("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest")
        .bind("tester")
        .bind("not_real")
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        ssh_key_result.is_err(),
        "invalid ssh key status was accepted"
    );

    let runtime_kind_result = sqlx::query(&insert_runtime_resource_sql(database_url))
        .bind(invalid_runtime_kind_id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind("not_real")
        .bind("runtime")
        .bind("invalid-kind")
        .bind("sandboxwich-contract")
        .bind("ready")
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        runtime_kind_result.is_err(),
        "invalid runtime resource kind was accepted"
    );

    let runtime_purpose_result = sqlx::query(&insert_runtime_resource_sql(database_url))
        .bind(invalid_runtime_purpose_id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind("pod")
        .bind("not_real")
        .bind("invalid-purpose")
        .bind("sandboxwich-contract")
        .bind("ready")
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        runtime_purpose_result.is_err(),
        "invalid runtime resource purpose was accepted"
    );

    let runtime_status_result = sqlx::query(&insert_runtime_resource_sql(database_url))
        .bind(invalid_runtime_status_id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind("pod")
        .bind("runtime")
        .bind("invalid-status")
        .bind("sandboxwich-contract")
        .bind("not_real")
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        runtime_status_result.is_err(),
        "invalid runtime resource status was accepted"
    );
}

fn insert_sandbox_sql(database_url: &str) -> String {
    format!(
        "insert into sandboxes
         (id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        placeholders(database_url, 8)
    )
}

fn insert_command_sql(database_url: &str) -> String {
    format!(
        "insert into commands
         (id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at)
         values ({})",
        placeholders(database_url, 10)
    )
}

fn insert_snapshot_sql(database_url: &str) -> String {
    format!(
        "insert into snapshots
         (id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error)
         values ({})",
        placeholders(database_url, 10)
    )
}

fn insert_desktop_session_sql(database_url: &str) -> String {
    format!(
        "insert into desktop_sessions
         (id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
          created_at, updated_at, expires_at, error)
         values ({})",
        placeholders(database_url, 11)
    )
}

fn insert_event_sql(database_url: &str) -> String {
    format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values ({})",
        placeholders(database_url, 5)
    )
}

fn insert_worker_sql(database_url: &str) -> String {
    format!(
        "insert into workers
         (id, name, status, provider, capabilities, labels, registered_at, last_heartbeat_at)
         values ({})",
        placeholders(database_url, 8)
    )
}

fn insert_guest_health_sql(database_url: &str) -> String {
    format!(
        "insert into guest_health (sandbox_id, status, last_probe_at, agent_version, checks, message)
         values ({})",
        placeholders(database_url, 6)
    )
}

fn insert_ssh_key_sql(database_url: &str) -> String {
    format!(
        "insert into ssh_keys
         (id, sandbox_id, public_key, principal, status, requested_at, updated_at, applied_at, error)
         values ({})",
        placeholders(database_url, 9)
    )
}

fn insert_runtime_resource_sql(database_url: &str) -> String {
    format!(
        "insert into runtime_resources
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, ready_at, deleted_at, error)
         values ({})",
        placeholders(database_url, 22)
    )
}

fn placeholders(database_url: &str, count: usize) -> String {
    (1..=count)
        .map(|index| {
            if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
                format!("${index}")
            } else {
                "?".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
