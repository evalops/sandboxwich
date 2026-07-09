use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

#[tokio::test]
pub(crate) async fn job_can_be_fetched_by_id_with_tenant_isolation() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-job-test.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("job-fetch".to_string()),
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

    let job: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::ProvisionSandbox,
            payload: serde_json::json!({
                "sandboxId": sandbox.sandbox.id
            }),
            required_capability: WorkerCapability::ProvisionSandbox,
            priority: None,
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

    let fetched: JobResponse = client
        .get(format!("{}/jobs/{}", server.base_url, job.job.id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched.job.id, job.job.id);
    assert_eq!(fetched.job.status, JobStatus::Queued);

    // Tenant identity now comes only from which bearer token authenticated
    // the request, never from a client-supplied header: authenticate as
    // "tenant-b" with its own token rather than spoofing a header.
    let hidden = reqwest::Client::new()
        .get(format!("{}/jobs/{}", server.base_url, job.job.id))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
}

pub(crate) async fn assert_failed_completion_rolls_back_lease_state(
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

    let worker_client = worker_client(worker);
    let claim_operation_id = uuid::Uuid::now_v7();
    let claimed: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .header("idempotency-key", claim_operation_id.to_string())
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

    let replayed_claim: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .header("idempotency-key", claim_operation_id.to_string())
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
    assert_eq!(replayed_claim.lease.unwrap().id, lease.id);

    let mut resources = provision_resources(sandbox.sandbox.id);
    resources[0].provider = String::new();
    let rejected = worker_client
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

    let failed: LeaseResponse = worker_client
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

    let replayed: LeaseResponse = worker_client
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
    assert_eq!(replayed.lease.status, LeaseStatus::Failed);
}

pub(crate) async fn assert_retryable_failure_requeues_command(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let command: QueueCommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["false".to_string()],
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
    assert_eq!(command.queued_job.sandbox_id, sandbox.sandbox.id);
    assert_eq!(command.queued_job.command_id, command.command.id);

    let worker_client = worker_client(worker);
    let claimed: ClaimLeaseResponse = worker_client
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
    assert_eq!(lease.job.id, command.queued_job.id);
    worker_client
        .post(format!("{}/leases/{}/output", server.base_url, lease.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "partial".to_string(),
            annotations: Vec::new(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let failed: LeaseResponse = worker_client
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
    assert_eq!(fetched.command.stdout, "");
    let chunks_after_retry: CommandOutputListResponse = client
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
    assert!(chunks_after_retry.chunks.is_empty());

    let claimed_again: ClaimLeaseResponse = worker_client
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
    let completed: LeaseResponse = worker_client
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

    let replayed: LeaseResponse = worker_client
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
    assert_eq!(replayed.lease.status, LeaseStatus::Completed);
}

pub(crate) async fn assert_expired_lease_requeues_command(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let command: QueueCommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["sleep".to_string(), "1".to_string()],
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
    assert_eq!(command.queued_job.sandbox_id, sandbox.sandbox.id);
    assert_eq!(command.queued_job.command_id, command.command.id);

    let claimed: ClaimLeaseResponse = worker_client(worker)
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
    let lease = claimed.lease.expect("expected expiring lease");
    assert_eq!(lease.job.id, command.queued_job.id);

    // Lease expiry now runs on a background sweep interval (see
    // SANDBOXWICH_SWEEP_INTERVAL_MS in TestServer) instead of inline on this GET,
    // so poll for the requeue instead of asserting it happened synchronously.
    let expired_job = poll_until(|| async {
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
        let job = job_for_command(&jobs.jobs, command.command.id);
        (job.status == JobStatus::Queued).then_some(job)
    })
    .await
    .expect("expired lease should requeue the job via the background sweep");
    assert_eq!(expired_job.status, JobStatus::Queued);

    let fetched = poll_until(|| async {
        let response: CommandResponse = client
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
        (response.command.status == CommandStatus::Queued).then_some(response)
    })
    .await
    .expect("expired lease should reset the command to queued via the background sweep");
    assert_eq!(fetched.command.status, CommandStatus::Queued);
}

pub(crate) async fn assert_prompt_job_lifecycle(
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

    let prompt_worker_client = worker_client(&prompt_worker);
    let claimed: ClaimLeaseResponse = prompt_worker_client
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

    let completed: LeaseResponse = prompt_worker_client
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
