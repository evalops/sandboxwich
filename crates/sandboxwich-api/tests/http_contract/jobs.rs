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

/// Regression test: a worker that runs a command to completion but the command
/// itself exits non-zero must still *complete* the lease (the worker did its job),
/// while the command's own status is derived from the exit code rather than being
/// unconditionally marked `Finished`. Exercises a successful (`exit_code: 0`,
/// `Finished`), a failing (`exit_code: 7`, `Failed`), and a code-less
/// (`exit_code: null`, e.g. killed by a signal, `Failed` with the null persisted
/// honestly rather than fabricated as 0) completion end-to-end through
/// `/leases/{id}/complete`.
pub(crate) async fn assert_command_status_is_derived_from_exit_code(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let worker_client = worker_client(worker);

    async fn queue_and_complete(
        client: &reqwest::Client,
        worker_client: &reqwest::Client,
        server: &TestServer,
        sandbox: &SandboxResponse,
        worker: &WorkerResponse,
        exit_code: Option<i32>,
    ) -> CommandRun {
        let command: QueueCommandResponse = client
            .post(format!(
                "{}/sandboxes/{}/commands",
                server.base_url, sandbox.sandbox.id
            ))
            .json(&CommandRequest {
                argv: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("exit {}", exit_code.unwrap_or(0)),
                ],
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
        let lease = claimed
            .lease
            .expect("expected worker to claim the exit-code test command");
        assert_eq!(lease.job.id, command.queued_job.id);

        let now = chrono::Utc::now();
        let completed: LeaseResponse = worker_client
            .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
            .json(&CompleteLeaseRequest {
                result: Some(WorkerJobResult::RunCommand {
                    result: AgentCommandResult {
                        exit_code,
                        stdout: "stdout\n".to_string(),
                        stderr: "stderr\n".to_string(),
                        started_at: now,
                        finished_at: now,
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
        // Completing the lease always succeeds the *job*: the worker did run the
        // command, regardless of what it exited with.
        assert_eq!(completed.lease.job.status, JobStatus::Succeeded);

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
        fetched.command
    }

    let succeeded =
        queue_and_complete(client, &worker_client, server, sandbox, worker, Some(0)).await;
    assert_eq!(succeeded.status, CommandStatus::Finished);
    assert_eq!(succeeded.exit_code, Some(0));

    let failed = queue_and_complete(client, &worker_client, server, sandbox, worker, Some(7)).await;
    assert_eq!(failed.status, CommandStatus::Failed);
    assert_eq!(failed.exit_code, Some(7));
    assert_eq!(failed.stdout, "stdout\n");
    assert_eq!(failed.stderr, "stderr\n");

    // A completion with no exit code at all (a process killed by a signal, or a
    // runner that couldn't capture the code) must land Failed -- "couldn't say
    // how it finished" is not success -- and the missing code must stay an
    // honest null instead of being coerced to a fabricated 0.
    let codeless = queue_and_complete(client, &worker_client, server, sandbox, worker, None).await;
    assert_eq!(codeless.status, CommandStatus::Failed);
    assert_eq!(codeless.exit_code, None);
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
    let prompt = client
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
        .unwrap();
    assert_eq!(prompt.status(), reqwest::StatusCode::NOT_IMPLEMENTED);
    let error: ErrorEnvelope = prompt.json().await.unwrap();
    assert_eq!(error.code, "agent_prompt_unavailable");
}
