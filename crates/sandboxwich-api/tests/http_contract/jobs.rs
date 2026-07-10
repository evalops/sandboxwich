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

/// Registers a worker capable of `ProvisionSandbox`, `RunCommand`, and `K8sPod`
/// jobs against `server`, returning it. Shared by the claim-filter tests below.
async fn register_claim_filter_worker(
    client: &reqwest::Client,
    server: &TestServer,
) -> WorkerResponse {
    client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "claim-filter-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::K8sPod,
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
            ],
            max_concurrent_jobs: Some(4),
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

async fn create_sandbox(
    client: &reqwest::Client,
    server: &TestServer,
    name: &str,
) -> SandboxResponse {
    client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some(name.to_string()),
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
        .unwrap()
}

fn payload_sandbox_id(job: &Job) -> SandboxId {
    serde_json::from_value(job.payload["sandboxId"].clone())
        .expect("job payload must carry a sandboxId")
}

/// The guest-side agent daemon claims leases from `POST
/// /workers/{worker_id}/leases/claim` with an optional `sandbox_id` filter so
/// it never runs a job destined for a different sandbox inside its own
/// filesystem/environment. Prove the filter actually narrows what the claim
/// endpoint returns: two sandboxes each have a queued (auto-created)
/// `ProvisionSandbox` job, and claiming with `sandbox_id` set to the
/// *second*-created sandbox must still return that sandbox's job -- not the
/// first-created one, which is what unfiltered FIFO claim order would return.
#[tokio::test]
pub(crate) async fn claim_lease_sandbox_filter_excludes_other_sandbox_jobs() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-claim-sandbox-filter-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let sandbox_a = create_sandbox(&client, &server, "claim-filter-a").await;
    let sandbox_b = create_sandbox(&client, &server, "claim-filter-b").await;
    let worker = register_claim_filter_worker(&client, &server).await;
    let worker_client = worker_client(&worker);

    // Unfiltered claim order is FIFO (scheduled_at asc), so without the
    // sandbox_id filter this claim would return sandbox_a's job, created first.
    let claimed: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_b.sandbox.id),
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
    let lease = claimed
        .lease
        .expect("expected a lease for sandbox_b's provision job");
    assert_eq!(lease.job.kind, JobKind::ProvisionSandbox);
    assert_eq!(payload_sandbox_id(&lease.job), sandbox_b.sandbox.id);

    // sandbox_a's job is still queued and untouched by the filtered claim above.
    let claimed_a: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_a.sandbox.id),
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
    let lease_a = claimed_a
        .lease
        .expect("expected a lease for sandbox_a's provision job");
    assert_eq!(payload_sandbox_id(&lease_a.job), sandbox_a.sandbox.id);
}

/// Companion to `claim_lease_sandbox_filter_excludes_other_sandbox_jobs`: proves
/// the `kinds` filter (used by `sandboxwich-agent`'s daemon to claim only
/// `run_command` leases, never a `ProvisionSandbox`/`Snapshot`/`Fork` job it
/// can't execute) excludes other kinds even when they would otherwise be
/// claimed first.
#[tokio::test]
pub(crate) async fn claim_lease_kinds_filter_excludes_other_kinds() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-claim-kinds-filter-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let worker = register_claim_filter_worker(&client, &server).await;
    let worker_client = worker_client(&worker);

    // Creating sandbox_a auto-queues a ProvisionSandbox job; ProvisionSandbox
    // jobs are claimable without a sandbox_placements row (see the `kind in
    // ('provision_sandbox', ...)` exemption in claim_lease's query), so this
    // claim succeeds immediately and -- as a side effect of try_claim_job --
    // records a sandbox_placement binding sandbox_a to this worker, which
    // RunCommand jobs require.
    let sandbox_a = create_sandbox(&client, &server, "claim-filter-kinds-a").await;
    let provision_a: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: Some(vec![JobKind::ProvisionSandbox]),
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
        provision_a
            .lease
            .expect("expected sandbox_a's provision job")
            .job
            .kind,
        JobKind::ProvisionSandbox
    );

    // sandbox_b's auto-queued ProvisionSandbox job is created next (and stays
    // queued, unclaimed) so it is the earlier-scheduled "other kind" job that
    // an unfiltered claim would return ahead of the RunCommand job queued
    // after it.
    create_sandbox(&client, &server, "claim-filter-kinds-b").await;

    // Now that sandbox_a has a placement, its RunCommand job (queued last) is
    // claimable by this worker.
    let command: QueueCommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox_a.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["echo".to_string(), "hi".to_string()],
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
            sandbox_id: None,
            kinds: Some(vec![JobKind::RunCommand]),
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
        .expect("expected the run_command job despite sandbox_b's earlier-scheduled provision job");
    assert_eq!(lease.job.kind, JobKind::RunCommand);
    assert_eq!(lease.job.id, command.queued_job.id);
}

/// Companion to the two filtered-claim tests above: an unfiltered claim
/// (`sandbox_id: None, kinds: None`) must keep working exactly as it did before
/// filters existed, since every non-`sandboxwich-agent` caller (the host-side
/// `sandboxwich-worker`, and every existing test) relies on that.
#[tokio::test]
pub(crate) async fn claim_lease_without_filters_still_claims_any_matching_job() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-claim-unfiltered-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let sandbox = create_sandbox(&client, &server, "claim-filter-unfiltered").await;
    let worker = register_claim_filter_worker(&client, &server).await;
    let worker_client = worker_client(&worker);

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
    let lease = claimed
        .lease
        .expect("unfiltered claim should still return the queued provision job");
    assert_eq!(lease.job.kind, JobKind::ProvisionSandbox);
    assert_eq!(payload_sandbox_id(&lease.job), sandbox.sandbox.id);
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
