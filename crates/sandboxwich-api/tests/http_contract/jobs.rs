use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;
use sha2::{Digest, Sha256};

async fn legacy_provision_fixture(name: &str) -> (TestServer, SandboxResponse, WorkerResponse) {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir.path().join(format!("{name}.db")).display()
        ),
        Some(data_dir),
    )
    .await;
    let client = server.client();
    let sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some(name.to_string()),
            template: None,
            memory_limit: Some(MemoryLimit::FourG),
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: Some(WorkspaceMode::Persistent),
            runtime_profile: None,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
            execution_class: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: format!("{name}-worker"),
            provider: "kubernetes".to_string(),
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
    (server, sandbox, worker)
}

#[tokio::test]
async fn legacy_queued_job_is_authoritatively_repaired_and_claimed() {
    let (server, sandbox, worker) = legacy_provision_fixture("legacy-repair").await;
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .connect(&server.database_url)
        .await
        .unwrap();
    let forged_image = format!("ghcr.io/attacker/root@sha256:{}", "f".repeat(64));
    sqlx::query("update jobs set payload = ? where kind = 'provision_sandbox'")
        .bind(
            serde_json::json!({
                "sandboxId": sandbox.sandbox.id,
                "runtimeImage": forged_image,
                "provisionSpec": {
                    "memory_limit": "16g",
                    "network_egress": {"mode": "deny_all"},
                    "workspace_mode": "persistent",
                    "runtime_profile": "apex_trusted_supervisor_v1"
                }
            })
            .to_string(),
        )
        .execute(&pool)
        .await
        .unwrap();

    let claimed: ClaimLeaseResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox.sandbox.id),
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
    let lease = claimed
        .lease
        .expect("legacy job should be repaired and claimed");
    assert_eq!(
        lease.job.payload["runtimeImage"],
        serde_json::json!(sandbox.sandbox.template)
    );
    assert_eq!(
        lease.job.payload["provisionSpec"]["memory_limit"],
        serde_json::json!("4g")
    );
    assert_eq!(
        lease.job.payload["provisionSpec"]["runtime_profile"],
        serde_json::json!("unprivileged")
    );
    assert_ne!(
        lease.job.payload["runtimeImage"],
        serde_json::json!(forged_image)
    );
}

#[tokio::test]
async fn irreparable_legacy_queued_job_becomes_observably_dead() {
    let (server, _sandbox, worker) = legacy_provision_fixture("legacy-dead").await;
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query("update jobs set payload = '{}' where kind = 'provision_sandbox'")
        .execute(&pool)
        .await
        .unwrap();

    let claimed: ClaimLeaseResponse = worker_client(&worker)
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
    assert!(claimed.lease.is_none());
    let jobs: JobListResponse = server
        .client()
        .get(format!("{}/jobs", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let job = jobs
        .jobs
        .iter()
        .find(|job| job.kind == JobKind::ProvisionSandbox)
        .unwrap();
    assert_eq!(job.status, JobStatus::Dead);
    assert_eq!(
        job.last_error.as_deref(),
        Some("authoritative_placement_unavailable")
    );
}

#[tokio::test]
async fn materialization_bytes_are_worker_fenced_ref_only_and_consumed_only_when_terminal() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("materialization.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let runtime_image = format!("image@sha256:{}", "a".repeat(64));
    let sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("materialization".to_string()),
            template: Some(runtime_image.clone()),
            memory_limit: None,
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: None,
            runtime_profile: Some(SandboxRuntimeProfile::ApexTrustedSupervisorV1),
            ttl_seconds: Some(120),
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
            execution_class: Some(ExecutionClass::SandboxedContainer),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "materialization-worker".into(),
            provider: "kubernetes".into(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::MaterializeFile,
                WorkerCapability::ApexTrustedSupervisorV1,
                WorkerCapability::SandboxedContainer,
            ],
            max_concurrent_jobs: Some(1),
            labels: [
                ("provider_mode".into(), "apply".into()),
                ("runtime_image".into(), runtime_image),
            ]
            .into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let worker_client = worker_client(&worker);
    let provision: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox.sandbox.id),
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
    let provision = provision.lease.unwrap();
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".into(),
                    sandbox_id: sandbox.sandbox.id,
                    resources: provision_resources(sandbox.sandbox.id),
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let secret = b"private-apex-task".to_vec();
    let uploaded: FileResponse = client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, sandbox.sandbox.id
        ))
        .multipart(
            reqwest::multipart::Form::new()
                .text("path", "task.zip")
                .part("file", reqwest::multipart::Part::bytes(secret.clone())),
        )
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let digest = format!("{:x}", Sha256::digest(&secret));
    let queued: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::MaterializeFile,
            payload: serde_json::json!({
                "sandboxId": sandbox.sandbox.id,
                "fileId": uploaded.file.id,
                "destination": "apex_task",
                "expectedSha256": digest,
            }),
            required_capability: WorkerCapability::MaterializeFile,
            priority: None,
            max_attempts: Some(2),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    async fn claim_materialization(
        client: &reqwest::Client,
        server: &TestServer,
        worker: &WorkerResponse,
        sandbox: SandboxId,
    ) -> JobLease {
        let claimed: ClaimLeaseResponse = client
            .post(format!(
                "{}/workers/{}/leases/claim",
                server.base_url, worker.worker.id
            ))
            .json(&ClaimLeaseRequest {
                lease_seconds: Some(60),
                sandbox_id: Some(sandbox),
                kinds: Some(vec![JobKind::MaterializeFile]),
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        claimed.lease.unwrap()
    }

    let first = claim_materialization(&worker_client, &server, &worker, sandbox.sandbox.id).await;
    assert_eq!(first.job.id, queued.job.id);
    assert!(first.job.payload.get("transientContentBase64").is_none());
    let tenant_fetch = client
        .get(format!(
            "{}/leases/{}/materialization",
            server.base_url, first.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_fetch.status(), StatusCode::UNAUTHORIZED);
    let fetched = worker_client
        .get(format!(
            "{}/leases/{}/materialization",
            server.base_url, first.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(fetched.content_length(), Some(secret.len() as u64));
    assert_eq!(fetched.bytes().await.unwrap().as_ref(), secret.as_slice());
    worker_client
        .post(format!("{}/leases/{}/fail", server.base_url, first.id))
        .json(&FailLeaseRequest {
            error: "retry".into(),
            retry: true,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let retained: ListFilesResponse = client
        .get(format!(
            "{}/sandboxes/{}/files",
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
    assert_eq!(retained.files.len(), 1);

    let second = claim_materialization(&worker_client, &server, &worker, sandbox.sandbox.id).await;
    worker_client
        .post(format!("{}/leases/{}/fail", server.base_url, second.id))
        .json(&FailLeaseRequest {
            error: "terminal".into(),
            retry: false,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let consumed: ListFilesResponse = client
        .get(format!(
            "{}/sandboxes/{}/files",
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
    assert!(consumed.files.is_empty());

    let cancelled_file: FileResponse = client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, sandbox.sandbox.id
        ))
        .multipart(
            reqwest::multipart::Form::new()
                .text("path", "cancelled-task.zip")
                .part("file", reqwest::multipart::Part::bytes(secret.clone())),
        )
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let cancelled_job: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::MaterializeFile,
            payload: serde_json::json!({
                "sandboxId": sandbox.sandbox.id,
                "fileId": cancelled_file.file.id,
                "destination": "apex_task",
                "expectedSha256": format!("{:x}", Sha256::digest(&secret)),
            }),
            required_capability: WorkerCapability::MaterializeFile,
            priority: None,
            max_attempts: Some(1),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    client
        .post(format!(
            "{}/operations/{}/cancel",
            server.base_url, cancelled_job.job.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let cancelled_consumed: ListFilesResponse = client
        .get(format!(
            "{}/sandboxes/{}/files",
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
    assert!(cancelled_consumed.files.is_empty());

    let attested_file: FileResponse = client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, sandbox.sandbox.id
        ))
        .multipart(
            reqwest::multipart::Form::new()
                .text("path", "attested-task.zip")
                .part("file", reqwest::multipart::Part::bytes(secret.clone())),
        )
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let attested_job: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::MaterializeFile,
            payload: serde_json::json!({
                "sandboxId": sandbox.sandbox.id,
                "fileId": attested_file.file.id,
                "destination": "apex_task",
                "expectedSha256": digest,
            }),
            required_capability: WorkerCapability::MaterializeFile,
            priority: None,
            max_attempts: Some(1),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let attested =
        claim_materialization(&worker_client, &server, &worker, sandbox.sandbox.id).await;
    assert_eq!(attested.job.id, attested_job.job.id);
    let completion = CompleteLeaseRequest {
        result: Some(WorkerJobResult::MaterializeFile {
            receipt: MaterializeFileReceipt {
                sandbox_id: sandbox.sandbox.id,
                file_id: attested_file.file.id,
                destination: MaterializeFileDestination::ApexTask,
                sha256: digest.clone(),
                destination_sha256: digest.clone(),
                size_bytes: secret.len() as u64,
                cleanup_owner: MaterializeFileCleanupOwner::ControlPlane,
            },
        }),
    };
    let mut forged_observation = completion.clone();
    let Some(WorkerJobResult::MaterializeFile { receipt }) = forged_observation.result.as_mut()
    else {
        unreachable!("materialization completion fixture")
    };
    receipt.destination_sha256 = "f".repeat(64);
    let rejected = worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, attested.id
        ))
        .json(&forged_observation)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, attested.id
        ))
        .json(&completion)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let replay = worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, attested.id
        ))
        .json(&completion)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);

    let mut changed_digest_replay = completion.clone();
    let Some(WorkerJobResult::MaterializeFile { receipt }) = changed_digest_replay.result.as_mut()
    else {
        unreachable!("materialization completion fixture")
    };
    receipt.destination_sha256 = "f".repeat(64);
    let mut changed_file_replay = completion.clone();
    let Some(WorkerJobResult::MaterializeFile { receipt }) = changed_file_replay.result.as_mut()
    else {
        unreachable!("materialization completion fixture")
    };
    receipt.file_id = FileId::new();
    let changed_kind_replay = CompleteLeaseRequest {
        result: Some(WorkerJobResult::RunPrompt {
            output: "not a materialization receipt".into(),
        }),
    };
    for changed_replay in [
        changed_digest_replay,
        changed_file_replay,
        changed_kind_replay,
    ] {
        let rejected = worker_client
            .post(format!(
                "{}/leases/{}/complete",
                server.base_url, attested.id
            ))
            .json(&changed_replay)
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    }

    let mut invalid_cleanup_replay = serde_json::to_value(&completion).unwrap();
    invalid_cleanup_replay["result"]["receipt"]["cleanupOwner"] = serde_json::json!("worker");
    let invalid_cleanup_replay = worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, attested.id
        ))
        .json(&invalid_cleanup_replay)
        .send()
        .await
        .unwrap();
    assert!(invalid_cleanup_replay.status().is_client_error());
    assert_ne!(invalid_cleanup_replay.status(), StatusCode::OK);

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query("update job_leases set completion_fingerprint = null where id = ?")
        .bind(attested.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let legacy_replay = worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, attested.id
        ))
        .json(&completion)
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_replay.status(), StatusCode::CONFLICT);
    let legacy_error: ErrorEnvelope = legacy_replay.json().await.unwrap();
    assert_eq!(legacy_error.code, "completion_replay_unavailable");

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
    let materialized: Vec<_> = events
        .events
        .iter()
        .filter(|event| event.kind == SandboxEventKind::FileMaterialized)
        .collect();
    assert_eq!(materialized.len(), 1);
    assert_eq!(materialized[0].data["sha256"], digest);
    assert_eq!(materialized[0].data["destinationSha256"], digest);
    assert_eq!(materialized[0].data["cleanupOwner"], "control_plane");
}

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
            execution_class: Some(ExecutionClass::VirtualMachine),
            workspace_mode: None,
            runtime_profile: None,
            name: Some("job-fetch".to_string()),
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
    assert_eq!(
        job.job.required_execution_class,
        ExecutionClass::VirtualMachine
    );
    assert_eq!(
        fetched.job.required_execution_class,
        ExecutionClass::VirtualMachine
    );
    assert_eq!(
        fetched.job.required_capability,
        WorkerCapability::ProvisionSandbox
    );

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

#[tokio::test]
pub(crate) async fn tenant_job_creation_rejects_isolation_only_required_capabilities() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-job-capability-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let sandbox = create_sandbox(&client, &server, "job-capability-boundary").await;
    let jobs_before: JobListResponse = client
        .get(format!("{}/jobs", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    for required_capability in [
        WorkerCapability::SandboxedContainer,
        WorkerCapability::VirtualMachine,
    ] {
        let response = client
            .post(format!("{}/jobs", server.base_url))
            .json(&CreateJobRequest {
                kind: JobKind::ProvisionSandbox,
                payload: serde_json::json!({"sandboxId": sandbox.sandbox.id}),
                required_capability,
                priority: None,
                max_attempts: None,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: ErrorEnvelope = response.json().await.unwrap();
        assert_eq!(error.code, "bad_request");
        assert!(error.message.contains("required_capability"));
    }

    let jobs_after_rejections: JobListResponse = client
        .get(format!("{}/jobs", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(jobs_after_rejections.jobs.len(), jobs_before.jobs.len());

    let accepted: JobResponse = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::ProvisionSandbox,
            payload: serde_json::json!({"sandboxId": sandbox.sandbox.id}),
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
    assert_eq!(
        accepted.job.required_capability,
        WorkerCapability::ProvisionSandbox
    );
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
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some(name.to_string()),
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
        .unwrap()
}

fn payload_sandbox_id(job: &Job) -> SandboxId {
    serde_json::from_value(job.payload["sandboxId"].clone())
        .expect("job payload must carry a sandboxId")
}

#[tokio::test]
pub(crate) async fn provisioning_stage_route_is_put_only_and_worker_fenced() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-stage-route.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let sandbox = create_sandbox(&client, &server, "stage-route").await;
    let worker = register_claim_filter_worker(&client, &server).await;
    let worker_client = worker_client(&worker);
    let claim: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox.sandbox.id),
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
    let lease = claim.lease.expect("claim provision lease");
    let request = ProvisioningStageUpdateRequest {
        stage: ProvisioningStage::WorkspacePlanned,
        resource_kind: None,
        resource_namespace: None,
        resource_name: None,
        resource_uid: None,
        observed_generation: None,
        attempt_count: lease.attempt,
        last_error_class: None,
        last_error_code: None,
        last_error: None,
    };
    let response: ProvisioningOperationResponse = worker_client
        .put(format!(
            "{}/leases/{}/provisioning",
            server.base_url, lease.id
        ))
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response.operation.lease_id, lease.id);

    let failed_stage = ProvisioningStageUpdateRequest {
        last_error_class: Some(ProvisioningErrorClass::RetryableProvider),
        last_error_code: Some("pod_ready_timeout".to_string()),
        last_error: Some("pod readiness timed out".to_string()),
        ..request.clone()
    };
    worker_client
        .put(format!(
            "{}/leases/{}/provisioning",
            server.base_url, lease.id
        ))
        .json(&failed_stage)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let wrong_method = worker_client
        .post(format!(
            "{}/leases/{}/provisioning",
            server.base_url, lease.id
        ))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

    let tenant_attempt = client
        .put(format!(
            "{}/leases/{}/provisioning",
            server.base_url, lease.id
        ))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_attempt.status(), StatusCode::UNAUTHORIZED);

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
    assert!(metrics.contains("sandboxwich_provisioning_stage_seconds_bucket{"));
    assert!(metrics.contains("stage=\"workspace_planned\""));
    assert!(metrics.contains("error_class=\"retryable_provider\""));
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
    let sibling = create_sandbox(client, server, "same-tenant-completion-target").await;
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
            sandbox_id: Some(sibling.sandbox.id),
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
    assert_eq!(payload_sandbox_id(&lease.job), sibling.sandbox.id);

    let replayed_claim: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .header("idempotency-key", claim_operation_id.to_string())
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sibling.sandbox.id),
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

    let mut malformed = provision_resources(sibling.sandbox.id);
    malformed[0].provider = String::new();
    let malformed_rejected = worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sibling.sandbox.id,
                    resources: malformed,
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(malformed_rejected.status(), StatusCode::BAD_REQUEST);

    let mut same_tenant_collision = provision_resources(sibling.sandbox.id);
    same_tenant_collision[0].resource_name = provision_resources(sandbox.sandbox.id)[0]
        .resource_name
        .clone();
    let collision_rejected = worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sibling.sandbox.id,
                    resources: same_tenant_collision,
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(collision_rejected.status(), StatusCode::BAD_REQUEST);

    let tenant_b_sandbox: SandboxResponse = reqwest::Client::new()
        .post(format!("{}/sandboxes", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("tenant-b-completion-target".to_string()),
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

    let mut cross_tenant = provision_resources(sibling.sandbox.id);
    cross_tenant[0].sandbox_id = tenant_b_sandbox.sandbox.id;
    let cross_tenant_rejected = worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sibling.sandbox.id,
                    resources: cross_tenant,
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_tenant_rejected.status(), StatusCode::BAD_REQUEST);

    let completed: LeaseResponse = worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sibling.sandbox.id,
                    resources: provision_resources(sibling.sandbox.id),
                    metadata: serde_json::json!({}),
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
    let completion = CompleteLeaseRequest {
        result: Some(command_result("retried\n", "", 0)),
    };
    let completed: LeaseResponse = worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, retry_lease.id
        ))
        .json(&completion)
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
        .json(&completion)
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

#[tokio::test]
pub(crate) async fn concurrent_provider_identity_collision_is_classified_over_postgres() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start(database_url, None).await;
    let client = server.client();
    let first_worker = register_claim_filter_worker(&client, &server).await;
    let second_worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "concurrent-collision-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::K8sPod, WorkerCapability::ProvisionSandbox],
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
        .unwrap();
    let first_worker_client = worker_client(&first_worker);
    let second_worker_client = worker_client(&second_worker);

    for attempt in 0..8 {
        let first = create_sandbox(&client, &server, &format!("collision-first-{attempt}")).await;
        let second = create_sandbox(&client, &server, &format!("collision-second-{attempt}")).await;
        let first_claim: ClaimLeaseResponse = first_worker_client
            .post(format!(
                "{}/workers/{}/leases/claim",
                server.base_url, first_worker.worker.id
            ))
            .json(&ClaimLeaseRequest {
                lease_seconds: Some(60),
                sandbox_id: Some(first.sandbox.id),
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
        let second_claim: ClaimLeaseResponse = second_worker_client
            .post(format!(
                "{}/workers/{}/leases/claim",
                server.base_url, second_worker.worker.id
            ))
            .json(&ClaimLeaseRequest {
                lease_seconds: Some(60),
                sandbox_id: Some(second.sandbox.id),
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
        let first_lease = first_claim.lease.expect("first collision lease");
        let second_lease = second_claim.lease.expect("second collision lease");
        let resource_name = format!("concurrent-provider-identity-{attempt}");
        let first_resource = provider_resource(
            first.sandbox.id,
            None,
            RuntimeResourceKind::PersistentVolumeClaim,
            RuntimeResourcePurpose::Workspace,
            resource_name.clone(),
        );
        let second_resource = provider_resource(
            second.sandbox.id,
            None,
            RuntimeResourceKind::PersistentVolumeClaim,
            RuntimeResourcePurpose::Workspace,
            resource_name,
        );
        let first_request = first_worker_client
            .post(format!(
                "{}/leases/{}/complete",
                server.base_url, first_lease.id
            ))
            .json(&CompleteLeaseRequest {
                result: Some(WorkerJobResult::ProvisionSandbox {
                    handle: ProviderSandboxHandle {
                        provider: "kubernetes".to_string(),
                        sandbox_id: first.sandbox.id,
                        resources: vec![first_resource],
                        metadata: serde_json::json!({}),
                    },
                }),
            });
        let second_request = second_worker_client
            .post(format!(
                "{}/leases/{}/complete",
                server.base_url, second_lease.id
            ))
            .json(&CompleteLeaseRequest {
                result: Some(WorkerJobResult::ProvisionSandbox {
                    handle: ProviderSandboxHandle {
                        provider: "kubernetes".to_string(),
                        sandbox_id: second.sandbox.id,
                        resources: vec![second_resource],
                        metadata: serde_json::json!({}),
                    },
                }),
            });

        let (first_response, second_response) =
            tokio::join!(first_request.send(), second_request.send(),);
        let statuses = [
            first_response.unwrap().status(),
            second_response.unwrap().status(),
        ];
        assert_eq!(
            statuses.iter().filter(|status| status.is_success()).count(),
            1,
            "exactly one first writer must win: {statuses:?}"
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::BAD_REQUEST)
                .count(),
            1,
            "the displaced association must be classified as 400, never 409: {statuses:?}"
        );

        let (loser_client, loser_lease_id) = if statuses[0] == StatusCode::BAD_REQUEST {
            (&first_worker_client, first_lease.id)
        } else {
            (&second_worker_client, second_lease.id)
        };
        loser_client
            .post(format!(
                "{}/leases/{}/fail",
                server.base_url, loser_lease_id
            ))
            .json(&FailLeaseRequest {
                error: "expected concurrent identity collision".to_string(),
                retry: false,
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
}
