use crate::common::*;
use sandboxwich_core::*;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Provisions a sandbox and worker, completes the `ProvisionSandbox` job, and
/// mints a guest token bound to that sandbox -- the shared setup every
/// resident-process test below needs before it can PUT/claim/bootstrap.
/// Returns `(sandbox_id, worker, guest_client)`; claims still go through
/// `/workers/{worker.worker.id}/leases/claim`, authenticated as the guest.
async fn provisioned_sandbox_with_guest(
    server: &TestServer,
    name: &str,
    provider_isolated_sidecar: bool,
) -> (SandboxId, WorkerResponse, reqwest::Client) {
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some(name.into()),
            template: Some("ubuntu-dev".into()),
            memory_limit: None,
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: None,
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: Some(3600),
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
    let sandbox_id = created.sandbox.id;

    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: format!("{name}-worker"),
            provider: "kubernetes".into(),
            capabilities: {
                let mut capabilities = vec![
                    WorkerCapability::ProvisionSandbox,
                    WorkerCapability::RunCommand,
                    WorkerCapability::UidIsolatedResidentProcess,
                ];
                if provider_isolated_sidecar {
                    capabilities.push(WorkerCapability::ProviderIsolatedResidentProcessV1);
                }
                capabilities
            },
            // Resident leases run inside the sandbox and therefore must not
            // consume the worker's ordinary job-execution slots. Keeping this
            // at one proves both persistent resident kinds can still be claimed.
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
    let provision: ClaimLeaseResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_id),
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
    worker_client(&worker)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".into(),
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

    let guest: GuestTokenResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker.worker.id, sandbox_id
        ))
        .json(&MintGuestTokenRequest {
            ttl_seconds: Some(300),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let guest_client = reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", guest.token).parse().unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    guest_client
        .post(format!(
            "{}/sandboxes/{sandbox_id}/guest-health",
            server.base_url
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/test".into()),
            checks: Some(serde_json::json!({
                (GUEST_AGENT_CAPABILITY_REPORT_CHECK): GuestAgentCapabilityReport::current()
            })),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    (sandbox_id, worker, guest_client)
}

/// Claims one `run_resident_process` lease as the guest and returns it. The
/// queue may hold jobs for more than one resident-process name at once (e.g.
/// both orb-executor and orb-sidecar); callers distinguish them via
/// `lease.job.payload["residentProcessId"]`.
async fn claim_resident_process_lease(
    server: &TestServer,
    worker: &WorkerResponse,
    guest_client: &reqwest::Client,
    sandbox_id: SandboxId,
) -> JobLease {
    let claimed: ClaimLeaseResponse = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::RunResidentProcess]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    claimed.lease.expect("resident process lease")
}

fn resident_process_request(
    program: &str,
    secret: &[u8],
    target_file: &str,
) -> ResidentProcessRequest {
    ResidentProcessRequest {
        argv: vec![program.into()],
        cwd: Some("/workspace".into()),
        env: BTreeMap::new(),
        restart_policy: ResidentProcessRestartPolicy::OnFailure,
        expected_generation: 0,
        bootstrap: Some(ResidentProcessBootstrap {
            content: secret.to_vec(),
            target_file: target_file.into(),
            mode: 0o600,
        }),
    }
}

#[tokio::test]
pub(crate) async fn resident_process_create_is_idempotent_tenant_scoped_and_redacted() {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir.path().join("resident-process.db").display()
        ),
        Some(data_dir),
    )
    .await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("resident-process".into()),
            template: Some("ubuntu-dev".into()),
            memory_limit: None,
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: None,
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: Some(3600),
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
    let request = ResidentProcessRequest {
        argv: vec!["/usr/local/bin/orb-executor".into()],
        cwd: Some("/workspace".into()),
        env: BTreeMap::from([(
            "ORB_TOKEN_FILE".into(),
            "/run/sandboxwich/bootstrap/orb-token".into(),
        )]),
        restart_policy: ResidentProcessRestartPolicy::OnFailure,
        expected_generation: 0,
        bootstrap: Some(ResidentProcessBootstrap {
            content: b"resident-canary-secret".to_vec(),
            target_file: "/run/sandboxwich/bootstrap/orb-token".into(),
            mode: 0o600,
        }),
    };
    let url = format!(
        "{}/sandboxes/{}/resident-processes/orb-executor",
        server.base_url, created.sandbox.id
    );
    let first = client
        .put(&url)
        .header("Idempotency-Key", "resident-process-create")
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let first_body = first.text().await.unwrap();
    assert!(!first_body.contains("resident-canary-secret"));
    let first: ResidentProcessResponse = serde_json::from_str(&first_body).unwrap();
    assert_eq!(first.resident_process.generation, 1);

    let replay: ResidentProcessResponse = client
        .put(&url)
        .header("Idempotency-Key", "resident-process-create")
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay.resident_process.id, first.resident_process.id);

    let fetched: ResidentProcessResponse = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched.resident_process.id, first.resident_process.id);

    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "resident-worker".into(),
            provider: "kubernetes".into(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
            ],
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
    let provision: ClaimLeaseResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
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
    worker_client(&worker)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".into(),
                    sandbox_id: created.sandbox.id,
                    resources: provision_resources(created.sandbox.id),
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let guest: GuestTokenResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker.worker.id, created.sandbox.id
        ))
        .json(&MintGuestTokenRequest {
            ttl_seconds: Some(300),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let guest_client = reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", guest.token).parse().unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    guest_client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, created.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/test".into()),
            checks: Some(serde_json::json!({
                (GUEST_AGENT_CAPABILITY_REPORT_CHECK): GuestAgentCapabilityReport::current()
            })),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let claimed: ClaimLeaseResponse = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
            kinds: Some(vec![JobKind::RunResidentProcess]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let claimed = claimed.lease.expect("resident process lease");
    let bootstrap: ResidentProcessBootstrapReadResponse = guest_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, first.resident_process.id
        ))
        .json(&ResidentProcessBootstrapReadRequest {
            generation: first.resident_process.generation,
            lease_id: claimed.id.0,
            expected_sha256: first.resident_process.bootstrap_sha256.clone().unwrap(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bootstrap.content, b"resident-canary-secret");
    guest_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, first.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: first.resident_process.generation,
            lease_id: claimed.id.0,
            observed_state: ResidentProcessObservedState::Starting,
            pid: Some(42),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    guest_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, first.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: first.resident_process.generation,
            lease_id: claimed.id.0,
            observed_state: ResidentProcessObservedState::Running,
            pid: Some(42),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let running: ResidentProcessResponse = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        running.resident_process.observed_state,
        ResidentProcessObservedState::Running
    );
    assert_eq!(running.resident_process.pid, Some(42));
    assert_eq!(
        guest_client
            .post(format!(
                "{}/resident-processes/{}/bootstrap",
                server.base_url, first.resident_process.id
            ))
            .json(&ResidentProcessBootstrapReadRequest {
                generation: first.resident_process.generation,
                lease_id: claimed.id.0,
                expected_sha256: first.resident_process.bootstrap_sha256.clone().unwrap(),
            })
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::GONE
    );
    client
        .post(format!(
            "{}/sandboxes/{}/stop",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let stopped: ResidentProcessResponse = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        stopped.resident_process.desired_state,
        ResidentProcessDesiredState::Stopped
    );

    let tenant_b = reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {TEST_TENANT_B_TOKEN}").parse().unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    assert_eq!(
        tenant_b.get(&url).send().await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

/// End-to-end coverage for issue #176's v1 sidecar placement primitive:
/// unsupported resident-process names are rejected, `orb-sidecar` gets its
/// own one-per-sandbox slot alongside `orb-executor` with the same
/// create/bootstrap/one-read/tenant-scoping contract, and -- the part unique
/// to the sidecar -- once a sandbox has an `orb-sidecar` configured,
/// `orb-executor`'s bootstrap-credential read is fail-closed: refused while
/// the sidecar isn't observed `Running`, allowed once it is. A sandbox that
/// never configures a sidecar sees no behavior change at all.
#[tokio::test]
async fn orb_sidecar_lifecycle_and_fail_closed_contract_works_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("orb-sidecar.db").display()
    );
    run_orb_sidecar_lifecycle_and_fail_closed_contract(
        TestServer::start(database_url, Some(data_dir)).await,
    )
    .await;
}

#[tokio::test]
async fn orb_sidecar_lifecycle_and_fail_closed_contract_works_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    run_orb_sidecar_lifecycle_and_fail_closed_contract(TestServer::start(database_url, None).await)
        .await;
}

async fn run_orb_sidecar_lifecycle_and_fail_closed_contract(server: TestServer) {
    let client = server.client();
    let (sandbox_id, worker, guest_client) =
        provisioned_sandbox_with_guest(&server, "orb-sidecar-contract", true).await;

    // 1. Names other than orb-executor/orb-sidecar are rejected outright.
    let unsupported_status = client
        .put(format!(
            "{}/sandboxes/{}/resident-processes/not-a-real-kind",
            server.base_url, sandbox_id
        ))
        .json(&resident_process_request(
            "/bin/true",
            b"irrelevant",
            "/run/sandboxwich/bootstrap/irrelevant",
        ))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(unsupported_status, reqwest::StatusCode::BAD_REQUEST);

    // 2. Create the sidecar with its own bootstrap secret.
    let sidecar_url = format!(
        "{}/sandboxes/{}/resident-processes/orb-sidecar",
        server.base_url, sandbox_id
    );
    let sidecar_request = resident_process_request(
        "/usr/local/bin/orb-sidecar",
        b"sidecar-canary-secret",
        "/run/sandboxwich/bootstrap/sidecar-token",
    );
    let (unsupported_sandbox_id, _, _) =
        provisioned_sandbox_with_guest(&server, "orb-sidecar-unsupported-worker", false).await;
    let unsupported_worker = client
        .put(format!(
            "{}/sandboxes/{unsupported_sandbox_id}/resident-processes/orb-sidecar",
            server.base_url
        ))
        .json(&sidecar_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        unsupported_worker.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let sidecar_create_response = client
        .put(&sidecar_url)
        .header("Idempotency-Key", "orb-sidecar-create")
        .json(&sidecar_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let sidecar_create_body = sidecar_create_response.text().await.unwrap();
    // The sidecar's claim credential must never appear raw in the create
    // response, same guarantee orb-executor already has.
    assert!(!sidecar_create_body.contains("sidecar-canary-secret"));
    let sidecar_created: ResidentProcessResponse =
        serde_json::from_str(&sidecar_create_body).unwrap();
    assert_eq!(sidecar_created.resident_process.generation, 1);
    assert_eq!(sidecar_created.resident_process.name, "orb-sidecar");

    // 2b. One-per-sandbox enforcement: a second, differently-specced
    // orb-sidecar PUT for the same sandbox must conflict rather than
    // silently creating (or replacing) a second slot.
    let mut conflicting_spec = sidecar_request.clone();
    conflicting_spec.argv = vec!["/usr/local/bin/orb-sidecar-v2".into()];
    let conflict_status = client
        .put(&sidecar_url)
        .json(&conflicting_spec)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(conflict_status, reqwest::StatusCode::CONFLICT);

    // 3. Create orb-executor (the workload) alongside the now-configured
    // sidecar, with its own, distinct bootstrap secret.
    let executor_url = format!(
        "{}/sandboxes/{}/resident-processes/orb-executor",
        server.base_url, sandbox_id
    );
    let executor_request = resident_process_request(
        "/usr/local/bin/orb-executor",
        b"executor-canary-secret",
        "/run/sandboxwich/bootstrap/orb-token",
    );
    let executor_create_response = client
        .put(&executor_url)
        .json(&executor_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let executor_create_body = executor_create_response.text().await.unwrap();
    assert!(!executor_create_body.contains("executor-canary-secret"));
    let executor_created: ResidentProcessResponse =
        serde_json::from_str(&executor_create_body).unwrap();

    // 4. A downgraded/old guest agent cannot claim orb-executor: dispatch
    // fails closed until the guest posts the exact current typed report.
    guest_client
        .post(format!(
            "{}/sandboxes/{sandbox_id}/guest-health",
            server.base_url
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/old".into()),
            checks: Some(serde_json::json!({})),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let sidecar_worker_client = worker_client(&worker);
    let sidecar_lease =
        claim_resident_process_lease(&server, &worker, &sidecar_worker_client, sandbox_id).await;
    assert_eq!(
        sidecar_lease
            .job
            .payload
            .get("name")
            .and_then(serde_json::Value::as_str),
        Some(ORB_SIDECAR_RESIDENT_PROCESS_NAME)
    );
    let worker_cannot_claim_executor: ClaimLeaseResponse = sidecar_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::RunResidentProcess]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(worker_cannot_claim_executor.lease.is_none());
    let unsupported_executor_claim: ClaimLeaseResponse = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::RunResidentProcess]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(unsupported_executor_claim.lease.is_none());
    guest_client
        .post(format!(
            "{}/sandboxes/{sandbox_id}/guest-health",
            server.base_url
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/current".into()),
            checks: Some(serde_json::json!({
                (GUEST_AGENT_CAPABILITY_REPORT_CHECK): GuestAgentCapabilityReport::current()
            })),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let executor_lease =
        claim_resident_process_lease(&server, &worker, &guest_client, sandbox_id).await;
    assert_eq!(
        executor_lease
            .job
            .payload
            .get("name")
            .and_then(serde_json::Value::as_str),
        Some(ORB_EXECUTOR_RESIDENT_PROCESS_NAME)
    );
    let unsupported_claim: ClaimLeaseResponse = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::RunResidentProcess]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(unsupported_claim.lease.is_none());
    assert_eq!(
        sidecar_lease.job.required_capability,
        WorkerCapability::ProviderIsolatedResidentProcessV1
    );
    assert_eq!(
        executor_lease.job.required_capability,
        WorkerCapability::RunCommand
    );

    let sidecar_bootstrap_request = ResidentProcessBootstrapReadRequest {
        generation: sidecar_created.resident_process.generation,
        lease_id: sidecar_lease.id.0,
        expected_sha256: sidecar_created
            .resident_process
            .bootstrap_sha256
            .clone()
            .unwrap(),
    };
    let sidecar_starting = ResidentProcessObservationRequest {
        generation: sidecar_created.resident_process.generation,
        lease_id: sidecar_lease.id.0,
        observed_state: ResidentProcessObservedState::Starting,
        pid: None,
        exit_code: None,
        error_code: None,
        error_message: None,
    };
    for response in [
        guest_client
            .post(format!(
                "{}/resident-processes/{}/bootstrap",
                server.base_url, sidecar_created.resident_process.id
            ))
            .json(&sidecar_bootstrap_request)
            .send()
            .await
            .unwrap(),
        guest_client
            .post(format!(
                "{}/resident-processes/{}/observations",
                server.base_url, sidecar_created.resident_process.id
            ))
            .json(&sidecar_starting)
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "a sandbox guest must not act as the authoritative sidecar worker"
        );
    }

    let executor_bootstrap_request = ResidentProcessBootstrapReadRequest {
        generation: executor_created.resident_process.generation,
        lease_id: executor_lease.id.0,
        expected_sha256: executor_created
            .resident_process
            .bootstrap_sha256
            .clone()
            .unwrap(),
    };
    let executor_starting = ResidentProcessObservationRequest {
        generation: executor_created.resident_process.generation,
        lease_id: executor_lease.id.0,
        observed_state: ResidentProcessObservedState::Starting,
        pid: None,
        exit_code: None,
        error_code: None,
        error_message: None,
    };
    for response in [
        sidecar_worker_client
            .post(format!(
                "{}/resident-processes/{}/bootstrap",
                server.base_url, executor_created.resident_process.id
            ))
            .json(&executor_bootstrap_request)
            .send()
            .await
            .unwrap(),
        sidecar_worker_client
            .post(format!(
                "{}/resident-processes/{}/observations",
                server.base_url, executor_created.resident_process.id
            ))
            .json(&executor_starting)
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "the authoritative worker must not act as the sandbox-bound executor guest"
        );
    }

    // 5. Fail-closed: the sidecar has been claimed but never reported
    // Running, so orb-executor's one-read bootstrap credential must be
    // refused loudly (503, distinct error code), not silently skipped.
    let blocked = guest_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, executor_created.resident_process.id
        ))
        .json(&executor_bootstrap_request)
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let blocked_body: ErrorEnvelope = blocked.json().await.unwrap();
    assert_eq!(blocked_body.code, "resident_sidecar_unavailable");

    let wrong_worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "wrong-sidecar-worker".into(),
            provider: "kubernetes".into(),
            capabilities: vec![WorkerCapability::ProviderIsolatedResidentProcessV1],
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
    let wrong_worker_client = worker_client(&wrong_worker);
    let sidecar_observation = ResidentProcessObservationRequest {
        generation: sidecar_created.resident_process.generation,
        lease_id: sidecar_lease.id.0,
        observed_state: ResidentProcessObservedState::Running,
        pid: None,
        exit_code: None,
        error_code: None,
        error_message: None,
    };
    assert_eq!(
        wrong_worker_client
            .post(format!(
                "{}/resident-processes/{}/observations",
                server.base_url, sidecar_created.resident_process.id
            ))
            .json(&sidecar_observation)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        wrong_worker_client
            .post(format!(
                "{}/resident-processes/{}/bootstrap",
                server.base_url, sidecar_created.resident_process.id
            ))
            .json(&ResidentProcessBootstrapReadRequest {
                generation: sidecar_created.resident_process.generation,
                lease_id: sidecar_lease.id.0,
                expected_sha256: sidecar_created
                    .resident_process
                    .bootstrap_sha256
                    .clone()
                    .unwrap(),
            })
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // 6. Bring the sidecar to Running.
    sidecar_worker_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, sidecar_created.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: sidecar_created.resident_process.generation,
            lease_id: sidecar_lease.id.0,
            observed_state: ResidentProcessObservedState::Running,
            pid: Some(77),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // A persisted Running observation is not enough: once its lease is no
    // longer active, the fail-closed gate must close before any replacement
    // claim has a chance to overwrite the observation.
    sidecar_worker_client
        .post(format!(
            "{}/leases/{}/fail",
            server.base_url, sidecar_lease.id
        ))
        .json(&FailLeaseRequest {
            error: "sidecar agent disconnected".into(),
            retry: true,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let stale_running = guest_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, executor_created.resident_process.id
        ))
        .json(&executor_bootstrap_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        stale_running.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let replacement_sidecar_lease =
        claim_resident_process_lease(&server, &worker, &sidecar_worker_client, sandbox_id).await;
    sidecar_worker_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, sidecar_created.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: sidecar_created.resident_process.generation,
            lease_id: replacement_sidecar_lease.id.0,
            observed_state: ResidentProcessObservedState::Running,
            pid: Some(78),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // 7. Now the gate opens: orb-executor's bootstrap read succeeds and
    // returns its OWN secret (never the sidecar's).
    let allowed: ResidentProcessBootstrapReadResponse = guest_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, executor_created.resident_process.id
        ))
        .json(&executor_bootstrap_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(allowed.content, b"executor-canary-secret");

    // 8. Delivery remains replayable by this exact lease until Starting
    // acknowledges that the bootstrap file was written atomically.
    let replayed: ResidentProcessBootstrapReadResponse = guest_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, executor_created.resident_process.id
        ))
        .json(&executor_bootstrap_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replayed.content, b"executor-canary-secret");
    guest_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, executor_created.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: executor_created.resident_process.generation,
            lease_id: executor_lease.id.0,
            observed_state: ResidentProcessObservedState::Starting,
            pid: Some(79),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        guest_client
            .post(format!(
                "{}/resident-processes/{}/bootstrap",
                server.base_url, executor_created.resident_process.id
            ))
            .json(&executor_bootstrap_request)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::GONE
    );

    // 9. The sidecar's own bootstrap read is never gated by anything (it is
    // the thing being depended on, not a dependent) and delivers its own
    // secret exactly once, same as any other resident process.
    let sidecar_bootstrap: ResidentProcessBootstrapReadResponse = sidecar_worker_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, sidecar_created.resident_process.id
        ))
        .json(&ResidentProcessBootstrapReadRequest {
            generation: sidecar_created.resident_process.generation,
            lease_id: replacement_sidecar_lease.id.0,
            expected_sha256: sidecar_created
                .resident_process
                .bootstrap_sha256
                .clone()
                .unwrap(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sidecar_bootstrap.content, b"sidecar-canary-secret");

    // A terminal resident transition emits one bounded durable event. A
    // duplicate terminal observation must not create success/heartbeat spam,
    // and the guest-provided error detail must never be copied into the event.
    let terminal_observation = ResidentProcessObservationRequest {
        generation: executor_created.resident_process.generation,
        lease_id: executor_lease.id.0,
        observed_state: ResidentProcessObservedState::Failed,
        pid: None,
        exit_code: Some(1),
        error_code: Some("terminal-error-canary".into()),
        error_message: None,
    };
    for _ in 0..2 {
        guest_client
            .post(format!(
                "{}/resident-processes/{}/observations",
                server.base_url, executor_created.resident_process.id
            ))
            .json(&terminal_observation)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    client
        .post(format!(
            "{}/sandboxes/{sandbox_id}/resident-processes/orb-sidecar/stop",
            server.base_url
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let stopped_renewal = sidecar_worker_client
        .post(format!(
            "{}/leases/{}/renew",
            server.base_url, replacement_sidecar_lease.id
        ))
        .json(&RenewLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(stopped_renewal.status(), reqwest::StatusCode::CONFLICT);
    let stopped_error: ErrorEnvelope = stopped_renewal.json().await.unwrap();
    assert_eq!(stopped_error.code, "resident_process_stopped");

    // 10. Tenant scoping applies identically to the sidecar's own resident-
    // process record as it does to orb-executor's (see the tenant_b check
    // above for orb-executor).
    let tenant_b = reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {TEST_TENANT_B_TOKEN}").parse().unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    assert_eq!(
        tenant_b.get(&sidecar_url).send().await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        tenant_b
            .get(format!("{}/sandboxes/{sandbox_id}/events", server.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    let events: EventListResponse = client
        .get(format!("{}/sandboxes/{sandbox_id}/events", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let blocked_events: Vec<_> = events
        .events
        .iter()
        .filter(|event| event.kind == SandboxEventKind::SidecarBootstrapBlocked)
        .collect();
    assert_eq!(blocked_events.len(), 2);
    assert!(blocked_events.iter().any(|event| {
        event.data["reason"] == "not_running"
            && event.data["processName"] == ORB_SIDECAR_RESIDENT_PROCESS_NAME
            && event.data["generation"] == sidecar_created.resident_process.generation
    }));
    assert!(
        blocked_events
            .iter()
            .any(|event| event.data["reason"] == "inactive_lease")
    );
    let terminal_events: Vec<_> = events
        .events
        .iter()
        .filter(|event| event.kind == SandboxEventKind::ResidentProcessTerminalFailure)
        .collect();
    assert_eq!(terminal_events.len(), 1);
    assert_eq!(
        terminal_events[0].data,
        serde_json::json!({
            "processName": ORB_EXECUTOR_RESIDENT_PROCESS_NAME,
            "generation": executor_created.resident_process.generation,
            "observedState": "failed",
        })
    );
    let event_text = serde_json::to_string(&events).unwrap();
    for secret in [
        "sidecar-canary-secret",
        "executor-canary-secret",
        "terminal-error-canary",
        executor_bootstrap_request.expected_sha256.as_str(),
    ] {
        assert!(!event_text.contains(secret), "event leaked {secret}");
    }

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
    assert!(metrics.contains("# TYPE sandboxwich_resident_process_count gauge"));
    assert!(metrics.contains("sandboxwich_resident_process_count{state=\"failed\"}"));
    assert!(metrics.contains("# TYPE sandboxwich_sidecar_bootstrap_block_total counter"));
    assert!(
        metrics.contains("sandboxwich_sidecar_bootstrap_block_total{reason=\"not_running\"} 1")
    );
    assert!(
        metrics.contains("sandboxwich_sidecar_bootstrap_block_total{reason=\"inactive_lease\"} 1")
    );
    for secret in [
        "sidecar-canary-secret",
        "executor-canary-secret",
        executor_bootstrap_request.expected_sha256.as_str(),
    ] {
        assert!(!metrics.contains(secret), "metrics leaked {secret}");
    }
    assert!(!metrics.contains(&sandbox_id.to_string()));

    // 11. Regression guard: a sandbox that never configures a sidecar at
    // all sees no change in orb-executor's bootstrap behavior -- the gate
    // is opt-in per sandbox, not a new universal requirement.
    let (other_sandbox_id, other_worker, other_guest) =
        provisioned_sandbox_with_guest(&server, "orb-sidecar-contract-no-sidecar", false).await;
    let other_executor_request = resident_process_request(
        "/usr/local/bin/orb-executor",
        b"unsidecared-executor-secret",
        "/run/sandboxwich/bootstrap/orb-token",
    );
    let other_executor_created: ResidentProcessResponse = client
        .put(format!(
            "{}/sandboxes/{}/resident-processes/orb-executor",
            server.base_url, other_sandbox_id
        ))
        .json(&other_executor_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_lease =
        claim_resident_process_lease(&server, &other_worker, &other_guest, other_sandbox_id).await;
    let other_bootstrap: ResidentProcessBootstrapReadResponse = other_guest
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, other_executor_created.resident_process.id
        ))
        .json(&ResidentProcessBootstrapReadRequest {
            generation: other_executor_created.resident_process.generation,
            lease_id: other_lease.id.0,
            expected_sha256: other_executor_created
                .resident_process
                .bootstrap_sha256
                .clone()
                .unwrap(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other_bootstrap.content, b"unsidecared-executor-secret");
}

#[tokio::test]
async fn bootstrap_delivery_handles_starting_before_delivery_and_first_running_ack() {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir.path().join("resident-bootstrap-race.db").display()
        ),
        Some(data_dir),
    )
    .await;
    let (sandbox_id, worker, guest_client) =
        provisioned_sandbox_with_guest(&server, "resident-bootstrap-race", false).await;
    let created: ResidentProcessResponse = server
        .client()
        .put(format!(
            "{}/sandboxes/{sandbox_id}/resident-processes/orb-executor",
            server.base_url
        ))
        .json(&resident_process_request(
            "/usr/local/bin/orb-executor",
            b"concurrent-bootstrap-secret",
            "/run/sandboxwich/bootstrap/orb-token",
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claim_resident_process_lease(&server, &worker, &guest_client, sandbox_id).await;
    let request = ResidentProcessBootstrapReadRequest {
        generation: created.resident_process.generation,
        lease_id: lease.id.0,
        expected_sha256: created.resident_process.bootstrap_sha256.unwrap(),
    };
    let url = format!(
        "{}/resident-processes/{}/bootstrap",
        server.base_url, created.resident_process.id
    );

    guest_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, created.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: request.generation,
            lease_id: request.lease_id,
            observed_state: ResidentProcessObservedState::Starting,
            pid: Some(90),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let mut wrong_hash = request.clone();
    wrong_hash.expected_sha256 = "0".repeat(64);
    assert_eq!(
        guest_client
            .post(&url)
            .json(&wrong_hash)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT,
        "a cache fence failure must restore the bootstrap"
    );
    let mut stale_lease = request.clone();
    stale_lease.lease_id = Uuid::now_v7();
    assert_eq!(
        guest_client
            .post(&url)
            .json(&stale_lease)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT,
        "a database fence failure must restore the bootstrap"
    );

    let lost_response = guest_client.post(&url).json(&request).send().await.unwrap();
    assert!(lost_response.status().is_success());
    drop(lost_response);

    let mut delivered_wrong_hash = request.clone();
    delivered_wrong_hash.expected_sha256 = "f".repeat(64);
    assert_eq!(
        guest_client
            .post(&url)
            .json(&delivered_wrong_hash)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT,
        "a delivered bootstrap must not replay under another digest"
    );
    let mut delivered_wrong_generation = request.clone();
    delivered_wrong_generation.generation += 1;
    assert_eq!(
        guest_client
            .post(&url)
            .json(&delivered_wrong_generation)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT,
        "a delivered bootstrap must not replay under another generation"
    );
    let mut delivered_wrong_lease = request.clone();
    delivered_wrong_lease.lease_id = Uuid::now_v7();
    assert!(
        !guest_client
            .post(&url)
            .json(&delivered_wrong_lease)
            .send()
            .await
            .unwrap()
            .status()
            .is_success(),
        "a delivered bootstrap must not replay under another lease"
    );

    let bootstrap: ResidentProcessBootstrapReadResponse = guest_client
        .post(&url)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bootstrap.content, b"concurrent-bootstrap-secret");

    guest_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, created.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: request.generation,
            lease_id: request.lease_id,
            observed_state: ResidentProcessObservedState::Running,
            pid: Some(91),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    assert_eq!(
        guest_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::GONE,
        "a first Running observation must permanently acknowledge the delivered bootstrap"
    );
}

#[tokio::test]
async fn terminal_and_tenant_stop_paths_reclaim_exact_bootstrap_entries() {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir
                .path()
                .join("resident-bootstrap-reclaim.db")
                .display()
        ),
        Some(data_dir),
    )
    .await;

    for (name, deliver_first, action) in [
        ("terminal-ready", false, "terminal"),
        ("terminal-delivered", true, "terminal"),
        ("resident-stop-ready", false, "resident-stop"),
        ("sandbox-stop-ready", false, "sandbox-stop"),
    ] {
        let (sandbox_id, worker, guest_client) =
            provisioned_sandbox_with_guest(&server, name, false).await;
        let created: ResidentProcessResponse = server
            .client()
            .put(format!(
                "{}/sandboxes/{sandbox_id}/resident-processes/orb-executor",
                server.base_url
            ))
            .json(&resident_process_request(
                "/usr/local/bin/orb-executor",
                name.as_bytes(),
                "/run/sandboxwich/bootstrap/orb-token",
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let lease = claim_resident_process_lease(&server, &worker, &guest_client, sandbox_id).await;
        let request = ResidentProcessBootstrapReadRequest {
            generation: created.resident_process.generation,
            lease_id: lease.id.0,
            expected_sha256: created.resident_process.bootstrap_sha256.clone().unwrap(),
        };
        let bootstrap_url = format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, created.resident_process.id
        );
        if deliver_first {
            guest_client
                .post(&bootstrap_url)
                .json(&request)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }

        match action {
            "terminal" => {
                guest_client
                    .post(format!(
                        "{}/resident-processes/{}/observations",
                        server.base_url, created.resident_process.id
                    ))
                    .json(&ResidentProcessObservationRequest {
                        generation: request.generation,
                        lease_id: request.lease_id,
                        observed_state: ResidentProcessObservedState::Failed,
                        pid: None,
                        exit_code: Some(1),
                        error_code: Some("test-terminal".into()),
                        error_message: None,
                    })
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            "resident-stop" => {
                server
                    .client()
                    .post(format!(
                        "{}/sandboxes/{sandbox_id}/resident-processes/orb-executor/stop",
                        server.base_url
                    ))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            "sandbox-stop" => {
                server
                    .client()
                    .post(format!("{}/sandboxes/{sandbox_id}/stop", server.base_url))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            _ => unreachable!(),
        }

        let expected_status = if action == "sandbox-stop" {
            // Sandbox-wide stop atomically revokes the guest credential as
            // well as reclaiming its resident bootstrap entries.
            reqwest::StatusCode::UNAUTHORIZED
        } else {
            reqwest::StatusCode::GONE
        };
        assert_eq!(
            guest_client
                .post(&bootstrap_url)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            expected_status,
            "{action} must reclaim the exact {name} bootstrap entry"
        );
    }
}
