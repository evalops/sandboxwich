use crate::common::*;
use sandboxwich_core::*;
use std::collections::BTreeMap;

/// Provisions a sandbox and worker, completes the `ProvisionSandbox` job, and
/// mints a guest token bound to that sandbox -- the shared setup every
/// resident-process test below needs before it can PUT/claim/bootstrap.
/// Returns `(sandbox_id, worker, guest_client)`; claims still go through
/// `/workers/{worker.worker.id}/leases/claim`, authenticated as the guest.
async fn provisioned_sandbox_with_guest(
    server: &TestServer,
    name: &str,
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
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
                WorkerCapability::UidIsolatedResidentProcess,
            ],
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
        provisioned_sandbox_with_guest(&server, "orb-sidecar-contract").await;

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
    guest_client
        .post(format!(
            "{}/sandboxes/{sandbox_id}/guest-health",
            server.base_url
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/old".into()),
            checks: Some(serde_json::json!({
                "exec": {"status": "ok"},
                "files": {"status": "ok"}
            })),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let unsupported_agent = client
        .put(&sidecar_url)
        .json(&sidecar_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        unsupported_agent.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    for unsupported_report in [
        serde_json::json!({
            "protocolVersion": 2,
            "capabilities": {
                "uidIsolatedResidentProcess": {"status": "ok", "version": 1}
            }
        }),
        serde_json::json!({
            "protocolVersion": 1,
            "capabilities": {
                "uidIsolatedResidentProcess": {"status": "ok", "version": 2}
            }
        }),
    ] {
        guest_client
            .post(format!(
                "{}/sandboxes/{sandbox_id}/guest-health",
                server.base_url
            ))
            .json(&UpdateGuestHealthRequest {
                status: GuestStatus::Ready,
                agent_version: Some("sandboxwich-agent/future".into()),
                checks: Some(serde_json::json!({
                    (GUEST_AGENT_CAPABILITY_REPORT_CHECK): unsupported_report
                })),
                message: None,
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let unsupported_agent = client
            .put(&sidecar_url)
            .json(&sidecar_request)
            .send()
            .await
            .unwrap();
        assert_eq!(
            unsupported_agent.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
    }
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

    // 4. A downgraded/old guest agent may still claim orb-executor, but it
    // cannot claim orb-sidecar and silently run it without uid isolation.
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
    let sidecar_lease =
        claim_resident_process_lease(&server, &worker, &guest_client, sandbox_id).await;
    assert_eq!(
        sidecar_lease.job.required_capability,
        WorkerCapability::UidIsolatedResidentProcess
    );
    assert_eq!(
        executor_lease.job.required_capability,
        WorkerCapability::RunCommand
    );

    let executor_bootstrap_request = ResidentProcessBootstrapReadRequest {
        generation: executor_created.resident_process.generation,
        lease_id: executor_lease.id.0,
        expected_sha256: executor_created
            .resident_process
            .bootstrap_sha256
            .clone()
            .unwrap(),
    };

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

    // 6. Bring the sidecar to Running.
    guest_client
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
    guest_client
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
        claim_resident_process_lease(&server, &worker, &guest_client, sandbox_id).await;
    guest_client
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

    // 8. One-read semantics are unaffected by the new gate: a repeat read is
    // GONE, not re-blocked as unavailable.
    let repeat_status = guest_client
        .post(format!(
            "{}/resident-processes/{}/bootstrap",
            server.base_url, executor_created.resident_process.id
        ))
        .json(&executor_bootstrap_request)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(repeat_status, reqwest::StatusCode::GONE);

    // 9. The sidecar's own bootstrap read is never gated by anything (it is
    // the thing being depended on, not a dependent) and delivers its own
    // secret exactly once, same as any other resident process.
    let sidecar_bootstrap: ResidentProcessBootstrapReadResponse = guest_client
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

    // 11. Regression guard: a sandbox that never configures a sidecar at
    // all sees no change in orb-executor's bootstrap behavior -- the gate
    // is opt-in per sandbox, not a new universal requirement.
    let (other_sandbox_id, other_worker, other_guest) =
        provisioned_sandbox_with_guest(&server, "orb-sidecar-contract-no-sidecar").await;
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
