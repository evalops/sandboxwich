use crate::common::*;
use sandboxwich_core::*;
use std::collections::BTreeMap;

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
