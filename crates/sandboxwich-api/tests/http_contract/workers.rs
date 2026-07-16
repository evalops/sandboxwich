use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

async fn register_execution_worker(
    client: &reqwest::Client,
    server: &TestServer,
    name: &str,
    capabilities: Vec<WorkerCapability>,
) -> WorkerResponse {
    client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: name.to_string(),
            provider: "kubernetes".to_string(),
            capabilities,
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
        .unwrap()
}

async fn create_execution_sandbox(
    client: &reqwest::Client,
    server: &TestServer,
    name: &str,
    execution_class: ExecutionClass,
    network_egress: Option<NetworkEgress>,
) -> SandboxResponse {
    client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: Some(execution_class),
            workspace_mode: None,
            name: Some(name.to_string()),
            template: None,
            memory_limit: None,
            network_egress,
            ttl_seconds: Some(120),
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
            runtime_profile: None,
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

async fn claim_execution_job(
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
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::ProvisionSandbox]),
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

#[tokio::test]
async fn workers_claim_only_jobs_matching_functional_and_execution_requirements() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("execution-routing.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let development = register_execution_worker(
        &client,
        &server,
        "execution-development",
        vec![WorkerCapability::ProvisionSandbox],
    )
    .await;
    let sandboxed = register_execution_worker(
        &client,
        &server,
        "execution-sandboxed",
        vec![
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::SandboxedContainer,
        ],
    )
    .await;
    let virtual_machine = register_execution_worker(
        &client,
        &server,
        "execution-vm",
        vec![
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::VirtualMachine,
        ],
    )
    .await;
    let sandboxed_only = register_execution_worker(
        &client,
        &server,
        "execution-sandboxed-only",
        vec![WorkerCapability::SandboxedContainer],
    )
    .await;
    let vm_only = register_execution_worker(
        &client,
        &server,
        "execution-vm-only",
        vec![WorkerCapability::VirtualMachine],
    )
    .await;

    let development_sandbox = create_execution_sandbox(
        &client,
        &server,
        "execution-development",
        ExecutionClass::DevelopmentContainer,
        None,
    )
    .await;
    assert!(
        claim_execution_job(&server, &sandboxed_only, development_sandbox.sandbox.id)
            .await
            .is_none(),
        "sandboxed execution support must not replace the ProvisionSandbox functional capability"
    );
    assert!(
        claim_execution_job(&server, &vm_only, development_sandbox.sandbox.id)
            .await
            .is_none(),
        "VM execution support must not replace the ProvisionSandbox functional capability"
    );
    assert!(
        claim_execution_job(&server, &development, development_sandbox.sandbox.id)
            .await
            .is_some()
    );

    let sandboxed_sandbox = create_execution_sandbox(
        &client,
        &server,
        "execution-sandboxed",
        ExecutionClass::SandboxedContainer,
        None,
    )
    .await;
    assert!(
        claim_execution_job(&server, &virtual_machine, sandboxed_sandbox.sandbox.id)
            .await
            .is_none()
    );
    let sandboxed_lease = claim_execution_job(&server, &sandboxed, sandboxed_sandbox.sandbox.id)
        .await
        .expect("sandboxed worker should claim sandboxed-container work");
    assert_eq!(
        sandboxed_lease.required_execution_class,
        ExecutionClass::SandboxedContainer
    );

    let vm_sandbox = create_execution_sandbox(
        &client,
        &server,
        "execution-vm",
        ExecutionClass::VirtualMachine,
        None,
    )
    .await;
    assert!(
        claim_execution_job(&server, &sandboxed, vm_sandbox.sandbox.id)
            .await
            .is_none()
    );
    let vm_lease = claim_execution_job(&server, &virtual_machine, vm_sandbox.sandbox.id)
        .await
        .expect("VM worker should claim virtual-machine work");
    assert_eq!(
        vm_lease.required_execution_class,
        ExecutionClass::VirtualMachine
    );

    let fqdn_only = register_execution_worker(
        &client,
        &server,
        "execution-fqdn-only",
        vec![WorkerCapability::FqdnEgress],
    )
    .await;
    let vm_and_fqdn = register_execution_worker(
        &client,
        &server,
        "execution-vm-fqdn",
        vec![
            WorkerCapability::VirtualMachine,
            WorkerCapability::FqdnEgress,
        ],
    )
    .await;
    let vm_fqdn_sandbox = create_execution_sandbox(
        &client,
        &server,
        "execution-vm-fqdn",
        ExecutionClass::VirtualMachine,
        Some(NetworkEgress::Allowlist {
            rules: vec![NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        }),
    )
    .await;
    assert!(
        claim_execution_job(&server, &vm_only, vm_fqdn_sandbox.sandbox.id)
            .await
            .is_none()
    );
    assert!(
        claim_execution_job(&server, &fqdn_only, vm_fqdn_sandbox.sandbox.id)
            .await
            .is_none()
    );
    let vm_fqdn_lease = claim_execution_job(&server, &vm_and_fqdn, vm_fqdn_sandbox.sandbox.id)
        .await
        .expect("worker satisfying both predicates should claim VM+FQDN work");
    assert_eq!(
        vm_fqdn_lease.job.required_capability,
        WorkerCapability::FqdnEgress
    );
    assert_eq!(
        vm_fqdn_lease.required_execution_class,
        ExecutionClass::VirtualMachine
    );
}

#[tokio::test]
pub(crate) async fn runtime_resource_inventory_is_worker_scoped_and_bounded() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("worker-inventory-test.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let registered: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "inventory-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::ProvisionSandbox],
            max_concurrent_jobs: Some(1),
            labels: std::collections::BTreeMap::from([(
                "cluster".to_string(),
                "kind-inventory".to_string(),
            )]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let worker = worker_client(&registered);

    let response = worker
        .get(format!(
            "{}/workers/{}/runtime-resource-inventory?namespace=sandboxwich-sandboxes&limit=1",
            server.base_url, registered.worker.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let inventory: RuntimeResourceInventoryResponse = response.json().await.unwrap();
    assert!(inventory.ok);
    assert_eq!(inventory.provider, "kubernetes");
    assert_eq!(inventory.cluster.as_deref(), Some("kind-inventory"));
    assert_eq!(inventory.namespace, "sandboxwich-sandboxes");
    assert!(inventory.sandbox_ids.is_empty());
    assert!(inventory.complete);
    assert!(inventory.resources.is_empty());
    assert!(inventory.next_cursor.is_none());

    let sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("inventory-sandbox".to_string()),
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
    let pre_ack_inventory: RuntimeResourceInventoryResponse = worker
        .get(format!(
            "{}/workers/{}/runtime-resource-inventory?namespace=sandboxwich-sandboxes",
            server.base_url, registered.worker.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(pre_ack_inventory.sandbox_ids.contains(&sandbox.sandbox.id));
    assert!(pre_ack_inventory.resources.is_empty());
    let claimed: ClaimLeaseResponse = worker
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, registered.worker.id
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
    let lease = claimed.lease.expect("claim provisioning lease");
    for request in [
        ProvisioningStageUpdateRequest {
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
        },
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspaceReady,
            resource_kind: Some(RuntimeResourceKind::PersistentVolumeClaim),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-pvc-{}", sandbox.sandbox.id)),
            resource_uid: Some("uid-inventory-workspace".to_string()),
            observed_generation: None,
            attempt_count: lease.attempt,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    ] {
        worker
            .put(format!(
                "{}/leases/{}/provisioning",
                server.base_url, lease.id
            ))
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    let replacement: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "inventory-worker-replacement".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::ProvisionSandbox],
            max_concurrent_jobs: Some(1),
            labels: std::collections::BTreeMap::from([(
                "cluster".to_string(),
                "kind-inventory".to_string(),
            )]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let replacement_inventory: RuntimeResourceInventoryResponse = worker_client(&replacement)
        .get(format!(
            "{}/workers/{}/runtime-resource-inventory?namespace=sandboxwich-sandboxes",
            server.base_url, replacement.worker.id
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
        replacement_inventory
            .sandbox_ids
            .contains(&sandbox.sandbox.id)
    );
    assert_eq!(replacement_inventory.resources.len(), 1);
    assert_eq!(
        replacement_inventory.resources[0].uid,
        "uid-inventory-workspace"
    );
    assert!(replacement_inventory.resources[0].expires_at.is_some());
    assert!(
        replacement_inventory.resources[0]
            .cleanup_deadline
            .is_none()
    );
}

/// Regression test for issue #64: the guest agent running inside a sandbox
/// previously authenticated with the same tenant-wide bearer token the CLI
/// uses for everything, so any compromised sandbox could act as the whole
/// tenant (claim/forge any lease, post guest-health for any sandbox, etc).
/// Workers now get a distinct, worker-scoped credential minted at
/// registration, and every guest-facing route (lease
/// claim/renew/complete/fail/output, guest-health) rejects tenant-wide
/// tokens outright and enforces that a worker-scoped token can only act on
/// its own worker id, its own leases, and sandboxes it has actually
/// provisioned.
#[tokio::test]
pub(crate) async fn worker_scoped_tokens_enforce_guest_route_boundaries() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-worker-scope-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    async fn register(client: &reqwest::Client, server: &TestServer, name: &str) -> WorkerResponse {
        client
            .post(format!("{}/workers/register", server.base_url))
            .json(&RegisterWorkerRequest {
                name: name.to_string(),
                provider: "kubernetes".to_string(),
                capabilities: vec![
                    WorkerCapability::ProvisionSandbox,
                    WorkerCapability::RunCommand,
                ],
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

    let first_worker_a = register(&client, &server, "worker-scope-a").await;
    let worker_a = register(&client, &server, "worker-scope-a").await;
    let worker_b = register(&client, &server, "worker-scope-b").await;
    assert_eq!(first_worker_a.worker.id, worker_a.worker.id);
    assert_ne!(first_worker_a.worker_token, worker_a.worker_token);
    assert!(worker_a.worker_token.is_some());
    assert!(worker_b.worker_token.is_some());
    assert_ne!(worker_a.worker_token, worker_b.worker_token);
    let worker_a_client = worker_client(&worker_a);
    let worker_b_client = worker_client(&worker_b);

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

    let sandbox_a = create_sandbox(&client, &server, "worker-scope-sandbox-a").await;
    let sandbox_b = create_sandbox(&client, &server, "worker-scope-sandbox-b").await;

    // A worker only "owns" a sandbox (for guest-health purposes) once it has
    // completed a provision lease for it, so give each worker exactly one
    // sandbox this way before attacking across the boundary.
    async fn provision(
        client: &reqwest::Client,
        worker_client: &reqwest::Client,
        server: &TestServer,
        worker: &WorkerResponse,
        sandbox: &SandboxResponse,
    ) {
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
        let queued = jobs
            .jobs
            .into_iter()
            .find(|job| {
                job.kind == JobKind::ProvisionSandbox
                    && job.payload["sandboxId"] == serde_json::json!(sandbox.sandbox.id)
            })
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
            .expect("worker should claim its own provision job");
        assert_eq!(lease.job.id, queued.id);
        let completed: LeaseResponse = worker_client
            .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
            .json(&CompleteLeaseRequest {
                result: Some(WorkerJobResult::ProvisionSandbox {
                    handle: ProviderSandboxHandle {
                        provider: "kubernetes".to_string(),
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
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(completed.lease.job.status, JobStatus::Succeeded);
    }

    provision(&client, &worker_a_client, &server, &worker_a, &sandbox_a).await;
    provision(&client, &worker_b_client, &server, &worker_b, &sandbox_b).await;

    let guest_token: GuestTokenResponse = worker_a_client
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker_a.worker.id, sandbox_a.sandbox.id
        ))
        .json(&MintGuestTokenRequest {
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
    assert_eq!(guest_token.sandbox_id, sandbox_a.sandbox.id);
    assert!(guest_token.token.starts_with("sbw_gtok_"));
    let guest_client = build_api_client(Some(&guest_token.token), None).unwrap();

    let guest_heartbeat = guest_client
        .post(format!(
            "{}/workers/{}/heartbeat",
            server.base_url, worker_a.worker.id
        ))
        .json(&WorkerHeartbeatRequest {
            max_concurrent_jobs: None,
            labels: Default::default(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(guest_heartbeat.status(), StatusCode::UNAUTHORIZED);

    let cross_sandbox_guest_claim = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker_a.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_b.sandbox.id),
            kinds: Some(vec![JobKind::RunCommand]),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_sandbox_guest_claim.status(), StatusCode::BAD_REQUEST);

    let replacement_token: GuestTokenResponse = worker_a_client
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker_a.worker.id, sandbox_a.sandbox.id
        ))
        .json(&MintGuestTokenRequest {
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
    let revoked_claim = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker_a.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_a.sandbox.id),
            kinds: Some(vec![JobKind::RunCommand]),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_claim.status(), StatusCode::UNAUTHORIZED);
    let guest_client = build_api_client(Some(&replacement_token.token), None).unwrap();

    // Give worker A a real active lease (a RunCommand job for its own
    // sandbox) to attack from worker B and from a tenant-wide token.
    let command: QueueCommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox_a.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["true".to_string()],
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
    let unscoped_guest_claim = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker_a.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(unscoped_guest_claim.status(), StatusCode::BAD_REQUEST);

    let claimed: ClaimLeaseResponse = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker_a.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox_a.sandbox.id),
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
    let lease_a = claimed
        .lease
        .expect("worker A should claim its own command job");
    assert_eq!(lease_a.job.id, command.queued_job.id);

    // (a) worker B's token cannot claim on worker A's behalf, ...
    let cross_claim = worker_b_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker_a.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_claim.status(), StatusCode::NOT_FOUND);

    // ... cannot renew worker A's lease, ...
    let cross_renew = worker_b_client
        .post(format!("{}/leases/{}/renew", server.base_url, lease_a.id))
        .json(&RenewLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_renew.status(), StatusCode::NOT_FOUND);

    // ... cannot append output to worker A's lease, ...
    let cross_output = worker_b_client
        .post(format!("{}/leases/{}/output", server.base_url, lease_a.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "attack".to_string(),
            annotations: Vec::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_output.status(), StatusCode::NOT_FOUND);

    // ... cannot complete worker A's lease, ...
    let cross_complete = worker_b_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, lease_a.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(command_result("owned\n", "", 0)),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_complete.status(), StatusCode::NOT_FOUND);

    // ... cannot fail worker A's lease, ...
    let cross_fail = worker_b_client
        .post(format!("{}/leases/{}/fail", server.base_url, lease_a.id))
        .json(&FailLeaseRequest {
            error: "attack".to_string(),
            retry: false,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_fail.status(), StatusCode::NOT_FOUND);

    // ... and cannot post guest-health for sandbox A, which worker B never
    // provisioned.
    let cross_health = worker_b_client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, sandbox_a.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: None,
            checks: None,
            message: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_health.status(), StatusCode::NOT_FOUND);

    // (b) a tenant-wide token is rejected outright on every guest-facing
    // route, even acting on its own tenant's worker/lease/sandbox -- the
    // whole point is that a sandbox holding only the tenant token (the
    // pre-fix state) must never be able to reach these routes at all.
    let tenant_claim = client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker_a.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_claim.status(), StatusCode::UNAUTHORIZED);

    let tenant_renew = client
        .post(format!("{}/leases/{}/renew", server.base_url, lease_a.id))
        .json(&RenewLeaseRequest {
            lease_seconds: Some(60),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_renew.status(), StatusCode::UNAUTHORIZED);

    let tenant_output = client
        .post(format!("{}/leases/{}/output", server.base_url, lease_a.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "attack".to_string(),
            annotations: Vec::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_output.status(), StatusCode::UNAUTHORIZED);

    let tenant_fail = client
        .post(format!("{}/leases/{}/fail", server.base_url, lease_a.id))
        .json(&FailLeaseRequest {
            error: "attack".to_string(),
            retry: false,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_fail.status(), StatusCode::UNAUTHORIZED);

    let tenant_health = client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, sandbox_a.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: None,
            checks: None,
            message: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_health.status(), StatusCode::UNAUTHORIZED);

    // Checked last (and left the lease untouched by every attack above): a
    // tenant-wide token cannot complete worker A's lease either.
    let tenant_complete = client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, lease_a.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(command_result("owned\n", "", 0)),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_complete.status(), StatusCode::UNAUTHORIZED);

    // (c) the happy path still works end to end: worker A can append
    // output to, renew, and complete its own lease; worker B can post
    // guest-health for its own sandbox.
    let output: sandboxwich_core::CommandOutputChunkResponse = guest_client
        .post(format!("{}/leases/{}/output", server.base_url, lease_a.id))
        .json(&AppendCommandOutputRequest {
            stream: CommandOutputStream::Stdout,
            chunk: "ok".to_string(),
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
    assert_eq!(output.chunk.sequence, 1);

    let renewed: LeaseResponse = guest_client
        .post(format!("{}/leases/{}/renew", server.base_url, lease_a.id))
        .json(&RenewLeaseRequest {
            lease_seconds: Some(120),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(renewed.lease.id, lease_a.id);

    let completed: LeaseResponse = guest_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, lease_a.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(command_result("ok\n", "", 0)),
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

    let health: GuestHealthResponse = worker_b_client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, sandbox_b.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/test".to_string()),
            checks: None,
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
    assert_eq!(health.guest_health.status, GuestStatus::Ready);

    let expiring_token: GuestTokenResponse = worker_a_client
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker_a.worker.id, sandbox_a.sandbox.id
        ))
        .json(&MintGuestTokenRequest {
            ttl_seconds: Some(1),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let expired_client = build_api_client(Some(&expiring_token.token), None).unwrap();
    let expired_health = expired_client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, sandbox_a.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: None,
            checks: None,
            message: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(expired_health.status(), StatusCode::UNAUTHORIZED);

    let draining: WorkerResponse = worker_a_client
        .post(format!(
            "{}/workers/{}/drain",
            server.base_url, worker_a.worker.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(draining.worker.status, WorkerStatus::Draining);
}

pub(crate) async fn assert_guest_health_and_ssh_key_lifecycle(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    // GH-64: guest-health updates are guest-facing and require a
    // worker-scoped token bound to the worker that provisioned/forked this
    // sandbox; the read side (GET) stays on the tenant client since
    // CLI/dashboard callers need to read it too.
    let worker_client = worker_client(worker);

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

    let ready_health: GuestHealthResponse = worker_client
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

    let unhealthy_health: GuestHealthResponse = worker_client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Unhealthy,
            agent_version: Some("sandboxwich-agent/test".to_string()),
            checks: Some(serde_json::json!({
                "exec": {"status": "failed"}
            })),
            message: Some("exec stream failed".to_string()),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unhealthy_health.guest_health.status, GuestStatus::Unhealthy);

    let health_events: EventListResponse = client
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
    assert!(health_events.events.iter().any(|event| {
        event.kind == SandboxEventKind::GuestHealthFailed
            && event.data["reason"] == serde_json::json!("guest_unhealthy")
    }));

    let _: GuestHealthResponse = worker_client
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
