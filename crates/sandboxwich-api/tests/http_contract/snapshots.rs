use crate::common::*;
use crate::types::placeholders;
use reqwest::StatusCode;
use sandboxwich_core::*;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;

#[tokio::test]
pub(crate) async fn legacy_snapshot_reads_and_expiry_survive_missing_placement_but_restore_fails_closed()
 {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir
                .path()
                .join("legacy-snapshot-placement.db")
                .display()
        ),
        Some(data_dir),
    )
    .await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("legacy-snapshot".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
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
    let snapshot: SnapshotResponse = client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, created.sandbox.id
        ))
        .json(&CreateSnapshotRequest {
            label: Some("legacy".to_string()),
            inventory: None,
            provider_metadata: None,
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
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query(
        "update snapshots
         set status = 'ready', runtime_image = null, provision_spec = null
         where id = ?",
    )
    .bind(snapshot.snapshot.id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "update snapshot_restore_sources
         set status = 'ready', runtime_image = null, provision_spec = null
         where snapshot_id = ?",
    )
    .bind(snapshot.snapshot.id.to_string())
    .execute(&pool)
    .await
    .unwrap();

    let fetched: SnapshotResponse = client
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
    assert!(fetched.snapshot.runtime_image.is_none());
    assert!(fetched.snapshot.provision_spec.is_none());
    let listed: SnapshotListResponse = client
        .get(format!(
            "{}/sandboxes/{}/snapshots",
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
    assert_eq!(listed.snapshots.len(), 1);
    assert!(listed.snapshots[0].runtime_image.is_none());

    let restore = client
        .post(format!(
            "{}/snapshots/{}/fork",
            server.base_url, snapshot.snapshot.id
        ))
        .json(&ForkSnapshotRequest {
            name: Some("must-not-restore".to_string()),
            template: created.sandbox.template.clone(),
            memory_limit: created.sandbox.memory_limit.clone(),
            network_egress: created.sandbox.network_egress.clone(),
            runtime_profile: created.sandbox.runtime_profile.clone(),
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(restore.status(), StatusCode::CONFLICT);
    assert_eq!(
        restore.json::<ErrorEnvelope>().await.unwrap().code,
        "snapshot_placement_unavailable"
    );

    sqlx::query("update snapshots set expires_at = ? where id = ?")
        .bind((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339())
        .bind(snapshot.snapshot.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    client
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let expired: SnapshotResponse = client
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
    assert_eq!(expired.snapshot.status, SnapshotStatus::Expired);
}

#[tokio::test]
pub(crate) async fn apex_snapshot_claim_requires_exact_profile_and_runtime_image() {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir.path().join("apex-snapshot-claim.db").display()
        ),
        Some(data_dir),
    )
    .await;
    let client = server.client();
    let runtime_image = format!("ghcr.io/evalops/apex@sha256:{}", "d".repeat(64));
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("apex-snapshot".to_string()),
            template: Some(runtime_image.clone()),
            memory_limit: Some(MemoryLimit::FourG),
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: Some(WorkspaceMode::Persistent),
            runtime_profile: Some(SandboxRuntimeProfile::ApexTrustedSupervisorV1),
            ttl_seconds: None,
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
    let exact: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "exact-apex-snapshot".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::Snapshot,
                WorkerCapability::ApexTrustedSupervisorV1,
                WorkerCapability::SandboxedContainer,
            ],
            max_concurrent_jobs: Some(1),
            labels: [("runtime_image".to_string(), runtime_image.clone())].into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let provision: ClaimLeaseResponse = worker_client(&exact)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, exact.worker.id
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
    let provision = provision.lease.expect("exact APEX worker claims provision");
    let mut resources = provision_resources(created.sandbox.id);
    for resource in &mut resources {
        resource.runtime_image = Some(runtime_image.clone());
    }
    worker_client(&exact)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: created.sandbox.id,
                    resources,
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, created.sandbox.id
        ))
        .json(&CreateSnapshotRequest {
            label: Some("apex".to_string()),
            inventory: None,
            provider_metadata: None,
            ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let wrong: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "generic-snapshot".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::Snapshot],
            max_concurrent_jobs: Some(1),
            labels: [("runtime_image".to_string(), runtime_image.clone())].into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let wrong_claim: ClaimLeaseResponse = worker_client(&wrong)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, wrong.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
            kinds: Some(vec![JobKind::CreateSnapshot]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(wrong_claim.lease.is_none());

    let exact_claim: ClaimLeaseResponse = worker_client(&exact)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, exact.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
            kinds: Some(vec![JobKind::CreateSnapshot]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = exact_claim
        .lease
        .expect("exact APEX worker claims snapshot");
    assert_eq!(
        lease.job.payload["runtimeImage"],
        serde_json::json!(runtime_image)
    );
}

async fn register_snapshot_worker(
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

#[tokio::test]
async fn snapshot_fork_preserves_vm_execution_class_and_requires_vm_worker() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("snapshot-vm-fork.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let source: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: Some(ExecutionClass::VirtualMachine),
            workspace_mode: Some(WorkspaceMode::Persistent),
            name: Some("snapshot-vm-source".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
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
        .unwrap();
    let vm_worker = register_snapshot_worker(
        &client,
        &server,
        "snapshot-vm-worker",
        vec![
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::Snapshot,
            WorkerCapability::VirtualMachine,
        ],
    )
    .await;
    assert_provision_job_persists_runtime_resources(&client, &server, &source, &vm_worker).await;

    let snapshot: SnapshotResponse = client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, source.sandbox.id
        ))
        .json(&CreateSnapshotRequest {
            label: Some("vm-restore-source".to_string()),
            inventory: None,
            provider_metadata: Some(serde_json::json!({
                "executionClass": "development_container",
                "diagnostic": "provider metadata is not ownership authority"
            })),
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

    let vm_worker_client = worker_client(&vm_worker);
    let snapshot_claim: ClaimLeaseResponse = vm_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, vm_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: Some(vec![JobKind::CreateSnapshot]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let snapshot_lease = snapshot_claim
        .lease
        .expect("VM snapshot worker must claim the VM snapshot job");
    vm_worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, snapshot_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::CreateSnapshot {
                handle: ProviderSnapshotHandle {
                    provider: "kubernetes".to_string(),
                    snapshot_id: snapshot.snapshot.id,
                    resources: snapshot_resources(source.sandbox.id, snapshot.snapshot.id),
                    metadata: serde_json::json!({"executionClass":"development_container"}),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let child: SandboxResponse = client
        .post(format!(
            "{}/snapshots/{}/fork",
            server.base_url, snapshot.snapshot.id
        ))
        .json(&ForkSnapshotRequest {
            name: Some("snapshot-vm-child".to_string()),
            template: source.sandbox.template.clone(),
            memory_limit: source.sandbox.memory_limit.clone(),
            network_egress: source.sandbox.network_egress.clone(),
            ttl_seconds: Some(120),
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
            runtime_profile: source.sandbox.runtime_profile.clone(),
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
        child.sandbox.execution_class,
        ExecutionClass::VirtualMachine
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
    let fork_job = jobs
        .jobs
        .iter()
        .find(|job| {
            job.kind == JobKind::ForkSandbox
                && job.payload["childSandboxId"] == serde_json::json!(child.sandbox.id)
        })
        .expect("snapshot fork must queue a child fork job");
    assert_eq!(
        fork_job.required_execution_class,
        ExecutionClass::VirtualMachine
    );
    assert_eq!(
        fork_job.payload["provisionSpec"]["execution_class"],
        serde_json::json!(ExecutionClass::VirtualMachine)
    );

    let development_worker = register_snapshot_worker(
        &client,
        &server,
        "snapshot-development-worker",
        vec![WorkerCapability::Snapshot],
    )
    .await;
    let development_claim: ClaimLeaseResponse = worker_client(&development_worker)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, development_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: Some(vec![JobKind::ForkSandbox]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        development_claim.lease.is_none(),
        "a development worker must not claim a VM snapshot fork"
    );

    let vm_claim: ClaimLeaseResponse = vm_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, vm_worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: Some(vec![JobKind::ForkSandbox]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let vm_fork_lease = vm_claim
        .lease
        .expect("a VM-capable snapshot worker must claim the VM fork job");
    assert_eq!(vm_fork_lease.job.id, fork_job.id);
    assert_eq!(
        vm_fork_lease.required_execution_class,
        ExecutionClass::VirtualMachine
    );
}

pub(crate) async fn assert_provision_job_persists_runtime_resources(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
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
        .expect("create must atomically queue a provision job");
    assert_eq!(queued.status, JobStatus::Queued);

    let worker_client = worker_client(worker);
    let lease = loop {
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
            .expect("expected worker to claim provision job");
        if lease.job.id == queued.id {
            break lease;
        }
        let response = worker_client
            .post(format!("{}/leases/{}/fail", server.base_url, lease.id))
            .json(&FailLeaseRequest {
                error: "unrelated contract fixture job".to_string(),
                retry: false,
            })
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "unexpected drain completion: {} {}",
            response.status(),
            response.text().await.unwrap()
        );
    };

    let completed: LeaseResponse = worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
                    sandbox_id: sandbox.sandbox.id,
                    resources: {
                        let mut resources = provision_resources(sandbox.sandbox.id);
                        resources.push(provider_resource(
                            sandbox.sandbox.id,
                            None,
                            RuntimeResourceKind::NetworkPolicy,
                            RuntimeResourcePurpose::Network,
                            format!("sandboxwich-fqdn-egress-{}", sandbox.sandbox.id),
                        ));
                        resources
                    },
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

pub(crate) async fn assert_runtime_resource_reconcile_marks_missing_resources_deleted(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let worker_api = worker_client(worker);
    let mut observed = provision_resources(sandbox.sandbox.id);
    observed.retain(|resource| {
        resource.resource_kind != RuntimeResourceKind::Service
            || resource.purpose == RuntimeResourcePurpose::Ssh
    });
    let reconciled: ReconcileRuntimeResourcesResponse = worker_api
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
    assert_eq!(reconciled.upserted.len(), 4);
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
    let edge_reconciled: ReconcileRuntimeResourcesResponse = worker_api
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
    assert_eq!(edge_reconciled.upserted.len(), 5);
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

pub(crate) async fn assert_snapshot_fork_and_cleanup_lifecycle(
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
            labels: [
                ("cluster".to_string(), "k3s-dev".to_string()),
                ("provider_mode".to_string(), "apply".to_string()),
                (
                    "runtime_image".to_string(),
                    "image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
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
    let snapshot_worker_client = worker_client(&snapshot_worker);

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

    let snapshot_claimed: ClaimLeaseResponse = snapshot_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
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
    let snapshot_lease = snapshot_claimed
        .lease
        .expect("expected snapshot worker to claim manual snapshot job");
    assert_eq!(snapshot_lease.job.kind, JobKind::CreateSnapshot);
    assert_eq!(
        snapshot_lease.job.payload["runtimeImage"],
        serde_json::json!(sandbox.sandbox.template)
    );
    assert_eq!(
        snapshot_lease.job.payload["provisionSpec"]["runtime_profile"],
        serde_json::json!(sandbox.sandbox.runtime_profile)
    );
    let snapshot_id = snapshot.snapshot.id.to_string();
    assert_eq!(
        snapshot_lease
            .job
            .payload
            .get("snapshotId")
            .and_then(|value| value.as_str()),
        Some(snapshot_id.as_str())
    );
    let completed_snapshot: LeaseResponse = snapshot_worker_client
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
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cleanup.cleanup_run.status, CleanupRunStatus::Succeeded);
    assert!(cleanup.cleanup_run.finished_at.is_some());
    // This server runs the background expiry sweeper (see
    // `start_with_expiry_sweeper`), and `expire_due_snapshots` is shared by
    // that sweeper and the cleanup controller. Whichever fires first expires
    // the due snapshot, so whether it shows up in *this* cleanup run's
    // `expired` list is a race by design. Assert on the outcome — the due
    // snapshot ends up expired — instead of on which actor expired it.
    poll_until(|| async {
        let response: SnapshotResponse = client
            .get(format!(
                "{}/snapshots/{}",
                server.base_url, expiring.snapshot.id
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        (response.snapshot.status == SnapshotStatus::Expired).then_some(response)
    })
    .await
    .expect("due snapshot should be expired by the cleanup run or the background sweep");

    let archived: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("cleanup-me".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(0),
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
    let lease = claimed.lease.expect("cleanup sandbox stop must be claimed");
    assert_eq!(lease.job.kind, JobKind::StopSandbox);
    worker_client
        .post(format!("{}/leases/{}/complete", server.base_url, lease.id))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id: archived.sandbox.id,
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let cleanup: SnapshotCleanupResponse = client
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
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
            && resource.status == RuntimeResourceStatus::Destroyed
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
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("contract-child".to_string()),
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
    assert_eq!(
        forked.operation.as_ref().map(|operation| &operation.kind),
        Some(&OperationKind::ForkSandbox)
    );
    assert_eq!(forked.sandbox.state, SandboxState::Planning);
    let fork_snapshot_id = forked
        .sandbox
        .parent_snapshot_id
        .expect("fork should point at a real snapshot");

    // The `sandboxes.parent_snapshot_id -> snapshot_restore_sources(snapshot_id)`
    // foreign key is `on delete restrict` (see
    // `postgres_sandbox_parent_snapshot_fk_statements` /
    // `sqlite_rebuild_sandboxes_with_parent_snapshot_fk` in `db.rs`; the FK
    // targets `snapshot_restore_sources`, not `snapshots`, precisely so that
    // deleting the `snapshots` row itself -- which legitimately happens via
    // cascade once its owning sandbox is cleaned up, see
    // `platform_provider_lifecycle_contract_is_tenant_bound_idempotent_and_correlated`
    // -- keeps working). `forked.sandbox` now references `fork_snapshot_id`,
    // so directly deleting its `snapshot_restore_sources` row -- bypassing
    // every application-level guard, since nothing in this codebase ever
    // does this deliberately -- must be rejected by the database itself
    // rather than silently orphaning `forked.sandbox`'s lineage.
    assert_deleting_referenced_snapshot_restore_source_is_rejected(server, fork_snapshot_id).await;

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

    let claimed_snapshot: ClaimLeaseResponse = snapshot_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
        ))
        .header("x-sandboxwich-job-id", fork_snapshot_job.id.to_string())
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
    let snapshot_lease = claimed_snapshot
        .lease
        .expect("expected snapshot worker to claim fork snapshot job");
    assert_eq!(snapshot_lease.job.id, fork_snapshot_job.id);

    let completed_fork_snapshot: LeaseResponse = snapshot_worker_client
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

    let claimed: ClaimLeaseResponse = snapshot_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
        ))
        .header("x-sandboxwich-job-id", fork_job.id.to_string())
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

    let completed: LeaseResponse = snapshot_worker_client
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

    let failed_fork: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/fork",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("failed-child".to_string()),
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
    assert_eq!(failed_fork.sandbox.state, SandboxState::Planning);
    let failed_snapshot_id = failed_fork
        .sandbox
        .parent_snapshot_id
        .expect("failed fork should point at a source snapshot");
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
    let failed_snapshot_job = job_for_snapshot(&jobs.jobs, &failed_snapshot_id.to_string());
    let claimed_failed_snapshot: ClaimLeaseResponse = snapshot_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, snapshot_worker.worker.id
        ))
        .header("x-sandboxwich-job-id", failed_snapshot_job.id.to_string())
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
    let failed_snapshot_lease = claimed_failed_snapshot
        .lease
        .expect("expected snapshot worker to claim failing fork snapshot job");
    assert_eq!(failed_snapshot_lease.job.id, failed_snapshot_job.id);
    let failed: LeaseResponse = snapshot_worker_client
        .post(format!(
            "{}/leases/{}/fail",
            server.base_url, failed_snapshot_lease.id
        ))
        .json(&FailLeaseRequest {
            error: "source snapshot failed".to_string(),
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
    // A permanently failed fork has no placement proof, so the public GET
    // intentionally fails closed. Verify the durable lifecycle transition
    // directly instead of weakening the placement-proof contract.
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    let row = sqlx::query(&format!(
        "select state from sandboxes where id = {}",
        crate::types::placeholders(&server.database_url, 1)
    ))
    .bind(failed_fork.sandbox.id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    let state: String = row.try_get("state").unwrap();
    assert_eq!(state, SandboxState::Error.as_db_str());
    pool.close().await;
}

/// Connects directly to the server's database and attempts to delete the
/// `snapshot_restore_sources` row that some sandbox's `parent_snapshot_id`
/// still points at. The `on delete restrict` foreign key (see `db.rs`) must
/// reject this on both backends, proving the constraint -- not just
/// application code -- is what stops that lineage record from disappearing
/// out from under a sandbox.
///
/// This deliberately does *not* test deleting the `snapshots` row itself:
/// that delete is expected to succeed (it happens for real, via cascade, once
/// the snapshot's owning sandbox is cleaned up -- see
/// `platform_provider_lifecycle_contract_is_tenant_bound_idempotent_and_correlated`),
/// which is exactly why the foreign key targets `snapshot_restore_sources`
/// instead.
pub(crate) async fn assert_deleting_referenced_snapshot_restore_source_is_rejected(
    server: &TestServer,
    referenced_snapshot_id: SnapshotId,
) {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();

    let sql = format!(
        "delete from snapshot_restore_sources where snapshot_id = {}",
        placeholders(&server.database_url, 1)
    );
    let result = sqlx::query(&sql)
        .bind(referenced_snapshot_id.to_string())
        .execute(&pool)
        .await;
    assert!(
        result.is_err(),
        "deleting a snapshot_restore_sources row still referenced by a sandbox's \
         parent_snapshot_id must be rejected by the on-delete-restrict foreign key"
    );

    let still_present_count: i64 = sqlx::query(&format!(
        "select count(*) as count from snapshot_restore_sources where snapshot_id = {}",
        placeholders(&server.database_url, 1)
    ))
    .bind(referenced_snapshot_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(
        still_present_count, 1,
        "the referenced snapshot_restore_sources row must survive the rejected delete"
    );
}
