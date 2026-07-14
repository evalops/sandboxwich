use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

#[tokio::test]
async fn execution_class_defaults_persists_and_inherits_through_fork() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("execution-class.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let defaulted: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("execution-default".to_string()),
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
    assert_eq!(
        defaulted.sandbox.execution_class,
        ExecutionClass::DevelopmentContainer
    );

    let vm: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: Some(ExecutionClass::VirtualMachine),
            workspace_mode: None,
            name: Some("execution-vm".to_string()),
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
    assert_eq!(vm.sandbox.execution_class, ExecutionClass::VirtualMachine);

    let fetched: SandboxResponse = client
        .get(format!("{}/sandboxes/{}", server.base_url, vm.sandbox.id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        fetched.sandbox.execution_class,
        ExecutionClass::VirtualMachine
    );

    let child: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/fork",
            server.base_url, vm.sandbox.id
        ))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("execution-vm-child".to_string()),
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
    assert_eq!(
        child.sandbox.execution_class,
        ExecutionClass::VirtualMachine
    );
}

#[tokio::test]
async fn disposable_workspace_mode_round_trips_and_rejects_durable_operations() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-workspace-mode.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: Some(WorkspaceMode::Ephemeral),
            name: Some("disposable-contract".to_string()),
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
    assert_eq!(created.sandbox.workspace_mode, WorkspaceMode::Ephemeral);

    let fetched: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
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
    assert_eq!(fetched.sandbox.workspace_mode, WorkspaceMode::Ephemeral);

    let snapshot = client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, created.sandbox.id
        ))
        .json(&CreateSnapshotRequest {
            label: None,
            inventory: None,
            provider_metadata: None,
            ttl_seconds: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(snapshot.status(), StatusCode::CONFLICT);
    assert_eq!(
        snapshot.json::<ErrorEnvelope>().await.unwrap().code,
        "workspace_mode_snapshot_unsupported"
    );

    let fork = client
        .post(format!(
            "{}/sandboxes/{}/fork",
            server.base_url, created.sandbox.id
        ))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("unsupported-child".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(fork.status(), StatusCode::CONFLICT);
    assert_eq!(
        fork.json::<ErrorEnvelope>().await.unwrap().code,
        "workspace_mode_fork_unsupported"
    );
}

/// Regression test for the `list_sandboxes` N+1: hydrating every allowlist sandbox's network
/// egress rules used to run one query per sandbox. Batching that into a single
/// `sandbox_id in (...)` query and grouping in memory must still attach each sandbox's *own*
/// rules -- not another sandbox's -- and must leave non-allowlist sandboxes untouched.
#[tokio::test]
pub(crate) async fn list_sandboxes_hydrates_each_allowlist_sandboxes_own_rules() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-egress-batch-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let single_rule: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("egress-batch-single-rule".to_string()),
            template: None,
            memory_limit: None,
            network_egress: Some(NetworkEgress::Allowlist {
                rules: vec![NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "10.0.0.0/8".to_string(),
                }],
            }),
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

    let multi_rule: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("egress-batch-multi-rule".to_string()),
            template: None,
            memory_limit: None,
            network_egress: Some(NetworkEgress::Allowlist {
                rules: vec![
                    NetworkAllowRule {
                        kind: NetworkAllowRuleKind::Cidr,
                        value: "172.16.0.0/12".to_string(),
                    },
                    NetworkAllowRule {
                        kind: NetworkAllowRuleKind::Cidr,
                        value: "192.168.0.0/16".to_string(),
                    },
                ],
            }),
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

    let no_rules: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("egress-batch-deny-all".to_string()),
            template: None,
            memory_limit: None,
            network_egress: Some(NetworkEgress::DenyAll),
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

    let find = |id: sandboxwich_core::SandboxId| {
        listed
            .sandboxes
            .iter()
            .find(|sandbox| sandbox.id == id)
            .unwrap_or_else(|| panic!("sandbox {id} missing from list_sandboxes response"))
    };

    assert_eq!(
        find(single_rule.sandbox.id).network_egress,
        NetworkEgress::Allowlist {
            rules: vec![NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            }]
        }
    );
    assert_eq!(
        find(multi_rule.sandbox.id).network_egress,
        NetworkEgress::Allowlist {
            rules: vec![
                NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "172.16.0.0/12".to_string(),
                },
                NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "192.168.0.0/16".to_string(),
                },
            ]
        }
    );
    assert_eq!(
        find(no_rules.sandbox.id).network_egress,
        NetworkEgress::DenyAll
    );
}

#[tokio::test]
async fn stop_before_first_provision_is_claimable_and_cannot_be_undone() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-pre-provision-stop.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("stop-before-provision".to_string()),
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
    assert_eq!(created.sandbox.state, SandboxState::Planning);

    let accepted: SandboxResponse = client
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
    assert_eq!(accepted.sandbox.state, SandboxState::Archiving);

    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "pre-provision-stop-worker".to_string(),
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
    let worker_client = worker_client(&worker);
    let stop_claim: ClaimLeaseResponse = worker_client
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
    let stop_lease = stop_claim
        .lease
        .expect("unplaced stop job must be claimable");
    assert_eq!(stop_lease.job.kind, JobKind::StopSandbox);
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, stop_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id: created.sandbox.id,
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let provision_claim: ClaimLeaseResponse = worker_client
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
    let provision_lease = provision_claim
        .lease
        .expect("original provision job remains drainable");
    assert_eq!(provision_lease.job.kind, JobKind::ProvisionSandbox);
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".to_string(),
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

    let final_state: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
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
    assert_eq!(final_state.sandbox.state, SandboxState::Archived);
}

pub(crate) async fn assert_resource_tiers_and_file_contracts(
    client: &reqwest::Client,
    server: &TestServer,
    default_sandbox: &SandboxResponse,
) -> FileResponse {
    let sized: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("sized-contract".to_string()),
            template: None,
            memory_limit: Some(MemoryLimit::FourG),
            network_egress: Some(NetworkEgress::Allowlist {
                rules: vec![NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "10.0.0.0/8".to_string(),
                }],
            }),
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
    assert_eq!(sized.sandbox.memory_limit, MemoryLimit::FourG);
    assert_eq!(
        sized.sandbox.network_egress,
        NetworkEgress::Allowlist {
            rules: vec![NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            }]
        }
    );

    let host_allowlist = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("host-egress-contract".to_string()),
            template: None,
            memory_limit: Some(MemoryLimit::OneG),
            network_egress: Some(NetworkEgress::Allowlist {
                rules: vec![NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Host,
                    value: "api.example.com".to_string(),
                }],
            }),
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(host_allowlist.status(), StatusCode::ACCEPTED);
    let host_allowlist: SandboxResponse = host_allowlist.json().await.unwrap();
    assert_eq!(
        host_allowlist.sandbox.network_egress,
        NetworkEgress::Allowlist {
            rules: vec![NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }]
        }
    );
    let jobs: JobListResponse = client
        .get(format!("{}/jobs?limit=100", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let host_job = jobs
        .jobs
        .iter()
        .find(|job| job.payload["sandboxId"] == serde_json::json!(host_allowlist.sandbox.id))
        .expect("host allowlist provisioning job must exist");
    assert_eq!(host_job.required_capability, WorkerCapability::FqdnEgress);

    client
        .post(format!(
            "{}/sandboxes/{}/stop",
            server.base_url, host_allowlist.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let jobs: JobListResponse = client
        .get(format!("{}/jobs?limit=100", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let host_stop_job = jobs
        .jobs
        .iter()
        .find(|job| {
            job.kind == JobKind::StopSandbox
                && job.payload["sandboxId"] == serde_json::json!(host_allowlist.sandbox.id)
        })
        .expect("host allowlist stop job must remain FQDN-worker scoped");
    assert_eq!(
        host_stop_job.required_capability,
        WorkerCapability::ProvisionSandbox
    );

    let fetched: SandboxResponse = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, sized.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched.sandbox.memory_limit, MemoryLimit::FourG);
    assert_eq!(fetched.sandbox.network_egress, sized.sandbox.network_egress);

    let invalid_tier = client
        .post(format!("{}/sandboxes", server.base_url))
        .header("content-type", "application/json")
        .body(r#"{"memory_limit":"2g"}"#)
        .send()
        .await
        .unwrap();
    assert!(invalid_tier.status().is_client_error());

    let form = reqwest::multipart::Form::new()
        .text("path", "/workspace/hello.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes("hello file\n".as_bytes().to_vec())
                .file_name("hello.txt")
                .mime_str("text/plain")
                .unwrap(),
        );
    let uploaded: FileResponse = client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, default_sandbox.sandbox.id
        ))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(uploaded.file.path, "/workspace/hello.txt");
    assert_eq!(uploaded.file.mime_type.as_deref(), Some("text/plain"));
    assert_eq!(uploaded.file.size_bytes, "hello file\n".len() as u64);

    let listed: ListFilesResponse = client
        .get(format!(
            "{}/sandboxes/{}/files",
            server.base_url, default_sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed.files.iter().any(|file| file.id == uploaded.file.id));

    let download_response = client
        .get(format!(
            "{}/sandboxes/{}/files/{}",
            server.base_url, default_sandbox.sandbox.id, uploaded.file.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        download_response
            .headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok()),
        Some("attachment; filename=\"hello.txt\"")
    );
    assert_eq!(
        download_response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff"),
        "file downloads must set X-Content-Type-Options: nosniff alongside the \
         reflected, client-supplied Content-Type"
    );
    let downloaded = download_response.bytes().await.unwrap();
    assert_eq!(&downloaded[..], b"hello file\n");

    let bad_mime_form = reqwest::multipart::Form::new()
        .text("path", "/workspace/nope.exe")
        .part(
            "file",
            reqwest::multipart::Part::bytes(vec![0, 1, 2])
                .file_name("nope.exe")
                .mime_str("application/x-msdownload")
                .unwrap(),
        );
    let bad_mime = client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, default_sandbox.sandbox.id
        ))
        .multipart(bad_mime_form)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_mime.status(), StatusCode::BAD_REQUEST);

    let hidden = reqwest::Client::new()
        .get(format!(
            "{}/sandboxes/{}/files",
            server.base_url, default_sandbox.sandbox.id
        ))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

    uploaded
}

/// A `ForkSandbox` job completing after its child sandbox was concurrently
/// archived must not resurrect it. This is the lost-update bug fixed by the
/// compare-and-swap state writes: previously every state write was an
/// unconditional `UPDATE ... SET state = ?`, so a job completion landing
/// after a user-initiated stop would silently overwrite the archive.
pub(crate) async fn assert_job_completion_does_not_resurrect_concurrently_archived_sandbox(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
) {
    let race_worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "race-fork-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::Snapshot,
                WorkerCapability::ProvisionSandbox,
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
    let race_worker_client = worker_client(&race_worker);

    let forked: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/fork",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            name: Some("race-child".to_string()),
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
    assert_eq!(forked.sandbox.state, SandboxState::Planning);
    let fork_snapshot_id = forked
        .sandbox
        .parent_snapshot_id
        .expect("fork should point at a real snapshot");

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
    let snapshot_job = job_for_snapshot(&jobs.jobs, &fork_snapshot_id.to_string());

    let claimed_snapshot: ClaimLeaseResponse = race_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, race_worker.worker.id
        ))
        .header("x-sandboxwich-job-id", snapshot_job.id.to_string())
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(sandbox.sandbox.id),
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
    let snapshot_lease = claimed_snapshot
        .lease
        .expect("expected race worker to claim the fork's snapshot job");
    assert_eq!(snapshot_lease.job.id, snapshot_job.id);

    race_worker_client
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
        .unwrap();

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

    let claimed_fork: ClaimLeaseResponse = race_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, race_worker.worker.id
        ))
        .header("x-sandboxwich-job-id", fork_job.id.to_string())
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(forked.sandbox.id),
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
    let fork_lease = claimed_fork
        .lease
        .expect("expected race worker to claim the fork job");
    assert_eq!(fork_lease.job.id, fork_job.id);

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

    // Race: archive the child while its ForkSandbox job is still in flight,
    // *before* the lease is completed below.
    let archived_child: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/stop",
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
    assert_eq!(archived_child.sandbox.state, SandboxState::Archiving);

    // The ForkSandbox job completes *after* the concurrent archive landed.
    // It must succeed (the job itself isn't at fault) without clobbering the
    // sandbox's archived state.
    race_worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, fork_lease.id
        ))
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
        .unwrap();

    let stop_claim: ClaimLeaseResponse = race_worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, race_worker.worker.id
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
    let stop_lease = stop_claim
        .lease
        .expect("concurrent stop must remain queued");
    assert_eq!(stop_lease.job.kind, JobKind::StopSandbox);
    race_worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, stop_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id: forked.sandbox.id,
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let after: SandboxResponse = client
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
    assert_eq!(
        after.sandbox.state,
        SandboxState::Archived,
        "a ForkSandbox job completing after a concurrent stop must not resurrect the sandbox"
    );
}
