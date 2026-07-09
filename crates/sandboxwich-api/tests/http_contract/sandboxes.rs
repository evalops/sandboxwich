use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

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

pub(crate) async fn assert_resource_tiers_and_file_contracts(
    client: &reqwest::Client,
    server: &TestServer,
    default_sandbox: &SandboxResponse,
) -> FileResponse {
    let sized: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
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
    assert_eq!(host_allowlist.status(), StatusCode::BAD_REQUEST);

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

    let downloaded = client
        .get(format!(
            "{}/sandboxes/{}/files/{}",
            server.base_url, default_sandbox.sandbox.id, uploaded.file.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();
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
