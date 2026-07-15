use crate::common::*;
use sandboxwich_core::*;

#[tokio::test]
pub(crate) async fn apex_command_claim_requires_exact_profile_and_runtime_image() {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir.path().join("apex-command-claim.db").display()
        ),
        Some(data_dir),
    )
    .await;
    let client = server.client();
    let runtime_image = format!("ghcr.io/evalops/apex@sha256:{}", "a".repeat(64));
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("apex-command".to_string()),
            template: Some(runtime_image.clone()),
            memory_limit: Some(MemoryLimit::FourG),
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: Some(WorkspaceMode::Persistent),
            runtime_profile: Some(SandboxRuntimeProfile::ApexTrustedSupervisorV1),
            ttl_seconds: None,
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
            name: "exact-apex-command".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
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
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
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
        .unwrap();

    let wrong: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "wrong-apex-command".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::RunCommand,
                WorkerCapability::ApexTrustedSupervisorV1,
                WorkerCapability::SandboxedContainer,
            ],
            max_concurrent_jobs: Some(1),
            labels: [(
                "runtime_image".to_string(),
                format!("wrong@sha256:{}", "c".repeat(64)),
            )]
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
    let wrong_claim: ClaimLeaseResponse = worker_client(&wrong)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, wrong.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
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
    assert!(wrong_claim.lease.is_none());

    assert!(
        exact
            .worker
            .capabilities
            .contains(&WorkerCapability::ApexTrustedSupervisorV1)
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
    let command_job = jobs
        .jobs
        .iter()
        .find(|job| job.kind == JobKind::RunCommand)
        .unwrap();
    assert_eq!(
        command_job.payload["provisionSpec"]["runtime_profile"],
        serde_json::json!("apex_trusted_supervisor_v1")
    );
    assert_eq!(
        command_job.payload["runtimeImage"],
        serde_json::json!(runtime_image)
    );
    let exact_claim: ClaimLeaseResponse = worker_client(&exact)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, exact.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
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
    let lease = exact_claim.lease.expect("exact APEX worker claims command");
    assert_eq!(
        lease.job.payload["runtimeImage"],
        serde_json::json!(runtime_image)
    );
}

#[tokio::test]
pub(crate) async fn command_stdin_is_redacted_from_tenant_jobs_but_preserved_for_worker_dispatch() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-command-stdin-redaction.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            workspace_mode: None,
            runtime_profile: None,
            name: Some("stdin-redaction-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: None,
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
            name: "stdin-dispatch-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::K8sPod,
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
    let worker_client = worker_client(&worker);
    let provision: ClaimLeaseResponse = worker_client
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
    let provision = provision.lease.expect("claim provision lease first");
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision.id
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
    let marker = b"apex-public-redaction-\0\xff".to_vec();
    let encoded = serde_json::to_value(AgentCommandRequest {
        argv: vec!["sha256sum".to_string()],
        cwd: None,
        env: Default::default(),
        stdin: Some(marker.clone()),
        timeout_secs: None,
    })
    .unwrap()["stdin"]
        .as_str()
        .unwrap()
        .to_string();

    let command_response = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["sha256sum".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: Some(marker.clone()),
            timeout_secs: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let command_json = command_response.text().await.unwrap();
    assert!(!command_json.contains("apex-public-redaction"));
    assert!(!command_json.contains(&encoded));
    let command: QueueCommandResponse = serde_json::from_str(&command_json).unwrap();

    let created_job_response = client
        .post(format!("{}/jobs", server.base_url))
        .json(&CreateJobRequest {
            kind: JobKind::RunCommand,
            payload: serde_json::json!({
                "sandboxId": created.sandbox.id,
                "commandId": command.command.id,
                "argv": ["sha256sum"],
                "cwd": null,
                "env": {},
                "stdin": encoded,
                "timeoutSecs": DEFAULT_COMMAND_TIMEOUT_SECS
            }),
            required_capability: WorkerCapability::RunCommand,
            priority: None,
            max_attempts: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let create_job_json = created_job_response.text().await.unwrap();
    assert!(!create_job_json.contains("apex-public-redaction"));
    assert!(!create_job_json.contains(&encoded));
    let created_job: JobResponse = serde_json::from_str(&create_job_json).unwrap();

    let get_job_json = client
        .get(format!("{}/jobs/{}", server.base_url, created_job.job.id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!get_job_json.contains("apex-public-redaction"));
    assert!(!get_job_json.contains(&encoded));
    let fetched: JobResponse = serde_json::from_str(&get_job_json).unwrap();
    assert!(!format!("{fetched:?}").contains(&encoded));

    let list_job_json = client
        .get(format!("{}/jobs", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!list_job_json.contains("apex-public-redaction"));
    assert!(!list_job_json.contains(&encoded));
    let listed: JobListResponse = serde_json::from_str(&list_job_json).unwrap();
    assert!(!format!("{listed:?}").contains(&encoded));

    let claim: ClaimLeaseResponse = worker_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
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
    let lease = claim
        .lease
        .expect("worker should receive a command dispatch");
    assert_eq!(
        lease.job.payload["runtimeImage"],
        serde_json::json!(created.sandbox.template)
    );
    assert_eq!(
        lease.job.payload["provisionSpec"]["runtime_profile"],
        serde_json::json!(created.sandbox.runtime_profile)
    );
    assert_eq!(lease.job.payload["stdin"], encoded);
    let dispatched: AgentCommandRequest = serde_json::from_value(serde_json::json!({
        "argv": lease.job.payload["argv"],
        "cwd": lease.job.payload["cwd"],
        "env": lease.job.payload["env"],
        "stdin": lease.job.payload["stdin"],
        "timeout_secs": lease.job.payload["timeoutSecs"]
    }))
    .unwrap();
    assert_eq!(dispatched.stdin, Some(marker));
    assert!(!format!("{lease:?}").contains("apex-public-redaction"));
    assert!(!format!("{lease:?}").contains(&encoded));
}

#[tokio::test]
pub(crate) async fn command_stdin_over_one_mib_is_rejected_before_job_dispatch() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-command-stdin-limit.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            workspace_mode: None,
            runtime_profile: None,
            name: Some("stdin-limit-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: None,
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

    let accepted = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["sha256sum".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: Some(vec![b'x'; MAX_COMMAND_STDIN_BYTES]),
            timeout_secs: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), reqwest::StatusCode::ACCEPTED);

    let response = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["sha256sum".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: Some(vec![b'x'; MAX_COMMAND_STDIN_BYTES + 1]),
            timeout_secs: None,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let error: ErrorEnvelope = response.json().await.unwrap();
    assert_eq!(error.code, "command_stdin_too_large");

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
    assert_eq!(
        jobs.jobs
            .iter()
            .filter(|job| job.kind == JobKind::RunCommand)
            .count(),
        1,
        "only the exactly-at-limit request may dispatch a command job"
    );

    let events: EventListResponse = client
        .get(format!(
            "{}/sandboxes/{}/events",
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
    let rendered_events = serde_json::to_string(&events).unwrap();
    assert!(!rendered_events.contains("stdin"));
    assert!(!rendered_events.contains(&"x".repeat(64)));
}

#[tokio::test]
pub(crate) async fn small_body_route_rejects_oversized_json_but_upload_route_accepts_large_file() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-body-limit-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("body-limit-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
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

    // The global default body limit (1 MiB) applies to ordinary JSON routes: a body padded well
    // past that with an otherwise-valid JSON payload must be rejected before it is ever buffered
    // or parsed. Without `Expect: 100-continue`, the server can reject and close the connection
    // while the client is still writing the oversized body, which surfaces to the client as a
    // connection error rather than a clean response; either outcome proves the body was rejected.
    let oversized_name = "x".repeat(2 * 1024 * 1024);
    let oversized_body = format!(r#"{{"name":"{oversized_name}"}}"#);
    match client
        .post(format!("{}/sandboxes", server.base_url))
        .header("content-type", "application/json")
        .body(oversized_body)
        .send()
        .await
    {
        Ok(response) => {
            assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(error) => {
            assert!(
                error.is_request() || error.is_body() || error.is_connect(),
                "unexpected error sending oversized body: {error}"
            );
        }
    }

    // The file upload route opts into a much larger, explicit limit and must still accept a
    // payload far above the small default (well below the new MAX_SANDBOX_FILE_BYTES cap).
    // Use a fresh client: rejecting the oversized body above closes the connection mid-write,
    // which can poison a pooled connection and surface here as a spurious send error.
    let upload_client = server.client();
    let large_content = vec![b'a'; 8 * 1024 * 1024];
    let form = reqwest::multipart::Form::new()
        .text("path", "/workspace/large.bin")
        .part(
            "file",
            reqwest::multipart::Part::bytes(large_content.clone())
                .file_name("large.bin")
                .mime_str("application/octet-stream")
                .unwrap(),
        );
    let uploaded: FileResponse = upload_client
        .post(format!(
            "{}/sandboxes/{}/files",
            server.base_url, created.sandbox.id
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
    assert_eq!(uploaded.file.size_bytes, large_content.len() as u64);
}

#[tokio::test]
pub(crate) async fn list_commands_respect_limit_and_paginate_with_cursor() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-pagination-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("pagination-test".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
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
    let sandbox_id = created.sandbox.id;

    const TOTAL_COMMANDS: usize = 5;
    let mut created_ids = Vec::with_capacity(TOTAL_COMMANDS);
    for index in 0..TOTAL_COMMANDS {
        let command: QueueCommandResponse = client
            .post(format!(
                "{}/sandboxes/{}/commands",
                server.base_url, sandbox_id
            ))
            .json(&CommandRequest {
                argv: vec!["echo".to_string(), index.to_string()],
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
        created_ids.push(command.command.id);
    }

    // limit=0 is rejected rather than silently treated as "no limit".
    let zero_limit = client
        .get(format!(
            "{}/sandboxes/{}/commands?limit=0",
            server.base_url, sandbox_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(zero_limit.status(), reqwest::StatusCode::BAD_REQUEST);

    // Passing both before and after is rejected as ambiguous.
    let both_cursors = client
        .get(format!(
            "{}/sandboxes/{}/commands?before=a&after=b",
            server.base_url, sandbox_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(both_cursors.status(), reqwest::StatusCode::BAD_REQUEST);

    // Page through the full set two at a time and confirm we see every command exactly once, in
    // creation order, with the cursor chain terminating cleanly on the last page.
    let mut collected = Vec::with_capacity(TOTAL_COMMANDS);
    let mut cursor: Option<String> = None;
    loop {
        let mut url = format!(
            "{}/sandboxes/{}/commands?limit=2",
            server.base_url, sandbox_id
        );
        if let Some(after) = &cursor {
            url.push_str(&format!("&after={after}"));
        }
        let page: CommandListResponse = client
            .get(url)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(page.commands.len() <= 2);
        collected.extend(page.commands.iter().map(|command| command.id));
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
        assert!(
            collected.len() < TOTAL_COMMANDS * 2,
            "pagination did not terminate"
        );
    }

    assert_eq!(collected, created_ids);
}
