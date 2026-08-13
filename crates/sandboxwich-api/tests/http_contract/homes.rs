use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

fn persistent_sandbox(name: &str) -> CreateSandboxRequest {
    CreateSandboxRequest {
        secret_ref_ids: Vec::new(),
        name: Some(name.into()),
        template: None,
        memory_limit: None,
        network_egress: None,
        workspace_mode: Some(WorkspaceMode::Persistent),
        runtime_profile: None,
        execution_class: None,
        provider_preference: None,
        ttl_seconds: Some(120),
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
    }
}

#[tokio::test]
async fn managed_home_preserves_explicit_cloudflare_provider_preference() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("managed-home-provider.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let home: HomeResponse = client
        .post(format!("{}/homes", server.base_url))
        .json(&CreateHomeRequest::default())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let register = |name: &str, provider: &str| RegisterWorkerRequest {
        name: name.into(),
        provider: provider.into(),
        capabilities: vec![WorkerCapability::ProvisionSandbox],
        max_concurrent_jobs: Some(1),
        labels: Default::default(),
    };
    let kubernetes: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&register("managed-home-kubernetes", "kubernetes"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let cloudflare: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&register("managed-home-cloudflare", "cloudflare"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut request = persistent_sandbox("cloudflare-home");
    request.provider_preference = Some(ProviderPreference::Cloudflare);
    client
        .post(format!(
            "{}/homes/{}/sandboxes",
            server.base_url, home.home.id
        ))
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let claim = ClaimLeaseRequest {
        lease_seconds: Some(60),
        sandbox_id: None,
        kinds: Some(vec![JobKind::ProvisionSandbox]),
        wait_ms: None,
    };
    let kubernetes_claim: ClaimLeaseResponse = worker_client(&kubernetes)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, kubernetes.worker.id
        ))
        .json(&claim)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(kubernetes_claim.lease.is_none());

    let cloudflare_claim: ClaimLeaseResponse = worker_client(&cloudflare)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, cloudflare.worker.id
        ))
        .json(&claim)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let job = cloudflare_claim
        .lease
        .expect("Cloudflare worker must claim the managed-home provision")
        .job;
    assert_eq!(
        job.payload["provisionSpec"]["provider_preference"],
        "cloudflare"
    );
}

#[tokio::test]
async fn managed_home_is_tenant_scoped_and_single_mount() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("managed-home.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: HomeResponse = client
        .post(format!("{}/homes", server.base_url))
        .json(&CreateHomeRequest::default())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.home.state, HomeState::Ready);

    let tenant_b = reqwest::Client::builder()
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {TEST_TENANT_B_TOKEN}").parse().unwrap(),
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .unwrap();
    assert_eq!(
        tenant_b
            .get(format!("{}/homes/{}", server.base_url, created.home.id))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    client
        .post(format!(
            "{}/homes/{}/sandboxes",
            server.base_url, created.home.id
        ))
        .json(&persistent_sandbox("first"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let conflict = client
        .post(format!(
            "{}/homes/{}/sandboxes",
            server.base_url, created.home.id
        ))
        .json(&persistent_sandbox("second"))
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict: ErrorEnvelope = conflict.json().await.unwrap();
    assert_eq!(conflict.code, "home_already_mounted");
    assert_eq!(
        client
            .delete(format!("{}/homes/{}", server.base_url, created.home.id))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    let wrong_tenant = tenant_b
        .post(format!(
            "{}/homes/{}/sandboxes",
            server.base_url, created.home.id
        ))
        .json(&persistent_sandbox("cross-tenant"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_tenant.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn managed_home_requires_persistent_workspace() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("managed-home-mode.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: HomeResponse = client
        .post(format!("{}/homes", server.base_url))
        .json(&CreateHomeRequest::default())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut request = persistent_sandbox("ephemeral");
    request.workspace_mode = Some(WorkspaceMode::GenericEphemeral);
    let response = client
        .post(format!(
            "{}/homes/{}/sandboxes",
            server.base_url, created.home.id
        ))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn managed_home_delete_is_explicit_and_asynchronous() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("managed-home-delete.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let created: HomeResponse = client
        .post(format!("{}/homes", server.base_url))
        .json(&CreateHomeRequest::default())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let deleting: HomeResponse = client
        .delete(format!("{}/homes/{}", server.base_url, created.home.id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deleting.home.state, HomeState::Deleting);
    assert_eq!(deleting.operation.unwrap().kind, OperationKind::DeleteHome);

    let registered: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "managed-home-delete-worker".into(),
            provider: "kubernetes".into(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::SandboxedContainer,
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
    let claimed: ClaimLeaseResponse = worker_client(&registered)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, registered.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: None,
            kinds: Some(vec![JobKind::DeleteHome]),
            wait_ms: None,
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
        claimed
            .lease
            .expect("home delete must be claimable")
            .job
            .kind,
        JobKind::DeleteHome
    );
    assert_eq!(
        client
            .delete(format!("{}/homes/{}", server.base_url, created.home.id))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn home_external_key_resolves_the_same_home_and_reports_its_mount() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("home-external-key.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    let request = CreateHomeRequest {
        external_key: Some("dex-computer:0a1b2c3d4e5f6071".into()),
    };

    let first = client
        .post(format!("{}/homes", server.base_url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first: HomeResponse = first.json().await.unwrap();
    assert_eq!(
        first.home.external_key.as_deref(),
        Some("dex-computer:0a1b2c3d4e5f6071")
    );
    assert!(first.mounted_sandbox.is_none());

    // A repeat create with the same key is an upsert: 200 with the same home,
    // never a duplicate.
    let second = client
        .post(format!("{}/homes", server.base_url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second: HomeResponse = second.json().await.unwrap();
    assert_eq!(second.home.id, first.home.id);

    // Another tenant using the identical key gets its own home.
    let tenant_b = reqwest::Client::builder()
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {TEST_TENANT_B_TOKEN}").parse().unwrap(),
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .unwrap();
    let other: HomeResponse = tenant_b
        .post(format!("{}/homes", server.base_url))
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(other.home.id, first.home.id);

    // Once a sandbox claims the home's mount, both the upsert response and
    // get_home report it, so a client that lost its own mapping can reattach.
    let mounted: SandboxResponse = client
        .post(format!(
            "{}/homes/{}/sandboxes",
            server.base_url, first.home.id
        ))
        .json(&persistent_sandbox("external-key-mount"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let resolved: HomeResponse = client
        .post(format!("{}/homes", server.base_url))
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mount = resolved
        .mounted_sandbox
        .expect("upsert response must report the live mount");
    assert_eq!(mount.sandbox_id, mounted.sandbox.id);
    let fetched: HomeResponse = client
        .get(format!("{}/homes/{}", server.base_url, first.home.id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        fetched.mounted_sandbox.map(|mount| mount.sandbox_id),
        Some(mounted.sandbox.id)
    );
}

#[tokio::test]
async fn home_external_key_validation_fails_closed() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("home-external-key-invalid.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    for bad in [
        "has whitespace".to_string(),
        "slash/es".to_string(),
        String::new(),
        "x".repeat(129),
    ] {
        let response = client
            .post(format!("{}/homes", server.base_url))
            .json(&CreateHomeRequest {
                external_key: Some(bad),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
