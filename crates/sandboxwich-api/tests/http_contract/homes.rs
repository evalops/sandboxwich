use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

fn persistent_sandbox(name: &str) -> CreateSandboxRequest {
    CreateSandboxRequest {
        name: Some(name.into()),
        template: None,
        memory_limit: None,
        network_egress: None,
        workspace_mode: Some(WorkspaceMode::Persistent),
        runtime_profile: None,
        execution_class: None,
        ttl_seconds: Some(120),
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
    }
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
        .json(&CreateHomeRequest {})
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
        .json(&CreateHomeRequest {})
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
        .json(&CreateHomeRequest {})
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
