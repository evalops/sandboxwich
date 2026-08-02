//! Contract for the tenant-scoped secret-reference store.
//!
//! Two properties are load-bearing and asserted here rather than left to
//! convention: a reference is invisible outside its own organization scope,
//! and no request or response on this surface can carry credential material.

use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;
use serde_json::json;

fn create_request(name: &str, workspace_id: &str) -> CreateSecretRefRequest {
    CreateSecretRefRequest {
        workspace_id: workspace_id.into(),
        name: name.into(),
        source: SecretSource {
            backend: SecretBackend::CsiSecretProviderClass,
            object_name: "tenant-model-credentials".into(),
            object_key: "openai.api-key".into(),
        },
        delivery: SecretDelivery::File,
    }
}

fn tenant_b_client() -> reqwest::Client {
    reqwest::Client::builder()
        .default_headers(
            [(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {TEST_TENANT_B_TOKEN}").parse().unwrap(),
            )]
            .into_iter()
            .collect(),
        )
        .build()
        .unwrap()
}

async fn run_secret_ref_contract(server: TestServer) {
    let client = server.client();

    let created: SecretRefResponse = client
        .post(format!("{}/secret-refs", server.base_url))
        .json(&create_request("openai-api-key", "ws-1"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.secret_ref.state, SecretRefState::Active);
    assert_eq!(created.secret_ref.workspace_id, "ws-1");
    assert_eq!(
        created.secret_ref.mount_dir(),
        "/run/sandboxwich/secrets/openai-api-key"
    );

    // Same name, same scope, still active: rejected, because the name is the
    // guest mount path.
    assert_eq!(
        client
            .post(format!("{}/secret-refs", server.base_url))
            .json(&create_request("openai-api-key", "ws-1"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    // Same name in another workspace is a different reference.
    client
        .post(format!("{}/secret-refs", server.base_url))
        .json(&create_request("openai-api-key", "ws-2"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let listed: SecretRefListResponse = client
        .get(format!("{}/secret-refs?workspaceId=ws-1", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed.secret_refs.len(), 1);
    assert_eq!(listed.secret_refs[0].id, created.secret_ref.id);

    // Tenant isolation: another organization can neither see nor revoke it.
    let tenant_b = tenant_b_client();
    assert_eq!(
        tenant_b
            .get(format!(
                "{}/secret-refs/{}",
                server.base_url, created.secret_ref.id
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        tenant_b
            .delete(format!(
                "{}/secret-refs/{}",
                server.base_url, created.secret_ref.id
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let tenant_b_list: SecretRefListResponse = tenant_b
        .get(format!("{}/secret-refs", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tenant_b_list.secret_refs.is_empty());
    // The other tenant's reference is still readable by its owner, so the
    // 404 above was scoping, not deletion.
    client
        .get(format!(
            "{}/secret-refs/{}",
            server.base_url, created.secret_ref.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Revocation is a durable state transition and is idempotent.
    for _ in 0..2 {
        let revoked: SecretRefResponse = client
            .delete(format!(
                "{}/secret-refs/{}",
                server.base_url, created.secret_ref.id
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(revoked.secret_ref.state, SecretRefState::Revoked);
        assert!(revoked.secret_ref.revoked_at.is_some());
    }
    // The name is free again once the reference is revoked.
    client
        .post(format!("{}/secret-refs", server.base_url))
        .json(&create_request("openai-api-key", "ws-1"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

#[tokio::test]
async fn secret_reference_store_is_tenant_scoped_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("secret-refs.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    run_secret_ref_contract(server).await;
}

#[tokio::test]
async fn secret_reference_store_is_tenant_scoped_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start(database_url, None).await;
    run_secret_ref_contract(server).await;
}

#[tokio::test]
async fn secret_reference_surface_cannot_carry_credential_material() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("secret-ref-redaction.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();
    const CANARY: &str = "sk-secret-material-canary";

    for body in [
        json!({
            "workspaceId": "ws-1",
            "name": "openai-api-key",
            "source": {
                "backend": "csi_secret_provider_class",
                "objectName": "tenant-model-credentials",
                "objectKey": "openai.api-key"
            },
            "value": CANARY
        }),
        json!({
            "workspaceId": "ws-1",
            "name": "openai-api-key",
            "source": {
                "backend": "csi_secret_provider_class",
                "objectName": "tenant-model-credentials",
                "objectKey": "openai.api-key",
                "data": CANARY
            }
        }),
    ] {
        let response = client
            .post(format!("{}/secret-refs", server.base_url))
            .json(&body)
            .send()
            .await
            .unwrap();
        // `deny_unknown_fields` on the typed contract rejects the body during
        // deserialization, so this never reaches a handler that could log it.
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "the store must refuse a request carrying raw material"
        );
        assert!(!response.text().await.unwrap().contains(CANARY));
    }

    // A name that would escape the read-only secret directory, or that cannot
    // be turned into an environment variable, is rejected before storage.
    for name in ["../escape", "Upper", "with space", ""] {
        let response = client
            .post(format!("{}/secret-refs", server.base_url))
            .json(&create_request(name, "ws-1"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{name} must not become a mount path"
        );
    }
    // A source locator naming an object outside the operator namespace
    // (or a traversal key) is rejected too.
    let mut cross_namespace = create_request("openai-api-key", "ws-1");
    cross_namespace.source.object_name = "kube-system/other-tenant".into();
    assert_eq!(
        client
            .post(format!("{}/secret-refs", server.base_url))
            .json(&cross_namespace)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    // Nothing on the read surface can echo material, because nothing on the
    // write surface can accept it.
    client
        .post(format!("{}/secret-refs", server.base_url))
        .json(&create_request("openai-api-key", "ws-1"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let listed = client
        .get(format!("{}/secret-refs", server.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!listed.contains(CANARY));
}

#[tokio::test]
async fn secret_reference_routes_require_authentication() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("secret-ref-auth.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let anonymous = reqwest::Client::new();
    assert_eq!(
        anonymous
            .get(format!("{}/secret-refs", server.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        anonymous
            .post(format!("{}/secret-refs", server.base_url))
            .json(&create_request("openai-api-key", "ws-1"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

fn create_sandbox_request(secret_ref_ids: Vec<SecretRefId>) -> CreateSandboxRequest {
    CreateSandboxRequest {
        secret_ref_ids,
        name: Some("secret-binding".into()),
        template: None,
        memory_limit: None,
        network_egress: None,
        workspace_mode: None,
        runtime_profile: None,
        ttl_seconds: Some(120),
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        execution_class: None,
    }
}

async fn create_ref(
    server: &TestServer,
    client: &reqwest::Client,
    name: &str,
    workspace: &str,
) -> SecretRef {
    client
        .post(format!("{}/secret-refs", server.base_url))
        .json(&create_request(name, workspace))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<SecretRefResponse>()
        .await
        .unwrap()
        .secret_ref
}

async fn run_secret_binding_contract(server: TestServer) {
    let client = server.client();
    let bound = create_ref(&server, &client, "openai-api-key", "ws-1").await;

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&create_sandbox_request(vec![bound.id]))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // The worker receives a locator, a derived read-only path, and a path
    // variable -- and nothing else. There is no field here that *could*
    // hold material.
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
    let job = jobs
        .jobs
        .iter()
        .find(|job| job.payload["sandboxId"] == serde_json::json!(created.sandbox.id))
        .expect("provisioning job");
    let mounts = &job.payload["provisionSpec"]["secret_mounts"];
    assert_eq!(mounts[0]["secretRefId"], serde_json::json!(bound.id));
    assert_eq!(
        mounts[0]["mountDir"],
        "/run/sandboxwich/secrets/openai-api-key"
    );
    assert_eq!(
        mounts[0]["filePath"],
        "/run/sandboxwich/secrets/openai-api-key/openai.api-key"
    );
    assert_eq!(
        mounts[0]["envFileVariable"],
        "SANDBOXWICH_SECRET_OPENAI_API_KEY_FILE"
    );

    // Another tenant's reference is not merely unauthorized, it does not
    // exist: binding it fails exactly like an unknown id.
    let foreign = create_ref(&server, &tenant_b_client(), "openai-api-key", "ws-1").await;
    for id in [foreign.id, SecretRefId::new()] {
        assert_eq!(
            client
                .post(format!("{}/sandboxes", server.base_url))
                .json(&create_sandbox_request(vec![id]))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    // Duplicates, over-binding, and cross-workspace sets are all refused
    // before a sandbox row exists.
    let other_workspace = create_ref(&server, &client, "anthropic-api-key", "ws-2").await;
    let many = (0..MAX_SANDBOX_SECRET_BINDINGS + 1)
        .map(|_| SecretRefId::new())
        .collect::<Vec<_>>();
    for ids in [
        vec![bound.id, bound.id],
        many,
        vec![bound.id, other_workspace.id],
    ] {
        assert_eq!(
            client
                .post(format!("{}/sandboxes", server.base_url))
                .json(&create_sandbox_request(ids))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    // A revoked reference can never come back through a binding.
    client
        .delete(format!("{}/secret-refs/{}", server.base_url, bound.id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        client
            .post(format!("{}/sandboxes", server.base_url))
            .json(&create_sandbox_request(vec![bound.id]))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn sandbox_secret_bindings_are_tenant_scoped_and_fail_closed_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("secret-bindings.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    run_secret_binding_contract(server).await;
}

#[tokio::test]
async fn sandbox_secret_bindings_are_tenant_scoped_and_fail_closed_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start(database_url, None).await;
    run_secret_binding_contract(server).await;
}
