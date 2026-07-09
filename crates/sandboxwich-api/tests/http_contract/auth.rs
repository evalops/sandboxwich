use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

#[tokio::test]
pub(crate) async fn api_token_is_required_when_configured() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-auth-test.db").display()
    );
    let server =
        TestServer::start_with_auth(database_url, Some(data_dir), Some("test-token")).await;
    let client = reqwest::Client::new();

    let missing = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let ready_without_token: HealthResponse = client
        .get(format!("{}/readyz", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ready_without_token.ok);

    let metrics_without_token = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics_without_token.status(), StatusCode::UNAUTHORIZED);

    let authorized: SandboxListResponse = client
        .get(format!("{}/sandboxes", server.base_url))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(authorized.ok);

    let spoofed_tenant: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .bearer_auth("test-token")
        .header("x-sandboxwich-tenant", "tenant-b")
        .json(&CreateSandboxRequest {
            name: Some("spoof-attempt".to_string()),
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
    assert_eq!(spoofed_tenant.sandbox.tenant_id, "default");
}

/// Regression for #111 and the worker/tenant confused-deputy boundary: the
/// one-time worker credential may authenticate only worker control-plane
/// calls. It must neither authorize tenant/operator APIs nor reappear in any
/// subsequent HTTP response body.
#[tokio::test]
pub(crate) async fn worker_tokens_are_role_scoped_and_never_reserialized() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-principal-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let tenant_client = server.client();

    let registration: WorkerResponse = tenant_client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "principal-boundary-worker".to_string(),
            provider: "kubernetes".to_string(),
            capabilities: vec![WorkerCapability::K8sPod],
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
    let canary = registration.worker_token.clone().unwrap();
    let worker_client = worker_client(&registration);

    let heartbeat = worker_client
        .post(format!(
            "{}/workers/{}/heartbeat",
            server.base_url, registration.worker.id
        ))
        .json(&WorkerHeartbeatRequest {
            max_concurrent_jobs: None,
            labels: Default::default(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(heartbeat.status(), StatusCode::OK);
    assert!(!heartbeat.text().await.unwrap().contains(&canary));

    let tenant_on_worker_route = tenant_client
        .post(format!(
            "{}/workers/{}/heartbeat",
            server.base_url, registration.worker.id
        ))
        .json(&WorkerHeartbeatRequest {
            max_concurrent_jobs: None,
            labels: Default::default(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_on_worker_route.status(), StatusCode::UNAUTHORIZED);

    for response in [
        worker_client
            .get(format!("{}/sandboxes", server.base_url))
            .send()
            .await
            .unwrap(),
        worker_client
            .post(format!("{}/sandboxes", server.base_url))
            .json(&CreateSandboxRequest {
                name: Some("must-not-exist".to_string()),
                template: None,
                memory_limit: None,
                network_egress: None,
                ttl_seconds: Some(120),
            })
            .send()
            .await
            .unwrap(),
        worker_client
            .get(format!("{}/workers", server.base_url))
            .send()
            .await
            .unwrap(),
        worker_client
            .post(format!("{}/snapshots/cleanup", server.base_url))
            .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
            .send()
            .await
            .unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.text().await.unwrap().contains(&canary));
    }

    let sandboxes: SandboxListResponse = tenant_client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(sandboxes.sandboxes.is_empty());
}

/// Regression test for issue #63: with neither `SANDBOXWICH_API_TOKEN` nor
/// `SANDBOXWICH_TENANT_TOKENS` configured, the server must fail closed and
/// refuse every non-probe request, rather than trusting a client-supplied
/// `x-sandboxwich-tenant` header to select tenant identity.
#[tokio::test]
pub(crate) async fn unauthenticated_deployment_rejects_tenant_header_spoofing() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-no-auth-test.db")
            .display()
    );
    let server = TestServer::start_with_no_auth_configured(database_url, Some(data_dir)).await;
    let client = reqwest::Client::new();

    // Probe paths remain open even with no auth configured, so kubernetes
    // liveness/readiness checks keep working.
    let health = client
        .get(format!("{}/healthz", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let ready = client
        .get(format!("{}/readyz", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);

    // A plain, credential-free request must be rejected.
    let plain = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap();
    assert!(
        plain.status() == StatusCode::UNAUTHORIZED
            || plain.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "expected an auth failure, got {}",
        plain.status()
    );

    // The previous vulnerability: an attacker supplies a bogus
    // `x-sandboxwich-tenant` header and no credential at all, expecting the
    // server to trust it and select that tenant. It must instead be
    // rejected exactly like the plain request above, never selecting a
    // tenant or creating data.
    let spoofed = client
        .post(format!("{}/sandboxes", server.base_url))
        .header("x-sandboxwich-tenant", "someone-elses-tenant")
        .json(&CreateSandboxRequest {
            name: Some("should-never-be-created".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap();
    assert!(
        spoofed.status() == StatusCode::UNAUTHORIZED
            || spoofed.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "expected the tenant-header request to be rejected, got {}",
        spoofed.status()
    );

    // Confirm no sandbox was created as a side effect of the rejected
    // request: with no auth configured at all, /sandboxes is also
    // unreachable, so we just assert it is consistently rejected rather
    // than sometimes trusting the header and sometimes not.
    let listed = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap();
    assert!(
        listed.status() == StatusCode::UNAUTHORIZED
            || listed.status() == StatusCode::INTERNAL_SERVER_ERROR
    );
}

/// Regression test for issue #65: `/snapshots/cleanup` acts across every
/// tenant's data, so it must never be reachable with an ordinary tenant
/// credential alone -- it requires a dedicated `SANDBOXWICH_OPERATOR_TOKEN`
/// credential, distinct from any tenant token.
#[tokio::test]
pub(crate) async fn cleanup_is_not_usable_cross_tenant() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-cleanup-auth-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;

    // A valid credential for the default tenant is not sufficient on its
    // own: no operator token was presented.
    let default_tenant_attempt = server
        .client()
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        default_tenant_attempt.status(),
        StatusCode::UNAUTHORIZED,
        "a tenant credential alone must not be able to run cross-tenant cleanup"
    );

    // A valid credential for a *different* tenant is equally insufficient --
    // this is the direct cross-tenant scenario from issue #65: tenant-b must
    // never be able to trigger cleanup that deletes tenant-default's data.
    let cross_tenant_attempt = reqwest::Client::new()
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(
        cross_tenant_attempt.status(),
        StatusCode::UNAUTHORIZED,
        "tenant-b's credential must not be able to run cleanup affecting other tenants"
    );

    // The dedicated operator credential, alongside normal tenant auth, is
    // required and sufficient.
    let operator_attempt: SnapshotCleanupResponse = server
        .client()
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
    assert!(operator_attempt.ok);

    // A wrong operator token is rejected just like a missing one.
    let wrong_operator_token = server
        .client()
        .post(format!("{}/snapshots/cleanup", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, "not-the-operator-token")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_operator_token.status(), StatusCode::UNAUTHORIZED);
}

pub(crate) async fn assert_tenant_boundaries_are_enforced(
    client: &reqwest::Client,
    server: &TestServer,
    default_sandbox: &SandboxResponse,
) {
    // Authenticate as "tenant-b" using its own bearer token: tenant identity
    // is derived solely from which credential matched, never from a
    // client-supplied header, so a plain `.header(...)` no longer switches
    // tenant context.
    let tenant_b_client = reqwest::Client::new();
    let tenant_sandbox: SandboxResponse = tenant_b_client
        .post(format!("{}/sandboxes", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .json(&CreateSandboxRequest {
            name: Some("tenant-b-sandbox".to_string()),
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
    assert_eq!(tenant_sandbox.sandbox.tenant_id, "tenant-b");

    let default_list: SandboxListResponse = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        default_list
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.id == default_sandbox.sandbox.id)
    );
    assert!(
        default_list
            .sandboxes
            .iter()
            .all(|sandbox| sandbox.id != tenant_sandbox.sandbox.id)
    );

    let hidden = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, tenant_sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

    let cross_tenant_job = tenant_b_client
        .post(format!("{}/jobs", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .json(&CreateJobRequest {
            kind: JobKind::ProvisionSandbox,
            payload: serde_json::json!({
                "sandboxId": default_sandbox.sandbox.id
            }),
            required_capability: WorkerCapability::ProvisionSandbox,
            priority: None,
            max_attempts: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_tenant_job.status(), StatusCode::NOT_FOUND);

    let tenant_list: SandboxListResponse = tenant_b_client
        .get(format!("{}/sandboxes", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        tenant_list
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.id == tenant_sandbox.sandbox.id)
    );
    assert!(
        tenant_list
            .sandboxes
            .iter()
            .all(|sandbox| sandbox.id != default_sandbox.sandbox.id)
    );
}
