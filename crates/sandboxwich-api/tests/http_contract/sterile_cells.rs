use crate::common::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use sandboxwich_core::*;
use sha2::Sha256;
use sqlx::{AnyPool, Row};
use uuid::Uuid;

fn signed_release(runtime_class: SterileCellRuntimeClass) -> SterileCellReleaseTrustClassV1 {
    let release_set_id = "release-set-2026-08-07".to_string();
    let policy_digest = "a".repeat(64);
    let canonical = format!(
        "sandboxwich-sterile-release-v1\0{release_set_id}\0{}\0{policy_digest}",
        runtime_class.as_db_str()
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(TEST_STERILE_CELL_SIGNING_KEY.as_bytes()).unwrap();
    mac.update(canonical.as_bytes());
    let signature = format!(
        "swrs1_{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    SterileCellReleaseTrustClassV1 {
        release_set_id,
        runtime_class,
        policy_digest,
        signature,
    }
}

async fn register_worker(server: &TestServer, client: &reqwest::Client) -> WorkerResponse {
    client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "sterile-cell-worker".into(),
            provider: "kubernetes".into(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::VirtualMachine,
                WorkerCapability::SandboxedContainer,
            ],
            max_concurrent_jobs: Some(8),
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
async fn tenant_release_and_status_are_exactly_fenced_and_provider_terminal() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("pool-release.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            secret_ref_ids: Vec::new(),
            execution_class: Some(ExecutionClass::VirtualMachine),
            workspace_mode: Some(WorkspaceMode::Ephemeral),
            runtime_profile: Some(SandboxRuntimeProfile::Unprivileged),
            name: Some("pool-contract".into()),
            template: Some("ubuntu-dev".into()),
            memory_limit: Some(MemoryLimit::OneG),
            network_egress: Some(NetworkEgress::DenyAll),
            provider_preference: Some(ProviderPreference::Kubernetes),
            ttl_seconds: None,
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
    let cell_id = SterileCellId(created.sandbox.id.0);
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, cell_id, release.clone()).await;
    let claimed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(release.clone()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed.lease.unwrap();
    let attestation = claimed.lease_attestation.unwrap();

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    let provision_job_id: String = sqlx::query_scalar(
        "select id from jobs where sandbox_id = ? and kind = 'provision_sandbox' order by created_at asc limit 1",
    )
    .bind(created.sandbox.id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "insert into sandbox_placements
         (sandbox_id, worker_id, provider, cluster, generation, created_at, updated_at)
         values (?, ?, 'kubernetes', null, 1, ?, ?)",
    )
    .bind(created.sandbox.id.to_string())
    .bind(worker.worker.id.to_string())
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "insert into sterile_pool_memberships
         (sandbox_id, tenant_id, state, worker_id, provision_job_id, release_set_id, runtime_class,
          policy_digest, release_signature, ready_ttl_seconds, cell_expires_at, lease_id, generation,
          candidate_agent_image, candidate_maestro_image, candidate_service_name,
          candidate_pod_name, candidate_pod_uid, created_at, updated_at)
         values (?, 'default', 'leased', ?, ?, ?, ?, ?, ?, 300, ?, ?, ?,
                 'agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                 'maestro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                 ?, ?, 'pod-uid-test', ?, ?)",
    )
    .bind(created.sandbox.id.to_string())
    .bind(worker.worker.id.to_string())
    .bind(provision_job_id)
    .bind(&release.release_set_id)
    .bind(release.runtime_class.as_db_str())
    .bind(&release.policy_digest)
    .bind(&release.signature)
    .bind(lease.expires_at.to_rfc3339())
    .bind(lease.lease_id.to_string())
    .bind(i64::try_from(lease.generation).unwrap())
    .bind(format!("sandboxwich-mc-{}", created.sandbox.id))
    .bind(format!("sandboxwich-{}", created.sandbox.id))
    .bind(&now)
    .bind(&now)
    .execute(&pool)
    .await
    .unwrap();

    let hidden_get = client
        .get(format!(
            "{}/sandboxes/{}",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(hidden_get.status(), StatusCode::NOT_FOUND);
    let inventory: SandboxListResponse = client
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
        inventory
            .sandboxes
            .iter()
            .all(|sandbox| sandbox.id != created.sandbox.id),
        "leased pool identity appeared in ordinary tenant inventory"
    );
    let divergence = client
        .post(format!("{}/divergence/reconcile", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .json(&DivergenceReconcileRequest {
            source: "limacharlie".into(),
            observations: vec![SensorObservation {
                external_id: "pool-identity-probe".into(),
                sandbox_id: created.sandbox.id,
                session_id: "pool-session".into(),
                activity_class: ActivityClass::ProcessSpawn,
                resource: "/usr/bin/true".into(),
                observed_at: Utc::now(),
            }],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(divergence.status(), StatusCode::NOT_FOUND);
    let observation_count: i64 =
        sqlx::query_scalar("select count(*) from sensor_observations where sandbox_id = ?")
            .bind(created.sandbox.id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(observation_count, 0);
    let guest_token: GuestTokenResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker.worker.id, created.sandbox.id
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
    assert_eq!(guest_token.sandbox_id, created.sandbox.id);

    let status_response = client
        .get(format!(
            "{}/sterile-cell-leases/{}",
            server.base_url, lease.lease_id
        ))
        .send()
        .await
        .unwrap();
    let status_code = status_response.status();
    let status_body = status_response.text().await.unwrap();
    assert!(
        status_code.is_success(),
        "status lookup failed: {status_code} {status_body}"
    );
    let status: SterileCellLeaseStatusResponseV1 = serde_json::from_str(&status_body).unwrap();
    assert_eq!(status.status.state, SterileCellState::Leased);
    assert!(!status.status.provider_absent);
    assert!(!status.status.cleanup_pending);
    let cross_tenant = reqwest::Client::new()
        .get(format!(
            "{}/sterile-cell-leases/{}",
            server.base_url, lease.lease_id
        ))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);

    let request = ReleaseSterileCellLeaseRequestV1 {
        lease_attestation: attestation.clone(),
        generation: lease.generation,
        organization_id: lease.organization_id.clone(),
        workspace_id: lease.workspace_id.clone(),
        thread_id: lease.thread_id.clone(),
        runner_session_id: lease.runner_session_id.clone(),
        disposition: SterileCellDisposition::Destroyed,
    };
    let mut stale = request.clone();
    stale.lease_attestation = "wrong".into();
    let rejected = client
        .post(format!(
            "{}/sterile-cell-leases/{}/release",
            server.base_url, lease.lease_id
        ))
        .json(&stale)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    let accepted = client
        .post(format!(
            "{}/sterile-cell-leases/{}/release",
            server.base_url, lease.lease_id
        ))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let accepted: SterileCellLeaseStatusResponseV1 = accepted.json().await.unwrap();
    assert_eq!(accepted.status.state, SterileCellState::Leased);
    assert!(!accepted.status.provider_absent);
    assert!(!accepted.status.cleanup_pending);

    let pool = AnyPool::connect(&server.database_url).await.unwrap();
    sqlx::query(
        "update sterile_pool_memberships set state = 'cleanup_pending' where sandbox_id = ?",
    )
    .bind(created.sandbox.id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let pending: SterileCellLeaseStatusResponseV1 = client
        .get(format!(
            "{}/sterile-cell-leases/{}",
            server.base_url, lease.lease_id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.status.state, SterileCellState::Leased);
    assert!(!pending.status.provider_absent);
    assert!(pending.status.cleanup_pending);
    sqlx::query("update sterile_pool_memberships set state = 'stopping' where sandbox_id = ?")
        .bind(created.sandbox.id.to_string())
        .execute(&pool)
        .await
        .unwrap();

    let claimed_stop: ClaimLeaseResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(created.sandbox.id),
            kinds: Some(vec![JobKind::StopSandbox]),
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
    let stop_lease = claimed_stop.lease.expect("placed pool stop is claimable");
    worker_client(&worker)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, stop_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                provider: "kubernetes".into(),
                sandbox_id: created.sandbox.id,
                custody_receipt: None,
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let replayed_completion = worker_client(&worker)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, stop_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                provider: "kubernetes".into(),
                sandbox_id: created.sandbox.id,
                custody_receipt: None,
            }),
        })
        .send()
        .await
        .unwrap();
    assert!(
        replayed_completion.status().is_success(),
        "provider completion response loss must allow an exact replay"
    );
    let terminal: SterileCellLeaseStatusResponseV1 = client
        .get(format!(
            "{}/sterile-cell-leases/{}",
            server.base_url, lease.lease_id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(terminal.status.state, SterileCellState::Destroyed);
    assert_eq!(
        terminal.status.disposition,
        Some(SterileCellDisposition::Destroyed)
    );
    assert!(terminal.status.provider_absent);
    assert!(!terminal.status.cleanup_pending);
}

async fn prepare(
    server: &TestServer,
    worker: &WorkerResponse,
    cell_id: SterileCellId,
    release: SterileCellReleaseTrustClassV1,
) -> SterileCellResponseV1 {
    worker_client(worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/prepare",
            server.base_url, worker.worker.id
        ))
        .json(&PrepareSterileCellRequestV1 {
            cell_id,
            release,
            provider_cell_id: format!("pod-{cell_id}"),
            expires_at: Utc::now() + Duration::minutes(5),
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

fn claim_request(release: SterileCellReleaseTrustClassV1) -> ClaimSterileCellRequestV1 {
    ClaimSterileCellRequestV1 {
        claim_id: Some(Uuid::now_v7()),
        release,
        organization_id: "org-1".into(),
        workspace_id: "workspace-1".into(),
        thread_id: "thread-1".into(),
        runner_session_id: "session-1".into(),
        lease_seconds: Some(120),
    }
}

#[tokio::test]
async fn feature_disabled_preserves_the_cold_path() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("disabled.db").display());
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let response = server
        .client()
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(signed_release(
            SterileCellRuntimeClass::KataMicrovm,
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signed_exact_trust_class_is_required_for_prepare_and_claim() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("trust.db").display());
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let mut tampered = signed_release(SterileCellRuntimeClass::KataMicrovm);
    tampered.policy_digest = "b".repeat(64);
    let response = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/prepare",
            server.base_url, worker.worker.id
        ))
        .json(&PrepareSterileCellRequestV1 {
            cell_id: SterileCellId::new(),
            release: tampered,
            provider_cell_id: "pod-tampered".into(),
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    let mut wrong_class = release;
    wrong_class.runtime_class = SterileCellRuntimeClass::GvisorLowerRisk;
    let response = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(wrong_class))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_lease_diagnosis_distinguishes_mismatched_and_already_leased_capacity() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("claim-diagnosis.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let kata_release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, SterileCellId::new(), kata_release.clone()).await;

    let mismatched: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(signed_release(
            SterileCellRuntimeClass::GvisorLowerRisk,
        )))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!mismatched.ok);
    assert!(mismatched.lease.is_none());
    assert!(mismatched.lease_attestation.is_none());
    assert_eq!(
        mismatched.no_lease_reason,
        Some(SterileCellNoLeaseReasonV1::ReleaseMismatch)
    );
    let evidence = mismatched.claimability.unwrap();
    assert_eq!(evidence.ready_cells, 0);
    assert_eq!(evidence.claimable_cells, 0);
    assert_eq!(evidence.mismatched_active_cells, 1);

    let claimed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(kata_release.clone()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(claimed.ok);
    assert!(claimed.lease.is_some());
    assert!(claimed.lease_attestation.is_some());
    assert!(claimed.no_lease_reason.is_none());
    assert!(claimed.claimability.is_none());

    let already_leased: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(kata_release))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!already_leased.ok);
    assert_eq!(
        already_leased.no_lease_reason,
        Some(SterileCellNoLeaseReasonV1::AlreadyLeased)
    );
    let evidence = already_leased.claimability.unwrap();
    assert_eq!(evidence.ready_cells, 0);
    assert_eq!(evidence.leased_cells, 1);
    assert_eq!(evidence.claimable_cells, 0);
}

#[tokio::test]
async fn atomic_claim_binds_identity_and_a_cell_is_never_reused() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("claim.db").display());
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    let cell_id = SterileCellId::new();
    let ready = prepare(&server, &worker, cell_id, release.clone()).await;
    assert_eq!(ready.cell.state, SterileCellState::Ready);
    assert_eq!(ready.cell.generation, 1);

    let url = format!("{}/sterile-cells/claim", server.base_url);
    let request = claim_request(release.clone());
    let mut competing_request = request.clone();
    competing_request.claim_id = Some(Uuid::now_v7());
    let (left, right) = tokio::join!(
        client.post(&url).json(&request).send(),
        client.post(&url).json(&competing_request).send()
    );
    let responses = [left.unwrap(), right.unwrap()];
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status() == StatusCode::OK)
            .count(),
        2
    );
    let mut claims = Vec::new();
    for response in responses {
        claims.push(response.json::<ClaimSterileCellResponseV1>().await.unwrap());
    }
    assert_eq!(
        claims.iter().filter(|claim| claim.lease.is_some()).count(),
        1
    );
    let claimed = claims
        .into_iter()
        .find(|claim| claim.lease.is_some())
        .unwrap();
    assert!(claimed.ok);
    assert!(claimed.no_lease_reason.is_none());
    assert!(claimed.claimability.is_none());
    let lease = claimed.lease.unwrap();
    let attestation = claimed.lease_attestation.unwrap();
    assert_eq!(lease.cell_id, cell_id);
    assert_eq!(lease.generation, 2);
    assert_eq!(lease.release, release);
    assert_eq!(lease.organization_id, "org-1");
    assert_eq!(lease.workspace_id, "workspace-1");
    assert_eq!(lease.thread_id, "thread-1");
    assert_eq!(lease.runner_session_id, "session-1");
    assert!(lease.expires_at <= Utc::now() + Duration::seconds(121));

    let validated: ValidateSterileCellLeaseResponseV1 = client
        .post(format!(
            "{}/sterile-cell-leases/{}/validate",
            server.base_url, lease.lease_id
        ))
        .json(&ValidateSterileCellLeaseRequestV1 {
            lease_attestation: attestation,
            generation: lease.generation,
            organization_id: lease.organization_id.clone(),
            workspace_id: lease.workspace_id.clone(),
            thread_id: lease.thread_id.clone(),
            runner_session_id: lease.runner_session_id.clone(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(validated.ok);
    assert_eq!(validated.lease, lease);

    let destroyed: SterileCellResponseV1 = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/{}/destroy",
            server.base_url, worker.worker.id, cell_id
        ))
        .json(&DestroySterileCellRequestV1 {
            lease_id: lease.lease_id,
            generation: lease.generation,
            disposition: SterileCellDisposition::Destroyed,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(destroyed.cell.state, SterileCellState::Destroyed);

    let contradictory_cleanup = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/{}/destroy",
            server.base_url, worker.worker.id, cell_id
        ))
        .json(&DestroySterileCellRequestV1 {
            lease_id: lease.lease_id,
            generation: lease.generation,
            disposition: SterileCellDisposition::Quarantined,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(contradictory_cleanup.status(), StatusCode::CONFLICT);

    let duplicate = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/prepare",
            server.base_url, worker.worker.id
        ))
        .json(&PrepareSterileCellRequestV1 {
            cell_id,
            release: signed_release(SterileCellRuntimeClass::KataMicrovm),
            provider_cell_id: "pod-reused".into(),
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn claim_attestation_is_never_persisted_for_idempotent_replay() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("claim-secret.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    let idempotency_key = Uuid::now_v7().to_string();
    let request = claim_request(release.clone());
    let claimed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .header("idempotency-key", &idempotency_key)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let attestation = claimed.lease_attestation.unwrap();

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    let persisted: i64 = sqlx::query(
        "select count(*) as count from idempotency_records
         where idempotency_key = ? and response_body_base64 is not null",
    )
    .bind(&idempotency_key)
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(persisted, 0, "raw lease attestation must not be persisted");

    let replayed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .header("idempotency-key", &idempotency_key)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replayed.lease, claimed.lease);
    assert_eq!(
        replayed.lease_attestation.as_deref(),
        Some(attestation.as_str())
    );
}

#[tokio::test]
async fn claim_id_replays_one_live_lease_and_conflicting_reuse_fails_closed() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("claim-fence.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    let first_cell = SterileCellId::new();
    let second_cell = SterileCellId::new();
    prepare(&server, &worker, first_cell, release.clone()).await;
    prepare(&server, &worker, second_cell, release.clone()).await;
    let request = claim_request(release.clone());
    let url = format!("{}/sterile-cells/claim", server.base_url);

    let (first, replay) = tokio::join!(
        client.post(&url).json(&request).send(),
        client.post(&url).json(&request).send()
    );
    let first = first
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimSterileCellResponseV1>()
        .await
        .unwrap();
    let replay = replay
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimSterileCellResponseV1>()
        .await
        .unwrap();
    assert_eq!(replay, first);

    let mut conflict = request.clone();
    conflict.runner_session_id = "session-conflict".into();
    let response = client.post(&url).json(&conflict).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let mut ttl_conflict = request.clone();
    ttl_conflict.lease_seconds = Some(121);
    let response = client.post(&url).json(&ttl_conflict).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    let leased: i64 =
        sqlx::query("select count(*) as count from sterile_cells where state = 'leased'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
    assert_eq!(
        leased, 1,
        "an exact retry must not consume another ready cell"
    );

    let lease = first.lease.unwrap();
    worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/{}/destroy",
            server.base_url, worker.worker.id, lease.cell_id
        ))
        .json(&DestroySterileCellRequestV1 {
            lease_id: lease.lease_id,
            generation: lease.generation,
            disposition: SterileCellDisposition::Destroyed,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let terminal_retry = client.post(&url).json(&request).send().await.unwrap();
    assert_eq!(terminal_retry.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn an_empty_claim_id_replays_empty_instead_of_consuming_later_inventory() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("empty-fence.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    let request = claim_request(release.clone());
    let url = format!("{}/sterile-cells/claim", server.base_url);

    let empty: ClaimSterileCellResponseV1 = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!empty.ok);
    assert!(empty.lease.is_none());
    assert_eq!(
        empty.no_lease_reason,
        Some(SterileCellNoLeaseReasonV1::CapacityAbsent)
    );
    assert_eq!(empty.claimability.as_ref().unwrap().claimable_cells, 0);
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    let replay: ClaimSterileCellResponseV1 = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay, empty);

    let fresh: ClaimSterileCellResponseV1 = client
        .post(&url)
        .json(&claim_request(release))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(fresh.lease.is_some());
}

#[tokio::test]
async fn missing_claim_id_preserves_legacy_unfenced_one_shot_semantics() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("legacy-claim.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    let mut legacy_request = serde_json::to_value(claim_request(release)).unwrap();
    legacy_request.as_object_mut().unwrap().remove("claim_id");
    let url = format!("{}/sterile-cells/claim", server.base_url);

    let first: ClaimSterileCellResponseV1 = client
        .post(&url)
        .json(&legacy_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: ClaimSterileCellResponseV1 = client
        .post(&url)
        .json(&legacy_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let first_lease = first.lease.unwrap();
    let second_lease = second.lease.unwrap();
    assert_ne!(first_lease.cell_id, second_lease.cell_id);

    let legacy_lookup: WorkerSterileCellLookupResponseV1 = worker_client(&worker)
        .get(format!(
            "{}/workers/{}/sterile-cells/{}",
            server.base_url, worker.worker.id, first_lease.cell_id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(legacy_lookup.cell.state, SterileCellState::Leased);
    assert!(legacy_lookup.claim.is_none());
}

#[tokio::test]
async fn worker_lookup_recovers_non_secret_claim_locator_and_ready_retire_is_fenced() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("worker-recovery.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    let ready_id = SterileCellId::new();
    prepare(&server, &worker, ready_id, release.clone()).await;
    let lookup_url = format!(
        "{}/workers/{}/sterile-cells/{ready_id}",
        server.base_url, worker.worker.id
    );

    let ready: WorkerSterileCellLookupResponseV1 = worker_client(&worker)
        .get(&lookup_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ready.cell.state, SterileCellState::Ready);
    assert!(ready.claim.is_none());

    let retired: SterileCellResponseV1 = worker_client(&worker)
        .post(format!("{lookup_url}/retire"))
        .json(&RetireSterileCellRequestV1 { generation: 1 })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retired.cell.state, SterileCellState::Quarantined);
    assert_eq!(
        retired.cell.disposition,
        Some(SterileCellDisposition::Quarantined)
    );
    worker_client(&worker)
        .post(format!("{lookup_url}/retire"))
        .json(&RetireSterileCellRequestV1 { generation: 1 })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let claimed_id = SterileCellId::new();
    prepare(&server, &worker, claimed_id, release.clone()).await;
    let claim = claim_request(release);
    let claimed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed.lease.unwrap();
    let response = worker_client(&worker)
        .get(format!(
            "{}/workers/{}/sterile-cells/{claimed_id}",
            server.base_url, worker.worker.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let raw = response.text().await.unwrap();
    assert!(!raw.contains("attestation"));
    assert!(!raw.contains("sha256"));
    let lookup: WorkerSterileCellLookupResponseV1 = serde_json::from_str(&raw).unwrap();
    let locator = lookup.claim.unwrap();
    assert_eq!(Some(locator.claim_id), claim.claim_id);
    assert_eq!(locator.lease_id, lease.lease_id);
    assert_eq!(locator.generation, lease.generation);
    assert_eq!(locator.expires_at, lease.expires_at);

    let stale_retire = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/{claimed_id}/retire",
            server.base_url, worker.worker.id
        ))
        .json(&RetireSterileCellRequestV1 { generation: 1 })
        .send()
        .await
        .unwrap();
    assert_eq!(stale_retire.status(), StatusCode::CONFLICT);
    let after: WorkerSterileCellLookupResponseV1 = worker_client(&worker)
        .get(format!(
            "{}/workers/{}/sterile-cells/{claimed_id}",
            server.base_url, worker.worker.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after.cell.state, SterileCellState::Leased);
}

#[tokio::test]
async fn ready_inventory_is_owned_by_the_preparing_workers_tenant() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("inventory-tenant.db").display()
    );
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;

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
    let cross_tenant: ClaimSterileCellResponseV1 = tenant_b
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(release.clone()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(cross_tenant.lease.is_none());

    let owner: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(release))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(owner.lease.is_some());
}

#[tokio::test]
async fn stale_generation_cross_tenant_and_ambiguous_cleanup_fail_closed() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("fences.db").display());
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::GvisorLowerRisk);
    let cell_id = SterileCellId::new();
    prepare(&server, &worker, cell_id, release.clone()).await;
    let claimed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&claim_request(release))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let lease = claimed.lease.unwrap();

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
    let cross_tenant = tenant_b
        .post(format!(
            "{}/sterile-cell-leases/{}/validate",
            server.base_url, lease.lease_id
        ))
        .json(&ValidateSterileCellLeaseRequestV1 {
            lease_attestation: claimed.lease_attestation.unwrap(),
            generation: lease.generation,
            organization_id: lease.organization_id.clone(),
            workspace_id: lease.workspace_id.clone(),
            thread_id: lease.thread_id.clone(),
            runner_session_id: lease.runner_session_id.clone(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);

    let stale = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sterile-cells/{}/destroy",
            server.base_url, worker.worker.id, cell_id
        ))
        .json(&DestroySterileCellRequestV1 {
            lease_id: lease.lease_id,
            generation: lease.generation - 1,
            disposition: SterileCellDisposition::Destroyed,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    let state: String = sqlx::query("select state from sterile_cells where id = ?")
        .bind(cell_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("state")
        .unwrap();
    assert_eq!(state, "quarantined");
}

#[tokio::test]
async fn expired_lease_is_quarantined_instead_of_returned_to_inventory() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("expiry.db").display());
    let server = TestServer::start_with_sterile_cells(database_url, Some(data_dir), true).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    let cell_id = SterileCellId::new();
    prepare(&server, &worker, cell_id, release.clone()).await;
    let mut request = claim_request(release);
    request.lease_seconds = Some(1);
    let claimed: ClaimSterileCellResponseV1 = client
        .post(format!("{}/sterile-cells/claim", server.base_url))
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(claimed.lease.is_some());

    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    let state = poll_until(|| async {
        let row = sqlx::query("select state from sterile_cells where id = $1")
            .bind(cell_id.to_string())
            .fetch_one(&pool)
            .await
            .ok()?;
        let state: String = row.try_get("state").ok()?;
        (state == "quarantined").then_some(state)
    })
    .await;
    assert_eq!(state.as_deref(), Some("quarantined"));
}

#[tokio::test]
async fn atomic_claim_works_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start_with_sterile_cells(database_url, None, false).await;
    let client = server.client();
    let worker = register_worker(&server, &client).await;
    let release = signed_release(SterileCellRuntimeClass::KataMicrovm);
    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    let url = format!("{}/sterile-cells/claim", server.base_url);
    let request = claim_request(release.clone());
    let (left, right) = tokio::join!(
        client.post(&url).json(&request).send(),
        client.post(&url).json(&request).send()
    );
    let left = left
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimSterileCellResponseV1>()
        .await
        .unwrap();
    let right = right
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimSterileCellResponseV1>()
        .await
        .unwrap();
    assert!(left.lease.is_some());
    assert_eq!(left, right);

    prepare(&server, &worker, SterileCellId::new(), release.clone()).await;
    let first_request = claim_request(release.clone());
    let second_request = claim_request(release);
    let (left, right) = tokio::join!(
        client.post(&url).json(&first_request).send(),
        client.post(&url).json(&second_request).send()
    );
    let left = left
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimSterileCellResponseV1>()
        .await
        .unwrap();
    let right = right
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ClaimSterileCellResponseV1>()
        .await
        .unwrap();
    assert_eq!(
        usize::from(left.lease.is_some()) + usize::from(right.lease.is_some()),
        1,
        "distinct claim IDs still compete for one cell"
    );
}
