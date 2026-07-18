//! Contract coverage for the idle-TTL activity signal completion
//! (`sandboxes.last_activity_at`): SSH access, desktop access, and
//! resident-process observations must each reset a sandbox's idle clock,
//! preventing reaping even when `updated_at` alone (the previous, partial
//! signal) is already past the `idle_ttl_seconds` deadline. See
//! `sandboxwich_api::activity` and the updated "Sandbox lifetime" section
//! of `docs/capabilities.md`.

use crate::common::*;
use sandboxwich_core::*;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;
use std::collections::BTreeMap;
use std::time::Duration;

async fn sandbox_state(pool: &sqlx::AnyPool, sandbox_id: SandboxId) -> String {
    sqlx::query(&format!(
        "select state from sandboxes where id = '{sandbox_id}'"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
    .try_get("state")
    .unwrap()
}

async fn create_sandbox_with_idle_ttl(
    client: &reqwest::Client,
    server: &TestServer,
    name: &str,
) -> SandboxResponse {
    client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some(name.to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            workspace_mode: Some(WorkspaceMode::Ephemeral),
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: Some(300),
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

/// Fast-forwards `sandbox_id` to `ready` with a stale `updated_at` -- already
/// past the `idle_ttl_seconds` deadline on `updated_at` alone -- via SQL,
/// mirroring `reap.rs`'s established pattern (no worker ever claims the
/// provision job in these tests, and `ready` is a real, reachable
/// `STOP_LEGAL_FROM` state; see that test's comments for why not
/// `running`/`idle`).
///
/// Callers must perform whichever activity-bumping action they're testing
/// (SSH access, desktop access, ...) *before* calling this, not after: the
/// background sweeper is already running and ticking every 25ms at this
/// point in every test in this file, and `Planning`/`Ready` are themselves
/// `STOP_LEGAL_FROM` states. Making a sandbox look idle-due before its
/// protective activity bump exists leaves a real race window -- reap.rs's
/// perf/173-idle-sweep-join PR and this one both hit variants of this same
/// race independently.
async fn make_idle_due(pool: &sqlx::AnyPool, sandbox_id: SandboxId) {
    let long_ago = (chrono::Utc::now() - chrono::Duration::seconds(600)).to_rfc3339();
    sqlx::query(&format!(
        "update sandboxes set state = 'ready', updated_at = '{long_ago}' where id = '{sandbox_id}'"
    ))
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn ssh_access_resets_the_idle_clock() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("ssh-activity.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    let client = server.client();

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();

    let kept_alive_by_ssh =
        create_sandbox_with_idle_ttl(&client, &server, "kept-alive-by-ssh").await;
    let left_untouched = create_sandbox_with_idle_ttl(&client, &server, "left-untouched").await;

    // Mint SSH access -- the activity signal under test -- *before* either
    // sandbox is made to look idle-due below (see `make_idle_due`'s docs
    // for why this order matters).
    client
        .post(format!(
            "{}/sandboxes/{}/ssh-access",
            server.base_url, kept_alive_by_ssh.sandbox.id
        ))
        .json(&SshAccessRequest {
            principal: None,
            ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    for sandbox in [&kept_alive_by_ssh, &left_untouched] {
        make_idle_due(&pool, sandbox.sandbox.id).await;
    }

    poll_until(|| async {
        (sandbox_state(&pool, left_untouched.sandbox.id).await == "archiving").then_some(())
    })
    .await
    .expect("the sandbox with no SSH access, idle on updated_at alone, should be reaped");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        sandbox_state(&pool, kept_alive_by_ssh.sandbox.id).await,
        "ready",
        "minting SSH access must bump last_activity_at and prevent reaping, \
         even though updated_at alone is already past the idle_ttl_seconds deadline"
    );
}

#[tokio::test]
async fn desktop_access_resets_the_idle_clock() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("desktop-activity.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    let client = server.client();

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();

    let kept_alive_by_desktop =
        create_sandbox_with_idle_ttl(&client, &server, "kept-alive-by-desktop").await;
    let left_untouched =
        create_sandbox_with_idle_ttl(&client, &server, "left-untouched-desktop").await;

    let desktop_session: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, kept_alive_by_desktop.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: None,
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

    // A freshly created session is `Pending`; `mint_desktop_access` requires
    // `Ready` (see `mint_desktop_access`'s first check).
    client
        .post(format!(
            "{}/desktop-sessions/{}/status",
            server.base_url, desktop_session.desktop_session.id
        ))
        .json(&UpdateDesktopSessionRequest {
            status: DesktopSessionStatus::Ready,
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: None,
            ttl_seconds: None,
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Mint desktop access -- the activity signal under test -- *before*
    // either sandbox is made to look idle-due below.
    client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop_session.desktop_session.id
        ))
        .json(&DesktopAccessRequest { ttl_seconds: None })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    for sandbox in [&kept_alive_by_desktop, &left_untouched] {
        make_idle_due(&pool, sandbox.sandbox.id).await;
    }

    poll_until(|| async {
        (sandbox_state(&pool, left_untouched.sandbox.id).await == "archiving").then_some(())
    })
    .await
    .expect("the sandbox with no desktop access, idle on updated_at alone, should be reaped");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        sandbox_state(&pool, kept_alive_by_desktop.sandbox.id).await,
        "ready",
        "minting desktop access must bump last_activity_at and prevent reaping, \
         even though updated_at alone is already past the idle_ttl_seconds deadline"
    );
}

/// Provisions `sandbox_id` for real (claim, complete, using the given
/// already-registered `worker`), unlike the SSH/desktop tests above which
/// fast-forward straight to `ready` via SQL: minting a guest token (needed
/// to authenticate the `observe_resident_process` call below as
/// `Principal::Guest`) requires a real `sandbox_placements` row *for that
/// specific worker* (`ensure_sandbox_worker_scope` checks the requesting
/// worker actually holds the placement, not merely that some placement
/// exists), which only a completed `ProvisionSandbox` lease creates.
async fn provision_for_real(server: &TestServer, worker: &WorkerResponse, sandbox_id: SandboxId) {
    let provision: ClaimLeaseResponse = worker_client(worker)
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
        .json()
        .await
        .unwrap();
    let provision = provision.lease.expect("provision lease");
    worker_client(worker)
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, provision.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".into(),
                    sandbox_id,
                    resources: provision_resources(sandbox_id),
                    metadata: serde_json::json!({}),
                },
            }),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

#[tokio::test]
async fn resident_process_observation_resets_the_idle_clock() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("resident-activity.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    let client = server.client();

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();

    let kept_alive_by_resident =
        create_sandbox_with_idle_ttl(&client, &server, "kept-alive-by-resident").await;
    let left_untouched =
        create_sandbox_with_idle_ttl(&client, &server, "left-untouched-resident").await;

    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "resident-activity-worker".into(),
            provider: "kubernetes".into(),
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
        .unwrap();

    // Both need a real ProvisionSandbox completion (by this same worker --
    // see `provision_for_real`'s docs) even though only one gets a resident
    // process, so the "must still be reaped" control isn't confounded by
    // never having a worker/guest-token/placement at all.
    provision_for_real(&server, &worker, kept_alive_by_resident.sandbox.id).await;
    provision_for_real(&server, &worker, left_untouched.sandbox.id).await;

    let guest: GuestTokenResponse = worker_client(&worker)
        .post(format!(
            "{}/workers/{}/sandboxes/{}/guest-token",
            server.base_url, worker.worker.id, kept_alive_by_resident.sandbox.id
        ))
        .json(&MintGuestTokenRequest {
            ttl_seconds: Some(300),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let guest_client = {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", guest.token).parse().unwrap(),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap()
    };
    guest_client
        .post(format!(
            "{}/sandboxes/{}/guest-health",
            server.base_url, kept_alive_by_resident.sandbox.id
        ))
        .json(&UpdateGuestHealthRequest {
            status: GuestStatus::Ready,
            agent_version: Some("sandboxwich-agent/test".into()),
            checks: Some(serde_json::json!({
                (GUEST_AGENT_CAPABILITY_REPORT_CHECK): GuestAgentCapabilityReport::current()
            })),
            message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let resident: ResidentProcessResponse = client
        .put(format!(
            "{}/sandboxes/{}/resident-processes/orb-executor",
            server.base_url, kept_alive_by_resident.sandbox.id
        ))
        .json(&ResidentProcessRequest {
            argv: vec!["/usr/local/bin/orb-executor".into()],
            cwd: Some("/workspace".into()),
            env: BTreeMap::new(),
            restart_policy: ResidentProcessRestartPolicy::OnFailure,
            expected_generation: 0,
            bootstrap: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let claimed: ClaimLeaseResponse = guest_client
        .post(format!(
            "{}/workers/{}/leases/claim",
            server.base_url, worker.worker.id
        ))
        .json(&ClaimLeaseRequest {
            lease_seconds: Some(60),
            sandbox_id: Some(kept_alive_by_resident.sandbox.id),
            kinds: Some(vec![JobKind::RunResidentProcess]),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let claimed = claimed.lease.expect("resident process lease");

    // The guest reporting an observation -- the activity signal under
    // test -- *before* either sandbox is made to look idle-due below.
    guest_client
        .post(format!(
            "{}/resident-processes/{}/observations",
            server.base_url, resident.resident_process.id
        ))
        .json(&ResidentProcessObservationRequest {
            generation: resident.resident_process.generation,
            lease_id: claimed.id.0,
            observed_state: ResidentProcessObservedState::Running,
            pid: Some(42),
            exit_code: None,
            error_code: None,
            error_message: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    for sandbox in [&kept_alive_by_resident, &left_untouched] {
        make_idle_due(&pool, sandbox.sandbox.id).await;
    }

    poll_until(|| async {
        (sandbox_state(&pool, left_untouched.sandbox.id).await == "archiving").then_some(())
    })
    .await
    .expect("the sandbox with no resident-process observation, idle on updated_at alone, should be reaped");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        sandbox_state(&pool, kept_alive_by_resident.sandbox.id).await,
        "ready",
        "a resident-process observation must bump last_activity_at and prevent \
         reaping, even though updated_at alone is already past the \
         idle_ttl_seconds deadline"
    );
}
