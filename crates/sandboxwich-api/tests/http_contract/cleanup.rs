//! Regression coverage for the SQLite `PRAGMA foreign_keys = ON` fix: before
//! it, every `ON DELETE CASCADE` in the migrations was live on Postgres but
//! dead on SQLite, so deleting an archived sandbox during cleanup silently
//! left its `commands`, `sandbox_events`, `snapshots`, and `runtime_resources`
//! rows behind as orphans. This starts a real server (which runs through the
//! production `connect_database` path, unlike the in-process unit tests) and
//! asserts those rows are actually gone afterward -- not just the sandbox.

use crate::common::*;
use crate::snapshots::assert_provision_job_persists_runtime_resources;
use reqwest::StatusCode;
use sandboxwich_core::*;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;

#[tokio::test]
async fn archived_sandbox_cleanup_cascades_dependent_rows_on_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("cascade-cleanup.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let client = server.client();

    let worker: WorkerResponse = client
        .post(format!("{}/workers/register", server.base_url))
        .json(&RegisterWorkerRequest {
            name: "cascade-cleanup-worker".to_string(),
            provider: "kubernetes".to_string(),
            // `StopSandbox` jobs are scheduled under the `ProvisionSandbox`
            // capability (see `handlers::sandboxes`), so that alone covers
            // both provisioning and stopping this sandbox.
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
            ],
            max_concurrent_jobs: Some(4),
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
    let worker_client = worker_client(&worker);

    // `ttl_seconds: Some(0)` mirrors the existing archived-sandbox cleanup
    // fixture: it does not affect eligibility until the sandbox actually
    // reaches `archived` (eligibility is `updated_at + ttl_seconds`), so it
    // is safe to set from creation.
    let sandbox: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("cascade-cleanup-me".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
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
    let sandbox_id = sandbox.sandbox.id;

    assert_provision_job_persists_runtime_resources(&client, &server, &sandbox, &worker).await;

    // Gives us a `commands` row (and the queued-command `sandbox_events` row)
    // FK'd to this sandbox. The command's own job never needs to be claimed
    // -- the row just needs to exist so we can prove it doesn't outlive the
    // sandbox.
    let queued: QueueCommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, sandbox_id
        ))
        .json(&CommandRequest {
            argv: vec!["true".to_string()],
            cwd: None,
            env: Default::default(),
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
    assert_eq!(queued.command.sandbox_id, sandbox_id);

    // Gives us a `snapshots` row FK'd to this sandbox, plus a decoupled
    // `snapshot_restore_sources` row that is *not* FK'd to `sandboxes` at all
    // (by design -- see the `snapshot_tenant_ownership` migration comment)
    // and must survive the sandbox delete below. `ttl_seconds: Some(0)`
    // makes it immediately eligible for the expiry pass that
    // `run_cleanup_controller` runs before the archived-sandbox pass, which
    // clears `sandbox_snapshot_is_referenced`'s block within the same
    // cleanup call.
    let snapshot: SnapshotResponse = client
        .post(format!(
            "{}/sandboxes/{}/snapshots",
            server.base_url, sandbox_id
        ))
        .json(&CreateSnapshotRequest {
            label: Some("cascade-cleanup-snapshot".to_string()),
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
    let snapshot_id = snapshot.snapshot.id;

    client
        .post(format!("{}/sandboxes/{}/stop", server.base_url, sandbox_id))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
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
    let stop_lease = claimed.lease.expect("expected worker to claim stop job");
    assert_eq!(stop_lease.job.kind, JobKind::StopSandbox);
    worker_client
        .post(format!(
            "{}/leases/{}/complete",
            server.base_url, stop_lease.id
        ))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::StopSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id,
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
    assert!(
        cleanup
            .expired
            .iter()
            .any(|expired_snapshot| expired_snapshot.id == snapshot_id),
        "the snapshot's own ttl=0 expiry must clear the restore-source block \
         in the same cleanup run that deletes the sandbox"
    );
    assert!(
        cleanup
            .archived_sandboxes
            .iter()
            .any(|deleted| deleted.id == sandbox_id),
        "sandbox should have been deleted once its only snapshot reference expired"
    );

    let missing = client
        .get(format!("{}/sandboxes/{}", server.base_url, sandbox_id))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();

    let sandbox_id_str = sandbox_id.to_string();
    for (table, column) in [
        ("commands", "sandbox_id"),
        ("sandbox_events", "sandbox_id"),
        ("snapshots", "sandbox_id"),
        ("runtime_resources", "sandbox_id"),
    ] {
        let count: i64 = sqlx::query(&format!(
            "select count(*) as count from {table} where {column} = ?"
        ))
        .bind(&sandbox_id_str)
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
        assert_eq!(
            count, 0,
            "deleting the archived sandbox must cascade-delete its {table} rows on SQLite \
             just as it already does on Postgres, instead of leaving them orphaned"
        );
    }

    // `snapshot_restore_sources` is deliberately *not* FK'd to `sandboxes`
    // (see the `snapshot_tenant_ownership` migration) so a restore chain can
    // keep working after its source sandbox is gone. Enabling foreign key
    // enforcement must not have accidentally started cascading this one too.
    let restore_source_count: i64 = sqlx::query(
        "select count(*) as count from snapshot_restore_sources where source_sandbox_id = ?",
    )
    .bind(&sandbox_id_str)
    .fetch_one(&pool)
    .await
    .unwrap()
    .try_get("count")
    .unwrap();
    assert_eq!(
        restore_source_count, 1,
        "snapshot_restore_sources rows must survive their source sandbox's deletion"
    );
}
