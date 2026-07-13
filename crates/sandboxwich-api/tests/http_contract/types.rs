use sqlx::any::AnyPoolOptions;
use uuid::Uuid;

pub(crate) async fn assert_database_rejects_invalid_typed_values(
    database_url: &str,
    sandbox_id: &str,
) {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap();

    let invalid_sandbox_id = Uuid::now_v7().to_string();
    let invalid_snapshot_id = Uuid::now_v7().to_string();
    let invalid_desktop_status_id = Uuid::now_v7().to_string();
    let invalid_desktop_access_mode_id = Uuid::now_v7().to_string();
    let invalid_command_id = Uuid::now_v7().to_string();
    let valid_output_command_id = Uuid::now_v7().to_string();
    let invalid_output_chunk_id = Uuid::now_v7().to_string();
    let invalid_event_id = Uuid::now_v7().to_string();
    let valid_worker_id = Uuid::now_v7().to_string();
    let invalid_job_kind_id = Uuid::now_v7().to_string();
    let invalid_job_status_id = Uuid::now_v7().to_string();
    let invalid_job_required_capability_id = Uuid::now_v7().to_string();
    let valid_job_id = Uuid::now_v7().to_string();
    let invalid_lease_id = Uuid::now_v7().to_string();
    let invalid_cleanup_run_id = Uuid::now_v7().to_string();
    let invalid_runtime_kind_id = Uuid::now_v7().to_string();
    let invalid_runtime_purpose_id = Uuid::now_v7().to_string();
    let invalid_runtime_status_id = Uuid::now_v7().to_string();
    let invalid_tombstone_kind_id = Uuid::now_v7().to_string();
    let invalid_tombstone_purpose_id = Uuid::now_v7().to_string();
    let invalid_tombstone_status_id = Uuid::now_v7().to_string();
    let now = "2026-07-04T00:00:00Z";

    let sandbox_result = sqlx::query(&insert_sandbox_sql(database_url))
        .bind(invalid_sandbox_id)
        .bind("invalid")
        .bind("not_real")
        .bind("ubuntu-dev")
        .bind("1g")
        .bind("deny_all")
        .bind("persistent")
        .bind(now)
        .bind(now)
        .bind(120_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        sandbox_result.is_err(),
        "invalid sandbox state was accepted"
    );

    let invalid_memory_result = sqlx::query(&insert_sandbox_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind("invalid-memory")
        .bind("ready")
        .bind("ubuntu-dev")
        .bind("2g")
        .bind("deny_all")
        .bind("persistent")
        .bind(now)
        .bind(now)
        .bind(120_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_memory_result.is_err(),
        "invalid sandbox memory limit was accepted"
    );

    let invalid_network_result = sqlx::query(&insert_sandbox_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind("invalid-network")
        .bind("ready")
        .bind("ubuntu-dev")
        .bind("1g")
        .bind("sometimes")
        .bind("persistent")
        .bind(now)
        .bind(now)
        .bind(120_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_network_result.is_err(),
        "invalid sandbox network egress mode was accepted"
    );

    let invalid_workspace_mode_result = sqlx::query(&insert_sandbox_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind("invalid-workspace-mode")
        .bind("ready")
        .bind("ubuntu-dev")
        .bind("1g")
        .bind("deny_all")
        .bind("forever")
        .bind(now)
        .bind(now)
        .bind(120_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_workspace_mode_result.is_err(),
        "invalid sandbox workspace mode was accepted"
    );

    let invalid_network_rule_result = sqlx::query(&insert_network_allow_rule_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind(sandbox_id)
        .bind("not_real")
        .bind("10.0.0.0/8")
        .bind(now)
        .execute(&pool)
        .await;
    assert!(
        invalid_network_rule_result.is_err(),
        "invalid network allow rule kind was accepted"
    );

    let command_result = sqlx::query(&insert_command_sql(database_url))
        .bind(invalid_command_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind(r#"["echo","nope"]"#)
        .bind(Option::<String>::None)
        .bind(Option::<i32>::None)
        .bind("")
        .bind("")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        command_result.is_err(),
        "invalid command status was accepted"
    );

    sqlx::query(&insert_command_sql(database_url))
        .bind(&valid_output_command_id)
        .bind(sandbox_id)
        .bind("queued")
        .bind(r#"["echo","ok"]"#)
        .bind(Option::<String>::None)
        .bind(Option::<i32>::None)
        .bind("")
        .bind("")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .unwrap();

    let command_output_stream_result = sqlx::query(&insert_command_output_chunk_sql(database_url))
        .bind(invalid_output_chunk_id)
        .bind(&valid_output_command_id)
        .bind("not_real")
        .bind(0_i64)
        .bind("nope")
        .bind("[]")
        .bind(now)
        .execute(&pool)
        .await;
    assert!(
        command_output_stream_result.is_err(),
        "invalid command output stream was accepted"
    );

    let snapshot_result = sqlx::query(&insert_snapshot_sql(database_url))
        .bind(invalid_snapshot_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("invalid")
        .bind("{}")
        .bind("{}")
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        snapshot_result.is_err(),
        "invalid snapshot status was accepted"
    );

    let desktop_status_result = sqlx::query(&insert_desktop_session_sql(database_url))
        .bind(invalid_desktop_status_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("k3s-broker")
        .bind(Option::<String>::None)
        .bind("browser")
        .bind("{}")
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        desktop_status_result.is_err(),
        "invalid desktop session status was accepted"
    );

    let desktop_access_mode_result = sqlx::query(&insert_desktop_session_sql(database_url))
        .bind(invalid_desktop_access_mode_id)
        .bind(sandbox_id)
        .bind("ready")
        .bind("k3s-broker")
        .bind(Option::<String>::None)
        .bind("not_real")
        .bind("{}")
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        desktop_access_mode_result.is_err(),
        "invalid desktop access mode was accepted"
    );

    let event_result = sqlx::query(&insert_event_sql(database_url))
        .bind(invalid_event_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("{}")
        .bind(now)
        .execute(&pool)
        .await;
    assert!(event_result.is_err(), "invalid event kind was accepted");

    let worker_result = sqlx::query(&insert_worker_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind("invalid-worker")
        .bind("not_real")
        .bind("kubernetes")
        .bind(r#"["k8s_pod"]"#)
        .bind("{}")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(worker_result.is_err(), "invalid worker status was accepted");

    sqlx::query(&insert_worker_sql(database_url))
        .bind(&valid_worker_id)
        .bind("valid-worker")
        .bind("registered")
        .bind("kubernetes")
        .bind(r#"["run_command"]"#)
        .bind("{}")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .unwrap();

    let invalid_job_kind_result = sqlx::query(&insert_job_sql(database_url))
        .bind(invalid_job_kind_id)
        .bind("not_real")
        .bind("queued")
        .bind("{}")
        .bind("run_command")
        .bind(0_i64)
        .bind(0_i64)
        .bind(3_i64)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_job_kind_result.is_err(),
        "invalid job kind was accepted"
    );

    let invalid_job_status_result = sqlx::query(&insert_job_sql(database_url))
        .bind(invalid_job_status_id)
        .bind("run_command")
        .bind("not_real")
        .bind("{}")
        .bind("run_command")
        .bind(0_i64)
        .bind(0_i64)
        .bind(3_i64)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_job_status_result.is_err(),
        "invalid job status was accepted"
    );

    let invalid_job_required_capability_result = sqlx::query(&insert_job_sql(database_url))
        .bind(invalid_job_required_capability_id)
        .bind("run_command")
        .bind("queued")
        .bind("{}")
        .bind("not_real")
        .bind(0_i64)
        .bind(0_i64)
        .bind(3_i64)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_job_required_capability_result.is_err(),
        "invalid job required capability was accepted"
    );

    sqlx::query(&insert_job_sql(database_url))
        .bind(&valid_job_id)
        .bind("run_command")
        .bind("succeeded")
        .bind("{}")
        .bind("run_command")
        .bind(0_i64)
        .bind(0_i64)
        .bind(3_i64)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .unwrap();

    let invalid_lease_status_result = sqlx::query(&insert_job_lease_sql(database_url))
        .bind(invalid_lease_id)
        .bind(&valid_job_id)
        .bind(&valid_worker_id)
        .bind("not_real")
        .bind(1_i64)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        invalid_lease_status_result.is_err(),
        "invalid job lease status was accepted"
    );

    let guest_health_result = sqlx::query(&insert_guest_health_sql(database_url))
        .bind(sandbox_id)
        .bind("not_real")
        .bind(now)
        .bind(Option::<String>::None)
        .bind("{}")
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        guest_health_result.is_err(),
        "invalid guest status was accepted"
    );

    let ssh_key_result = sqlx::query(&insert_ssh_key_sql(database_url))
        .bind(Uuid::now_v7().to_string())
        .bind(sandbox_id)
        .bind("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest")
        .bind("tester")
        .bind("not_real")
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        ssh_key_result.is_err(),
        "invalid ssh key status was accepted"
    );

    let cleanup_run_result = sqlx::query(&insert_cleanup_run_sql(database_url))
        .bind(invalid_cleanup_run_id)
        .bind("not_real")
        .bind(now)
        .bind(Option::<String>::None)
        .bind(0_i64)
        .bind(0_i64)
        .bind(0_i64)
        .bind(0_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        cleanup_run_result.is_err(),
        "invalid cleanup run status was accepted"
    );

    let runtime_kind_result = sqlx::query(&insert_runtime_resource_sql(database_url))
        .bind(invalid_runtime_kind_id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind("not_real")
        .bind("runtime")
        .bind("invalid-kind")
        .bind("sandboxwich-contract")
        .bind("ready")
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        runtime_kind_result.is_err(),
        "invalid runtime resource kind was accepted"
    );

    let runtime_purpose_result = sqlx::query(&insert_runtime_resource_sql(database_url))
        .bind(invalid_runtime_purpose_id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind("pod")
        .bind("not_real")
        .bind("invalid-purpose")
        .bind("sandboxwich-contract")
        .bind("ready")
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        runtime_purpose_result.is_err(),
        "invalid runtime resource purpose was accepted"
    );

    let runtime_status_result = sqlx::query(&insert_runtime_resource_sql(database_url))
        .bind(invalid_runtime_status_id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind("pod")
        .bind("runtime")
        .bind("invalid-status")
        .bind("sandboxwich-contract")
        .bind("not_real")
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        runtime_status_result.is_err(),
        "invalid runtime resource status was accepted"
    );

    let tombstone_kind_result = insert_runtime_resource_tombstone(
        &pool,
        database_url,
        sandbox_id,
        invalid_tombstone_kind_id,
        "not_real",
        "runtime",
        "ready",
        now,
    )
    .await;
    assert!(
        tombstone_kind_result.is_err(),
        "invalid runtime resource tombstone kind was accepted"
    );

    let tombstone_purpose_result = insert_runtime_resource_tombstone(
        &pool,
        database_url,
        sandbox_id,
        invalid_tombstone_purpose_id,
        "pod",
        "not_real",
        "ready",
        now,
    )
    .await;
    assert!(
        tombstone_purpose_result.is_err(),
        "invalid runtime resource tombstone purpose was accepted"
    );

    let tombstone_status_result = insert_runtime_resource_tombstone(
        &pool,
        database_url,
        sandbox_id,
        invalid_tombstone_status_id,
        "pod",
        "runtime",
        "not_real",
        now,
    )
    .await;
    assert!(
        tombstone_status_result.is_err(),
        "invalid runtime resource tombstone status was accepted"
    );
}

pub(crate) fn insert_sandbox_sql(database_url: &str) -> String {
    format!(
        "insert into sandboxes
         (id, name, state, template, memory_limit, network_egress_mode, workspace_mode,
          created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        placeholders(database_url, 11)
    )
}

pub(crate) fn insert_network_allow_rule_sql(database_url: &str) -> String {
    format!(
        "insert into sandbox_network_egress_rules (id, sandbox_id, kind, value, created_at)
         values ({})",
        placeholders(database_url, 5)
    )
}

pub(crate) fn insert_command_sql(database_url: &str) -> String {
    format!(
        "insert into commands
         (id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at)
         values ({})",
        placeholders(database_url, 10)
    )
}

pub(crate) fn insert_command_output_chunk_sql(database_url: &str) -> String {
    format!(
        "insert into command_output_chunks
         (id, command_id, stream, sequence, chunk, annotations, created_at)
         values ({})",
        placeholders(database_url, 7)
    )
}

pub(crate) fn insert_snapshot_sql(database_url: &str) -> String {
    format!(
        "insert into snapshots
         (id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error)
         values ({})",
        placeholders(database_url, 10)
    )
}

pub(crate) fn insert_desktop_session_sql(database_url: &str) -> String {
    format!(
        "insert into desktop_sessions
         (id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
          created_at, updated_at, expires_at, error)
         values ({})",
        placeholders(database_url, 11)
    )
}

pub(crate) fn insert_event_sql(database_url: &str) -> String {
    format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values ({})",
        placeholders(database_url, 5)
    )
}

pub(crate) fn insert_worker_sql(database_url: &str) -> String {
    format!(
        "insert into workers
         (id, name, status, provider, capabilities, labels, registered_at, last_heartbeat_at)
         values ({})",
        placeholders(database_url, 8)
    )
}

pub(crate) fn insert_job_sql(database_url: &str) -> String {
    format!(
        "insert into jobs
         (id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error)
         values ({})",
        placeholders(database_url, 12)
    )
}

pub(crate) fn insert_job_lease_sql(database_url: &str) -> String {
    format!(
        "insert into job_leases
         (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
         values ({})",
        placeholders(database_url, 9)
    )
}

pub(crate) fn insert_guest_health_sql(database_url: &str) -> String {
    format!(
        "insert into guest_health (sandbox_id, status, last_probe_at, agent_version, checks, message)
         values ({})",
        placeholders(database_url, 6)
    )
}

pub(crate) fn insert_ssh_key_sql(database_url: &str) -> String {
    format!(
        "insert into ssh_keys
         (id, sandbox_id, public_key, principal, status, requested_at, updated_at, applied_at, error)
         values ({})",
        placeholders(database_url, 9)
    )
}

pub(crate) fn insert_cleanup_run_sql(database_url: &str) -> String {
    format!(
        "insert into cleanup_runs
         (id, status, started_at, finished_at, expired_snapshots, archived_sandboxes_deleted,
          archived_sandboxes_skipped, runtime_resources_deleted, error)
         values ({})",
        placeholders(database_url, 9)
    )
}

pub(crate) fn insert_runtime_resource_sql(database_url: &str) -> String {
    format!(
        "insert into runtime_resources
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, ready_at, deleted_at, error)
         values ({})",
        placeholders(database_url, 22)
    )
}

pub(crate) fn insert_runtime_resource_tombstone_sql(database_url: &str) -> String {
    format!(
        "insert into runtime_resource_tombstones
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, observed_at, last_reconciled_at,
          ready_at, deleted_at, error, tombstoned_at)
         values ({})",
        placeholders(database_url, 25)
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_runtime_resource_tombstone(
    pool: &sqlx::AnyPool,
    database_url: &str,
    sandbox_id: &str,
    id: String,
    resource_kind: &str,
    purpose: &str,
    status: &str,
    now: &str,
) -> Result<sqlx::any::AnyQueryResult, sqlx::Error> {
    let sql = insert_runtime_resource_tombstone_sql(database_url);
    sqlx::query(&sql)
        .bind(id)
        .bind(sandbox_id)
        .bind(Option::<String>::None)
        .bind("kubernetes")
        .bind(resource_kind)
        .bind(purpose)
        .bind("invalid-tombstone")
        .bind("sandboxwich-contract")
        .bind(status)
        .bind(Some("k3s-dev"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .bind(now)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(now)
        .execute(pool)
        .await
}

pub(crate) fn placeholders(database_url: &str, count: usize) -> String {
    (1..=count)
        .map(|index| {
            if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
                format!("${index}")
            } else {
                "?".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
