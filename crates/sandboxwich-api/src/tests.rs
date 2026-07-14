use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::auth::*;
use crate::cleanup::*;
use crate::config::*;
use crate::db::*;
use crate::handlers::commands::*;
use crate::handlers::jobs::*;
use crate::handlers::leases::*;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::handlers::workers::*;
use crate::state::{Principal, TenantContext};
use sandboxwich_core::*;
use std::collections::BTreeSet;

#[test]
fn db_enum_registry_covers_persisted_variant_columns() {
    let mut seen = BTreeSet::new();
    for column in db_enum_columns() {
        assert!(
            seen.insert((column.table, column.column)),
            "duplicate db enum registry entry for {}.{}",
            column.table,
            column.column
        );
        assert!(
            !column.values.is_empty(),
            "empty db enum values for {}.{}",
            column.table,
            column.column
        );
    }

    for expected in [
        ("sandboxes", "state"),
        ("sandboxes", "memory_limit"),
        ("sandboxes", "network_egress_mode"),
        ("sandboxes", "execution_class"),
        ("sandbox_network_egress_rules", "kind"),
        ("commands", "status"),
        ("command_output_chunks", "stream"),
        ("sandbox_events", "kind"),
        ("workers", "status"),
        ("jobs", "kind"),
        ("jobs", "status"),
        ("jobs", "required_capability"),
        ("jobs", "required_execution_class"),
        ("job_leases", "status"),
        ("guest_health", "status"),
        ("snapshots", "status"),
        ("desktop_sessions", "status"),
        ("desktop_sessions", "access_mode"),
        ("ssh_keys", "status"),
        ("runtime_resources", "resource_kind"),
        ("runtime_resources", "purpose"),
        ("runtime_resources", "status"),
        ("runtime_resource_tombstones", "resource_kind"),
        ("runtime_resource_tombstones", "purpose"),
        ("runtime_resource_tombstones", "status"),
        ("cleanup_runs", "status"),
        ("provisioning_operations", "stage"),
        ("provisioning_operations", "resource_kind"),
        ("provisioning_operations", "last_error_class"),
        ("provisioning_operation_resources", "stage"),
        ("provisioning_operation_resources", "resource_kind"),
        ("provisioning_stage_observations", "stage"),
        ("provisioning_stage_observations", "error_class"),
    ] {
        assert!(
            seen.contains(&expected),
            "missing db enum registry entry for {}.{}",
            expected.0,
            expected.1
        );
    }
}

#[test]
fn generated_sql_quotes_enum_values_and_errors() {
    let column = DbEnumColumn::new(
        "widgets",
        "state",
        "widgets_state_check",
        &["ready", "it''s-weird"],
        "invalid widget's state",
    );

    let postgres = postgres_enum_constraint_statements(column).join("\n");
    assert!(postgres.contains("'ready', 'it''''s-weird'"));

    let sqlite = sqlite_enum_trigger_statements(column).join("\n");
    assert!(sqlite.contains("'ready', 'it''''s-weird'"));
    assert!(sqlite.contains("'invalid widget''s state'"));
}

#[test]
fn api_command_parser_accepts_operational_modes() {
    assert!(matches!(
        parse_api_command(Vec::<String>::new()).unwrap(),
        ApiCommand::Serve
    ));
    assert!(matches!(
        parse_api_command(["serve".to_string()]).unwrap(),
        ApiCommand::Serve
    ));
    assert!(matches!(
        parse_api_command(["migrate".to_string()]).unwrap(),
        ApiCommand::Migrate
    ));
    assert!(matches!(
        parse_api_command(["check-schema".to_string()]).unwrap(),
        ApiCommand::CheckSchema
    ));
    assert!(matches!(
        parse_api_command(["openapi".to_string()]).unwrap(),
        ApiCommand::OpenApi
    ));
    assert!(parse_api_command(["migrate".to_string(), "extra".to_string()]).is_err());
    assert!(parse_api_command(["wat".to_string()]).is_err());
}

#[test]
fn looks_like_cidr_accepts_valid_v4_and_v6_networks() {
    assert!(looks_like_cidr("10.0.0.0/8"));
    assert!(looks_like_cidr("192.168.1.0/24"));
    assert!(looks_like_cidr("0.0.0.0/0"));
    assert!(looks_like_cidr("203.0.113.5/32"));
    assert!(looks_like_cidr("2001:db8::/32"));
    assert!(looks_like_cidr("::1/128"));
    assert!(looks_like_cidr("::/0"));
}

#[test]
fn dns_allow_rules_accept_controlled_wildcards_and_reject_ambiguous_names() {
    for valid in [
        "api.github.com",
        "example.com",
        "a-b.example",
        "*.packages.example.com",
    ] {
        assert!(
            looks_like_host_rule(valid),
            "expected valid DNS name: {valid}"
        );
    }
    for invalid in [
        "*",
        "*.localhost",
        "api.*.example.com",
        "**.example.com",
        ".example.com",
        "Example.com",
        "example.com.",
        "-edge.example",
        "edge-.example",
        "example..com",
        "127.0.0.1",
    ] {
        assert!(
            !looks_like_host_rule(invalid),
            "expected invalid DNS name: {invalid}"
        );
    }
}

#[test]
fn looks_like_cidr_rejects_garbage_and_out_of_range_prefixes() {
    // Not an IP address at all.
    assert!(!looks_like_cidr("notanip/24"));
    assert!(!looks_like_cidr("/24"));
    assert!(!looks_like_cidr("10.0.0.0"));
    assert!(!looks_like_cidr(""));
    // IPv4 prefix must be <= 32, even though it "looks" like a plausible
    // (0..=128) prefix -- this was the exact gap in the old prefix-only check.
    assert!(!looks_like_cidr("10.0.0.0/33"));
    assert!(!looks_like_cidr("10.0.0.0/128"));
    // IPv6 prefix must be <= 128.
    assert!(!looks_like_cidr("2001:db8::/129"));
    // Prefix must parse as an integer at all.
    assert!(!looks_like_cidr("10.0.0.0/abc"));
    assert!(!looks_like_cidr("10.0.0.0/-1"));
}

#[test]
fn db_enum_fingerprint_is_versioned_and_stable_for_current_registry() {
    let fingerprint = db_enum_schema_fingerprint();
    assert!(fingerprint.starts_with("db-enum-v5:"));
    assert_eq!(fingerprint, db_enum_schema_fingerprint());
}

#[test]
fn effective_command_timeout_secs_defaults_clamps_and_rejects_unbounded() {
    // Omitted falls back to the default.
    assert_eq!(
        effective_command_timeout_secs(None),
        DEFAULT_COMMAND_TIMEOUT_SECS
    );
    // A reasonable explicit value passes through untouched.
    assert_eq!(effective_command_timeout_secs(Some(45)), 45);
    // `0` would mean "always times out instantly", not "unbounded"; a
    // client can't use it (or any other absurd value) to make a command
    // execution hang forever -- it's clamped to a floor of 1s and a
    // ceiling of MAX_COMMAND_TIMEOUT_SECS either way.
    assert_eq!(effective_command_timeout_secs(Some(0)), 1);
    assert_eq!(
        effective_command_timeout_secs(Some(u64::MAX)),
        MAX_COMMAND_TIMEOUT_SECS
    );
}

#[test]
fn effective_lease_seconds_defaults_clamps_and_rejects_unbounded() {
    // Omitted falls back to the default.
    assert_eq!(effective_lease_seconds(None), DEFAULT_LEASE_SECONDS);
    // A reasonable explicit value passes through untouched.
    assert_eq!(effective_lease_seconds(Some(45)), 45);
    // `0` is clamped to a floor of 1s rather than granting an
    // already-expired lease.
    assert_eq!(effective_lease_seconds(Some(0)), MIN_LEASE_SECONDS);
    // Values large enough that `as i64` would still be positive are
    // clamped to the ceiling rather than granting an effectively unbounded
    // lease.
    assert_eq!(
        effective_lease_seconds(Some(u32::MAX as u64)),
        MAX_LEASE_SECONDS
    );
    // The original bug: a `lease_seconds` greater than `i64::MAX` wraps
    // negative when cast to `i64` (an already-expired lease, causing the
    // sweeper to requeue a job a worker is still running), and values in
    // `(i64::MAX / 1000, i64::MAX]` panic `chrono::Duration::seconds`
    // outright. Both must clamp instead.
    assert_eq!(
        effective_lease_seconds(Some(i64::MAX as u64)),
        MAX_LEASE_SECONDS
    );
    assert_eq!(effective_lease_seconds(Some(u64::MAX)), MAX_LEASE_SECONDS);

    // The clamped value must always be safe to feed into
    // `chrono::Duration::seconds` without panicking, for every input we
    // exercised above.
    for input in [
        None,
        Some(0),
        Some(45),
        Some(u32::MAX as u64),
        Some(i64::MAX as u64),
        Some(u64::MAX),
    ] {
        let seconds = effective_lease_seconds(input);
        let _ = chrono::Duration::seconds(seconds as i64);
    }
}

async fn test_sqlite_db() -> Database {
    sqlx::any::install_default_drivers();
    // A single pooled connection: `sqlite::memory:` gives each new
    // connection its own private, anonymous database, so more than one
    // pooled connection would see the migrations/schema on one connection
    // but not the others.
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    let db = Database {
        pool,
        dialect: SqlDialect::Sqlite,
    };
    sqlx::migrate!("./migrations")
        .run(&db.pool)
        .await
        .expect("run migrations");
    ensure_database_constraints(&db)
        .await
        .expect("reconcile enum constraints");
    db
}

#[tokio::test]
async fn provisioning_operation_migration_has_fenced_stage_columns() {
    let db = test_sqlite_db().await;
    let columns = sqlx::query("pragma table_info(provisioning_operations)")
        .fetch_all(&db.pool)
        .await
        .expect("inspect provisioning_operations");
    let names = columns
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<BTreeSet<_>>();

    for expected in [
        "sandbox_id",
        "lease_id",
        "lease_attempt",
        "stage",
        "stage_index",
        "resource_kind",
        "resource_namespace",
        "resource_name",
        "resource_uid",
        "observed_generation",
        "attempt_count",
        "last_error_class",
        "last_error_code",
        "last_error",
        "updated_at",
    ] {
        assert!(names.contains(expected), "missing column {expected}");
    }

    let resource_columns = sqlx::query("pragma table_info(provisioning_operation_resources)")
        .fetch_all(&db.pool)
        .await
        .expect("inspect provisioning_operation_resources");
    let resource_names = resource_columns
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<BTreeSet<_>>();
    for expected in [
        "sandbox_id",
        "stage",
        "resource_kind",
        "resource_namespace",
        "resource_name",
        "resource_uid",
        "observed_generation",
        "updated_at",
    ] {
        assert!(
            resource_names.contains(expected),
            "missing resource column {expected}"
        );
    }
}

#[tokio::test]
async fn provisioning_stage_update_persists_active_lease_fence() {
    let db = test_sqlite_db().await;
    let worker_id = seed_worker(&db).await;
    let sandbox = seed_sandbox_with_state(&db, SandboxState::Provisioning).await;
    let now = Utc::now();
    let job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Leased,
        payload: json!({ "sandboxId": sandbox.id }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 1,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job(&db, &job).await.expect("insert job");
    let lease_id = LeaseId::new();
    seed_expired_active_lease(
        &db,
        lease_id,
        job.id,
        worker_id,
        now + chrono::Duration::minutes(5),
    )
    .await;

    let operation = update_provisioning_stage_in_transaction(
        &db,
        lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspaceReady,
            resource_kind: Some(RuntimeResourceKind::PersistentVolumeClaim),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-pvc-{}", sandbox.id)),
            resource_uid: Some("uid-workspace".to_string()),
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("persist provisioning stage");

    assert_eq!(operation.sandbox_id, sandbox.id);
    assert_eq!(operation.lease_id, lease_id);
    assert_eq!(operation.lease_attempt, 1);
    assert_eq!(operation.stage, ProvisioningStage::WorkspaceReady);
    assert_eq!(operation.resource_uid.as_deref(), Some("uid-workspace"));

    let replayed = update_provisioning_stage_in_transaction(
        &db,
        lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspaceReady,
            resource_kind: Some(RuntimeResourceKind::PersistentVolumeClaim),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-pvc-{}", sandbox.id)),
            resource_uid: Some("uid-workspace".to_string()),
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("identical stage replay succeeds");
    assert_eq!(replayed.updated_at, operation.updated_at);

    let identity_conflict = update_provisioning_stage_in_transaction(
        &db,
        lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspaceReady,
            resource_kind: Some(RuntimeResourceKind::PersistentVolumeClaim),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-pvc-{}", sandbox.id)),
            resource_uid: Some("different-workspace-uid".to_string()),
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect_err("same resource identity cannot change within a stage");
    assert_eq!(
        identity_conflict.code,
        "provisioning_resource_identity_conflict"
    );

    let regression = update_provisioning_stage_in_transaction(
        &db,
        lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspacePlanned,
            resource_kind: None,
            resource_namespace: None,
            resource_name: None,
            resource_uid: None,
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect_err("a provisioning operation must not move backward");
    assert_eq!(regression.code, "provisioning_stage_regression");

    let network_ready = update_provisioning_stage_in_transaction(
        &db,
        lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::NetworkPolicyReady,
            resource_kind: Some(RuntimeResourceKind::NetworkPolicy),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-network-{}", sandbox.id)),
            resource_uid: Some("uid-network-policy".to_string()),
            observed_generation: Some(1),
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("advance first attempt to network policy ready");
    assert_eq!(network_ready.stage, ProvisioningStage::NetworkPolicyReady);

    for competing_attempt in [1_i64, 2_i64] {
        let competing_lease_id = LeaseId::new();
        sqlx::query(
            "insert into job_leases
             (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
             values (?, ?, ?, 'active', ?, ?, ?, NULL, NULL)",
        )
        .bind(competing_lease_id.to_string())
        .bind(job.id.to_string())
        .bind(worker_id.to_string())
        .bind(competing_attempt)
        .bind(now.to_rfc3339())
        .bind((now + chrono::Duration::minutes(5)).to_rfc3339())
        .execute(&db.pool)
        .await
        .expect("insert competing same-job lease");
        let competing = update_provisioning_stage_in_transaction(
            &db,
            competing_lease_id,
            ProvisioningStageUpdateRequest {
                stage: ProvisioningStage::NetworkPolicyReady,
                resource_kind: Some(RuntimeResourceKind::NetworkPolicy),
                resource_namespace: Some("sandboxwich-sandboxes".to_string()),
                resource_name: Some(format!("sandboxwich-network-{}", sandbox.id)),
                resource_uid: Some("uid-network-policy".to_string()),
                observed_generation: Some(1),
                attempt_count: competing_attempt,
                last_error_class: None,
                last_error_code: None,
                last_error: None,
            },
        )
        .await
        .expect_err("a same-job lease cannot take over while its predecessor is active");
        assert_eq!(competing.code, "provisioning_operation_fenced");
        sqlx::query("update job_leases set status = 'failed' where id = ?")
            .bind(competing_lease_id.to_string())
            .execute(&db.pool)
            .await
            .expect("retire competing same-job lease");
    }

    sqlx::query("update job_leases set status = 'expired' where id = ?")
        .bind(lease_id.to_string())
        .execute(&db.pool)
        .await
        .expect("expire first lease");
    let reclaimed_lease_id = LeaseId::new();
    sqlx::query(
        "insert into job_leases
         (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
         values (?, ?, ?, 'active', 2, ?, ?, NULL, NULL)",
    )
    .bind(reclaimed_lease_id.to_string())
    .bind(job.id.to_string())
    .bind(worker_id.to_string())
    .bind(now.to_rfc3339())
    .bind((now + chrono::Duration::minutes(5)).to_rfc3339())
    .execute(&db.pool)
    .await
    .expect("insert reclaimed lease");

    let handshake = update_provisioning_stage_in_transaction(
        &db,
        reclaimed_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspacePlanned,
            resource_kind: None,
            resource_namespace: None,
            resource_name: None,
            resource_uid: None,
            observed_generation: None,
            attempt_count: 2,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("new lease attempt resumes without regressing durable stage");
    assert_eq!(handshake.stage, ProvisioningStage::NetworkPolicyReady);
    assert_eq!(handshake.lease_attempt, 1);

    let replayed_workspace = update_provisioning_stage_in_transaction(
        &db,
        reclaimed_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspaceReady,
            resource_kind: Some(RuntimeResourceKind::PersistentVolumeClaim),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-pvc-{}", sandbox.id)),
            resource_uid: Some("uid-workspace".to_string()),
            observed_generation: None,
            attempt_count: 2,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("new attempt replays workspace stage without regression");
    assert_eq!(
        replayed_workspace.stage,
        ProvisioningStage::NetworkPolicyReady
    );
    assert_eq!(replayed_workspace.lease_attempt, 1);

    let replayed_network = update_provisioning_stage_in_transaction(
        &db,
        reclaimed_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::NetworkPolicyReady,
            resource_kind: Some(RuntimeResourceKind::NetworkPolicy),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-network-{}", sandbox.id)),
            resource_uid: Some("uid-network-policy".to_string()),
            observed_generation: Some(1),
            attempt_count: 2,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("new attempt catches up to durable network stage");
    assert_eq!(replayed_network.lease_attempt, 2);

    let reclaimed = update_provisioning_stage_in_transaction(
        &db,
        reclaimed_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::PodReady,
            resource_kind: Some(RuntimeResourceKind::Pod),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some(format!("sandboxwich-{}", sandbox.id)),
            resource_uid: Some("uid-pod".to_string()),
            observed_generation: Some(1),
            attempt_count: 2,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("new lease attempt owns operation");
    assert_eq!(reclaimed.lease_attempt, 2);

    let failed_stage = update_provisioning_stage_in_transaction(
        &db,
        reclaimed_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::PodReady,
            resource_kind: None,
            resource_namespace: None,
            resource_name: None,
            resource_uid: None,
            observed_generation: None,
            attempt_count: 2,
            last_error_class: Some(ProvisioningErrorClass::RetryableCapacity),
            last_error_code: Some("workspace_capacity_pending".to_string()),
            last_error: Some("workspace_capacity_pending: pod unschedulable".to_string()),
        },
    )
    .await
    .expect("typed failure updates the current durable stage");
    assert_eq!(
        failed_stage.last_error_class,
        Some(ProvisioningErrorClass::RetryableCapacity)
    );
    assert_eq!(
        failed_stage.last_error_code.as_deref(),
        Some("workspace_capacity_pending")
    );

    let competing_job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Leased,
        payload: json!({ "sandboxId": sandbox.id }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 1,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job(&db, &competing_job)
        .await
        .expect("insert competing provision job");
    let competing_lease_id = LeaseId::new();
    seed_expired_active_lease(
        &db,
        competing_lease_id,
        competing_job.id,
        worker_id,
        now + chrono::Duration::minutes(5),
    )
    .await;
    let competing = update_provisioning_stage_in_transaction(
        &db,
        competing_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspacePlanned,
            resource_kind: None,
            resource_namespace: None,
            resource_name: None,
            resource_uid: None,
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect_err("a second active provision lease must not steal the operation");
    assert_eq!(competing.code, "provisioning_operation_fenced");
    sqlx::query("update job_leases set status = 'failed' where id = ?")
        .bind(competing_lease_id.to_string())
        .execute(&db.pool)
        .await
        .expect("retire competing lease");

    let stale = update_provisioning_stage_in_transaction(
        &db,
        lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::SandboxReady,
            resource_kind: None,
            resource_namespace: None,
            resource_name: None,
            resource_uid: None,
            observed_generation: None,
            attempt_count: 2,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect_err("expired lease holder must be fenced");
    assert_eq!(stale.code, "lease_not_active");

    sqlx::query("update job_leases set status = 'completed' where id = ?")
        .bind(reclaimed_lease_id.to_string())
        .execute(&db.pool)
        .await
        .expect("complete prior provisioning lease");
    let reprovision_job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Leased,
        payload: json!({ "sandboxId": sandbox.id }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 1,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job(&db, &reprovision_job)
        .await
        .expect("insert reprovision job");
    let reprovision_lease_id = LeaseId::new();
    seed_expired_active_lease(
        &db,
        reprovision_lease_id,
        reprovision_job.id,
        worker_id,
        now + chrono::Duration::minutes(5),
    )
    .await;

    let reprovision = update_provisioning_stage_in_transaction(
        &db,
        reprovision_lease_id,
        ProvisioningStageUpdateRequest {
            stage: ProvisioningStage::WorkspacePlanned,
            resource_kind: None,
            resource_namespace: None,
            resource_name: None,
            resource_uid: None,
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    )
    .await
    .expect("a fresh reprovision job starts a new staged operation");
    assert_eq!(reprovision.lease_id, reprovision_lease_id);
    assert_eq!(reprovision.lease_attempt, 1);
    assert_eq!(reprovision.stage, ProvisioningStage::WorkspacePlanned);
}

async fn seed_worker(db: &Database) -> WorkerId {
    let now = Utc::now();
    let worker = Worker {
        id: WorkerId::new(),
        tenant_id: "default".to_string(),
        name: "test-worker".to_string(),
        status: WorkerStatus::Online,
        provider: "test".to_string(),
        capabilities: vec![WorkerCapability::ProvisionSandbox],
        max_concurrent_jobs: 1,
        labels: BTreeMap::new(),
        registered_at: now,
        last_heartbeat_at: Some(now),
    };
    let token_hash = hash_worker_token(&format!("test-token-{}", worker.id));
    insert_worker(db, &worker, &token_hash)
        .await
        .expect("insert worker");
    worker.id
}

async fn seed_provision_job(db: &Database) -> Job {
    let now = Utc::now();
    let job = Job {
        id: JobId::new(),
        tenant_id: "default".to_string(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Leased,
        payload: json!({ "sandboxId": Uuid::now_v7().to_string() }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job(db, &job).await.expect("insert job");
    job
}

async fn seed_expired_active_lease(
    db: &Database,
    lease_id: LeaseId,
    job_id: JobId,
    worker_id: WorkerId,
    expires_at: DateTime<Utc>,
) {
    sqlx::query(
        "insert into job_leases
         (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
         values (?, ?, ?, 'active', 1, ?, ?, NULL, NULL)",
    )
    .bind(lease_id.to_string())
    .bind(job_id.to_string())
    .bind(worker_id.to_string())
    .bind((expires_at - chrono::Duration::seconds(60)).to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(&db.pool)
    .await
    .expect("seed active lease");
}

#[tokio::test]
async fn expire_active_lease_on_connection_only_transitions_once() {
    let db = test_sqlite_db().await;
    let worker_id = seed_worker(&db).await;
    let job = seed_provision_job(&db).await;
    let lease_id = LeaseId::new();
    let now = Utc::now();
    seed_expired_active_lease(&db, lease_id, job.id, worker_id, now).await;

    // First caller wins the guarded active->expired transition...
    let mut tx = db.pool.begin().await.expect("begin tx");
    let first = expire_active_lease_on_connection(&db, &mut tx, lease_id, now, "lease expired")
        .await
        .expect("first expiry attempt");
    tx.commit().await.expect("commit first expiry");
    assert!(
        first,
        "first caller must observe the active->expired transition"
    );

    // ...and a racing second caller (e.g. another concurrent request or an
    // overlapping sweep) must see zero rows affected and must not re-run any
    // requeue/fail side effects.
    let mut tx = db.pool.begin().await.expect("begin tx");
    let second = expire_active_lease_on_connection(&db, &mut tx, lease_id, now, "lease expired")
        .await
        .expect("second expiry attempt");
    tx.commit().await.expect("commit second expiry");
    assert!(
        !second,
        "second caller must not double-process an already-expired lease"
    );

    let status: String = sqlx::query("select status from job_leases where id = ?")
        .bind(lease_id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("fetch lease")
        .try_get("status")
        .expect("read status");
    assert_eq!(status, "expired");
}

#[tokio::test]
async fn expire_active_lease_on_connection_does_not_clobber_a_renewal_race() {
    // Regression test for the renewal-vs-expiry race: `expire_due_leases`
    // SELECTs active leases (and their `expires_at`) on the pool, then
    // later applies `expire_active_lease_on_connection`'s guarded UPDATE.
    // If a `renew_lease` call commits a later `expires_at` in between
    // those two steps, the sweep must not still expire the
    // freshly-renewed lease -- otherwise the job gets re-queued and a
    // second worker ends up running it alongside the first.
    let db = test_sqlite_db().await;
    let worker_id = seed_worker(&db).await;
    let job = seed_provision_job(&db).await;
    let lease_id = LeaseId::new();

    // The sweep observes the lease as due at this point in time...
    let stale_now = Utc::now();
    seed_expired_active_lease(&db, lease_id, job.id, worker_id, stale_now).await;

    // ...but before the sweep's UPDATE runs, `renew_lease` commits,
    // pushing `expires_at` into the future.
    let renewed_expires_at = stale_now + chrono::Duration::seconds(60);
    let sql = format!(
        "update job_leases set expires_at = {} where id = {} and status = 'active'",
        db.placeholder(1),
        db.placeholder(2)
    );
    let renewed = sqlx::query(&sql)
        .bind(renewed_expires_at.to_rfc3339())
        .bind(lease_id.to_string())
        .execute(&db.pool)
        .await
        .expect("renew lease");
    assert_eq!(renewed.rows_affected(), 1, "renewal must apply");

    // The sweep now runs its guarded expire UPDATE using the stale `now`
    // it captured before the renewal landed.
    let mut tx = db.pool.begin().await.expect("begin tx");
    let won = expire_active_lease_on_connection(&db, &mut tx, lease_id, stale_now, "lease expired")
        .await
        .expect("expire attempt");
    tx.commit().await.expect("commit expire attempt");

    assert!(
        !won,
        "a renewed lease must not be expired by a sweep using a stale notion of time"
    );

    let (status, expires_at): (String, String) = {
        let row = sqlx::query("select status, expires_at from job_leases where id = ?")
            .bind(lease_id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch lease");
        (
            row.try_get("status").expect("read status"),
            row.try_get("expires_at").expect("read expires_at"),
        )
    };
    assert_eq!(
        status, "active",
        "renewed lease must remain active, not be expired and its job re-queued"
    );
    assert_eq!(
        expires_at,
        renewed_expires_at.to_rfc3339(),
        "renewed expires_at must survive the racing sweep"
    );

    // The job must still be in its leased state -- it must not have been
    // re-queued for a second worker to pick up alongside the one holding
    // the still-active, renewed lease.
    let job_after = fetch_job(&db, job.id).await.expect("fetch job");
    assert_eq!(job_after.status, JobStatus::Leased);
}

#[tokio::test]
async fn expire_due_leases_does_not_double_process_concurrent_sweeps() {
    let db = test_sqlite_db().await;
    let worker_id = seed_worker(&db).await;
    let now = Utc::now();
    let sandbox = Sandbox {
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        id: SandboxId::new(),
        tenant_id: "default".to_string(),
        name: "test-sandbox".to_string(),
        state: SandboxState::Running,
        template: "default".to_string(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::default(),
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        parent_snapshot_id: None,
    };
    insert_sandbox(&db, &sandbox).await.expect("insert sandbox");
    let prompt_event_id = Uuid::now_v7();
    let job = Job {
        id: JobId::new(),
        tenant_id: "default".to_string(),
        kind: JobKind::RunPrompt,
        status: JobStatus::Leased,
        payload: json!({
            "sandboxId": sandbox.id.to_string(),
            "promptEventId": prompt_event_id.to_string(),
        }),
        required_capability: WorkerCapability::AgentPrompt,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job(&db, &job).await.expect("insert job");
    seed_expired_active_lease(&db, LeaseId::new(), job.id, worker_id, now).await;

    // Two overlapping sweeps racing on the same expired lease (this is what
    // used to happen when the sweep ran unguarded on every read handler).
    let (first, second) = tokio::join!(expire_due_leases(&db), expire_due_leases(&db));
    first.expect("first sweep succeeds");
    second.expect("second sweep succeeds");

    let requeued = fetch_job(&db, job.id).await.expect("fetch job");
    assert_eq!(requeued.status, JobStatus::Queued);

    let event_count: i64 =
        sqlx::query("select count(*) as count from sandbox_events where kind = 'prompt_queued'")
            .fetch_one(&db.pool)
            .await
            .expect("count events")
            .try_get("count")
            .expect("read count");
    assert_eq!(
        event_count, 1,
        "guarded expiry must apply requeue side effects exactly once, not once per racing sweep"
    );
}

async fn seed_sandbox_with_state(db: &Database, state: SandboxState) -> Sandbox {
    let now = Utc::now();
    let sandbox = Sandbox {
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        id: SandboxId::new(),
        tenant_id: "default".to_string(),
        name: "test-sandbox".to_string(),
        state,
        template: "default".to_string(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::default(),
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        parent_snapshot_id: None,
    };
    insert_sandbox(db, &sandbox).await.expect("insert sandbox");
    sandbox
}

#[tokio::test]
async fn stop_returns_conflict_on_double_stop() {
    let db = test_sqlite_db().await;
    let sandbox = seed_sandbox_with_state(&db, SandboxState::Archived).await;

    let result = transition_sandbox(
        &db,
        sandbox.id,
        SandboxState::STOP_LEGAL_FROM,
        SandboxState::Archiving,
        "stop_requested",
    )
    .await;

    let error = result.expect_err("stopping an already-archived sandbox must conflict");
    assert_eq!(error.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn snapshot_restore_claim_rejects_expired_ready_source() {
    let db = test_sqlite_db().await;
    let sandbox = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    let now = Utc::now();
    let snapshot = Snapshot {
        id: SnapshotId::new(),
        sandbox_id: sandbox.id,
        status: SnapshotStatus::Ready,
        label: "expired-restore-source".to_string(),
        inventory: json!({}),
        provider_metadata: json!({}),
        created_at: now,
        ready_at: Some(now),
        expires_at: Some(now - chrono::Duration::seconds(1)),
        error: None,
    };
    let mut connection = db.pool.acquire().await.expect("acquire connection");
    insert_snapshot_on_connection(&db, &mut connection, &snapshot)
        .await
        .expect("insert expired ready snapshot");

    let error = claim_snapshot_restore_source_on_connection(
        &db,
        &mut connection,
        snapshot.id,
        &TenantContext {
            tenant_id: sandbox.tenant_id.clone(),
            principal: Principal::Tenant,
        },
        now,
    )
    .await
    .expect_err("expired ready snapshot must not be restorable");

    assert_eq!(error.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn job_completion_racing_a_concurrent_archive_does_not_resurrect_the_sandbox() {
    // Simulates the lost-update bug this change fixes: a ForkSandbox job is
    // in flight (child sandbox in Provisioning) and, before its completion
    // lands, the sandbox is archived by an unrelated user request. The
    // job's completion must not clobber the archive.
    let db = test_sqlite_db().await;
    let child = seed_sandbox_with_state(&db, SandboxState::Provisioning).await;

    let _ = transition_sandbox(
        &db,
        child.id,
        SandboxState::STOP_LEGAL_FROM,
        SandboxState::Archiving,
        "stop_requested",
    )
    .await
    .expect("stop concurrently while the fork job is still in flight");

    let mut connection = db.pool.acquire().await.expect("acquire connection");
    set_sandbox_state_on_connection(
        &db,
        &mut connection,
        child.id,
        SandboxState::PROVISION_COMPLETED_LEGAL_FROM,
        SandboxState::Ready,
        json!({ "state": "ready", "reason": "provision_ready" }),
    )
    .await
    .expect("late provision completion must be an idempotent lost race");
    let stopping = fetch_sandbox_on_connection(&db, &mut connection, child.id)
        .await
        .expect("fetch stopping sandbox");
    assert_eq!(
        stopping.state,
        SandboxState::Archiving,
        "a late provision completion must not undo an accepted stop"
    );
    set_sandbox_state_on_connection(
        &db,
        &mut connection,
        child.id,
        SandboxState::STOP_COMPLETED_LEGAL_FROM,
        SandboxState::Archived,
        json!({ "state": "archived", "reason": "stop_completed" }),
    )
    .await
    .expect("provider-confirmed stop completes archival");
    set_sandbox_state_on_connection(
        &db,
        &mut connection,
        child.id,
        SandboxState::FORK_COMPLETED_LEGAL_FROM,
        SandboxState::Ready,
        json!({ "state": "ready", "reason": "fork_ready" }),
    )
    .await
    .expect("job-completion path must not error on a lost race");
    // The test db pool has exactly one connection; release it explicitly
    // before fetching through the shared pool below.
    drop(connection);

    let after = fetch_sandbox(&db, child.id).await.expect("fetch sandbox");
    assert_eq!(
        after.state,
        SandboxState::Archived,
        "a completing fork job must never resurrect a concurrently-archived sandbox"
    );
}

#[tokio::test]
async fn database_trigger_rejects_a_transition_no_action_ever_performs() {
    // Defense-in-depth check for the trigger backstop installed by
    // `ensure_sqlite_constraints`: even a raw UPDATE that bypasses every
    // Rust-level CAS helper must be rejected for an edge that is not in
    // `sandbox_legal_transition_pairs()` (e.g. archived -> provisioning,
    // which no handler ever performs).
    let db = test_sqlite_db().await;
    let sandbox = seed_sandbox_with_state(&db, SandboxState::Archived).await;

    let result = sqlx::query("update sandboxes set state = 'provisioning' where id = ?")
        .bind(sandbox.id.to_string())
        .execute(&db.pool)
        .await;

    assert!(
        result.is_err(),
        "the database trigger backstop must reject archived -> provisioning"
    );

    let unchanged = fetch_sandbox(&db, sandbox.id).await.expect("fetch sandbox");
    assert_eq!(unchanged.state, SandboxState::Archived);
}

#[test]
fn command_output_bounds_cap_bytes_chunks_and_individual_payloads() {
    assert!(validate_command_output_bounds(0, 0, 1).is_ok());
    assert!(validate_command_output_bounds(MAX_COMMAND_OUTPUT_CHUNKS, 0, 1).is_err());
    assert!(validate_command_output_bounds(0, MAX_COMMAND_OUTPUT_BYTES as i64, 1).is_err());
    assert!(validate_command_output_bounds(0, 0, MAX_COMMAND_OUTPUT_CHUNK_BYTES + 1).is_err());
}

#[tokio::test]
async fn worker_liveness_reconciliation_batch_deletes_only_expired_history() {
    let db = test_sqlite_db().await;
    let worker_id = seed_worker(&db).await;
    let now = Utc::now();
    insert_worker_heartbeat(&db, worker_id, "{}", now - chrono::Duration::days(8))
        .await
        .expect("insert old heartbeat");
    insert_worker_heartbeat(&db, worker_id, "{}", now)
        .await
        .expect("insert current heartbeat");

    reconcile_worker_liveness(&db)
        .await
        .expect("reconcile liveness");
    let remaining: i64 = sqlx::query("select count(*) as count from worker_heartbeats")
        .fetch_one(&db.pool)
        .await
        .expect("count heartbeats")
        .try_get("count")
        .expect("integer count");
    assert_eq!(remaining, 1);
}

#[tokio::test]
async fn cleanup_archived_sandboxes_never_deletes_a_sandbox_with_a_live_restore_reference() {
    // `cleanup_archived_sandboxes`'s authoritative reference check now runs
    // on the same connection as the delete, immediately before it, instead
    // of only once against the pool before the transaction even opens (the
    // TOCTOU this change closes: a concurrent fork/`create_snapshot` could
    // previously insert a `snapshot_restore_sources` row referencing the
    // sandbox in the gap between that pool-level check and the delete
    // transaction's commit, and the parent got deleted anyway). This test
    // can't reproduce the original interleaving itself -- the harness has no
    // seam to pause `cleanup_archived_sandboxes` mid-transaction, and the
    // real window it closes is a sub-millisecond gap between two statements
    // in the same DB transaction -- but it does pin the outcome the fix
    // guarantees: a referenced sandbox is never deleted, regardless of which
    // of the two checks (the pool pre-check or the in-transaction recheck)
    // is the one that catches it.
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let sandbox = Sandbox {
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        id: SandboxId::new(),
        tenant_id: "default".to_string(),
        name: "referenced-archived".to_string(),
        state: SandboxState::Archived,
        template: "default".to_string(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::default(),
        created_at: now,
        updated_at: now,
        ttl_seconds: Some(0),
        parent_snapshot_id: None,
    };
    insert_sandbox(&db, &sandbox)
        .await
        .expect("insert archived sandbox");

    // The exact row a concurrent `create_snapshot` leaves behind
    // (`insert_snapshot_on_connection` in `handlers/snapshots.rs`): a live,
    // unexpired restore source pointing at this sandbox.
    sqlx::query(
        "insert into snapshot_restore_sources
         (snapshot_id, tenant_id, source_sandbox_id, status, expires_at)
         values (?, ?, ?, 'ready', NULL)",
    )
    .bind(SnapshotId::new().to_string())
    .bind(&sandbox.tenant_id)
    .bind(sandbox.id.to_string())
    .execute(&db.pool)
    .await
    .expect("seed restore source");

    let result = cleanup_archived_sandboxes(&db)
        .await
        .expect("cleanup run must not error on a referenced sandbox");
    assert!(
        result.deleted.is_empty(),
        "a sandbox with a live restore reference must never be deleted"
    );
    assert_eq!(result.skipped.len(), 1);
    assert_eq!(result.skipped[0].sandbox.id, sandbox.id);

    let still_present = fetch_sandbox(&db, sandbox.id).await;
    assert!(
        still_present.is_ok(),
        "the sandbox row must survive when the reference check inside the delete transaction \
         finds a reference"
    );
}
