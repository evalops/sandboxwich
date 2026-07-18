use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::Digest;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::activity::*;
use crate::auth::*;
use crate::cleanup::*;
use crate::config::*;
use crate::db::*;
use crate::handlers::commands::*;
use crate::handlers::files::*;
use crate::handlers::jobs::*;
use crate::handlers::leases::*;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::handlers::workers::*;
use crate::reap::*;
use crate::reconcile::*;
use crate::rows::*;
use crate::state::{Principal, ResidentBootstrapStore, TenantContext};
use sandboxwich_core::*;
use std::collections::BTreeSet;

#[test]
fn materialization_job_input_is_ref_only_and_exact() {
    let sandbox_id = SandboxId::new();
    let file_id = FileId::new();
    let digest = "a".repeat(64);
    validate_materialize_file_job_input(&json!({
        "sandboxId": sandbox_id,
        "fileId": file_id,
        "destination": "apex_task",
        "expectedSha256": digest,
    }))
    .expect("closed ref-only payload should be valid");

    for forbidden in ["transientContentBase64", "content", "extra"] {
        let mut payload = json!({
            "sandboxId": sandbox_id,
            "fileId": file_id,
            "destination": "apex_task",
            "expectedSha256": "a".repeat(64),
        });
        payload[forbidden] = json!("private");
        let error = validate_materialize_file_job_input(&payload).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    let traversal = validate_materialize_file_job_input(&json!({
        "sandboxId": sandbox_id,
        "fileId": file_id,
        "destination": "../../workspace/.apex/grader",
        "expectedSha256": "a".repeat(64),
    }))
    .unwrap_err();
    assert_eq!(traversal.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn lease_completion_fingerprint_schema_is_applied() {
    let db = test_sqlite_db().await;
    let row = sqlx::query("select completion_fingerprint from job_leases where 1 = 0")
        .fetch_optional(&db.pool)
        .await
        .expect("completion fingerprint column must be migrated");
    assert!(row.is_none());
}

#[tokio::test]
async fn resident_process_storage_has_generation_fence_and_no_secret_column() {
    let db = test_sqlite_db().await;
    let columns = sqlx::query("pragma table_info(resident_processes)")
        .fetch_all(&db.pool)
        .await
        .expect("inspect resident_processes");
    let names = columns
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<BTreeSet<_>>();

    for required in [
        "id",
        "sandbox_id",
        "tenant_id",
        "name",
        "argv",
        "env",
        "bootstrap_sha256",
        "bootstrap_byte_count",
        "generation",
        "active_lease_id",
        "desired_state",
        "observed_state",
    ] {
        assert!(names.contains(required), "missing column {required}");
    }
    for forbidden in ["bootstrap_content", "content", "secret", "token"] {
        assert!(
            !names.contains(forbidden),
            "forbidden secret column {forbidden}"
        );
    }
}

#[tokio::test]
async fn resident_process_storage_round_trips_public_metadata() {
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let sandbox = Sandbox {
        id: SandboxId::new(),
        tenant_id: "tenant-a".into(),
        name: "resident-test".into(),
        state: SandboxState::Ready,
        template: "ubuntu-dev".into(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::DenyAll,
        workspace_mode: WorkspaceMode::default(),
        runtime_profile: SandboxRuntimeProfile::default(),
        execution_class: ExecutionClass::default(),
        created_at: now,
        updated_at: now,
        ttl_seconds: Some(3600),
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
    };
    let mut tx = db.pool.begin().await.unwrap();
    insert_sandbox_on_connection(&db, &mut tx, &sandbox)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let id = ResidentProcessId::new();
    sqlx::query(
        "insert into resident_processes (
            id, sandbox_id, tenant_id, name, argv, cwd, env,
            bootstrap_sha256, bootstrap_byte_count, bootstrap_target_file, bootstrap_mode,
            restart_policy, desired_state, observed_state, generation,
            created_at, updated_at
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(sandbox.id.to_string())
    .bind(&sandbox.tenant_id)
    .bind("orb-executor")
    .bind(r#"["/usr/local/bin/orb-executor"]"#)
    .bind("/workspace")
    .bind(r#"{"ORB_TOKEN_FILE":"/run/sandboxwich/bootstrap/orb-token"}"#)
    .bind("a".repeat(64))
    .bind(6_i64)
    .bind("/run/sandboxwich/bootstrap/orb-token")
    .bind(0o600_i64)
    .bind("on_failure")
    .bind("running")
    .bind("pending")
    .bind(1_i64)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&db.pool)
    .await
    .unwrap();

    let row = sqlx::query("select * from resident_processes where id = ?")
        .bind(id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let resident = row_to_resident_process(row).unwrap();
    assert_eq!(resident.id, id);
    assert_eq!(resident.sandbox_id, sandbox.id);
    assert_eq!(resident.generation, 1);
    assert_eq!(
        resident.env.get("ORB_TOKEN_FILE").map(String::as_str),
        Some("/run/sandboxwich/bootstrap/orb-token")
    );
}

/// Inserts a minimal resident-process row for `name`, mirroring the fixture
/// shape `resident_process_storage_round_trips_public_metadata` uses.
async fn insert_resident_process_row(db: &Database, sandbox: &Sandbox, name: &str) -> Uuid {
    let id = ResidentProcessId::new();
    let now = Utc::now();
    sqlx::query(
        "insert into resident_processes (
            id, sandbox_id, tenant_id, name, argv, cwd, env,
            restart_policy, desired_state, observed_state, generation,
            created_at, updated_at
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(sandbox.id.to_string())
    .bind(&sandbox.tenant_id)
    .bind(name)
    .bind(format!(r#"["/usr/local/bin/{name}"]"#))
    .bind(Option::<String>::None)
    .bind("{}")
    .bind("never")
    .bind("running")
    .bind("pending")
    .bind(1_i64)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&db.pool)
    .await
    .unwrap();
    id.0
}

#[tokio::test]
async fn orb_sidecar_and_orb_executor_are_independent_one_per_sandbox_slots() {
    // issue #176: orb-sidecar must be a distinct resident-process kind from
    // orb-executor -- a sandbox can hold one row of each -- while each
    // individual name is still limited to one row per sandbox via the
    // storage layer's `unique(sandbox_id, name)` constraint (see the
    // resident_processes migration).
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let sandbox = Sandbox {
        id: SandboxId::new(),
        tenant_id: "tenant-a".into(),
        name: "resident-sidecar-test".into(),
        state: SandboxState::Ready,
        template: "ubuntu-dev".into(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::DenyAll,
        workspace_mode: WorkspaceMode::default(),
        runtime_profile: SandboxRuntimeProfile::default(),
        execution_class: ExecutionClass::default(),
        created_at: now,
        updated_at: now,
        ttl_seconds: Some(3600),
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
    };
    let mut tx = db.pool.begin().await.unwrap();
    insert_sandbox_on_connection(&db, &mut tx, &sandbox)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    insert_resident_process_row(&db, &sandbox, "orb-executor").await;
    insert_resident_process_row(&db, &sandbox, "orb-sidecar").await;
    let count: i64 =
        sqlx::query("select count(*) as c from resident_processes where sandbox_id = ?")
            .bind(sandbox.id.to_string())
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get("c");
    assert_eq!(
        count, 2,
        "orb-executor and orb-sidecar must coexist as independent rows"
    );

    // A second orb-sidecar row for the *same* sandbox must be rejected by
    // storage -- this is the one-per-sandbox enforcement for the sidecar
    // slot, identical in mechanism to orb-executor's.
    let second_sidecar = sqlx::query(
        "insert into resident_processes (
            id, sandbox_id, tenant_id, name, argv, cwd, env,
            restart_policy, desired_state, observed_state, generation,
            created_at, updated_at
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(ResidentProcessId::new().to_string())
    .bind(sandbox.id.to_string())
    .bind(&sandbox.tenant_id)
    .bind("orb-sidecar")
    .bind(r#"["/usr/local/bin/orb-sidecar"]"#)
    .bind(Option::<String>::None)
    .bind("{}")
    .bind("never")
    .bind("running")
    .bind("pending")
    .bind(1_i64)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(&db.pool)
    .await;
    assert!(
        second_sidecar.is_err(),
        "a second orb-sidecar row for the same sandbox must violate the unique(sandbox_id, name) constraint"
    );
}

#[test]
fn lease_completion_fingerprint_is_versioned_and_canonicalizes_object_order() {
    let sandbox_id = SandboxId::new();
    let result = |metadata| WorkerJobResult::ProvisionSandbox {
        handle: ProviderSandboxHandle {
            provider: "kubernetes".into(),
            sandbox_id,
            resources: Vec::new(),
            metadata,
        },
    };
    let mut first = serde_json::Map::new();
    first.insert("zeta".into(), json!(1));
    first.insert("alpha".into(), json!({"nested_z": 2, "nested_a": 3}));
    let mut second = serde_json::Map::new();
    second.insert("alpha".into(), json!({"nested_a": 3, "nested_z": 2}));
    second.insert("zeta".into(), json!(1));

    let first = completion_result_fingerprint(&result(first.into())).unwrap();
    let second = completion_result_fingerprint(&result(second.into())).unwrap();
    assert_eq!(first, second);
    assert!(first.starts_with("sha256:v1:"));
}

#[test]
fn authoritative_job_enrichment_overwrites_caller_placement_metadata() {
    let now = Utc::now();
    let sandbox = Sandbox {
        id: SandboxId::new(),
        tenant_id: "tenant".to_string(),
        name: "apex".to_string(),
        state: SandboxState::Ready,
        template: format!("ghcr.io/evalops/apex@sha256:{}", "a".repeat(64)),
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        workspace_mode: WorkspaceMode::Persistent,
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
        execution_class: ExecutionClass::SandboxedContainer,
    };
    let mut job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::RunCommand,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox.id,
            "runtimeImage": "attacker:latest",
            "provisionSpec": SandboxProvisionSpec::default()
        }),
        required_capability: WorkerCapability::RunCommand,
        priority: 0,
        attempts: 0,
        max_attempts: 1,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
        required_execution_class: ExecutionClass::DevelopmentContainer,
    };

    add_provision_spec_to_payload(&mut job, &sandbox).expect("enrich job");

    assert_eq!(job.payload["runtimeImage"], json!(sandbox.template));
    assert_eq!(
        serde_json::from_value::<SandboxProvisionSpec>(job.payload["provisionSpec"].clone())
            .expect("provision spec"),
        SandboxProvisionSpec {
            memory_limit: sandbox.memory_limit,
            network_egress: sandbox.network_egress,
            workspace_mode: sandbox.workspace_mode,
            runtime_profile: sandbox.runtime_profile,
            execution_class: ExecutionClass::SandboxedContainer,
        }
    );
}

#[test]
fn apex_runtime_profile_requires_pinned_image_and_deny_by_default_egress() {
    let pinned = format!("ghcr.io/evalops/apex@sha256:{}", "a".repeat(64));
    let request = |template: &str, network_egress| CreateSandboxRequest {
        name: None,
        template: Some(template.to_string()),
        memory_limit: None,
        network_egress: Some(network_egress),
        workspace_mode: None,
        runtime_profile: Some(SandboxRuntimeProfile::ApexTrustedSupervisorV1),
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        execution_class: Some(ExecutionClass::SandboxedContainer),
    };
    assert!(provision_spec_from_request(&request(&pinned, NetworkEgress::DenyAll), None).is_ok());
    assert!(
        provision_spec_from_request(
            &request(
                &pinned,
                NetworkEgress::Allowlist {
                    rules: vec![NetworkAllowRule {
                        kind: NetworkAllowRuleKind::Host,
                        value: "model-gateway.example.com".to_string(),
                    }],
                },
            ),
            None,
        )
        .is_ok()
    );
    assert!(
        provision_spec_from_request(
            &request("ghcr.io/evalops/apex:latest", NetworkEgress::DenyAll),
            None
        )
        .is_err()
    );
    assert!(provision_spec_from_request(&request(&pinned, NetworkEgress::AllowAll), None).is_err());
    let mut wrong_execution_class = request(&pinned, NetworkEgress::DenyAll);
    wrong_execution_class.execution_class = Some(ExecutionClass::DevelopmentContainer);
    assert!(provision_spec_from_request(&wrong_execution_class, None).is_err());
    let now = Utc::now();
    let parent = Sandbox {
        id: SandboxId::new(),
        tenant_id: "tenant".to_string(),
        name: "parent".to_string(),
        state: SandboxState::Ready,
        template: pinned,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        workspace_mode: WorkspaceMode::Persistent,
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
        execution_class: ExecutionClass::SandboxedContainer,
    };
    let inherited = CreateSandboxRequest {
        name: None,
        template: None,
        memory_limit: None,
        network_egress: None,
        workspace_mode: None,
        runtime_profile: None,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        execution_class: None,
    };
    assert!(provision_spec_from_request(&inherited, Some(&parent)).is_ok());
}

#[test]
fn snapshot_fork_request_rejects_placement_mismatches() {
    let image = format!("ghcr.io/evalops/apex@sha256:{}", "e".repeat(64));
    let source = SnapshotRestoreSource {
        source_sandbox_id: SandboxId::new(),
        runtime_image: image.clone(),
        provision_spec: SandboxProvisionSpec {
            memory_limit: MemoryLimit::FourG,
            network_egress: NetworkEgress::DenyAll,
            workspace_mode: WorkspaceMode::Persistent,
            runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
            execution_class: ExecutionClass::SandboxedContainer,
        },
        execution_class: ExecutionClass::SandboxedContainer,
    };
    let matching = ForkSnapshotRequest {
        name: None,
        template: image,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
    };
    validate_snapshot_fork_request(&matching, &source).expect("matching placement");
    let mut mismatch = matching.clone();
    mismatch.template = "attacker:latest".to_string();
    assert!(validate_snapshot_fork_request(&mismatch, &source).is_err());
    let mut mismatch = matching.clone();
    mismatch.memory_limit = MemoryLimit::OneG;
    assert!(validate_snapshot_fork_request(&mismatch, &source).is_err());
    let mut mismatch = matching.clone();
    mismatch.network_egress = NetworkEgress::AllowAll;
    assert!(validate_snapshot_fork_request(&mismatch, &source).is_err());
    let mut mismatch = matching;
    mismatch.runtime_profile = SandboxRuntimeProfile::Unprivileged;
    assert!(validate_snapshot_fork_request(&mismatch, &source).is_err());
}

#[tokio::test]
async fn transient_authority_refresh_error_leaves_queued_job_retryable() {
    let db = test_sqlite_db().await;
    let sandbox = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    let now = Utc::now();
    let mut job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Queued,
        payload: json!({"sandboxId": sandbox.id}),
        required_capability: WorkerCapability::ProvisionSandbox,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
        required_execution_class: ExecutionClass::DevelopmentContainer,
    };
    insert_job(&db, &job).await.expect("insert queued job");
    sqlx::query("alter table sandboxes rename to unavailable_sandboxes")
        .execute(&db.pool)
        .await
        .expect("make authoritative store unavailable");

    let error = authoritatively_refresh_job_placement(&db, &mut job)
        .await
        .expect_err("internal authority read must propagate");
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    let status: String = sqlx::query("select status from jobs where id = ?")
        .bind(job.id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("read job")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "queued");
}

#[test]
fn apex_profile_bound_jobs_only_match_the_exact_profile_worker_image() {
    let now = Utc::now();
    let requested_image = format!("ghcr.io/evalops/apex@sha256:{}", "a".repeat(64));
    let job = Job {
        id: JobId::new(),
        tenant_id: "tenant-a".to_string(),
        kind: JobKind::MaterializeFile,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": SandboxId::new(),
            "runtimeImage": requested_image,
            "provisionSpec": SandboxProvisionSpec {
                memory_limit: MemoryLimit::FourG,
                network_egress: NetworkEgress::DenyAll,
                workspace_mode: WorkspaceMode::Persistent,
                runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
                execution_class: ExecutionClass::SandboxedContainer,
            }
        }),
        required_capability: WorkerCapability::MaterializeFile,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
        required_execution_class: ExecutionClass::SandboxedContainer,
    };
    let worker = |capabilities, image: &str| Worker {
        id: WorkerId::new(),
        tenant_id: "tenant-a".to_string(),
        name: "worker".to_string(),
        status: WorkerStatus::Online,
        provider: "kubernetes".to_string(),
        capabilities,
        max_concurrent_jobs: 1,
        labels: std::collections::BTreeMap::from([(
            "runtime_image".to_string(),
            image.to_string(),
        )]),
        registered_at: now,
        last_heartbeat_at: Some(now),
    };
    assert!(worker_supports_runtime_profile(
        &worker(
            vec![
                WorkerCapability::MaterializeFile,
                WorkerCapability::ApexTrustedSupervisorV1,
            ],
            job.payload["runtimeImage"].as_str().unwrap(),
        ),
        &job,
    ));
    assert!(!worker_supports_runtime_profile(
        &worker(
            vec![WorkerCapability::ProvisionSandbox],
            job.payload["runtimeImage"].as_str().unwrap()
        ),
        &job,
    ));
    assert!(!worker_supports_runtime_profile(
        &worker(
            vec![
                WorkerCapability::MaterializeFile,
                WorkerCapability::ApexTrustedSupervisorV1,
            ],
            &format!("ghcr.io/evalops/apex@sha256:{}", "b".repeat(64)),
        ),
        &job,
    ));

    let run_command = Job {
        kind: JobKind::RunCommand,
        required_capability: WorkerCapability::RunCommand,
        ..job.clone()
    };
    assert!(worker_supports_runtime_profile(
        &worker(
            vec![
                WorkerCapability::RunCommand,
                WorkerCapability::ApexTrustedSupervisorV1,
            ],
            run_command.payload["runtimeImage"].as_str().unwrap(),
        ),
        &run_command,
    ));
    assert!(!worker_supports_runtime_profile(
        &worker(
            vec![WorkerCapability::RunCommand],
            run_command.payload["runtimeImage"].as_str().unwrap(),
        ),
        &run_command,
    ));
    for payload in [
        json!({"sandboxId": SandboxId::new()}),
        json!({"sandboxId": SandboxId::new(), "runtimeImage": requested_image, "provisionSpec": {"runtime_profile": "apex_trusted_supervisor_v1"}}),
        json!({"sandboxId": SandboxId::new(), "runtimeImage": requested_image, "provisionSpec": {"runtime_profile": "unknown"}}),
    ] {
        let malformed = Job {
            payload,
            ..run_command.clone()
        };
        assert!(!worker_supports_runtime_profile(
            &worker(
                vec![
                    WorkerCapability::RunCommand,
                    WorkerCapability::ApexTrustedSupervisorV1,
                ],
                run_command.payload["runtimeImage"].as_str().unwrap(),
            ),
            &malformed,
        ));
    }
}

#[tokio::test]
async fn materialization_rejects_a_file_from_another_sandbox() {
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let make = |name: &str| Sandbox {
        id: SandboxId::new(),
        tenant_id: "tenant-a".into(),
        name: name.into(),
        state: SandboxState::Ready,
        template: "apex".into(),
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::default(),
        workspace_mode: WorkspaceMode::Persistent,
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        created_at: now,
        updated_at: now,
        ttl_seconds: Some(600),
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
        execution_class: ExecutionClass::SandboxedContainer,
    };
    let first = make("first");
    let second = make("second");
    insert_sandbox(&db, &first).await.unwrap();
    insert_sandbox(&db, &second).await.unwrap();
    let content = b"private";
    let file = upsert_sandbox_file(
        &db,
        first.id,
        "/input/task",
        Some("application/octet-stream"),
        content,
    )
    .await
    .unwrap();
    let job = Job {
        id: JobId::new(),
        tenant_id: "tenant-a".into(),
        kind: JobKind::MaterializeFile,
        status: JobStatus::Queued,
        payload: json!({"sandboxId":second.id,"fileId":file.id,"destination":"apex_task",
            "expectedSha256":format!("{:x}", sha2::Sha256::digest(content))}),
        required_capability: WorkerCapability::MaterializeFile,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
        required_execution_class: ExecutionClass::DevelopmentContainer,
    };
    let ctx = TenantContext {
        tenant_id: "tenant-a".into(),
        principal: Principal::Tenant,
    };
    let error = validate_job_payload_tenant(&db, &job, &ctx)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::NOT_FOUND);

    let mut generic = make("generic");
    generic.runtime_profile = SandboxRuntimeProfile::Unprivileged;
    insert_sandbox(&db, &generic).await.unwrap();
    let mut generic_job = job;
    generic_job.payload["sandboxId"] = json!(generic.id);
    let error = validate_job_payload_tenant(&db, &generic_job, &ctx)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
}

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
    assert!(fingerprint.starts_with("db-enum-v6:"));
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
async fn schema_verification_requires_the_latest_compiled_migration() {
    let db = test_sqlite_db().await;
    verify_database_schema(&db)
        .await
        .expect("fully migrated database verifies");

    let expected = latest_compiled_migration();
    let sql = format!(
        "delete from _sqlx_migrations where version = {}",
        db.placeholder(1)
    );
    sqlx::query(&sql)
        .bind(expected.version)
        .execute(&db.pool)
        .await
        .expect("remove latest migration ledger row");

    let error = verify_database_schema(&db)
        .await
        .expect_err("missing latest migration must fail schema verification");
    assert!(error.to_string().contains(&expected.version.to_string()));
    assert!(error.to_string().contains("has not been applied"));
}

#[tokio::test]
async fn schema_verification_rejects_an_incomplete_latest_migration() {
    let db = test_sqlite_db().await;
    let expected = latest_compiled_migration();
    let sql = format!(
        "update _sqlx_migrations set success = false where version = {}",
        db.placeholder(1)
    );
    sqlx::query(&sql)
        .bind(expected.version)
        .execute(&db.pool)
        .await
        .expect("mark latest migration incomplete");

    let error = verify_database_schema(&db)
        .await
        .expect_err("incomplete latest migration must fail schema verification");
    assert!(error.to_string().contains(&expected.version.to_string()));
    assert!(error.to_string().contains("did not complete successfully"));
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
        runtime_profile: SandboxRuntimeProfile::Unprivileged,
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
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
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
        runtime_profile: SandboxRuntimeProfile::Unprivileged,
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
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
    };
    insert_sandbox(db, &sandbox).await.expect("insert sandbox");
    sandbox
}

async fn insert_test_command(db: &Database, sandbox_id: SandboxId, created_at: DateTime<Utc>) {
    let mut tx = db.pool.begin().await.expect("begin command insert");
    insert_command_on_connection(
        db,
        &mut tx,
        &CommandRun {
            id: CommandId::new(),
            sandbox_id,
            status: CommandStatus::Finished,
            argv: vec!["true".to_string()],
            cwd: None,
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            created_at,
            finished_at: Some(created_at),
        },
    )
    .await
    .expect("insert test command");
    tx.commit().await.expect("commit command insert");
}

/// Regression/equivalence test for evalops/sandboxwich#173: folding the
/// per-candidate `select max(created_at) from commands` into
/// `reap_expired_active_sandboxes`'s own candidate query (a correlated
/// scalar subquery) must produce the exact same reap decisions the old
/// per-row Rust computation did. Exercises the real query end to end
/// (not just the pure `expired_deadline`/`resolve_last_activity` functions,
/// which the unit tests below already cover in isolation) against a fixture
/// covering every case the "more recent of updated_at or last queued
/// command" rule has to get right, plus a `max_lifetime_seconds` sandbox
/// that doesn't depend on `commands` at all and a boundary-exact idle case.
#[tokio::test]
async fn idle_ttl_sweep_query_matches_documented_semantics_across_a_seeded_fixture() {
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let seed = |updated_at: DateTime<Utc>,
                created_at: DateTime<Utc>,
                max_lifetime_seconds: Option<u64>,
                idle_ttl_seconds: Option<u64>| Sandbox {
        execution_class: ExecutionClass::DevelopmentContainer,
        workspace_mode: WorkspaceMode::Ephemeral,
        runtime_profile: SandboxRuntimeProfile::Unprivileged,
        id: SandboxId::new(),
        tenant_id: "default".to_string(),
        name: "idle-sweep-fixture".to_string(),
        state: SandboxState::Ready,
        template: "default".to_string(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::default(),
        created_at,
        updated_at,
        ttl_seconds: None,
        max_lifetime_seconds,
        idle_ttl_seconds,
        parent_snapshot_id: None,
        last_activity_at: None,
    };

    // (a) idle_ttl_seconds=300, no commands at all: last activity falls
    // back to `updated_at` (400s ago), which is past the 300s deadline.
    // Must be reaped.
    let no_commands_idle = seed(
        now - chrono::Duration::seconds(400),
        now - chrono::Duration::seconds(400),
        None,
        Some(300),
    );
    insert_sandbox(&db, &no_commands_idle).await.unwrap();

    // (b) idle_ttl_seconds=300, `updated_at` 400s ago, but a command queued
    // only 100s ago: the command is the *more recent* signal, so the idle
    // clock resets to 100s ago -- well inside the 300s window. Must survive.
    let recent_command_active = seed(
        now - chrono::Duration::seconds(400),
        now - chrono::Duration::seconds(400),
        None,
        Some(300),
    );
    insert_sandbox(&db, &recent_command_active).await.unwrap();
    insert_test_command(
        &db,
        recent_command_active.id,
        now - chrono::Duration::seconds(100),
    )
    .await;

    // (c) idle_ttl_seconds=300, `updated_at` 400s ago, with a command that
    // is *older* than `updated_at` (500s ago). The more-recent-of-the-two
    // rule must still use `updated_at` (400s ago), not the stale command --
    // proving a sandbox can't dodge reaping by having only ancient command
    // history. Must be reaped.
    let stale_command_still_idle = seed(
        now - chrono::Duration::seconds(400),
        now - chrono::Duration::seconds(400),
        None,
        Some(300),
    );
    insert_sandbox(&db, &stale_command_still_idle)
        .await
        .unwrap();
    insert_test_command(
        &db,
        stale_command_still_idle.id,
        now - chrono::Duration::seconds(500),
    )
    .await;

    // (d) idle boundary exactly at the deadline: `updated_at` is exactly
    // `idle_ttl_seconds` in the past relative to `now` captured just above.
    // `idle_ttl_expired` treats `deadline <= now` as due, and wall-clock
    // time only moves forward between this line and the sweep's own
    // `Utc::now()` call, so this is deterministically past due, not a race.
    // No commands, to isolate the boundary case from the activity-signal
    // cases above.
    let exactly_at_idle_boundary = seed(
        now - chrono::Duration::seconds(300),
        now - chrono::Duration::seconds(300),
        None,
        Some(300),
    );
    insert_sandbox(&db, &exactly_at_idle_boundary)
        .await
        .unwrap();

    // (e) max_lifetime_seconds only (no idle_ttl_seconds at all): must be
    // reaped without ever consulting `commands`, proving the join doesn't
    // interfere with the max-lifetime trigger.
    let max_lifetime_only = seed(now, now - chrono::Duration::seconds(999_999), Some(0), None);
    insert_sandbox(&db, &max_lifetime_only).await.unwrap();

    // (f) control: no lifetime knobs at all. Must never be selected as a
    // candidate in the first place, regardless of age.
    let untouched = seed(
        now - chrono::Duration::seconds(999_999),
        now - chrono::Duration::seconds(999_999),
        None,
        None,
    );
    insert_sandbox(&db, &untouched).await.unwrap();

    let reaped = reap_expired_active_sandboxes(&db, &ResidentBootstrapStore::default())
        .await
        .expect("sweep must not error");
    let reaped_ids: std::collections::HashSet<SandboxId> =
        reaped.iter().map(|reaped| reaped.sandbox.id).collect();

    assert!(
        reaped_ids.contains(&no_commands_idle.id),
        "(a) idle with no commands, past the updated_at-based deadline, must be reaped"
    );
    assert!(
        !reaped_ids.contains(&recent_command_active.id),
        "(b) a recent command must reset the idle clock and prevent reaping"
    );
    assert!(
        reaped_ids.contains(&stale_command_still_idle.id),
        "(c) a command *older* than updated_at must not override the more-recent \
         updated_at signal -- this sandbox must still be reaped"
    );
    assert!(
        reaped_ids.contains(&exactly_at_idle_boundary.id),
        "(d) exactly-at-deadline must count as due, not one tick short"
    );
    assert!(
        reaped_ids.contains(&max_lifetime_only.id),
        "(e) max_lifetime_seconds alone must reap independently of any commands join"
    );
    assert!(
        !reaped_ids.contains(&untouched.id),
        "(f) a sandbox with no lifetime knobs set must never be a candidate"
    );
    assert_eq!(
        reaped_ids.len(),
        4,
        "exactly the four due sandboxes (a, c, d, e) should have been reaped, no more"
    );
}

async fn sandbox_last_activity_at(db: &Database, sandbox_id: SandboxId) -> Option<DateTime<Utc>> {
    let raw: Option<String> = sqlx::query("select last_activity_at from sandboxes where id = ?")
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap()
        .try_get("last_activity_at")
        .unwrap();
    raw.map(|value| parse_timestamp(&value).unwrap())
}

/// `bump_sandbox_activity` must set `last_activity_at` on the first call,
/// must **not** move it forward again while still inside the throttle
/// window (bounding write volume for chatty callers -- see `activity.rs`'s
/// module docs for why), and must move it forward again once the throttle
/// window has elapsed.
#[tokio::test]
async fn bump_sandbox_activity_is_throttled_but_eventually_advances() {
    let db = test_sqlite_db().await;
    let sandbox = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    assert_eq!(sandbox_last_activity_at(&db, sandbox.id).await, None);

    let first_bump = Utc::now() - chrono::Duration::seconds(200);
    bump_sandbox_activity(&db, sandbox.id, first_bump)
        .await
        .unwrap();
    assert_eq!(
        sandbox_last_activity_at(&db, sandbox.id).await,
        Some(first_bump),
        "the first bump must set last_activity_at"
    );

    // Still inside the throttle window (60s): a later timestamp must NOT
    // overwrite the first bump.
    let still_throttled = first_bump + chrono::Duration::seconds(10);
    bump_sandbox_activity(&db, sandbox.id, still_throttled)
        .await
        .unwrap();
    assert_eq!(
        sandbox_last_activity_at(&db, sandbox.id).await,
        Some(first_bump),
        "a bump inside the throttle window must be a no-op"
    );

    // Past the throttle window: must advance.
    let past_throttle = first_bump + chrono::Duration::seconds(61);
    bump_sandbox_activity(&db, sandbox.id, past_throttle)
        .await
        .unwrap();
    assert_eq!(
        sandbox_last_activity_at(&db, sandbox.id).await,
        Some(past_throttle),
        "a bump past the throttle window must advance last_activity_at"
    );
}

/// Regression/completeness test for the idle-TTL activity signal: a
/// sandbox with no recent command activity and a stale `updated_at` must
/// still survive reaping if `last_activity_at` (bumped by SSH/desktop/
/// resident-process touchpoints -- exercised live in
/// `tests/http_contract/reap.rs`) is recent, and a sandbox with no
/// `last_activity_at` at all (the pre-this-PR case, or one that predates
/// the column) must fall back to the pre-existing updated_at/commands
/// signal exactly as before.
#[tokio::test]
async fn idle_ttl_reap_considers_last_activity_at_alongside_updated_at_and_commands() {
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let seed = |updated_at: DateTime<Utc>| Sandbox {
        execution_class: ExecutionClass::DevelopmentContainer,
        workspace_mode: WorkspaceMode::Ephemeral,
        runtime_profile: SandboxRuntimeProfile::Unprivileged,
        id: SandboxId::new(),
        tenant_id: "default".to_string(),
        name: "activity-signal-fixture".to_string(),
        state: SandboxState::Ready,
        template: "default".to_string(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::default(),
        created_at: updated_at,
        updated_at,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: Some(300),
        last_activity_at: None,
        parent_snapshot_id: None,
    };

    let recent_ssh_activity = seed(now - chrono::Duration::seconds(400));
    insert_sandbox(&db, &recent_ssh_activity).await.unwrap();
    bump_sandbox_activity(
        &db,
        recent_ssh_activity.id,
        now - chrono::Duration::seconds(100),
    )
    .await
    .unwrap();

    let no_activity_at_all = seed(now - chrono::Duration::seconds(400));
    insert_sandbox(&db, &no_activity_at_all).await.unwrap();

    let reaped = reap_expired_active_sandboxes(&db, &ResidentBootstrapStore::default())
        .await
        .unwrap();
    let reaped_ids: std::collections::HashSet<SandboxId> =
        reaped.iter().map(|reaped| reaped.sandbox.id).collect();

    assert!(
        !reaped_ids.contains(&recent_ssh_activity.id),
        "a recent last_activity_at bump must reset the idle clock and prevent reaping, \
         even though updated_at alone is already past the deadline"
    );
    assert!(
        reaped_ids.contains(&no_activity_at_all.id),
        "with last_activity_at never set (NULL), the sweep must fall back to the \
         pre-existing updated_at/commands signal and reap this sandbox exactly as \
         it would have before this column existed"
    );
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

/// Regression test for evalops/sandboxwich#172: a reaper sweep tick racing a
/// manual stop (or another sweep tick) used to fall through past a
/// compare-and-swap miss and enqueue a second, redundant `StopSandbox` job
/// anyway. Reproduces the race deterministically -- no real concurrency or
/// timing needed -- by calling `attempt_reap_candidate` (the exact per-row
/// function `reap_expired_active_sandboxes`'s sweep loop calls) with a
/// stale, pre-race `Sandbox` snapshot *after* a separate `stop_sandbox_via_job`
/// call has already won the race for real.
#[tokio::test]
async fn reap_cas_miss_skips_instead_of_enqueuing_a_redundant_stop_job() {
    let db = test_sqlite_db().await;
    // `Ready` is a real `STOP_LEGAL_FROM` state a sweep would select as a
    // live candidate. `max_lifetime_seconds: Some(0)` (set on the in-memory
    // snapshot only, mirroring the existing `ttl_seconds: Some(0)`
    // immediate-eligibility idiom) makes it immediately due; `expired_deadline`
    // reads this field off the passed-in snapshot, not a fresh DB fetch, so
    // this is exactly what a sweep's own candidate SELECT would have seen.
    let mut sandbox = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    sandbox.max_lifetime_seconds = Some(0);

    // The concurrent actor -- a manual stop, or another sweep tick -- wins
    // the race first, for real: this is the call that must succeed and be
    // the *only* one to enqueue a job.
    let winner = stop_sandbox_via_job(
        &db,
        &ResidentBootstrapStore::default(),
        &sandbox,
        json!({"state": "archiving", "reason": "stop_requested"}),
    )
    .await
    .expect("the winning stop must not error");
    assert!(
        winner.is_some(),
        "the winning stop must actually enqueue a StopSandbox job"
    );

    // Now attempt to reap the *same* sandbox using the stale `Ready`
    // snapshot a sweep would have fetched moments before the winner above
    // landed. `stop_sandbox_via_job`'s internal CAS must miss (the real row
    // is `Archiving` now, not `Ready`), and `attempt_reap_candidate` must
    // report `Skipped` rather than treating this as a second successful
    // reap or an error.
    let outcome = attempt_reap_candidate(
        &db,
        &ResidentBootstrapStore::default(),
        sandbox.clone(),
        None,
        Utc::now(),
    )
    .await
    .expect("a CAS miss inside attempt_reap_candidate must not surface as an error");
    assert!(
        matches!(outcome, CandidateOutcome::Skipped),
        "a sandbox concurrently stopped between candidate selection and this \
         sweep's own CAS must be skipped, not reaped again or treated as a \
         failure; got {outcome:?}"
    );
    // `CandidateOutcome::Skipped` is returned from the exact match arm in
    // `attempt_reap_candidate` that also emits the "reap skipped" info log,
    // so asserting the returned variant is a direct, deterministic proxy for
    // "that log line fired" without standing up a tracing-capture harness
    // this codebase has no other use for.

    // The concrete regression #172 exists for: exactly one StopSandbox job
    // for this sandbox, not two.
    let stop_job_count: i64 =
        sqlx::query("select count(*) as count from jobs where kind = ? and payload like ?")
            .bind(job_kind_to_str(&JobKind::StopSandbox))
            .bind(format!("%{}%", sandbox.id))
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
    assert_eq!(
        stop_job_count, 1,
        "a CAS miss must not enqueue a second, redundant StopSandbox job"
    );

    let final_state = fetch_sandbox_state(&db, sandbox.id)
        .await
        .unwrap()
        .expect("sandbox must still exist");
    assert_eq!(
        final_state,
        SandboxState::Archiving,
        "the skipped attempt must not have clobbered the winner's state"
    );
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
        runtime_image: Some(sandbox.template.clone()),
        provision_spec: Some(SandboxProvisionSpec {
            memory_limit: sandbox.memory_limit.clone(),
            network_egress: sandbox.network_egress.clone(),
            workspace_mode: sandbox.workspace_mode.clone(),
            runtime_profile: sandbox.runtime_profile.clone(),
            execution_class: ExecutionClass::DevelopmentContainer,
        }),
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
async fn snapshot_restore_claim_retains_authoritative_placement_after_source_deletion() {
    let db = test_sqlite_db().await;
    let mut sandbox = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    sandbox.template = format!("ghcr.io/evalops/apex@sha256:{}", "b".repeat(64));
    sandbox.memory_limit = MemoryLimit::FourG;
    sandbox.network_egress = NetworkEgress::DenyAll;
    sandbox.workspace_mode = WorkspaceMode::Persistent;
    sandbox.runtime_profile = SandboxRuntimeProfile::ApexTrustedSupervisorV1;
    let sql = format!(
        "update sandboxes set template = {}, memory_limit = {}, runtime_profile = {} where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(&sandbox.template)
        .bind("4g")
        .bind("apex_trusted_supervisor_v1")
        .bind(sandbox.id.to_string())
        .execute(&db.pool)
        .await
        .expect("persist source placement");
    let now = Utc::now();
    let expected_spec = SandboxProvisionSpec {
        memory_limit: sandbox.memory_limit.clone(),
        network_egress: sandbox.network_egress.clone(),
        workspace_mode: sandbox.workspace_mode.clone(),
        runtime_profile: sandbox.runtime_profile.clone(),
        execution_class: ExecutionClass::DevelopmentContainer,
    };
    let snapshot = Snapshot {
        id: SnapshotId::new(),
        sandbox_id: sandbox.id,
        status: SnapshotStatus::Ready,
        label: "durable-placement".to_string(),
        inventory: json!({}),
        provider_metadata: json!({}),
        runtime_image: Some(sandbox.template.clone()),
        provision_spec: Some(expected_spec.clone()),
        created_at: now,
        ready_at: Some(now),
        expires_at: None,
        error: None,
    };
    let mut connection = db.pool.acquire().await.expect("acquire connection");
    insert_snapshot_on_connection(&db, &mut connection, &snapshot)
        .await
        .expect("insert snapshot");
    sqlx::query("delete from snapshots where id = ?")
        .bind(snapshot.id.to_string())
        .execute(&mut *connection)
        .await
        .expect("delete tenant-facing snapshot row");
    sqlx::query("delete from sandboxes where id = ?")
        .bind(sandbox.id.to_string())
        .execute(&mut *connection)
        .await
        .expect("delete source sandbox");

    let restored = claim_snapshot_restore_source_on_connection(
        &db,
        &mut connection,
        snapshot.id,
        &TenantContext {
            tenant_id: sandbox.tenant_id,
            principal: Principal::Tenant,
        },
        now,
    )
    .await
    .expect("retained restore source");

    assert_eq!(Some(restored.runtime_image), snapshot.runtime_image);
    assert_eq!(restored.provision_spec, expected_spec);
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
        runtime_profile: SandboxRuntimeProfile::Unprivileged,
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
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
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

#[tokio::test]
async fn sandbox_insert_rejects_a_nonexistent_parent_snapshot_id() {
    // The `sandboxes.parent_snapshot_id -> snapshot_restore_sources(snapshot_id)`
    // foreign key (see `sqlite_rebuild_sandboxes_with_parent_snapshot_fk` /
    // `ensure_sqlite_constraints` in `db.rs`) must reject an insert that
    // points at a snapshot that was never created, through the same
    // `insert_sandbox` path every handler uses -- not just a raw SQL
    // statement issued directly against the pool.
    let db = test_sqlite_db().await;
    let now = Utc::now();
    let sandbox = Sandbox {
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        id: SandboxId::new(),
        tenant_id: "default".to_string(),
        name: "dangling-parent-snapshot".to_string(),
        state: SandboxState::Planning,
        template: "default".to_string(),
        memory_limit: MemoryLimit::default(),
        network_egress: NetworkEgress::default(),
        runtime_profile: SandboxRuntimeProfile::default(),
        execution_class: ExecutionClass::default(),
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        last_activity_at: None,
        parent_snapshot_id: Some(SnapshotId::new()),
    };

    let result = insert_sandbox(&db, &sandbox).await;
    assert!(
        result.is_err(),
        "inserting a sandbox with a parent_snapshot_id pointing at a nonexistent snapshot must fail"
    );

    let missing = fetch_sandbox(&db, sandbox.id).await;
    assert!(
        missing.is_err(),
        "the rejected insert must not leave a partial sandbox row behind"
    );
}

#[tokio::test]
async fn parent_snapshot_fk_migration_nulls_pre_existing_orphans_before_enforcing() {
    // Simulates upgrading a database that predates the
    // `sandboxes.parent_snapshot_id -> snapshot_restore_sources(snapshot_id)`
    // foreign key and already has a row whose `parent_snapshot_id` points at
    // nothing -- the column only ever had an index
    // (20260704000500_snapshots.sql), so nothing ever stopped that from
    // happening. The migration added alongside the FK
    // (20260716000400_sandbox_parent_snapshot_fk.sql) must null those out
    // before `ensure_sqlite_constraints` starts enforcing the constraint, or
    // the upgrade itself would fail applying to real, already-drifted data.
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");

    const FK_MIGRATION_VERSION: i64 = 20260716000400;
    let mut migrations: Vec<_> = sqlx::migrate!("./migrations").iter().cloned().collect();
    migrations.sort_by_key(|migration| migration.version);

    for migration in migrations
        .iter()
        .filter(|m| m.version < FK_MIGRATION_VERSION)
    {
        sqlx::raw_sql(&migration.sql)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("apply migration {}: {error}", migration.version));
    }

    let now = Utc::now().to_rfc3339();
    let orphan_sandbox_id = Uuid::now_v7().to_string();
    let dangling_snapshot_id = Uuid::now_v7().to_string();
    sqlx::query(
        "insert into sandboxes
            (id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id,
             tenant_id, memory_limit, network_egress_mode, workspace_mode)
         values (?, 'orphaned', 'ready', 'default', ?, ?, NULL, ?, 'default', '1g', 'deny_all', 'persistent')",
    )
    .bind(&orphan_sandbox_id)
    .bind(&now)
    .bind(&now)
    .bind(&dangling_snapshot_id)
    .execute(&pool)
    .await
    .expect("seed a pre-existing orphan sandbox row (no FK exists at this schema version yet)");

    for migration in migrations
        .iter()
        .filter(|m| m.version >= FK_MIGRATION_VERSION)
    {
        sqlx::raw_sql(&migration.sql)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("apply migration {}: {error}", migration.version));
    }

    let db = Database {
        pool,
        dialect: SqlDialect::Sqlite,
    };
    ensure_database_constraints(&db)
        .await
        .expect("reconcile constraints, including the new parent_snapshot_id foreign key");

    let parent_snapshot_id: Option<String> =
        sqlx::query("select parent_snapshot_id from sandboxes where id = ?")
            .bind(&orphan_sandbox_id)
            .fetch_one(&db.pool)
            .await
            .expect("fetch orphan sandbox row")
            .try_get("parent_snapshot_id")
            .expect("read parent_snapshot_id");
    assert_eq!(
        parent_snapshot_id, None,
        "the orphan-cleanup migration must null out a parent_snapshot_id with no matching snapshot"
    );

    // With the orphan cleaned up and the FK now enforced, a fresh insert
    // pointing at the same nonexistent snapshot id must be rejected.
    let result = sqlx::query(
        "insert into sandboxes
            (id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id,
             tenant_id, memory_limit, network_egress_mode, workspace_mode)
         values (?, 'still-dangling', 'ready', 'default', ?, ?, NULL, ?, 'default', '1g', 'deny_all', 'persistent')",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&now)
    .bind(&now)
    .bind(&dangling_snapshot_id)
    .execute(&db.pool)
    .await;
    assert!(
        result.is_err(),
        "the foreign key must reject the same dangling snapshot id post-upgrade"
    );
}

#[tokio::test]
async fn apex_execution_class_migration_backfills_legacy_rows() {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect upgrade database");
    let migrations = sqlx::migrate!("./migrations");
    // This test simulates rows written *before* the corrective backfill
    // migration below, then applies it and asserts it ran correctly.
    //
    // It used to build "prior_migrations" by slicing off just the literal
    // last migration, on the assumption that the backfill migration was
    // always the newest one -- true when this test was written, but silently
    // stale since (several unrelated migrations, most recently the active-
    // lifetime-reaping columns, have landed after it without breaking this
    // test, purely because none of them touched a column the legacy inserts
    // below depend on -- unlike the active-lifetime columns, which
    // `insert_sandbox` now unconditionally writes).
    //
    // The fix excludes only the backfill migration itself (found by name,
    // not position) rather than truncating everything after it, so
    // `insert_sandbox`/`insert_job` below run against the *current* full
    // schema (every column they need exists) with only this one migration's
    // row-level fixup not yet applied -- exactly the legacy state this test
    // means to construct, regardless of how many migrations land on either
    // side of the backfill one in the future.
    let backfill_index = migrations
        .migrations
        .iter()
        .position(|migration| {
            migration
                .description
                .contains("apex execution class backfill")
        })
        .expect("apex_execution_class_backfill migration must still exist");
    let prior_migrations = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            migrations
                .migrations
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != backfill_index)
                .map(|(_, migration)| migration.clone())
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    prior_migrations
        .run(&pool)
        .await
        .expect("migrate to pre-backfill schema");
    let db = Database {
        pool,
        dialect: SqlDialect::Sqlite,
    };
    let now = Utc::now();
    let sandbox = Sandbox {
        id: SandboxId::new(),
        tenant_id: "legacy-apex-tenant".to_string(),
        name: "legacy-apex".to_string(),
        state: SandboxState::Ready,
        template: format!("ghcr.io/evalops/apex@sha256:{}", "a".repeat(64)),
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        workspace_mode: WorkspaceMode::Persistent,
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        execution_class: ExecutionClass::DevelopmentContainer,
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
    };
    insert_sandbox(&db, &sandbox)
        .await
        .expect("insert legacy sandbox");
    let mut deleted_source = sandbox.clone();
    deleted_source.id = SandboxId::new();
    deleted_source.name = "deleted-apex-source".to_string();
    insert_sandbox(&db, &deleted_source)
        .await
        .expect("insert source that will be deleted");
    let mut non_apex = sandbox.clone();
    non_apex.id = SandboxId::new();
    non_apex.name = "legacy-unprivileged".to_string();
    non_apex.runtime_profile = SandboxRuntimeProfile::Unprivileged;
    insert_sandbox(&db, &non_apex)
        .await
        .expect("insert non-APEX control sandbox");

    let job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Queued,
        payload: json!({"sandboxId": sandbox.id}),
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
    insert_job(&db, &job).await.expect("insert legacy job");
    let snapshot_job = Job {
        id: JobId::new(),
        kind: JobKind::CreateSnapshot,
        payload: json!({
            "sandboxId": sandbox.id,
            "snapshotId": SnapshotId::new(),
        }),
        required_capability: WorkerCapability::Snapshot,
        ..job.clone()
    };
    insert_job(&db, &snapshot_job)
        .await
        .expect("insert legacy snapshot job");
    let fork_job = Job {
        id: JobId::new(),
        kind: JobKind::ForkSandbox,
        payload: json!({
            "parentSandboxId": non_apex.id,
            "childSandboxId": sandbox.id,
            "snapshotId": SnapshotId::new(),
        }),
        ..job.clone()
    };
    insert_job(&db, &fork_job)
        .await
        .expect("insert legacy fork-child job");
    let non_apex_job = Job {
        id: JobId::new(),
        payload: json!({"sandboxId": non_apex.id}),
        ..job.clone()
    };
    insert_job(&db, &non_apex_job)
        .await
        .expect("insert non-APEX control job");

    let snapshot_id = SnapshotId::new();
    let deleted_restore_id = SnapshotId::new();
    let non_apex_restore_id = SnapshotId::new();
    let provision_spec = serde_json::to_string(&SandboxProvisionSpec {
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        execution_class: ExecutionClass::DevelopmentContainer,
        ..SandboxProvisionSpec::default()
    })
    .expect("serialize legacy provision spec");
    let non_apex_provision_spec = serde_json::to_string(&SandboxProvisionSpec::default())
        .expect("serialize non-APEX provision spec");
    for (restore_id, source_sandbox_id, spec) in [
        (snapshot_id, sandbox.id, provision_spec.clone()),
        (
            deleted_restore_id,
            deleted_source.id,
            provision_spec.clone(),
        ),
        (non_apex_restore_id, non_apex.id, non_apex_provision_spec),
    ] {
        sqlx::query(
            "insert into snapshot_restore_sources
             (snapshot_id, tenant_id, source_sandbox_id, execution_class, status, provision_spec)
             values (?, ?, ?, ?, ?, ?)",
        )
        .bind(restore_id.to_string())
        .bind(&sandbox.tenant_id)
        .bind(source_sandbox_id.to_string())
        .bind("development_container")
        .bind("ready")
        .bind(spec)
        .execute(&db.pool)
        .await
        .expect("insert legacy restore source");
    }
    sqlx::query("delete from sandboxes where id = ?")
        .bind(deleted_source.id.to_string())
        .execute(&db.pool)
        .await
        .expect("delete APEX restore source before backfill");

    migrations
        .run(&db.pool)
        .await
        .expect("apply corrective backfill migration");
    sqlx::raw_sql(include_str!(
        "../migrations/20260714000300_apex_execution_class_backfill.sql"
    ))
    .execute(&db.pool)
    .await
    .expect("corrective backfill remains idempotent");

    let sandbox_class: String = sqlx::query("select execution_class from sandboxes where id = ?")
        .bind(sandbox.id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("fetch sandbox class")
        .try_get("execution_class")
        .expect("sandbox execution_class");
    let job_class: String = sqlx::query("select required_execution_class from jobs where id = ?")
        .bind(job.id.to_string())
        .fetch_one(&db.pool)
        .await
        .expect("fetch job class")
        .try_get("required_execution_class")
        .expect("job required_execution_class");
    let restore_class: String =
        sqlx::query("select execution_class from snapshot_restore_sources where snapshot_id = ?")
            .bind(snapshot_id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch restore source class")
            .try_get("execution_class")
            .expect("restore execution_class");

    assert_eq!(sandbox_class, "sandboxed_container");
    assert_eq!(job_class, "sandboxed_container");
    assert_eq!(restore_class, "sandboxed_container");

    for backfilled_job_id in [snapshot_job.id, fork_job.id] {
        let class: String = sqlx::query("select required_execution_class from jobs where id = ?")
            .bind(backfilled_job_id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch backfilled job class")
            .try_get("required_execution_class")
            .expect("backfilled job required_execution_class");
        assert_eq!(class, "sandboxed_container");
    }
    let deleted_restore_class: String =
        sqlx::query("select execution_class from snapshot_restore_sources where snapshot_id = ?")
            .bind(deleted_restore_id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch deleted-source restore class")
            .try_get("execution_class")
            .expect("deleted-source execution_class");
    assert_eq!(deleted_restore_class, "sandboxed_container");

    let non_apex_sandbox_class: String =
        sqlx::query("select execution_class from sandboxes where id = ?")
            .bind(non_apex.id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch non-APEX sandbox class")
            .try_get("execution_class")
            .expect("non-APEX sandbox execution_class");
    let non_apex_job_class: String =
        sqlx::query("select required_execution_class from jobs where id = ?")
            .bind(non_apex_job.id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch non-APEX job class")
            .try_get("required_execution_class")
            .expect("non-APEX job required_execution_class");
    let non_apex_restore_class: String =
        sqlx::query("select execution_class from snapshot_restore_sources where snapshot_id = ?")
            .bind(non_apex_restore_id.to_string())
            .fetch_one(&db.pool)
            .await
            .expect("fetch non-APEX restore class")
            .try_get("execution_class")
            .expect("non-APEX restore execution_class");
    assert_eq!(non_apex_sandbox_class, "development_container");
    assert_eq!(non_apex_job_class, "development_container");
    assert_eq!(non_apex_restore_class, "development_container");
}

#[tokio::test]
async fn provider_identity_collision_requires_exact_association_tuple() {
    let db = test_sqlite_db().await;
    let first = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    let second = seed_sandbox_with_state(&db, SandboxState::Ready).await;
    let snapshot_one = SnapshotId::new();
    let snapshot_two = SnapshotId::new();
    for snapshot_id in [snapshot_one, snapshot_two] {
        sqlx::query(
            "insert into snapshots
             (id, sandbox_id, tenant_id, status, label, inventory, provider_metadata, created_at)
             values (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(snapshot_id.to_string())
        .bind(first.id.to_string())
        .bind(&first.tenant_id)
        .bind("ready")
        .bind("identity-collision-test")
        .bind("{}")
        .bind("{}")
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await
        .expect("seed snapshot association");
    }
    let make_resource =
        |name: &str,
         sandbox_id: SandboxId,
         snapshot_id: Option<SnapshotId>,
         source_snapshot_id: Option<SnapshotId>| ProviderRuntimeResource {
            sandbox_id,
            snapshot_id,
            provider: "kubernetes".to_string(),
            resource_kind: RuntimeResourceKind::Pod,
            purpose: RuntimeResourcePurpose::Runtime,
            resource_name: name.to_string(),
            namespace: "identity-collision-test".to_string(),
            status: RuntimeResourceStatus::Ready,
            cluster: Some("test-cluster".to_string()),
            storage_class: None,
            snapshot_class: None,
            storage_size: None,
            runtime_image: Some("image@sha256:test".to_string()),
            service_port: None,
            target_port: None,
            source_snapshot_id,
            ready_at: Some(Utc::now()),
            error: None,
        };
    let cases = [
        make_resource("provision-sibling", first.id, None, None),
        make_resource("snapshot-move", first.id, Some(snapshot_one), None),
        make_resource("fork-child-move", first.id, None, Some(snapshot_one)),
        make_resource("fork-source-move", first.id, None, Some(snapshot_one)),
    ];
    let mut connection = db.pool.acquire().await.expect("acquire connection");

    for (index, original) in cases.into_iter().enumerate() {
        let inserted = upsert_provider_runtime_resource_on_connection(
            &db,
            &mut connection,
            &original,
            None,
            None,
            Some(&first.tenant_id),
        )
        .await
        .expect("insert original provider identity");
        let retried = upsert_provider_runtime_resource_on_connection(
            &db,
            &mut connection,
            &original,
            None,
            None,
            Some(&first.tenant_id),
        )
        .await
        .expect("an exact association retry must be accepted");
        assert_eq!(retried.id, inserted.id);

        let mut displaced = original.clone();
        match index {
            0 | 2 => displaced.sandbox_id = second.id,
            1 => displaced.snapshot_id = Some(snapshot_two),
            3 => displaced.source_snapshot_id = Some(snapshot_two),
            _ => unreachable!(),
        }
        let error = upsert_provider_runtime_resource_on_connection(
            &db,
            &mut connection,
            &displaced,
            None,
            None,
            Some(&first.tenant_id),
        )
        .await
        .expect_err("provider identity ownership cannot move");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        let persisted = fetch_runtime_resource_on_connection(&db, &mut connection, inserted.id)
            .await
            .expect("fetch persisted association");
        assert_eq!(persisted.sandbox_id, original.sandbox_id);
        assert_eq!(persisted.snapshot_id, original.snapshot_id);
        assert_eq!(persisted.source_snapshot_id, original.source_snapshot_id);
    }
}
