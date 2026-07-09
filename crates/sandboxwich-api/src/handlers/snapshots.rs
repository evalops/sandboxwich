use crate::auth::*;
use crate::cleanup::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::jobs::*;
use crate::handlers::leases::*;
use crate::handlers::sandboxes::*;
use crate::pagination::*;
use crate::reconcile::*;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

pub(crate) async fn create_snapshot(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateSnapshotRequest>,
) -> Result<Json<SnapshotResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let snapshot = pending_snapshot_from_request(sandbox_id, request)?;
    let scheduled_at = snapshot.created_at;
    insert_snapshot(&state.db, &snapshot).await?;
    insert_event(
        &state.db,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "reason": "snapshot_created",
            "snapshotId": snapshot.id,
            "snapshotStatus": snapshot.status
        }),
    )
    .await?;
    insert_job(
        &state.db,
        &Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id,
            kind: JobKind::CreateSnapshot,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": sandbox_id,
                "snapshotId": snapshot.id
            }),
            required_capability: WorkerCapability::Snapshot,
            priority: 0,
            attempts: 0,
            max_attempts: 3,
            scheduled_at,
            created_at: scheduled_at,
            updated_at: scheduled_at,
            last_error: None,
        },
    )
    .await?;

    Ok(Json(SnapshotResponse { ok: true, snapshot }))
}

pub(crate) async fn list_snapshots(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Query(page): Query<PageParams>,
) -> Result<Json<SnapshotListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;
    let (snapshots, next_cursor) =
        list_snapshots_for_sandbox(&state.db, sandbox_id, limit, &cursor).await?;
    Ok(Json(SnapshotListResponse {
        ok: true,
        snapshots,
        next_cursor,
    }))
}

pub(crate) async fn get_snapshot(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(snapshot_id): Path<Uuid>,
) -> Result<Json<SnapshotResponse>, ApiError> {
    let snapshot = fetch_snapshot(&state.db, SnapshotId(snapshot_id)).await?;
    ensure_sandbox_tenant(&state.db, snapshot.sandbox_id, &ctx).await?;
    Ok(Json(SnapshotResponse { ok: true, snapshot }))
}

pub(crate) async fn cleanup_snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SnapshotCleanupResponse>, ApiError> {
    ensure_operator_authorized(&state, &headers)?;
    let cleanup = run_cleanup_controller(&state.db).await?;
    Ok(Json(SnapshotCleanupResponse {
        ok: true,
        cleanup_run: cleanup.cleanup_run,
        expired: cleanup.expired,
        archived_sandboxes_deleted: cleanup.archived_sandboxes_deleted,
        archived_sandboxes: cleanup.archived_sandboxes,
        archived_sandboxes_skipped: cleanup.archived_sandboxes_skipped,
        runtime_resources_deleted: cleanup.runtime_resources_deleted,
    }))
}

pub(crate) fn pending_snapshot_from_request(
    sandbox_id: SandboxId,
    request: CreateSnapshotRequest,
) -> Result<Snapshot, ApiError> {
    let now = Utc::now();
    let label = match request.label {
        Some(label) if label.trim().is_empty() => {
            return Err(ApiError::bad_request("snapshot label cannot be empty"));
        }
        Some(label) => label,
        None => "manual-snapshot".to_string(),
    };

    Ok(Snapshot {
        id: SnapshotId::new(),
        sandbox_id,
        status: SnapshotStatus::Pending,
        label,
        inventory: request.inventory.unwrap_or_else(|| json!({})),
        provider_metadata: request.provider_metadata.unwrap_or_else(|| json!({})),
        created_at: now,
        ready_at: None,
        expires_at: expires_at_from_ttl(now, request.ttl_seconds)?,
        error: None,
    })
}

pub(crate) async fn insert_snapshot(db: &Database, snapshot: &Snapshot) -> Result<(), ApiError> {
    let mut connection = db.pool.acquire().await?;
    insert_snapshot_on_connection(db, &mut connection, snapshot).await
}

pub(crate) async fn insert_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot: &Snapshot,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into snapshots
         (id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error)
         values ({})",
        db.placeholders(10)
    );
    sqlx::query(&sql)
        .bind(snapshot.id.to_string())
        .bind(snapshot.sandbox_id.to_string())
        .bind(snapshot_status_to_str(&snapshot.status))
        .bind(&snapshot.label)
        .bind(serde_json::to_string(&snapshot.inventory)?)
        .bind(serde_json::to_string(&snapshot.provider_metadata)?)
        .bind(snapshot.created_at.to_rfc3339())
        .bind(snapshot.ready_at.map(|time| time.to_rfc3339()))
        .bind(snapshot.expires_at.map(|time| time.to_rfc3339()))
        .bind(&snapshot.error)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn fetch_snapshot(
    db: &Database,
    snapshot_id: SnapshotId,
) -> Result<Snapshot, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("snapshot not found"))?;

    row_to_snapshot(row)
}

pub(crate) async fn fetch_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
) -> Result<Snapshot, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("snapshot not found"))?;

    row_to_snapshot(row)
}

pub(crate) async fn list_snapshots_for_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
    limit: u32,
    cursor: &Option<(PageDirection, PageCursor)>,
) -> Result<(Vec<Snapshot>, Option<String>), ApiError> {
    let base_sql = format!(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where sandbox_id = {}",
        db.placeholder(1)
    );
    fetch_keyset_page(
        db,
        &base_sql,
        &[sandbox_id.to_string()],
        limit,
        cursor,
        row_to_snapshot,
    )
    .await
}

pub(crate) async fn expire_due_snapshots(db: &Database) -> Result<Vec<Snapshot>, ApiError> {
    let now = Utc::now();
    let rows = sqlx::query(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where status in ('pending', 'ready') and expires_at is not null
         order by expires_at asc, id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let mut expired = Vec::new();
    for row in rows {
        let snapshot = row_to_snapshot(row)?;
        let Some(expires_at) = snapshot.expires_at else {
            continue;
        };
        if expires_at > now {
            continue;
        }
        let mut tx = db.pool.begin().await?;
        let expired_snapshot = async {
            let won_transition =
                expire_active_snapshot_on_connection(db, &mut tx, snapshot.id, now).await?;
            if !won_transition {
                // The snapshot's TTL was extended, or another caller (e.g. an
                // overlapping sweep instance) already expired it, since this
                // sweep's SELECT was taken. Don't re-apply expiry side
                // effects on top of that.
                return Ok(None);
            }
            dead_queued_snapshot_jobs_on_connection(db, &mut tx, snapshot.id, "snapshot expired")
                .await?;
            fail_sandboxes_waiting_on_snapshot_on_connection(
                db,
                &mut tx,
                snapshot.id,
                "snapshot_expired",
                "snapshot expired",
            )
            .await?;
            let expired_snapshot = fetch_snapshot_on_connection(db, &mut tx, snapshot.id).await?;
            insert_event_on_connection(
                db,
                &mut tx,
                expired_snapshot.sandbox_id,
                SandboxEventKind::LifecycleChanged,
                json!({
                    "reason": "snapshot_expired",
                    "snapshotId": expired_snapshot.id,
                    "snapshotStatus": expired_snapshot.status
                }),
            )
            .await?;
            Ok(Some(expired_snapshot))
        }
        .await;
        match expired_snapshot {
            Ok(Some(expired_snapshot)) => {
                tx.commit().await?;
                expired.push(expired_snapshot);
            }
            Ok(None) => {
                tx.commit().await?;
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back snapshot expiration");
                }
                return Err(error);
            }
        }
    }

    Ok(expired)
}

/// Guarded, atomic `pending`/`ready` -> `expired` transition for a snapshot
/// that a sweep has observed as due. Returns `true` only if this call
/// performed the transition (`rows_affected() == 1`); returns `false` if the
/// snapshot's TTL was extended or it was already expired by another caller
/// since the sweep's SELECT was taken, in which case no further side effects
/// (dead-lettering queued jobs, failing waiting sandboxes, emitting events)
/// should run. This mirrors `expire_active_lease_on_connection`'s guard
/// against the renewal-vs-expiry race.
pub(crate) async fn expire_active_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let sql = format!(
        "update snapshots
         set status = {}, error = {}
         where id = {} and status in ('pending', 'ready')
           and expires_at is not null and expires_at <= {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let result = sqlx::query(&sql)
        .bind(snapshot_status_to_str(&SnapshotStatus::Expired))
        .bind(Option::<String>::None)
        .bind(snapshot_id.to_string())
        .bind(now.to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn update_snapshot_status_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    status: SnapshotStatus,
    error: Option<&str>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update snapshots
         set status = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    let result = sqlx::query(&sql)
        .bind(snapshot_status_to_str(&status))
        .bind(error)
        .bind(snapshot_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("snapshot not found"));
    }
    Ok(())
}

pub(crate) async fn dead_queued_snapshot_jobs_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    error: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "select id
         from jobs
         where kind = 'create_snapshot' and status = 'queued' and snapshot_id = {}",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    let now = Utc::now();
    for row in rows {
        let job_id: String = row.try_get("id")?;
        update_job_status_on_connection(
            db,
            connection,
            JobId(parse_uuid(&job_id)?),
            JobStatus::Dead,
            Some(error),
            now,
        )
        .await?;
    }

    Ok(())
}

pub(crate) async fn cleanup_runtime_resources_for_expired_snapshots(
    db: &Database,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let rows = sqlx::query(
        "select runtime_resources.id, runtime_resources.sandbox_id, runtime_resources.snapshot_id,
                runtime_resources.provider, runtime_resources.resource_kind, runtime_resources.purpose,
                runtime_resources.resource_name, runtime_resources.namespace, runtime_resources.status,
                runtime_resources.cluster, runtime_resources.storage_class, runtime_resources.snapshot_class,
                runtime_resources.storage_size, runtime_resources.runtime_image, runtime_resources.service_port,
                runtime_resources.target_port, runtime_resources.source_snapshot_id, runtime_resources.created_at,
                runtime_resources.updated_at, runtime_resources.observed_at, runtime_resources.last_reconciled_at,
                runtime_resources.ready_at, runtime_resources.deleted_at, runtime_resources.error
         from runtime_resources
         join snapshots on snapshots.id = runtime_resources.snapshot_id
         where snapshots.status = 'expired' and runtime_resources.status not in ('deleted', 'destroyed')
         order by runtime_resources.updated_at asc, runtime_resources.id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let mut deleted = Vec::new();
    for row in rows {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(
            mark_runtime_resource_deleted(
                db,
                resource.id,
                Utc::now(),
                "snapshot expired during cleanup",
            )
            .await?,
        );
    }

    Ok(deleted)
}

pub(crate) async fn mark_snapshot_ready_from_provider_handle_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    handle: sandboxwich_core::ProviderSnapshotHandle,
) -> Result<(), ApiError> {
    let snapshot_id = handle.snapshot_id;
    upsert_provider_runtime_resources_on_connection(db, connection, &handle.resources).await?;
    let snapshot = fetch_snapshot_on_connection(db, connection, snapshot_id).await?;
    let provider = handle.provider.clone();
    let inventory = if snapshot.inventory == json!({}) {
        json!({
            "sandboxId": sandbox_id,
            "snapshotId": snapshot_id,
            "provider": provider
        })
    } else {
        snapshot.inventory
    };
    let provider_metadata = handle.metadata;
    let now = Utc::now();
    let sql = format!(
        "update snapshots
         set status = {}, inventory = {}, provider_metadata = {}, ready_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let result = sqlx::query(&sql)
        .bind(snapshot_status_to_str(&SnapshotStatus::Ready))
        .bind(serde_json::to_string(&inventory)?)
        .bind(serde_json::to_string(&provider_metadata)?)
        .bind(now.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(snapshot_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("snapshot not found"));
    }
    queue_forks_waiting_on_snapshot_on_connection(db, connection, snapshot_id, sandbox_id).await?;
    Ok(())
}

pub(crate) async fn queue_forks_waiting_on_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    parent_sandbox_id: SandboxId,
) -> Result<(), ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where parent_snapshot_id = {} and state = 'planning'
         order by created_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    for row in rows {
        let mut child = row_to_sandbox(row)?;
        hydrate_sandbox_network_egress_on_connection(db, connection, &mut child).await?;
        let now = Utc::now();
        insert_job_on_connection(
            db,
            connection,
            &Job {
                id: JobId::new(),
                tenant_id: child.tenant_id.clone(),
                kind: JobKind::ForkSandbox,
                status: JobStatus::Queued,
                payload: json!({
                    "parentSandboxId": parent_sandbox_id,
                    "childSandboxId": child.id,
                    "snapshotId": snapshot_id,
                    "provisionSpec": SandboxProvisionSpec {
                        memory_limit: child.memory_limit.clone(),
                        network_egress: child.network_egress.clone(),
                    }
                }),
                required_capability: WorkerCapability::Snapshot,
                priority: 0,
                attempts: 0,
                max_attempts: 3,
                scheduled_at: now,
                created_at: now,
                updated_at: now,
                last_error: None,
            },
        )
        .await?;
        insert_event_on_connection(
            db,
            connection,
            child.id,
            SandboxEventKind::LifecycleChanged,
            json!({
                "state": child.state,
                "reason": "fork_snapshot_ready",
                "parentSandboxId": parent_sandbox_id,
                "parentSnapshotId": snapshot_id
            }),
        )
        .await?;
    }

    Ok(())
}

pub(crate) async fn fail_sandboxes_waiting_on_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    reason: &'static str,
    error: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where parent_snapshot_id = {} and state = 'planning'
         order by created_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    for row in rows {
        let mut child = row_to_sandbox(row)?;
        hydrate_sandbox_network_egress_on_connection(db, connection, &mut child).await?;
        let next_state = SandboxState::Error;
        set_sandbox_state_on_connection(
            db,
            connection,
            child.id,
            SandboxState::SNAPSHOT_FAILED_CHILD_LEGAL_FROM,
            next_state.clone(),
            json!({
                "state": next_state,
                "reason": reason,
                "parentSnapshotId": snapshot_id,
                "error": error
            }),
        )
        .await?;
    }

    Ok(())
}

pub(crate) fn snapshot_id_from_job(job: &Job) -> Result<SnapshotId, ApiError> {
    uuid_from_job_payload(job, "snapshotId", "snapshot job is missing snapshot id").map(SnapshotId)
}
