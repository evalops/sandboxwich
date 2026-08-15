use crate::db::*;
use crate::error::*;
use crate::handlers::jobs::enqueue_archived_runtime_cleanup_on_connection;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::reconcile::*;
use crate::rows::*;
use crate::util::*;
use chrono::Utc;
use sandboxwich_core::*;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

const ARCHIVED_RUNTIME_RECONCILIATION_BATCH_SIZE: u32 = 100;
/// Cap retention deletes per sweep tick so a large archived set cannot hold
/// the write FIFO for an entire TTL backlog (mirrors archived-runtime repair).
const ARCHIVED_SANDBOX_CLEANUP_BATCH_SIZE: i64 = 100;

/// Finds archived sandboxes that still have provider-owned runtime rows, plus
/// archiving sandboxes whose last stop failed, and queues one idempotent stop
/// job for each. This is a repair loop, not the retention cleanup: it runs
/// independently of TTL so provider teardown cannot remain stranded.
pub(crate) async fn reconcile_archived_runtime_resources(db: &Database) -> Result<usize, ApiError> {
    let candidate_sql = format!(
        "select distinct sandboxes.id
         from sandboxes
         left join runtime_resources on runtime_resources.sandbox_id = sandboxes.id
         where ((sandboxes.state = 'archived'
                 and runtime_resources.snapshot_id is null
                 and runtime_resources.purpose <> 'snapshot'
                 and runtime_resources.status not in ('deleted', 'destroyed'))
                or (sandboxes.state = 'archiving'
                    and exists (
                        select 1 from jobs failed_stops
                        where failed_stops.sandbox_id = sandboxes.id
                          and failed_stops.kind = 'stop_sandbox'
                          and failed_stops.status = 'failed'
                    )))
           and not exists (
             select 1 from jobs
             where jobs.sandbox_id = sandboxes.id
               and jobs.kind = 'stop_sandbox'
               and jobs.status in ('queued', 'leased')
           )
         order by sandboxes.id asc
         limit {ARCHIVED_RUNTIME_RECONCILIATION_BATCH_SIZE}"
    );
    let rows = sqlx::query(&candidate_sql).fetch_all(&db.pool).await?;
    let mut enqueued = 0;

    for row in rows {
        let sandbox_id: String = row.try_get("id")?;
        let sandbox_id = SandboxId(
            Uuid::parse_str(&sandbox_id)
                .map_err(|_| ApiError::internal("database contains invalid sandbox id"))?,
        );
        let mut tx = db.pool.begin().await?;
        let result = async {
            let sandbox = match fetch_sandbox_on_connection(db, &mut tx, sandbox_id).await {
                Ok(sandbox)
                    if matches!(
                        sandbox.state,
                        SandboxState::Archiving | SandboxState::Archived
                    ) =>
                {
                    sandbox
                }
                Ok(_) => return Ok(false),
                Err(error) if error.status == axum::http::StatusCode::NOT_FOUND => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            let active_resource_sql = format!(
                "select 1
                 from runtime_resources
                 where sandbox_id = {} and snapshot_id is null
                   and purpose <> 'snapshot'
                   and status not in ('deleted', 'destroyed')
                 limit 1",
                db.placeholder(1)
            );
            if sandbox.state == SandboxState::Archived
                && sqlx::query(&active_resource_sql)
                    .bind(sandbox_id.to_string())
                    .fetch_optional(&mut *tx)
                    .await?
                    .is_none()
            {
                return Ok(false);
            }
            let reason = if sandbox.state == SandboxState::Archiving {
                "failed_stop_reconciliation"
            } else {
                "archived_runtime_reconciliation"
            };
            enqueue_archived_runtime_cleanup_on_connection(db, &mut tx, &sandbox, None, reason)
                .await
        }
        .await;
        match result {
            Ok(inserted) => {
                tx.commit().await?;
                if inserted {
                    enqueued += 1;
                }
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(
                        sandbox_id = %sandbox_id,
                        %rollback_error,
                        "failed to roll back archived runtime reconciliation"
                    );
                }
                tracing::warn!(
                    sandbox_id = %sandbox_id,
                    ?error,
                    "archived runtime reconciliation skipped one sandbox"
                );
            }
        }
    }

    Ok(enqueued)
}

pub(crate) async fn insert_cleanup_run(
    db: &Database,
    cleanup_run: &CleanupRun,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into cleanup_runs
         (id, status, started_at, finished_at, expired_snapshots, archived_sandboxes_deleted,
          archived_sandboxes_skipped, runtime_resources_deleted, error)
         values ({})",
        db.placeholders(9)
    );
    sqlx::query(&sql)
        .bind(cleanup_run.id.to_string())
        .bind(cleanup_run_status_to_str(&cleanup_run.status))
        .bind(cleanup_run.started_at.to_rfc3339())
        .bind(cleanup_run.finished_at.map(|time| time.to_rfc3339()))
        .bind(count_to_i64(cleanup_run.expired_snapshots)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_deleted)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_skipped)?)
        .bind(count_to_i64(cleanup_run.runtime_resources_deleted)?)
        .bind(&cleanup_run.error)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(crate) async fn update_cleanup_run(
    db: &Database,
    cleanup_run: &CleanupRun,
) -> Result<(), ApiError> {
    let sql = format!(
        "update cleanup_runs
         set status = {}, finished_at = {}, expired_snapshots = {},
             archived_sandboxes_deleted = {}, archived_sandboxes_skipped = {},
             runtime_resources_deleted = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8)
    );
    let result = sqlx::query(&sql)
        .bind(cleanup_run_status_to_str(&cleanup_run.status))
        .bind(cleanup_run.finished_at.map(|time| time.to_rfc3339()))
        .bind(count_to_i64(cleanup_run.expired_snapshots)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_deleted)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_skipped)?)
        .bind(count_to_i64(cleanup_run.runtime_resources_deleted)?)
        .bind(&cleanup_run.error)
        .bind(cleanup_run.id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("cleanup run not found"));
    }
    Ok(())
}

pub(crate) struct CleanupControllerReport {
    pub(crate) cleanup_run: CleanupRun,
    pub(crate) expired: Vec<Snapshot>,
    pub(crate) archived_sandboxes_deleted: u64,
    pub(crate) archived_sandboxes: Vec<Sandbox>,
    pub(crate) archived_sandboxes_skipped: Vec<ArchivedSandboxCleanupSkip>,
    pub(crate) runtime_resources_deleted: Vec<RuntimeResource>,
}

pub(crate) struct ArchivedSandboxCleanupResult {
    pub(crate) deleted: Vec<Sandbox>,
    pub(crate) skipped: Vec<ArchivedSandboxCleanupSkip>,
    pub(crate) runtime_resources_deleted: Vec<RuntimeResource>,
}

pub(crate) async fn run_cleanup_controller(
    db: &Database,
) -> Result<CleanupControllerReport, ApiError> {
    let started_at = Utc::now();
    let cleanup_run = CleanupRun {
        id: CleanupRunId::new(),
        status: CleanupRunStatus::Running,
        started_at,
        finished_at: None,
        expired_snapshots: 0,
        archived_sandboxes_deleted: 0,
        archived_sandboxes_skipped: 0,
        runtime_resources_deleted: 0,
        error: None,
    };
    insert_cleanup_run(db, &cleanup_run).await?;

    let mut expired_count = 0;
    let mut archived_deleted_count = 0;
    let mut archived_skipped_count = 0;
    let mut runtime_deleted_count = 0;

    if let Err(error) = terminalize_queued_snapshot_jobs_for_archived_sandboxes(db).await {
        mark_cleanup_run_failed(
            db,
            &cleanup_run,
            expired_count,
            archived_deleted_count,
            archived_skipped_count,
            runtime_deleted_count,
            &error,
        )
        .await;
        return Err(error);
    }

    let expired = match expire_due_snapshots(db).await {
        Ok(expired) => {
            expired_count = expired.len() as u64;
            expired
        }
        Err(error) => {
            mark_cleanup_run_failed(
                db,
                &cleanup_run,
                expired_count,
                archived_deleted_count,
                archived_skipped_count,
                runtime_deleted_count,
                &error,
            )
            .await;
            return Err(error);
        }
    };
    let mut runtime_resources_deleted =
        match cleanup_runtime_resources_for_expired_snapshots(db).await {
            Ok(deleted) => {
                runtime_deleted_count = deleted.len() as u64;
                deleted
            }
            Err(error) => {
                mark_cleanup_run_failed(
                    db,
                    &cleanup_run,
                    expired_count,
                    archived_deleted_count,
                    archived_skipped_count,
                    runtime_deleted_count,
                    &error,
                )
                .await;
                return Err(error);
            }
        };
    let archived = match cleanup_archived_sandboxes(db).await {
        Ok(archived) => archived,
        Err(error) => {
            mark_cleanup_run_failed(
                db,
                &cleanup_run,
                expired_count,
                archived_deleted_count,
                archived_skipped_count,
                runtime_deleted_count,
                &error,
            )
            .await;
            return Err(error);
        }
    };
    runtime_resources_deleted.extend(archived.runtime_resources_deleted);
    archived_deleted_count = archived.deleted.len() as u64;
    archived_skipped_count = archived.skipped.len() as u64;
    runtime_deleted_count = runtime_resources_deleted.len() as u64;

    let cleanup_run = CleanupRun {
        status: CleanupRunStatus::Succeeded,
        finished_at: Some(Utc::now()),
        expired_snapshots: expired_count,
        archived_sandboxes_deleted: archived_deleted_count,
        archived_sandboxes_skipped: archived_skipped_count,
        runtime_resources_deleted: runtime_deleted_count,
        ..cleanup_run
    };
    update_cleanup_run(db, &cleanup_run).await?;

    Ok(CleanupControllerReport {
        cleanup_run,
        expired,
        archived_sandboxes_deleted: archived_deleted_count,
        archived_sandboxes: archived.deleted,
        archived_sandboxes_skipped: archived.skipped,
        runtime_resources_deleted,
    })
}

pub(crate) async fn mark_cleanup_run_failed(
    db: &Database,
    cleanup_run: &CleanupRun,
    expired_snapshots: u64,
    archived_sandboxes_deleted: u64,
    archived_sandboxes_skipped: u64,
    runtime_resources_deleted: u64,
    error: &ApiError,
) {
    let failed = CleanupRun {
        status: CleanupRunStatus::Failed,
        finished_at: Some(Utc::now()),
        expired_snapshots,
        archived_sandboxes_deleted,
        archived_sandboxes_skipped,
        runtime_resources_deleted,
        error: Some(format!("{error:?}")),
        ..cleanup_run.clone()
    };
    if let Err(update_error) = update_cleanup_run(db, &failed).await {
        tracing::warn!(?update_error, "failed to mark cleanup run failed");
    }
}

pub(crate) async fn cleanup_archived_sandboxes(
    db: &Database,
) -> Result<ArchivedSandboxCleanupResult, ApiError> {
    // Oldest first, bounded batch. Deletion does not need allowlist rules, so
    // skip network hydration that every archived row previously paid for.
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, runtime_profile, execution_class,
                created_at, updated_at, ttl_seconds, max_lifetime_seconds, idle_ttl_seconds, last_activity_at, parent_snapshot_id
         from sandboxes
         where state = 'archived' and ttl_seconds is not null
         order by updated_at asc, id asc
         limit {}",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(ARCHIVED_SANDBOX_CLEANUP_BATCH_SIZE)
        .fetch_all(db.read_pool())
        .await?;

    let now = Utc::now();
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    let mut runtime_resources_deleted = Vec::new();
    for row in rows {
        let sandbox = row_to_sandbox(row)?;
        let Some(ttl_seconds) = sandbox.ttl_seconds else {
            continue;
        };
        let expires_at = expires_at_from_ttl(sandbox.updated_at, Some(ttl_seconds))?;
        if expires_at.is_some_and(|expires_at| expires_at > now) {
            continue;
        }
        // Cheap pool-level pre-check: skip opening a transaction at all for
        // the common case of a sandbox that's obviously still referenced.
        // This is purely an optimization -- it is *not* what makes the
        // delete below safe, since the state it observes can be stale by
        // the time the transaction underneath actually deletes the row.
        if sandbox_snapshot_is_referenced(db, sandbox.id).await? {
            skipped.push(ArchivedSandboxCleanupSkip {
                sandbox,
                reason: "sandbox has active snapshots referenced by restores".to_string(),
            });
            continue;
        }
        let mut tx = db.pool.begin().await?;
        let cleaned = async {
            // A normal stop completion may already have retired these rows
            // before the archived record reaches its TTL. Include those
            // durable records in both the cleanup evidence and the tombstone
            // input so retention cleanup remains an auditable finalization
            // step even when provider teardown was eagerly fenced earlier.
            let mut deleted_resources =
                list_runtime_resources_for_sandbox_on_connection(db, &mut tx, sandbox.id)
                    .await?
                    .into_iter()
                    .filter(|resource| {
                        matches!(
                            resource.status,
                            RuntimeResourceStatus::Deleted | RuntimeResourceStatus::Destroyed
                        )
                    })
                    .collect::<Vec<_>>();
            let newly_deleted = mark_runtime_resources_deleted_for_sandbox_on_connection(
                db,
                &mut tx,
                sandbox.id,
                // The sandbox row itself is about to be deleted, so nothing may
                // be left pointing at it -- including its snapshot resources.
                RuntimeResourceGeneration::All,
                now,
                "archived sandbox deleted during cleanup",
            )
            .await?;
            let mut resources_to_tombstone = deleted_resources.clone();
            resources_to_tombstone.extend(newly_deleted.iter().cloned());
            for resource in &resources_to_tombstone {
                insert_runtime_resource_tombstone_on_connection(db, &mut tx, resource, now).await?;
            }
            deleted_resources.extend(newly_deleted);
            // Authoritative re-check: run it on the *same* connection as the
            // delete, as late as possible, right before the delete itself.
            // The pre-check above runs against the pool before this
            // transaction even opens, so a concurrent fork (`create_snapshot`
            // -> `insert_snapshot_on_connection`, which inserts a
            // `snapshot_restore_sources` row referencing this sandbox) can
            // land in the gap between that pre-check and this transaction's
            // commit -- the parent would otherwise get deleted anyway. Doing
            // the check again here, inside the transaction that performs the
            // delete, reads a consistent view immediately before the
            // mutation instead of a possibly-stale one from before the
            // transaction started.
            if sandbox_snapshot_is_referenced_on_connection(db, &mut tx, sandbox.id).await? {
                return Ok(CleanupOutcome::Referenced);
            }
            let sql = format!(
                "delete from sandboxes where id = {} and state = 'archived'",
                db.placeholder(1)
            );
            let result = sqlx::query(&sql)
                .bind(sandbox.id.to_string())
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() == 0 {
                return Ok(CleanupOutcome::NotFound);
            }
            Ok(CleanupOutcome::Deleted(deleted_resources))
        }
        .await;
        match cleaned {
            Ok(CleanupOutcome::Deleted(deleted_resources)) => {
                tx.commit().await?;
                runtime_resources_deleted.extend(deleted_resources);
                deleted.push(sandbox);
            }
            Ok(CleanupOutcome::Referenced) => {
                tx.rollback().await?;
                skipped.push(ArchivedSandboxCleanupSkip {
                    sandbox,
                    reason: "sandbox has active snapshots referenced by restores".to_string(),
                });
            }
            Ok(CleanupOutcome::NotFound) => {
                tx.rollback().await?;
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back archived sandbox cleanup");
                }
                return Err(error);
            }
        }
    }

    Ok(ArchivedSandboxCleanupResult {
        deleted,
        skipped,
        runtime_resources_deleted,
    })
}

/// Outcome of attempting to delete a single archived sandbox inside its own
/// transaction. Distinguishes "another actor already removed it" (lost race
/// with a concurrent cleanup run or manual delete -- not an error) from "a
/// reference showed up since the pool-level pre-check" (the TOCTOU this type
/// exists to make unrepresentable as a silent delete).
enum CleanupOutcome {
    Deleted(Vec<RuntimeResource>),
    Referenced,
    NotFound,
}

pub(crate) async fn sandbox_snapshot_is_referenced(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let mut connection = db.pool.acquire().await?;
    sandbox_snapshot_is_referenced_on_connection(db, &mut connection, sandbox_id).await
}

/// Same check as `sandbox_snapshot_is_referenced`, but run on a caller-owned
/// connection so it can be issued from inside an in-flight transaction (see
/// `cleanup_archived_sandboxes`) instead of against the pool.
pub(crate) async fn sandbox_snapshot_is_referenced_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select 1
           from snapshots
           join sandboxes on sandboxes.parent_snapshot_id = snapshots.id
          where snapshots.sandbox_id = {}
         union all
         select 1
           from snapshot_restore_sources
          where source_sandbox_id = {}
            and status in ('pending', 'ready')
            and (expires_at is null or expires_at > {})
         limit 1",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(chrono::Utc::now().to_rfc3339())
        .fetch_optional(&mut *connection)
        .await?;
    Ok(row.is_some())
}
