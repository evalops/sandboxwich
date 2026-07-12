use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::jobs::*;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::reconcile::*;
use crate::rows::*;
use crate::state::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

pub(crate) async fn claim_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ClaimLeaseRequest>,
) -> Result<Json<ClaimLeaseResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    // GH-64: guest-facing route -- only a token scoped to exactly this
    // worker may claim on its behalf; tenant-wide tokens are rejected.
    ensure_worker_scope(&ctx, worker_id)?;
    if let Some(sandbox_id) = ctx.guest_sandbox_id()
        && (request.sandbox_id != Some(sandbox_id)
            || request.kinds.as_deref() != Some(&[JobKind::RunCommand]))
    {
        return Err(ApiError::bad_request(
            "guest lease claims must specify their own sandbox_id and only run_command kind",
        ));
    }
    let worker = ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let operation_id = headers
        .get("idempotency-key")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::bad_request("invalid idempotency-key"))
        })
        .transpose()?
        .map(|value| {
            Uuid::parse_str(value)
                .map_err(|_| ApiError::bad_request("idempotency-key must be a UUID"))
        })
        .transpose()?;
    let requested_job_id = headers
        .get("x-sandboxwich-job-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::bad_request("invalid x-sandboxwich-job-id"))
        })
        .transpose()?
        .map(|value| {
            Uuid::parse_str(value)
                .map(JobId)
                .map_err(|_| ApiError::bad_request("x-sandboxwich-job-id must be a UUID"))
        })
        .transpose()?;
    if let Some(operation_id) = operation_id
        && let Some(lease) = fetch_claim_operation(&state.db, worker_id, operation_id).await?
    {
        return Ok(Json(ClaimLeaseResponse {
            ok: true,
            lease: Some(lease),
        }));
    }
    let now = Utc::now();
    let capabilities = worker
        .capabilities
        .iter()
        .map(worker_capability_to_str)
        .collect::<Vec<_>>();
    if capabilities.is_empty() {
        return Ok(Json(ClaimLeaseResponse {
            ok: true,
            lease: None,
        }));
    }
    let mut query = state.db.query_builder(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where tenant_id = ",
    );
    query
        .push_bind(&worker.tenant_id)
        .push(" and status = 'queued' and scheduled_at <= ")
        .push_bind(now.to_rfc3339())
        .push(" and required_capability in (");
    {
        let mut required = query.separated(", ");
        for capability in capabilities {
            required.push_bind(capability);
        }
    }
    query
        .push(
            ")
           and (
             kind in ('provision_sandbox', 'run_prompt', 'stop_sandbox')
             or exists (
               select 1 from sandbox_placements p
               where p.sandbox_id = coalesce(jobs.sandbox_id, jobs.parent_sandbox_id)
                 and (p.worker_id = ",
        )
        .push_bind(worker.id.to_string())
        .push(" or (p.provider = ")
        .push_bind(&worker.provider)
        .push(" and (p.cluster is null or p.cluster = ")
        .push_bind(worker.labels.get("cluster").cloned().unwrap_or_default())
        .push(
            ")))
             )
           )",
        );
    if let Some(job_id) = requested_job_id {
        query.push(" and id = ").push_bind(job_id.to_string());
    }
    // Guest-facing scoping (advisory, see the doc comment on
    // `ClaimLeaseRequest::sandbox_id`): a caller such as `sandboxwich-agent`'s
    // daemon loop can narrow claims to the sandbox and job kinds it actually
    // handles, so a job destined for a different sandbox -- or a job kind the
    // caller isn't equipped to execute -- is never handed to it in the first
    // place. Matches any of the job's own sandbox, fork parent, or fork child
    // columns so the filter also makes sense for provision/fork jobs.
    if let Some(sandbox_id) = request.sandbox_id {
        query
            .push(" and (jobs.sandbox_id = ")
            .push_bind(sandbox_id.to_string())
            .push(" or jobs.parent_sandbox_id = ")
            .push_bind(sandbox_id.to_string())
            .push(" or jobs.child_sandbox_id = ")
            .push_bind(sandbox_id.to_string())
            .push(")");
    }
    if let Some(kinds) = request.kinds.as_deref() {
        if kinds.is_empty() {
            // An explicit empty kinds filter can never match anything; short-circuit
            // rather than emit `and kind in ()`, which is invalid SQL.
            return Ok(Json(ClaimLeaseResponse {
                ok: true,
                lease: None,
            }));
        }
        query.push(" and kind in (");
        {
            let mut separated = query.separated(", ");
            for kind in kinds {
                separated.push_bind(job_kind_to_str(kind));
            }
        }
        query.push(")");
    }
    query.push(
        "
         order by priority desc, scheduled_at asc, created_at asc, id asc
         limit 25",
    );
    let rows = query.build().fetch_all(&state.db.pool).await?;

    for row in rows {
        let job = row_to_job(row)?;
        // Defense in depth: SQL is the efficient scheduling filter, but keep the typed
        // capability check at the claim boundary so a future query refactor cannot lease
        // work to an incompatible worker.
        if !worker.capabilities.contains(&job.required_capability) {
            continue;
        }
        // Defense in depth: re-check the caller's sandbox/kind filters (if any) against
        // the typed job for the same reason as the capability check above.
        if let Some(sandbox_id) = request.sandbox_id
            && !job_matches_sandbox(&job, sandbox_id)
        {
            continue;
        }
        if let Some(kinds) = request.kinds.as_deref()
            && !kinds.contains(&job.kind)
        {
            continue;
        }
        if let Some(lease) = try_claim_job(
            &state.db,
            &worker,
            &job,
            request.lease_seconds,
            operation_id,
        )
        .await?
        {
            return Ok(Json(ClaimLeaseResponse {
                ok: true,
                lease: Some(lease),
            }));
        }
    }

    Ok(Json(ClaimLeaseResponse {
        ok: true,
        lease: None,
    }))
}

/// True if `job` references `sandbox_id` as its own sandbox, its fork parent, or its
/// fork child. Used to re-check a claim request's `sandbox_id` filter against the
/// typed job, mirroring the SQL `where` clause built in `claim_lease`.
fn job_matches_sandbox(job: &Job, sandbox_id: SandboxId) -> bool {
    sandbox_id_from_job(job).ok() == Some(sandbox_id)
        || parent_sandbox_id_from_job(job).ok() == Some(sandbox_id)
        || child_sandbox_id_from_job(job).ok() == Some(sandbox_id)
}

async fn fetch_claim_operation(
    db: &Database,
    worker_id: WorkerId,
    operation_id: Uuid,
) -> Result<Option<JobLease>, ApiError> {
    let sql = format!(
        "select lease_id from lease_claim_operations where worker_id = {} and operation_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .bind(operation_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    match row {
        Some(row) => {
            let lease_id: String = row.try_get("lease_id")?;
            Ok(Some(
                fetch_lease(db, LeaseId(parse_uuid(&lease_id)?)).await?,
            ))
        }
        None => Ok(None),
    }
}

pub(crate) async fn renew_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<RenewLeaseRequest>,
) -> Result<Json<LeaseResponse>, ApiError> {
    let lease_id = LeaseId(lease_id);
    // GH-64: guest-facing route -- only the worker holding this lease may
    // renew it; tenant-wide tokens are rejected.
    ensure_lease_worker_scope(&state.db, lease_id, &ctx).await?;
    let now = Utc::now();
    let expires_at =
        now + chrono::Duration::seconds(effective_lease_seconds(request.lease_seconds) as i64);
    let sql = format!(
        "update job_leases
         set expires_at = {}
         where id = {} and status = 'active'",
        state.db.placeholder(1),
        state.db.placeholder(2)
    );
    let result = sqlx::query(&sql)
        .bind(expires_at.to_rfc3339())
        .bind(lease_id.to_string())
        .execute(&state.db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("active lease not found"));
    }

    let lease = fetch_lease(&state.db, lease_id).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

pub(crate) async fn update_provisioning_stage(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<ProvisioningStageUpdateRequest>,
) -> Result<Json<ProvisioningOperationResponse>, ApiError> {
    let lease_id = LeaseId(lease_id);
    ensure_lease_worker_scope(&state.db, lease_id, &ctx).await?;
    let operation = update_provisioning_stage_in_transaction(&state.db, lease_id, request).await?;
    Ok(Json(ProvisioningOperationResponse {
        ok: true,
        operation,
    }))
}

pub(crate) async fn update_provisioning_stage_in_transaction(
    db: &Database,
    lease_id: LeaseId,
    request: ProvisioningStageUpdateRequest,
) -> Result<ProvisioningOperation, ApiError> {
    if request.attempt_count < 1 {
        return Err(ApiError::bad_request("attempt_count must be positive"));
    }
    if request
        .last_error
        .as_ref()
        .is_some_and(|error| error.len() > 2048)
    {
        return Err(ApiError::bad_request(
            "last_error must not exceed 2048 bytes",
        ));
    }
    let identity_field_count = [
        request.resource_kind.is_some(),
        request.resource_namespace.is_some(),
        request.resource_name.is_some(),
        request.resource_uid.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if identity_field_count != 0 && identity_field_count != 4 {
        return Err(ApiError::bad_request(
            "resource identity requires kind, namespace, name, and uid",
        ));
    }

    let mut tx = db.pool.begin().await?;
    let updated = async {
        let lease = fetch_lease_on_connection(db, &mut tx, lease_id).await?;
        let now = Utc::now();
        if lease.status != LeaseStatus::Active || lease.expires_at <= now {
            return Err(ApiError::conflict_code(
                "lease_not_active",
                "provisioning progress requires an active lease",
            ));
        }
        if lease.job.kind != JobKind::ProvisionSandbox {
            return Err(ApiError::bad_request(
                "provisioning progress requires a provision_sandbox lease",
            ));
        }
        if request.attempt_count != lease.attempt {
            return Err(ApiError::conflict_code(
                "provisioning_operation_fenced",
                "request attempt does not match the active lease attempt",
            ));
        }
        let sandbox_id = sandbox_id_from_job(&lease.job)?;

        let existing_sql = format!(
            "select lease_id, lease_attempt, stage, stage_index, resource_kind,
                    resource_namespace, resource_name, resource_uid, observed_generation,
                    attempt_count, last_error_class, last_error_code, last_error, updated_at
             from provisioning_operations where sandbox_id = {}",
            db.placeholder(1)
        );
        let existing = sqlx::query(&existing_sql)
            .bind(sandbox_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = existing.as_ref() {
            let existing_attempt: i64 = row.try_get("lease_attempt")?;
            let existing_stage_index: i64 = row.try_get("stage_index")?;
            if lease.attempt < existing_attempt {
                return Err(ApiError::conflict_code(
                    "provisioning_operation_fenced",
                    "a newer lease attempt owns this provisioning operation",
                ));
            }
            if lease.attempt == existing_attempt
                && i64::from(request.stage.ordinal()) < existing_stage_index
            {
                return Err(ApiError::conflict_code(
                    "provisioning_stage_regression",
                    "provisioning stage cannot move backward",
                ));
            }

            if let (
                Some(resource_kind),
                Some(resource_namespace),
                Some(resource_name),
                Some(resource_uid),
            ) = (
                request.resource_kind.as_ref(),
                request.resource_namespace.as_deref(),
                request.resource_name.as_deref(),
                request.resource_uid.as_deref(),
            ) {
                let resource_sql = format!(
                    "select resource_uid, observed_generation
                     from provisioning_operation_resources
                     where sandbox_id = {} and stage = {} and resource_kind = {}
                       and resource_namespace = {} and resource_name = {}",
                    db.placeholder(1),
                    db.placeholder(2),
                    db.placeholder(3),
                    db.placeholder(4),
                    db.placeholder(5),
                );
                if let Some(resource) = sqlx::query(&resource_sql)
                    .bind(sandbox_id.to_string())
                    .bind(request.stage.as_db_str())
                    .bind(resource_kind.as_db_str())
                    .bind(resource_namespace)
                    .bind(resource_name)
                    .fetch_optional(&mut *tx)
                    .await?
                {
                    let stored_uid: String = resource.try_get("resource_uid")?;
                    let stored_generation: Option<i64> =
                        resource.try_get("observed_generation")?;
                    if stored_uid != resource_uid
                        || stored_generation != request.observed_generation
                    {
                        return Err(ApiError::conflict_code(
                            "provisioning_resource_identity_conflict",
                            "durable resource identity cannot change within a stage",
                        ));
                    }
                    if lease.attempt == existing_attempt
                        && i64::from(request.stage.ordinal()) == existing_stage_index
                    {
                        return provisioning_operation_from_row(sandbox_id, row);
                    }
                }
            } else if lease.attempt == existing_attempt
                && i64::from(request.stage.ordinal()) == existing_stage_index
            {
                let stored_error_class: Option<String> = row.try_get("last_error_class")?;
                let requested_error_class = request
                    .last_error_class
                    .as_ref()
                    .map(DbVariant::as_db_str);
                let stored_error: Option<String> = row.try_get("last_error")?;
                let stored_error_code: Option<String> = row.try_get("last_error_code")?;
                if stored_error_class.as_deref() == requested_error_class
                    && stored_error_code == request.last_error_code
                    && stored_error == request.last_error
                {
                    return provisioning_operation_from_row(sandbox_id, row);
                }
            }
        }

        let sql = format!(
            "insert into provisioning_operations
             (sandbox_id, lease_id, lease_attempt, stage, stage_index, resource_kind,
              resource_namespace, resource_name, resource_uid, observed_generation,
              attempt_count, last_error_class, last_error_code, last_error, updated_at)
             select {}
             where exists (
               select 1 from job_leases
               where id = {} and status = 'active' and attempt = {} and expires_at > {}
             )
             on conflict (sandbox_id) do update set
               lease_id = excluded.lease_id,
               lease_attempt = excluded.lease_attempt,
               stage = case when excluded.stage_index > provisioning_operations.stage_index
                            then excluded.stage else provisioning_operations.stage end,
               stage_index = case when excluded.stage_index > provisioning_operations.stage_index
                                  then excluded.stage_index else provisioning_operations.stage_index end,
               resource_kind = case when excluded.stage_index >= provisioning_operations.stage_index
                                    then excluded.resource_kind else provisioning_operations.resource_kind end,
               resource_namespace = case when excluded.stage_index >= provisioning_operations.stage_index
                                         then excluded.resource_namespace else provisioning_operations.resource_namespace end,
               resource_name = case when excluded.stage_index >= provisioning_operations.stage_index
                                    then excluded.resource_name else provisioning_operations.resource_name end,
               resource_uid = case when excluded.stage_index >= provisioning_operations.stage_index
                                   then excluded.resource_uid else provisioning_operations.resource_uid end,
               observed_generation = case when excluded.stage_index >= provisioning_operations.stage_index
                                          then excluded.observed_generation else provisioning_operations.observed_generation end,
               attempt_count = excluded.attempt_count,
               last_error_class = excluded.last_error_class,
               last_error_code = excluded.last_error_code,
               last_error = excluded.last_error,
               updated_at = excluded.updated_at
             where (provisioning_operations.lease_attempt < excluded.lease_attempt
                or (provisioning_operations.lease_attempt = excluded.lease_attempt
                    and provisioning_operations.stage_index <= excluded.stage_index))
               and exists (
                 select 1 from job_leases
                 where id = {} and status = 'active' and attempt = {} and expires_at > {}
               )",
            (1..=15)
                .map(|index| db.placeholder(index))
                .collect::<Vec<_>>()
                .join(", "),
            db.placeholder(16),
            db.placeholder(17),
            db.placeholder(18),
            db.placeholder(19),
            db.placeholder(20),
            db.placeholder(21),
        );
        let result = sqlx::query(&sql)
            .bind(sandbox_id.to_string())
            .bind(lease.id.to_string())
            .bind(lease.attempt)
            .bind(request.stage.as_db_str())
            .bind(i64::from(request.stage.ordinal()))
            .bind(request.resource_kind.as_ref().map(DbVariant::as_db_str))
            .bind(request.resource_namespace.as_deref())
            .bind(request.resource_name.as_deref())
            .bind(request.resource_uid.as_deref())
            .bind(request.observed_generation)
            .bind(request.attempt_count)
            .bind(request.last_error_class.as_ref().map(DbVariant::as_db_str))
            .bind(request.last_error_code.as_deref())
            .bind(request.last_error.as_deref())
            .bind(now.to_rfc3339())
            .bind(lease.id.to_string())
            .bind(lease.attempt)
            .bind(now.to_rfc3339())
            .bind(lease.id.to_string())
            .bind(lease.attempt)
            .bind(now.to_rfc3339())
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::conflict_code(
                "provisioning_operation_fenced",
                "provisioning operation changed concurrently",
            ));
        }

        if let (
            Some(resource_kind),
            Some(resource_namespace),
            Some(resource_name),
            Some(resource_uid),
        ) = (
            request.resource_kind.as_ref(),
            request.resource_namespace.as_deref(),
            request.resource_name.as_deref(),
            request.resource_uid.as_deref(),
        ) {
            let resource_sql = format!(
                "insert into provisioning_operation_resources
                 (sandbox_id, stage, resource_kind, resource_namespace, resource_name,
                  resource_uid, observed_generation, updated_at)
                 values ({}) on conflict do nothing",
                (1..=8)
                    .map(|index| db.placeholder(index))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            sqlx::query(&resource_sql)
                .bind(sandbox_id.to_string())
                .bind(request.stage.as_db_str())
                .bind(resource_kind.as_db_str())
                .bind(resource_namespace)
                .bind(resource_name)
                .bind(resource_uid)
                .bind(request.observed_generation)
                .bind(now.to_rfc3339())
                .execute(&mut *tx)
                .await?;
            let verify_sql = format!(
                "select resource_uid, observed_generation
                 from provisioning_operation_resources
                 where sandbox_id = {} and stage = {} and resource_kind = {}
                   and resource_namespace = {} and resource_name = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4),
                db.placeholder(5),
            );
            let stored = sqlx::query(&verify_sql)
                .bind(sandbox_id.to_string())
                .bind(request.stage.as_db_str())
                .bind(resource_kind.as_db_str())
                .bind(resource_namespace)
                .bind(resource_name)
                .fetch_one(&mut *tx)
                .await?;
            let stored_uid: String = stored.try_get("resource_uid")?;
            let stored_generation: Option<i64> = stored.try_get("observed_generation")?;
            if stored_uid != resource_uid || stored_generation != request.observed_generation {
                return Err(ApiError::conflict_code(
                    "provisioning_resource_identity_conflict",
                    "durable resource identity changed concurrently",
                ));
            }
        }

        let row = sqlx::query(&existing_sql)
            .bind(sandbox_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        provisioning_operation_from_row(sandbox_id, &row)
    }
    .await;

    match updated {
        Ok(operation) => {
            tx.commit().await?;
            Ok(operation)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::error!(%rollback_error, "failed to roll back provisioning stage update");
            }
            Err(error)
        }
    }
}

fn provisioning_operation_from_row(
    sandbox_id: SandboxId,
    row: &sqlx::any::AnyRow,
) -> Result<ProvisioningOperation, ApiError> {
    let lease_id: String = row.try_get("lease_id")?;
    let stage: String = row.try_get("stage")?;
    let resource_kind: Option<String> = row.try_get("resource_kind")?;
    let last_error_class: Option<String> = row.try_get("last_error_class")?;
    let updated_at: String = row.try_get("updated_at")?;
    Ok(ProvisioningOperation {
        sandbox_id,
        lease_id: LeaseId(parse_uuid(&lease_id)?),
        lease_attempt: row.try_get("lease_attempt")?,
        stage: ProvisioningStage::parse_db_str(&stage)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        resource_kind: resource_kind
            .map(|value| RuntimeResourceKind::parse_db_str(&value))
            .transpose()
            .map_err(|error| ApiError::internal(error.to_string()))?,
        resource_namespace: row.try_get("resource_namespace")?,
        resource_name: row.try_get("resource_name")?,
        resource_uid: row.try_get("resource_uid")?,
        observed_generation: row.try_get("observed_generation")?,
        attempt_count: row.try_get("attempt_count")?,
        last_error_class: last_error_class
            .map(|value| ProvisioningErrorClass::parse_db_str(&value))
            .transpose()
            .map_err(|error| ApiError::internal(error.to_string()))?,
        last_error_code: row.try_get("last_error_code")?,
        last_error: row.try_get("last_error")?,
        updated_at: parse_timestamp(&updated_at)?,
    })
}

pub(crate) async fn append_lease_output(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<AppendCommandOutputRequest>,
) -> Result<Json<CommandOutputChunkResponse>, ApiError> {
    if request.chunk.is_empty() {
        return Err(ApiError::bad_request(
            "command output chunk cannot be empty",
        ));
    }
    // GH-64: guest-facing route -- only the worker holding this lease may
    // append output for it; tenant-wide tokens are rejected.
    let lease = ensure_lease_worker_scope(&state.db, LeaseId(lease_id), &ctx).await?;
    if lease.status != LeaseStatus::Active {
        return Err(ApiError::bad_request("lease is not active"));
    }
    if lease.job.kind != JobKind::RunCommand {
        return Err(ApiError::bad_request(
            "lease does not belong to a run command job",
        ));
    }
    let command_id = command_id_from_job(&lease.job)?;
    let sandbox_id = sandbox_id_from_job(&lease.job)?;
    let operation_id = headers
        .get("idempotency-key")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::bad_request("invalid idempotency-key"))
        })
        .transpose()?
        .map(|value| {
            Uuid::parse_str(value)
                .map_err(|_| ApiError::bad_request("idempotency-key must be a UUID"))
        })
        .transpose()?;
    let chunk = append_command_output_chunk(
        &state.db,
        command_id,
        sandbox_id,
        request.stream,
        request.chunk,
        request.annotations,
        operation_id.map(|id| (LeaseId(lease_id), id)),
    )
    .await?;
    Ok(Json(CommandOutputChunkResponse { ok: true, chunk }))
}

pub(crate) async fn complete_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<CompleteLeaseRequest>,
) -> Result<Json<LeaseResponse>, ApiError> {
    let lease_id = LeaseId(lease_id);
    // GH-64: guest-facing route -- only the worker holding this lease may
    // complete it; tenant-wide tokens are rejected.
    ensure_lease_worker_scope(&state.db, lease_id, &ctx).await?;
    let result = request
        .result
        .ok_or_else(|| ApiError::bad_request("completion result is required"))?;
    let lease = complete_lease_in_transaction(&state.db, lease_id, result).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

pub(crate) async fn complete_lease_in_transaction(
    db: &Database,
    lease_id: LeaseId,
    result: WorkerJobResult,
) -> Result<JobLease, ApiError> {
    let mut tx = db.pool.begin().await?;

    let completed = async {
        let lease = fetch_lease_on_connection(db, &mut tx, lease_id).await?;
        if lease.status == LeaseStatus::Completed {
            return Ok(lease);
        }
        if lease.status != LeaseStatus::Active {
            return Err(ApiError::bad_request(
                "lease is already terminal with a different outcome",
            ));
        }

        let now = Utc::now();
        complete_active_lease_on_connection(db, &mut tx, lease_id, now).await?;
        apply_completed_job_on_connection(db, &mut tx, &lease.job, result).await?;
        update_job_status_on_connection(db, &mut tx, lease.job_id, JobStatus::Succeeded, None, now)
            .await?;

        fetch_lease_on_connection(db, &mut tx, lease_id).await
    }
    .await;

    match completed {
        Ok(lease) => {
            tx.commit().await?;
            Ok(lease)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::error!(%rollback_error, "failed to roll back lease completion");
            }
            Err(error)
        }
    }
}

pub(crate) async fn fail_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<FailLeaseRequest>,
) -> Result<Json<LeaseResponse>, ApiError> {
    if request.error.trim().is_empty() {
        return Err(ApiError::bad_request("error is required"));
    }
    let lease_id = LeaseId(lease_id);
    // GH-64: guest-facing route -- only the worker holding this lease may
    // fail it; tenant-wide tokens are rejected.
    ensure_lease_worker_scope(&state.db, lease_id, &ctx).await?;
    let lease =
        fail_lease_in_transaction(&state.db, lease_id, request.retry, &request.error).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

pub(crate) async fn fail_lease_in_transaction(
    db: &Database,
    lease_id: LeaseId,
    retry_requested: bool,
    error: &str,
) -> Result<JobLease, ApiError> {
    let mut tx = db.pool.begin().await?;

    let failed = async {
        let lease = fetch_lease_on_connection(db, &mut tx, lease_id).await?;
        if lease.status == LeaseStatus::Failed {
            return Ok(lease);
        }
        if lease.status != LeaseStatus::Active {
            return Err(ApiError::bad_request(
                "lease is already terminal with a different outcome",
            ));
        }

        let now = Utc::now();
        fail_active_lease_on_connection(db, &mut tx, lease_id, now, error).await?;
        let retry = retry_requested && lease.job.attempts < lease.job.max_attempts;
        if retry {
            update_job_status_on_connection(
                db,
                &mut tx,
                lease.job_id,
                JobStatus::Queued,
                Some(error),
                now,
            )
            .await?;
            apply_retryable_job_on_connection(db, &mut tx, &lease.job, error).await?;
        } else {
            update_job_status_on_connection(
                db,
                &mut tx,
                lease.job_id,
                JobStatus::Failed,
                Some(error),
                now,
            )
            .await?;
            apply_failed_job_on_connection(db, &mut tx, &lease.job, error).await?;
        }

        fetch_lease_on_connection(db, &mut tx, lease_id).await
    }
    .await;

    match failed {
        Ok(lease) => {
            tx.commit().await?;
            Ok(lease)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back lease failure");
            }
            Err(error)
        }
    }
}

pub(crate) async fn insert_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease: &JobLease,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into job_leases
         (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
         values ({})",
        db.placeholders(9)
    );
    sqlx::query(&sql)
        .bind(lease.id.to_string())
        .bind(lease.job_id.to_string())
        .bind(lease.worker_id.to_string())
        .bind(lease_status_to_str(&lease.status))
        .bind(lease.attempt)
        .bind(lease.leased_at.to_rfc3339())
        .bind(lease.expires_at.to_rfc3339())
        .bind(lease.completed_at.map(|time| time.to_rfc3339()))
        .bind(&lease.error)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn expire_due_leases(db: &Database) -> Result<(), ApiError> {
    // At the default one-second interval this can catch up 60,000 leases per
    // minute while bounding each tick. Deployments that increase
    // SANDBOXWICH_SWEEP_INTERVAL_MS should tune the interval against their
    // maximum concurrent lease population.
    const LEASE_EXPIRY_BATCH_SIZE: u32 = 1_000;
    let now = Utc::now();
    let sql = format!(
        "select id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error
         from job_leases
         where status = 'active' and expires_at <= {}
         order by expires_at asc, id asc
         limit {LEASE_EXPIRY_BATCH_SIZE}",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(now.to_rfc3339())
        .fetch_all(&db.pool)
        .await?;

    for row in rows {
        let lease = row_to_lease_without_job(row)?;
        expire_lease_if_still_active(db, lease.id, now).await?;
    }

    Ok(())
}

/// Atomically transitions a single lease from `active` to `expired` and, only if
/// this caller actually won that transition, applies the job re-queue/fail side
/// effects. Concurrent callers racing on the same expired lease (e.g. multiple
/// requests hitting `claim_lease`/`list_jobs`/`get_capacity`, or overlapping
/// background sweeps) must not both observe the lease as active and both emit
/// side effects.
pub(crate) async fn expire_lease_if_still_active(
    db: &Database,
    lease_id: LeaseId,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let mut tx = db.pool.begin().await?;
    let outcome = async {
        let won_transition =
            expire_active_lease_on_connection(db, &mut tx, lease_id, now, "lease expired").await?;
        if !won_transition {
            // Another caller already expired this lease and applied its side
            // effects; nothing left to do.
            return Ok(());
        }

        let lease = fetch_lease_on_connection(db, &mut tx, lease_id).await?;
        let job = lease.job;
        let next_status = if job.attempts >= job.max_attempts {
            JobStatus::Dead
        } else {
            JobStatus::Queued
        };
        update_job_status_on_connection(
            db,
            &mut tx,
            job.id,
            next_status,
            Some("lease expired"),
            now,
        )
        .await?;
        if job.attempts >= job.max_attempts {
            apply_failed_job_on_connection(db, &mut tx, &job, "lease expired").await?;
        } else {
            apply_retryable_job_on_connection(db, &mut tx, &job, "lease expired").await?;
        }
        Ok(())
    }
    .await;

    match outcome {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back lease expiration");
            }
            Err(error)
        }
    }
}

/// Guarded, atomic `active` -> `expired` transition. Returns `true` only if this
/// call performed the transition (`rows_affected() == 1`); returns `false` if the
/// lease was already expired/completed/failed by another caller, in which case
/// no further side effects should run.
///
/// The `expires_at <= completed_at` guard closes a renewal-vs-expiry race: the
/// sweep that calls this function reads candidate leases (and their
/// `expires_at`) on the pool *before* opening this transaction, so a
/// concurrent `renew_lease` call can commit a later `expires_at` in between
/// the sweep's SELECT and this UPDATE. Without re-checking `expires_at` here,
/// that freshly-renewed lease would still be expired, its job re-queued, and
/// two workers would end up running the same job. Re-checking `expires_at`
/// against the *current* row (not the sweep's stale in-memory copy) means a
/// renewal that lands first makes this UPDATE affect zero rows, so
/// `won_transition` is `false` and no side effects run.
pub(crate) async fn expire_active_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
    completed_at: DateTime<Utc>,
    error: &str,
) -> Result<bool, ApiError> {
    let sql = format!(
        "update job_leases
         set status = {}, completed_at = {}, error = {}
         where id = {} and status = 'active' and expires_at <= {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5)
    );
    let result = sqlx::query(&sql)
        .bind(lease_status_to_str(&LeaseStatus::Expired))
        .bind(completed_at.to_rfc3339())
        .bind(error)
        .bind(lease_id.to_string())
        .bind(completed_at.to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn fetch_lease(db: &Database, lease_id: LeaseId) -> Result<JobLease, ApiError> {
    let sql = format!(
        "select id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error
         from job_leases
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("lease not found"))?;
    let lease = row_to_lease_without_job(row)?;
    let job = fetch_job(db, lease.job_id).await?;
    Ok(JobLease { job, ..lease })
}

pub(crate) async fn fetch_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
) -> Result<JobLease, ApiError> {
    let sql = format!(
        "select id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error
         from job_leases
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("lease not found"))?;
    let lease = row_to_lease_without_job(row)?;
    let job = fetch_job_on_connection(db, connection, lease.job_id).await?;
    Ok(JobLease { job, ..lease })
}

pub(crate) async fn complete_active_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
    completed_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update job_leases
         set status = {}, completed_at = {}, error = {}
         where id = {} and status = 'active'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let result = sqlx::query(&sql)
        .bind(lease_status_to_str(&LeaseStatus::Completed))
        .bind(completed_at.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(lease_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::bad_request("lease is not active"));
    }
    Ok(())
}

pub(crate) async fn fail_active_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
    completed_at: DateTime<Utc>,
    error: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "update job_leases
         set status = {}, completed_at = {}, error = {}
         where id = {} and status = 'active'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let result = sqlx::query(&sql)
        .bind(lease_status_to_str(&LeaseStatus::Failed))
        .bind(completed_at.to_rfc3339())
        .bind(error)
        .bind(lease_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::bad_request("lease is not active"));
    }
    Ok(())
}

pub(crate) async fn update_job_status_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job_id: JobId,
    status: JobStatus,
    error: Option<&str>,
    updated_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update jobs
         set status = {}, last_error = {}, updated_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(job_status_to_str(&status))
        .bind(error)
        .bind(updated_at.to_rfc3339())
        .bind(job_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn finish_command_from_lease_result_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    status: CommandStatus,
    exit_code: Option<i32>,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let sql = format!(
        "update commands
         set status = {}, exit_code = {}, finished_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(command_status_to_str(&status))
        .bind(exit_code)
        .bind(now.to_rfc3339())
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn append_completion_output_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    sandbox_id: SandboxId,
    stream: CommandOutputStream,
    chunk: &str,
) -> Result<(), ApiError> {
    if chunk.is_empty() {
        return Ok(());
    }
    let current =
        command_output_for_stream_on_connection(db, connection, command_id, &stream).await?;
    if current == chunk {
        return Ok(());
    }
    if let Some(suffix) = chunk.strip_prefix(&current) {
        if suffix.is_empty() {
            return Ok(());
        }
        append_command_output_chunk_on_connection(
            db,
            connection,
            command_id,
            sandbox_id,
            stream,
            suffix.to_string(),
            Vec::new(),
        )
        .await?;
        return Ok(());
    }
    replace_command_output_stream_on_connection(db, connection, command_id, &stream).await?;
    append_command_output_chunk_on_connection(
        db,
        connection,
        command_id,
        sandbox_id,
        stream,
        chunk.to_string(),
        Vec::new(),
    )
    .await?;
    Ok(())
}

pub(crate) async fn command_output_for_stream_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
) -> Result<String, ApiError> {
    let sql = format!(
        "select chunk from command_output_chunks
         where command_id = {} and stream = {}
         order by sequence asc",
        db.placeholder(1),
        db.placeholder(2)
    );
    let rows = sqlx::query(&sql)
        .bind(command_id.to_string())
        .bind(command_output_stream_to_str(stream))
        .fetch_all(&mut *connection)
        .await?;
    let mut output = String::new();
    for row in rows {
        let chunk: String = row.try_get("chunk")?;
        output.push_str(&chunk);
    }
    Ok(output)
}

pub(crate) async fn replace_command_output_stream_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
) -> Result<(), ApiError> {
    let column = stream.as_db_str();
    let delete_sql = format!(
        "delete from command_output_chunks
         where command_id = {} and stream = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&delete_sql)
        .bind(command_id.to_string())
        .bind(command_output_stream_to_str(stream))
        .execute(&mut *connection)
        .await?;

    let update_sql = format!(
        "update commands
         set {column} = ''
         where id = {}",
        db.placeholder(1)
    );
    let result = sqlx::query(&update_sql)
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("command not found"));
    }
    Ok(())
}

pub(crate) async fn apply_completed_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    result: WorkerJobResult,
) -> Result<(), ApiError> {
    match (&job.kind, result) {
        (JobKind::RunCommand, WorkerJobResult::RunCommand { result }) => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            let stdout = result.stdout.as_str();
            let stderr = result.stderr.as_str();
            // A worker completes the lease this way whenever it actually ran the
            // command to a terminal exit -- exit code 0 as well as non-zero. The
            // command's own status must reflect that outcome instead of being
            // unconditionally marked Finished: a `sandboxwich exec` whose command
            // exited 1 is a completed lease but a failed command, and callers (CI
            // gating on command status, `sandboxwich exec --wait`'s exit code)
            // need to be able to tell the two apart. `None` (no exit code at all,
            // e.g. a process killed by a signal, or a runner that could not
            // capture the code) is treated the same as non-zero: a command that
            // could not report how it finished is not a success either. The
            // missing code is persisted and emitted as an honest null -- the
            // `commands.exit_code` column and `CommandRun.exit_code` are already
            // nullable, and the failed-lease path below emits `"exitCode": null`
            // the same way -- rather than fabricating a 0 that would claim the
            // command succeeded.
            let exit_code = result.exit_code;
            let status = if exit_code == Some(0) {
                CommandStatus::Finished
            } else {
                CommandStatus::Failed
            };
            append_completion_output_on_connection(
                db,
                connection,
                command_id,
                sandbox_id,
                CommandOutputStream::Stdout,
                stdout,
            )
            .await?;
            append_completion_output_on_connection(
                db,
                connection,
                command_id,
                sandbox_id,
                CommandOutputStream::Stderr,
                stderr,
            )
            .await?;
            finish_command_from_lease_result_on_connection(
                db, connection, command_id, status, exit_code,
            )
            .await?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::CommandFinished,
                json!({
                    "commandId": command_id,
                    "exitCode": exit_code,
                    "stdout": stdout,
                    "stderr": stderr
                }),
            )
            .await?;
        }
        (JobKind::CreateSnapshot, WorkerJobResult::CreateSnapshot { handle }) => {
            let snapshot_id = snapshot_id_from_job(job)?;
            if handle.snapshot_id != snapshot_id {
                return Err(ApiError::bad_request(
                    "snapshot completion result does not match job snapshot",
                ));
            }
            mark_snapshot_ready_from_provider_handle_on_connection(
                db,
                connection,
                sandbox_id_from_job(job)?,
                handle,
            )
            .await?;
        }
        (JobKind::RunPrompt, WorkerJobResult::RunPrompt { output }) => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::PromptFinished,
                json!({
                    "promptEventId": prompt_event_id,
                    "output": output
                }),
            )
            .await?;
        }
        (JobKind::ForkSandbox, WorkerJobResult::ForkSandbox { handle }) => {
            let parent_id = parent_sandbox_id_from_job(job)?;
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            if handle.parent_sandbox_id != parent_id
                || handle.child_sandbox_id != child_id
                || handle.snapshot_id != snapshot_id
            {
                return Err(ApiError::bad_request(
                    "fork completion result does not match job payload",
                ));
            }
            upsert_provider_runtime_resources_on_connection(db, connection, &handle.resources)
                .await?;
            let next_state = SandboxState::Ready;
            set_sandbox_state_on_connection(
                db,
                connection,
                child_id,
                SandboxState::FORK_COMPLETED_LEGAL_FROM,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_ready",
                    "parentSnapshotId": snapshot_id
                }),
            )
            .await?;
        }
        (JobKind::ProvisionSandbox, WorkerJobResult::ProvisionSandbox { handle }) => {
            let sandbox_id = sandbox_id_from_job(job)?;
            if handle.sandbox_id != sandbox_id {
                return Err(ApiError::bad_request(
                    "provision completion result does not match job sandbox",
                ));
            }
            upsert_provider_runtime_resources_on_connection(db, connection, &handle.resources)
                .await?;
            let next_state = SandboxState::Ready;
            set_sandbox_state_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxState::PROVISION_COMPLETED_LEGAL_FROM,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "provision_ready",
                    "provider": handle.provider
                }),
            )
            .await?;
        }
        (JobKind::StopSandbox, WorkerJobResult::StopSandbox { sandbox_id, .. }) => {
            if sandbox_id != sandbox_id_from_job(job)? {
                return Err(ApiError::bad_request(
                    "stop completion result does not match job sandbox",
                ));
            }
            set_sandbox_state_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxState::STOP_COMPLETED_LEGAL_FROM,
                SandboxState::Archived,
                json!({"state": SandboxState::Archived, "reason": "stop_completed"}),
            )
            .await?;
        }
        (JobKind::ResumeSandbox, WorkerJobResult::ResumeSandbox { sandbox_id, .. }) => {
            if sandbox_id != sandbox_id_from_job(job)? {
                return Err(ApiError::bad_request(
                    "resume completion result does not match job sandbox",
                ));
            }
        }
        _ => {
            return Err(ApiError::bad_request(
                "completion result kind does not match job kind",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn apply_claimed_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            let sql = format!(
                "update commands
                 set status = {}
                 where id = {}",
                db.placeholder(1),
                db.placeholder(2)
            );
            sqlx::query(&sql)
                .bind(command_status_to_str(&CommandStatus::Running))
                .bind(command_id.to_string())
                .execute(&mut *connection)
                .await?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::CommandStarted,
                json!({
                    "commandId": command_id
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            update_snapshot_status_on_connection(
                db,
                connection,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Pending,
                None,
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::PromptStarted,
                json!({
                    "promptEventId": prompt_event_id
                }),
            )
            .await?;
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            let next_state = SandboxState::Provisioning;
            set_sandbox_state_on_connection(
                db,
                connection,
                child_id,
                SandboxState::FORK_CLAIMED_LEGAL_FROM,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_provisioning",
                    "parentSnapshotId": snapshot_id
                }),
            )
            .await?;
        }
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

pub(crate) async fn apply_retryable_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    error: &str,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            reset_command_for_retry_on_connection(db, connection, command_id).await?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::CommandQueued,
                json!({
                    "commandId": command_id,
                    "reason": "retry",
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            update_snapshot_status_on_connection(
                db,
                connection,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Pending,
                Some(error),
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::PromptQueued,
                json!({
                    "promptEventId": prompt_event_id,
                    "reason": "retry",
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            let next_state = SandboxState::Planning;
            set_sandbox_state_on_connection(
                db,
                connection,
                child_id,
                SandboxState::FORK_RETRIED_LEGAL_FROM,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_retry",
                    "parentSnapshotId": snapshot_id,
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

pub(crate) async fn apply_failed_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    error: &str,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            append_command_output_chunk_on_connection(
                db,
                connection,
                command_id,
                sandbox_id,
                CommandOutputStream::Stderr,
                error.to_string(),
                Vec::new(),
            )
            .await?;
            finish_command_from_lease_result_on_connection(
                db,
                connection,
                command_id,
                CommandStatus::Failed,
                None,
            )
            .await?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::CommandFinished,
                json!({
                    "commandId": command_id,
                    "exitCode": null,
                    "stderr": error
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            let snapshot_id = snapshot_id_from_job(job)?;
            update_snapshot_status_on_connection(
                db,
                connection,
                snapshot_id,
                SnapshotStatus::Failed,
                Some(error),
            )
            .await?;
            fail_sandboxes_waiting_on_snapshot_on_connection(
                db,
                connection,
                snapshot_id,
                "snapshot_failed",
                error,
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::PromptFinished,
                json!({
                    "promptEventId": prompt_event_id,
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            let next_state = SandboxState::Error;
            set_sandbox_state_on_connection(
                db,
                connection,
                child_id,
                SandboxState::FORK_FAILED_LEGAL_FROM,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_failed",
                    "parentSnapshotId": snapshot_id,
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {}
    }
    Ok(())
}
