use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::sandboxes::fetch_sandbox;
use crate::pagination::*;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DrainWorkerRequest {
    pub(crate) shutdown_id: Uuid,
    pub(crate) hard_deadline: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DrainLeaseFence {
    #[schema(value_type = Uuid)]
    pub(crate) lease_id: LeaseId,
    #[schema(value_type = Uuid)]
    pub(crate) job_id: JobId,
    pub(crate) attempt: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resolved_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DrainReceipt {
    pub(crate) shutdown_id: Uuid,
    #[schema(value_type = Uuid)]
    pub(crate) worker_id: WorkerId,
    pub(crate) hard_deadline: DateTime<Utc>,
    pub(crate) leases: Vec<DrainLeaseFence>,
}

#[derive(Clone, Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DrainWorkerResponse {
    pub(crate) ok: bool,
    #[schema(value_type = Object)]
    pub(crate) worker: Worker,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) worker_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) drain_receipt: Option<DrainReceipt>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct RuntimeResourceInventoryQuery {
    namespace: String,
    limit: Option<u32>,
    before: Option<String>,
    after: Option<String>,
}

pub(crate) async fn runtime_resource_inventory(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Query(query): Query<RuntimeResourceInventoryQuery>,
) -> Result<Json<RuntimeResourceInventoryResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    ensure_worker_scope(&ctx, worker_id)?;
    let worker = ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    if query.namespace.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource namespace is required",
        ));
    }
    let page = crate::pagination::PageParams {
        limit: query.limit,
        before: query.before,
        after: query.after,
    };
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;
    // Reconciliation is a cluster/namespace authority boundary, not a tenant
    // boundary: this worker can already list and delete every resource in the
    // shared Kubernetes namespace. Its expected inventory must therefore span
    // every tenant using that provider+cluster, or one tenant's worker would
    // misclassify another tenant's live resources as orphans.
    // Scope only through workers that can contribute live reconciliation
    // evidence. Worker logical identities are pod names and therefore grow
    // without bound across rollouts; pre-filtering the first 201 historical
    // workers made every inventory permanently incomplete once production
    // crossed that count, even when almost all rows were unrelated history.
    let scope_sql = format!(
        "select w.id, w.labels from workers w
         where w.provider = {}
           and (
             w.id = {}
             or exists (
               select 1 from job_leases jl
               join provisioning_operations po on po.lease_id = jl.id
               join provisioning_operation_resources por on por.sandbox_id = po.sandbox_id
               join sandboxes s on s.id = por.sandbox_id
               where jl.worker_id = w.id
                 and por.resource_namespace = {}
                 and s.state != 'archived'
             )
             or exists (
               select 1 from job_leases jl
               join jobs j on j.id = jl.job_id
               where jl.worker_id = w.id
                 and jl.status = 'active'
                 and j.kind = 'run_resident_process'
             )
           )
         order by w.id asc limit 201",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
    );
    let worker_cluster = worker.labels.get("cluster");
    let mut scope_worker_ids = Vec::new();
    let scope_rows = sqlx::query(&scope_sql)
        .bind(&worker.provider)
        .bind(worker.id.to_string())
        .bind(&query.namespace)
        .fetch_all(state.db.read_pool())
        .await?;
    let scope_complete = scope_rows.len() <= 200;
    for row in scope_rows {
        let labels: String = row.try_get("labels")?;
        let labels: std::collections::BTreeMap<String, String> = serde_json::from_str(&labels)?;
        if labels.get("cluster") == worker_cluster {
            scope_worker_ids.push(row.try_get::<String, _>("id")?);
        }
    }
    scope_worker_ids.truncate(200);
    if scope_worker_ids.is_empty() {
        return Err(ApiError::not_found("resource not found"));
    }
    let scope_placeholders = (1..=scope_worker_ids.len())
        .map(|index| state.db.placeholder(index))
        .collect::<Vec<_>>()
        .join(", ");
    let sandbox_sql = "select id as sandbox_id
         from sandboxes
         where state != 'archived'
         order by id asc limit 201";
    let mut sandbox_ids = sqlx::query(sandbox_sql)
        .fetch_all(state.db.read_pool())
        .await?
        .into_iter()
        .map(|row| {
            let value: String = row.try_get("sandbox_id")?;
            Ok(SandboxId(parse_uuid(&value)?))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let complete = sandbox_ids.len() <= 200 && scope_complete;
    sandbox_ids.truncate(200);
    let sql = format!(
        "select * from (
         select por.updated_at as created_at, por.resource_uid as id,
                por.sandbox_id, por.resource_kind, por.resource_namespace,
                por.resource_name, por.resource_uid, s.state,
                s.created_at as sandbox_created_at, s.updated_at as sandbox_updated_at,
                s.ttl_seconds
         from provisioning_operation_resources por
         join provisioning_operations po on po.sandbox_id = por.sandbox_id
         join job_leases jl on jl.id = po.lease_id
         join sandboxes s on s.id = por.sandbox_id
         where jl.worker_id in ({scope_placeholders})
           and por.resource_namespace = {}
           and s.state != 'archived'
         ) inventory where 1 = 1",
        state.db.placeholder(scope_worker_ids.len() + 1),
    );
    let resident_lease_sql = format!(
        "select jl.id from job_leases jl join jobs j on j.id = jl.job_id
         where jl.worker_id in ({scope_placeholders})
           and jl.status = 'active'
           and j.kind = 'run_resident_process'
         order by jl.id asc limit 201"
    );
    let mut resident_lease_query = sqlx::query(&resident_lease_sql);
    for worker_id in &scope_worker_ids {
        resident_lease_query = resident_lease_query.bind(worker_id);
    }
    let mut active_resident_lease_ids = resident_lease_query
        .fetch_all(state.db.read_pool())
        .await?
        .into_iter()
        .map(|row| {
            let value: String = row.try_get("id")?;
            Uuid::parse_str(&value).map_err(|_| ApiError::internal("invalid resident lease"))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let complete = complete && active_resident_lease_ids.len() <= 200;
    active_resident_lease_ids.truncate(200);
    let mut fixed_binds = scope_worker_ids;
    fixed_binds.push(query.namespace.clone());
    let inventory_started = Instant::now();
    let (resources, next_cursor) =
        fetch_keyset_page(&state.db, &sql, &fixed_binds, limit, &cursor, |row| {
            // Keyset columns are aliased as created_at/id on the inventory subquery.
            let page_created_at: &str = row.try_get("created_at")?;
            let page_id: &str = row.try_get("id")?;
            let page_cursor = PageCursor::new(page_created_at, page_id);
            let created_at: &str = row.try_get("sandbox_created_at")?;
            let updated_at: &str = row.try_get("sandbox_updated_at")?;
            let ttl_seconds: Option<i64> = row.try_get("ttl_seconds")?;
            let expires_at = ttl_seconds
                .map(|ttl| {
                    parse_timestamp(created_at)
                        .map(|created| created + chrono::Duration::seconds(ttl))
                })
                .transpose()?;
            let state: &str = row.try_get("state")?;
            let cleanup_deadline = if matches!(state, "archiving" | "archived") {
                Some(parse_timestamp(updated_at)?)
            } else {
                None
            };
            let resource_kind: &str = row.try_get("resource_kind")?;
            let sandbox_id: &str = row.try_get("sandbox_id")?;
            Ok((
                page_cursor,
                RuntimeResourceInventoryItem {
                    sandbox_id: SandboxId(parse_uuid(sandbox_id)?),
                    resource_kind: RuntimeResourceKind::parse_db_str(resource_kind)
                        .map_err(|_| ApiError::internal("invalid runtime resource kind"))?,
                    namespace: row.try_get("resource_namespace")?,
                    name: row.try_get("resource_name")?,
                    uid: row.try_get("resource_uid")?,
                    expires_at,
                    cleanup_deadline,
                },
            ))
        })
        .await?;
    let inventory_duration_ms = inventory_started.elapsed().as_millis() as u64;
    if inventory_duration_ms >= 500 {
        tracing::warn!(
            worker_id = %worker_id.0,
            namespace = %query.namespace,
            scope_workers = fixed_binds.len().saturating_sub(1),
            page_limit = limit,
            cursor_present = cursor.is_some(),
            rows_returned = resources.len(),
            duration_ms = inventory_duration_ms,
            "sandboxwich_runtime_inventory_slow"
        );
    } else {
        tracing::debug!(
            worker_id = %worker_id.0,
            namespace = %query.namespace,
            scope_workers = fixed_binds.len().saturating_sub(1),
            page_limit = limit,
            cursor_present = cursor.is_some(),
            rows_returned = resources.len(),
            duration_ms = inventory_duration_ms,
            "sandboxwich_runtime_inventory_completed"
        );
    }
    Ok(Json(RuntimeResourceInventoryResponse {
        ok: true,
        provider: worker.provider,
        cluster: worker.labels.get("cluster").cloned(),
        namespace: query.namespace,
        sandbox_ids,
        complete,
        resources,
        active_resident_lease_ids,
        next_cursor,
    }))
}

pub(crate) fn validate_max_concurrent_jobs(max_concurrent_jobs: u32) -> Result<u32, ApiError> {
    if max_concurrent_jobs == 0 {
        return Err(ApiError::bad_request(
            "max_concurrent_jobs must be greater than 0",
        ));
    }
    Ok(max_concurrent_jobs)
}

pub(crate) async fn mint_guest_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((worker_id, sandbox_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<MintGuestTokenRequest>,
) -> Result<Json<GuestTokenResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    let sandbox_id = SandboxId(sandbox_id);
    ensure_worker_scope(&ctx, worker_id)?;
    ensure_sandbox_worker_scope(&state.db, sandbox_id, &ctx).await?;
    let response = issue_guest_token(
        &state.db,
        &ctx.tenant_id,
        worker_id,
        sandbox_id,
        request.ttl_seconds,
        /* revalidate_lifecycle */ false,
    )
    .await?;
    Ok(Json(response))
}

/// Guest-principal refresh: re-mints a sandbox-bound guest token after
/// revalidating that the sandbox is still active, still placed on the token's
/// worker, and has not crossed its hard lifetime. Used by long-running guest
/// daemons so a 3600s default TTL is not a deterministic death mode.
pub(crate) async fn refresh_guest_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<RefreshGuestTokenRequest>,
) -> Result<Json<GuestTokenResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    let Some(bound_sandbox) = ctx.guest_sandbox_id() else {
        return Err(ApiError::unauthorized(
            "guest token refresh requires a guest bearer token",
        ));
    };
    if bound_sandbox != sandbox_id {
        return Err(ApiError::unauthorized(
            "guest token is not bound to this sandbox",
        ));
    }
    let Some(worker_id) = ctx.worker_id() else {
        return Err(ApiError::unauthorized(
            "guest token refresh requires a guest bearer token",
        ));
    };
    let response = issue_guest_token(
        &state.db,
        &ctx.tenant_id,
        worker_id,
        sandbox_id,
        request.ttl_seconds,
        /* revalidate_lifecycle */ true,
    )
    .await?;
    Ok(Json(response))
}

async fn issue_guest_token(
    db: &Database,
    tenant_id: &str,
    worker_id: WorkerId,
    sandbox_id: SandboxId,
    ttl_seconds: Option<u64>,
    revalidate_lifecycle: bool,
) -> Result<GuestTokenResponse, ApiError> {
    let ttl_seconds = ttl_seconds.unwrap_or(3600);
    if !(1..=86_400).contains(&ttl_seconds) {
        return Err(ApiError::bad_request(
            "guest token ttl_seconds must be between 1 and 86400",
        ));
    }
    let now = Utc::now();
    if revalidate_lifecycle {
        revalidate_guest_token_lifecycle(db, tenant_id, worker_id, sandbox_id, now).await?;
    }
    let expires_at = now + chrono::Duration::seconds(ttl_seconds as i64);
    let token = generate_guest_token();
    let token_hash = hash_worker_token(&token);
    let mut tx = db.pool.begin().await?;
    let revoke_sql = format!(
        "update guest_tokens set revoked_at = {}
         where tenant_id = {} and sandbox_id = {} and revoked_at is null",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    sqlx::query(&revoke_sql)
        .bind(now.to_rfc3339())
        .bind(tenant_id)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    let insert_sql = format!(
        "insert into guest_tokens
         (id, tenant_id, worker_id, sandbox_id, token_hash, expires_at, revoked_at, created_at)
         values ({})",
        db.placeholders(8)
    );
    sqlx::query(&insert_sql)
        .bind(Uuid::now_v7().to_string())
        .bind(tenant_id)
        .bind(worker_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(token_hash)
        .bind(expires_at.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(GuestTokenResponse {
        ok: true,
        token,
        tenant_id: tenant_id.to_string(),
        worker_id,
        sandbox_id,
        expires_at,
    })
}

async fn revalidate_guest_token_lifecycle(
    db: &Database,
    tenant_id: &str,
    worker_id: WorkerId,
    sandbox_id: SandboxId,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    if sandbox.tenant_id != tenant_id {
        return Err(ApiError {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "guest_token_revoked",
            message: "guest token sandbox is no longer authorized".into(),
        });
    }
    if !matches!(
        sandbox.state,
        SandboxState::Ready
            | SandboxState::Provisioning
            | SandboxState::Running
            | SandboxState::Idle
    ) {
        return Err(ApiError {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "guest_token_revoked",
            message: format!(
                "sandbox is not active for guest token refresh (state={:?})",
                sandbox.state
            ),
        });
    }
    if let Some(max_lifetime) = sandbox.max_lifetime_seconds {
        let deadline = sandbox.created_at + chrono::Duration::seconds(max_lifetime as i64);
        if now >= deadline {
            return Err(ApiError {
                status: axum::http::StatusCode::UNAUTHORIZED,
                code: "guest_token_revoked",
                message: "sandbox hard lifetime has elapsed".into(),
            });
        }
    }
    let placement_sql = format!(
        "select worker_id from sandbox_placements where sandbox_id = {}",
        db.placeholder(1)
    );
    let placement = sqlx::query(&placement_sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    let Some(row) = placement else {
        return Err(ApiError {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "guest_token_revoked",
            message: "sandbox has no active placement".into(),
        });
    };
    let placed_worker: String = row.try_get("worker_id")?;
    if placed_worker != worker_id.to_string() {
        return Err(ApiError {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "guest_token_revoked",
            message: "sandbox placement no longer matches this guest token".into(),
        });
    }
    Ok(())
}

pub(crate) async fn register_worker(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<RegisterWorkerRequest>,
) -> Result<Json<WorkerResponse>, ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::bad_request("worker name is required"));
    }
    if request.provider.trim().is_empty() {
        return Err(ApiError::bad_request("worker provider is required"));
    }
    if request.capabilities.is_empty() {
        return Err(ApiError::bad_request(
            "worker must report at least one capability",
        ));
    }
    let max_concurrent_jobs =
        validate_max_concurrent_jobs(request.max_concurrent_jobs.unwrap_or(1))?;

    let now = Utc::now();
    let existing = fetch_worker_by_logical_identity(
        &state.db,
        &ctx.tenant_id,
        request.name.trim(),
        request.provider.trim(),
    )
    .await?;
    let worker = Worker {
        id: existing
            .as_ref()
            .map(|worker| worker.id)
            .unwrap_or_else(WorkerId::new),
        tenant_id: ctx.tenant_id,
        name: request.name,
        status: WorkerStatus::Registered,
        provider: request.provider,
        capabilities: request.capabilities,
        max_concurrent_jobs,
        labels: request.labels,
        resource_envelope: None,
        registered_at: now,
        last_heartbeat_at: None,
    };
    // Mint this worker's scoped credential now (GH-64): the raw token is
    // returned once, below, and never persisted -- only its hash is stored,
    // so the API itself cannot produce the plaintext token again after this
    // response.
    let worker_token = generate_worker_token();
    let token_hash = hash_worker_token(&worker_token);
    if existing.is_some() {
        let sql = format!(
            "update workers set status = case
                 when exists (
                   select 1 from worker_drain_receipts
                   where worker_id = workers.id and retired_at is null
                 ) then 'draining' else {} end,
             capabilities = {}, max_concurrent_jobs = {},
             labels = {}, registered_at = {}, last_heartbeat_at = null, token_hash = {}
             where id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2),
            state.db.placeholder(3),
            state.db.placeholder(4),
            state.db.placeholder(5),
            state.db.placeholder(6),
            state.db.placeholder(7)
        );
        sqlx::query(&sql)
            .bind(worker_status_to_str(&WorkerStatus::Registered))
            .bind(serde_json::to_string(&worker.capabilities)?)
            .bind(i64::from(worker.max_concurrent_jobs))
            .bind(serde_json::to_string(&worker.labels)?)
            .bind(now.to_rfc3339())
            .bind(&token_hash)
            .bind(worker.id.to_string())
            .execute(&state.db.pool)
            .await?;
        let generation_sql = format!(
            "update worker_sessions set generation = generation + 1, started_at = {} where worker_id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2)
        );
        sqlx::query(&generation_sql)
            .bind(now.to_rfc3339())
            .bind(worker.id.to_string())
            .execute(&state.db.pool)
            .await?;
    } else {
        insert_worker(&state.db, &worker, &token_hash).await?;
        let sql = format!(
            "insert into worker_sessions (worker_id, generation, started_at) values ({})",
            state.db.placeholders(3)
        );
        sqlx::query(&sql)
            .bind(worker.id.to_string())
            .bind(1_i64)
            .bind(now.to_rfc3339())
            .execute(&state.db.pool)
            .await?;
    }

    let worker = fetch_worker(&state.db, worker.id).await?;

    Ok(Json(WorkerResponse {
        ok: true,
        worker,
        worker_token: Some(worker_token),
    }))
}

async fn fetch_worker_by_logical_identity(
    db: &Database,
    tenant_id: &str,
    name: &str,
    provider: &str,
) -> Result<Option<Worker>, ApiError> {
    let sql =
        format!(
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels,
                resource_envelope, registered_at, last_heartbeat_at from workers
         where tenant_id = {} and name = {} and provider = {}",
        db.placeholder(1), db.placeholder(2), db.placeholder(3)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(name)
        .bind(provider)
        .fetch_optional(&db.pool)
        .await?
        .map(row_to_worker)
        .transpose()
}

#[utoipa::path(
    post,
    path = "/v1/workers/{worker_id}/drain",
    params(("worker_id" = Uuid, Path)),
    request_body = Option<DrainWorkerRequest>,
    responses((status = 200, description = "Worker admission closed; typed requests return a durable drain receipt", body = DrainWorkerResponse))
)]
pub(crate) async fn drain_worker(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    request: Option<Json<DrainWorkerRequest>>,
) -> Result<Json<DrainWorkerResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let Some(Json(request)) = request else {
        let sql = format!(
            "update workers set status = {} where id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2)
        );
        sqlx::query(&sql)
            .bind(worker_status_to_str(&WorkerStatus::Draining))
            .bind(worker_id.to_string())
            .execute(&state.db.pool)
            .await?;
        return Ok(Json(DrainWorkerResponse {
            ok: true,
            worker: fetch_worker(&state.db, worker_id).await?,
            worker_token: None,
            drain_receipt: None,
        }));
    };
    let now = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let receipt = async {
        // Serialize before receipt lookup. Under PostgreSQL, two concurrent
        // retries can both observe no receipt under READ COMMITTED unless the
        // worker row is locked first; ordering here makes the second request
        // observe and replay the first committed receipt.
        let serialize_sql = format!(
            "update workers set last_heartbeat_at = last_heartbeat_at where id = {}",
            state.db.placeholder(1)
        );
        let serialized = sqlx::query(&serialize_sql)
            .bind(worker_id.to_string())
            .execute(&mut *tx)
            .await?;
        if serialized.rows_affected() != 1 {
            return Err(ApiError::not_found("worker not found"));
        }
        let existing_sql = format!(
            "select worker_id, tenant_id, hard_deadline from worker_drain_receipts
             where shutdown_id = {}",
            state.db.placeholder(1)
        );
        if let Some(row) = sqlx::query(&existing_sql)
            .bind(request.shutdown_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
        {
            let existing_worker_id: String = row.try_get("worker_id")?;
            let existing_tenant_id: String = row.try_get("tenant_id")?;
            let existing_deadline: String = row.try_get("hard_deadline")?;
            if existing_worker_id != worker_id.to_string()
                || existing_tenant_id != ctx.tenant_id
                || parse_timestamp(&existing_deadline)? != request.hard_deadline
            {
                return Err(ApiError::conflict_code(
                    "worker_drain_receipt_conflict",
                    "shutdown id is already bound to a different drain fence",
                ));
            }
        } else {
            if request.hard_deadline <= now {
                return Err(ApiError::bad_request(
                    "drain hard deadline must be in the future",
                ));
            }
            if request.hard_deadline > now + chrono::Duration::hours(1) {
                return Err(ApiError::bad_request(
                    "drain hard deadline cannot exceed one hour",
                ));
            }
            // This write is the claim/drain serialization point. A claim that
            // commits first is captured below; a drain that commits first
            // prevents the claim's online-only lock from succeeding.
            let worker_sql = format!(
                "update workers set status = {}
                 where id = {} and status in ('registered', 'online')",
                state.db.placeholder(1),
                state.db.placeholder(2)
            );
            let result = sqlx::query(&worker_sql)
                .bind(worker_status_to_str(&WorkerStatus::Draining))
                .bind(worker_id.to_string())
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(ApiError::conflict_code(
                    "worker_not_drainable",
                    "worker is not online or draining",
                ));
            }
            let insert_sql = format!(
                "insert into worker_drain_receipts
                 (shutdown_id, worker_id, tenant_id, hard_deadline, created_at)
                 values ({})",
                state.db.placeholders(5)
            );
            sqlx::query(&insert_sql)
                .bind(request.shutdown_id.to_string())
                .bind(worker_id.to_string())
                .bind(&ctx.tenant_id)
                .bind(request.hard_deadline.to_rfc3339())
                .bind(now.to_rfc3339())
                .execute(&mut *tx)
                .await?;

            let leases_sql = format!(
                "select id, job_id, attempt from job_leases
                 where worker_id = {} and status = 'active'
                 order by id asc",
                state.db.placeholder(1)
            );
            let active_leases = sqlx::query(&leases_sql)
                .bind(worker_id.to_string())
                .fetch_all(&mut *tx)
                .await?;
            let fence_sql = format!(
                "insert into worker_drain_lease_fences
                 (shutdown_id, lease_id, worker_id, job_id, attempt, hard_deadline)
                 values ({})",
                state.db.placeholders(6)
            );
            for lease in active_leases {
                sqlx::query(&fence_sql)
                    .bind(request.shutdown_id.to_string())
                    .bind(lease.try_get::<String, _>("id")?)
                    .bind(worker_id.to_string())
                    .bind(lease.try_get::<String, _>("job_id")?)
                    .bind(lease.try_get::<i64, _>("attempt")?)
                    .bind(request.hard_deadline.to_rfc3339())
                    .execute(&mut *tx)
                    .await?;
            }
            let cap_sql = format!(
                "update job_leases set expires_at = {}
                 where worker_id = {} and status = 'active' and expires_at > {}",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3)
            );
            sqlx::query(&cap_sql)
                .bind(request.hard_deadline.to_rfc3339())
                .bind(worker_id.to_string())
                .bind(request.hard_deadline.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }

        fetch_drain_receipt_on_connection(&state.db, &mut tx, request.shutdown_id).await
    }
    .await;
    let receipt = match receipt {
        Ok(receipt) => {
            tx.commit().await?;
            receipt
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back worker drain receipt");
            }
            return Err(error);
        }
    };

    Ok(Json(DrainWorkerResponse {
        ok: true,
        worker: fetch_worker(&state.db, worker_id).await?,
        worker_token: None,
        drain_receipt: Some(receipt),
    }))
}

async fn fetch_drain_receipt_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    shutdown_id: Uuid,
) -> Result<DrainReceipt, ApiError> {
    let sql = format!(
        "select worker_id, hard_deadline from worker_drain_receipts where shutdown_id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(shutdown_id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    let worker_id = WorkerId(parse_uuid(row.try_get::<&str, _>("worker_id")?)?);
    let hard_deadline = parse_timestamp(row.try_get("hard_deadline")?)?;
    let leases_sql = format!(
        "select lease_id, job_id, attempt, outcome, resolved_at
         from worker_drain_lease_fences
         where shutdown_id = {} order by lease_id asc",
        db.placeholder(1)
    );
    let leases = sqlx::query(&leases_sql)
        .bind(shutdown_id.to_string())
        .fetch_all(&mut *connection)
        .await?
        .into_iter()
        .map(|row| {
            let resolved_at = row
                .try_get::<Option<String>, _>("resolved_at")?
                .map(|value| parse_timestamp(&value))
                .transpose()?;
            Ok(DrainLeaseFence {
                lease_id: LeaseId(parse_uuid(row.try_get::<&str, _>("lease_id")?)?),
                job_id: JobId(parse_uuid(row.try_get::<&str, _>("job_id")?)?),
                attempt: row.try_get("attempt")?,
                outcome: row.try_get("outcome")?,
                resolved_at,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(DrainReceipt {
        shutdown_id,
        worker_id,
        hard_deadline,
        leases,
    })
}

pub(crate) async fn heartbeat_worker(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Json(request): Json<WorkerHeartbeatRequest>,
) -> Result<Json<WorkerResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let now = Utc::now();
    let labels = serde_json::to_string(&request.labels)?;
    let envelope_json = request
        .resource_envelope
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let max_concurrent_jobs = request
        .max_concurrent_jobs
        .map(validate_max_concurrent_jobs)
        .transpose()?;

    // Always touch heartbeat/status/labels. max_concurrent_jobs and the
    // resource envelope update only when the worker supplies them so a partial
    // heartbeat cannot wipe observed capacity evidence.
    let sql = match (max_concurrent_jobs, envelope_json.as_ref()) {
        (Some(max_concurrent_jobs), Some(envelope)) => {
            let sql = format!(
                "update workers
                 set status = case
                       when exists (
                         select 1 from worker_drain_receipts
                         where worker_id = workers.id and retired_at is null
                       ) then 'draining'
                       when status = 'draining' then status else {} end,
                     last_heartbeat_at = {}, labels = {},
                     max_concurrent_jobs = {}, resource_envelope = {}
                 where id = {}",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3),
                state.db.placeholder(4),
                state.db.placeholder(5),
                state.db.placeholder(6)
            );
            sqlx::query(&sql)
                .bind(worker_status_to_str(&WorkerStatus::Online))
                .bind(now.to_rfc3339())
                .bind(labels.clone())
                .bind(i64::from(max_concurrent_jobs))
                .bind(envelope)
                .bind(worker_id.to_string())
                .execute(&state.db.pool)
                .await?
        }
        (Some(max_concurrent_jobs), None) => {
            let sql = format!(
                "update workers
                 set status = case
                       when exists (
                         select 1 from worker_drain_receipts
                         where worker_id = workers.id and retired_at is null
                       ) then 'draining'
                       when status = 'draining' then status else {} end,
                     last_heartbeat_at = {}, labels = {}, max_concurrent_jobs = {}
                 where id = {}",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3),
                state.db.placeholder(4),
                state.db.placeholder(5)
            );
            sqlx::query(&sql)
                .bind(worker_status_to_str(&WorkerStatus::Online))
                .bind(now.to_rfc3339())
                .bind(labels.clone())
                .bind(i64::from(max_concurrent_jobs))
                .bind(worker_id.to_string())
                .execute(&state.db.pool)
                .await?
        }
        (None, Some(envelope)) => {
            let sql = format!(
                "update workers
                 set status = case
                       when exists (
                         select 1 from worker_drain_receipts
                         where worker_id = workers.id and retired_at is null
                       ) then 'draining'
                       when status = 'draining' then status else {} end,
                     last_heartbeat_at = {}, labels = {}, resource_envelope = {}
                 where id = {}",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3),
                state.db.placeholder(4),
                state.db.placeholder(5)
            );
            sqlx::query(&sql)
                .bind(worker_status_to_str(&WorkerStatus::Online))
                .bind(now.to_rfc3339())
                .bind(labels.clone())
                .bind(envelope)
                .bind(worker_id.to_string())
                .execute(&state.db.pool)
                .await?
        }
        (None, None) => {
            let sql = format!(
                "update workers
                 set status = case
                       when exists (
                         select 1 from worker_drain_receipts
                         where worker_id = workers.id and retired_at is null
                       ) then 'draining'
                       when status = 'draining' then status else {} end,
                     last_heartbeat_at = {}, labels = {}
                 where id = {}",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3),
                state.db.placeholder(4)
            );
            sqlx::query(&sql)
                .bind(worker_status_to_str(&WorkerStatus::Online))
                .bind(now.to_rfc3339())
                .bind(labels.clone())
                .bind(worker_id.to_string())
                .execute(&state.db.pool)
                .await?
        }
    };

    if sql.rows_affected() == 0 {
        return Err(ApiError::not_found("worker not found"));
    }

    insert_worker_heartbeat(&state.db, worker_id, &labels, now).await?;
    let worker = fetch_worker(&state.db, worker_id).await?;

    Ok(Json(WorkerResponse {
        ok: true,
        worker,
        worker_token: None,
    }))
}

pub(crate) async fn list_workers(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<WorkerListResponse>, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels,
                resource_envelope, registered_at, last_heartbeat_at
         from workers
         where tenant_id = {}
         order by registered_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .fetch_all(state.db.read_pool())
        .await?;

    let workers = rows
        .into_iter()
        .map(row_to_worker)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(WorkerListResponse { ok: true, workers }))
}

pub(crate) async fn get_capacity(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<CapacityResponse>, ApiError> {
    let workers = list_worker_capacities(&state.db, &ctx.tenant_id).await?;
    let total_max_concurrent_jobs = workers
        .iter()
        .filter(|worker| worker.status == WorkerStatus::Online)
        .map(|worker| worker.max_concurrent_jobs)
        .sum();
    let total_active_leases = workers.iter().map(|worker| worker.active_leases).sum();
    let total_available_slots = workers.iter().map(|worker| worker.available_slots).sum();

    Ok(Json(CapacityResponse {
        ok: true,
        workers,
        total_max_concurrent_jobs,
        total_active_leases,
        total_available_slots,
    }))
}

pub(crate) async fn get_guest_health(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<GuestHealthResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let guest_health = fetch_guest_health(&state.db, sandbox_id)
        .await?
        .unwrap_or_else(|| GuestHealth {
            sandbox_id,
            status: GuestStatus::Pending,
            last_probe_at: Utc::now(),
            agent_version: None,
            checks: json!({}),
            message: Some("guest has not reported health yet".to_string()),
        });

    Ok(Json(GuestHealthResponse {
        ok: true,
        guest_health,
    }))
}

pub(crate) async fn update_guest_health(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<UpdateGuestHealthRequest>,
) -> Result<Json<GuestHealthResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    // GH-64: guest-facing route -- only the worker that provisioned/forked
    // this sandbox may report its guest health; tenant-wide tokens are
    // rejected. (The read side, `get_guest_health`, stays on tenant auth --
    // CLI/dashboard callers need to read it too.)
    ensure_sandbox_worker_scope(&state.db, sandbox_id, &ctx).await?;
    let now = Utc::now();
    let guest_health = GuestHealth {
        sandbox_id,
        status: request.status,
        last_probe_at: now,
        agent_version: request.agent_version,
        checks: request.checks.unwrap_or_else(|| json!({})),
        message: request.message,
    };
    upsert_guest_health(&state.db, &guest_health).await?;
    maybe_insert_guest_failure_event(&state.db, &guest_health).await?;

    Ok(Json(GuestHealthResponse {
        ok: true,
        guest_health,
    }))
}

pub(crate) async fn maybe_insert_guest_failure_event(
    db: &Database,
    guest_health: &GuestHealth,
) -> Result<(), ApiError> {
    let reason = match &guest_health.status {
        GuestStatus::Unhealthy => "guest_unhealthy",
        GuestStatus::Unreachable => "guest_unreachable",
        GuestStatus::Pending | GuestStatus::Ready | GuestStatus::Terminated => return Ok(()),
    };

    insert_event(
        db,
        guest_health.sandbox_id,
        SandboxEventKind::GuestHealthFailed,
        json!({
            "reason": reason,
            "guestStatus": &guest_health.status,
            "agentVersion": &guest_health.agent_version,
            "checks": &guest_health.checks,
            "message": &guest_health.message,
            "lastProbeAt": &guest_health.last_probe_at
        }),
    )
    .await?;
    Ok(())
}

pub(crate) async fn fetch_worker(db: &Database, worker_id: WorkerId) -> Result<Worker, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels,
                resource_envelope, registered_at, last_heartbeat_at
         from workers
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("worker not found"))?;

    row_to_worker(row)
}

/// Pure-read active lease count for claim saturation short-circuit. Uses the
/// query-only pool so claim polls do not take a writer connection just to
/// learn the worker is already full.
pub(crate) async fn active_lease_count_for_worker(
    db: &Database,
    worker_id: WorkerId,
) -> Result<u32, ApiError> {
    let mut connection = db.read_pool().acquire().await?;
    active_lease_count_for_worker_on_connection(db, &mut connection, worker_id).await
}

pub(crate) async fn active_lease_count_for_worker_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    worker_id: WorkerId,
) -> Result<u32, ApiError> {
    let sql = format!(
        "select count(*) as active_leases
         from job_leases
         join jobs on jobs.id = job_leases.job_id
         where job_leases.worker_id = {} and job_leases.status = 'active'
           and jobs.kind != 'run_resident_process'",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    let active_leases: i64 = row.try_get("active_leases")?;
    u32::try_from(active_leases)
        .map_err(|_| ApiError::internal("database contains invalid active lease count"))
}

pub(crate) async fn list_worker_capacities(
    db: &Database,
    tenant_id: &str,
) -> Result<Vec<WorkerCapacity>, ApiError> {
    let sql = format!(
        "select workers.id, workers.tenant_id, workers.name, workers.status, workers.provider,
                workers.capabilities, workers.max_concurrent_jobs, workers.labels,
                workers.resource_envelope, workers.registered_at, workers.last_heartbeat_at,
                coalesce(sum(case when jobs.kind != 'run_resident_process' then 1 else 0 end), 0) as active_leases
         from workers
         left join job_leases on job_leases.worker_id = workers.id and job_leases.status = 'active'
         left join jobs on jobs.id = job_leases.job_id
         where workers.tenant_id = {}
         group by workers.id, workers.tenant_id, workers.name, workers.status, workers.provider,
                  workers.capabilities, workers.max_concurrent_jobs, workers.labels,
                  workers.resource_envelope, workers.registered_at, workers.last_heartbeat_at
         order by workers.registered_at asc, workers.id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(db.read_pool())
        .await?;

    let mut capacities = Vec::new();
    for row in rows {
        let active_leases = count_to_u32(row.try_get("active_leases")?)?;
        let worker = row_to_worker(row)?;
        let available_slots = if worker.status == WorkerStatus::Online {
            worker.max_concurrent_jobs.saturating_sub(active_leases)
        } else {
            0
        };
        capacities.push(WorkerCapacity {
            worker_id: worker.id,
            worker_name: worker.name,
            provider: worker.provider,
            status: worker.status,
            max_concurrent_jobs: worker.max_concurrent_jobs,
            active_leases,
            available_slots,
        });
    }

    Ok(capacities)
}

pub(crate) async fn fetch_guest_health(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Option<GuestHealth>, ApiError> {
    let sql = format!(
        "select sandbox_id, status, last_probe_at, agent_version, checks, message
         from guest_health
         where sandbox_id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    row.map(row_to_guest_health).transpose()
}

pub(crate) async fn upsert_guest_health(
    db: &Database,
    guest_health: &GuestHealth,
) -> Result<(), ApiError> {
    if fetch_guest_health(db, guest_health.sandbox_id)
        .await?
        .is_some()
    {
        let sql = format!(
            "update guest_health
             set status = {}, last_probe_at = {}, agent_version = {}, checks = {}, message = {}
             where sandbox_id = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4),
            db.placeholder(5),
            db.placeholder(6)
        );
        sqlx::query(&sql)
            .bind(guest_status_to_str(&guest_health.status))
            .bind(guest_health.last_probe_at.to_rfc3339())
            .bind(&guest_health.agent_version)
            .bind(serde_json::to_string(&guest_health.checks)?)
            .bind(&guest_health.message)
            .bind(guest_health.sandbox_id.to_string())
            .execute(&db.pool)
            .await?;
    } else {
        let sql = format!(
            "insert into guest_health
             (sandbox_id, status, last_probe_at, agent_version, checks, message)
             values ({})",
            db.placeholders(6)
        );
        sqlx::query(&sql)
            .bind(guest_health.sandbox_id.to_string())
            .bind(guest_status_to_str(&guest_health.status))
            .bind(guest_health.last_probe_at.to_rfc3339())
            .bind(&guest_health.agent_version)
            .bind(serde_json::to_string(&guest_health.checks)?)
            .bind(&guest_health.message)
            .execute(&db.pool)
            .await?;
    }

    Ok(())
}

/// `token_hash` is the SHA-256 hash (see [`hash_worker_token`]) of this
/// worker's scoped credential (GH-64), never the raw token itself.
pub(crate) async fn insert_worker(
    db: &Database,
    worker: &Worker,
    token_hash: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into workers
         (id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at, token_hash)
         values ({})",
        db.placeholders(11)
    );
    sqlx::query(&sql)
        .bind(worker.id.to_string())
        .bind(&worker.tenant_id)
        .bind(&worker.name)
        .bind(worker_status_to_str(&worker.status))
        .bind(&worker.provider)
        .bind(serde_json::to_string(&worker.capabilities)?)
        .bind(i64::from(worker.max_concurrent_jobs))
        .bind(serde_json::to_string(&worker.labels)?)
        .bind(worker.registered_at.to_rfc3339())
        .bind(worker.last_heartbeat_at.map(|time| time.to_rfc3339()))
        .bind(token_hash)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// Minimum spacing between append-only heartbeat history rows for one worker.
/// Liveness still updates `workers.last_heartbeat_at` on every beat; this only
/// throttles the history table that scrapers and offline-reconciliation bound.
const WORKER_HEARTBEAT_HISTORY_INTERVAL_SECS: i64 = 30;

pub(crate) async fn insert_worker_heartbeat(
    db: &Database,
    worker_id: WorkerId,
    labels: &str,
    created_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    // Skip history write when a recent sample already exists for this worker.
    // Workers heartbeat every ~15s; writing history every beat doubles write
    // traffic on the SQLite FIFO for no liveness benefit.
    let recent_sql = format!(
        "select 1 from worker_heartbeats
         where worker_id = {} and created_at >= {}
         limit 1",
        db.placeholder(1),
        db.placeholder(2)
    );
    let cutoff = created_at - chrono::Duration::seconds(WORKER_HEARTBEAT_HISTORY_INTERVAL_SECS);
    if sqlx::query(&recent_sql)
        .bind(worker_id.to_string())
        .bind(cutoff.to_rfc3339())
        .fetch_optional(db.read_pool())
        .await?
        .is_some()
    {
        return Ok(());
    }
    let sql = format!(
        "insert into worker_heartbeats (id, worker_id, labels, created_at)
         values ({})",
        db.placeholders(4)
    );
    sqlx::query(&sql)
        .bind(EventId::new().to_string())
        .bind(worker_id.to_string())
        .bind(labels)
        .bind(created_at.to_rfc3339())
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// Reconciles liveness from durable heartbeat timestamps and bounds the
/// append-only heartbeat history. This is deliberately idempotent so every
/// API replica may run the periodic controller safely.
pub(crate) async fn reconcile_worker_liveness(db: &Database) -> Result<(), ApiError> {
    let now = Utc::now();
    let offline_before = now - chrono::Duration::seconds(90);
    let sql = format!(
        "update workers set status = {}
         where status in ('online', 'draining')
           and (last_heartbeat_at is null or last_heartbeat_at < {})",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&sql)
        .bind(worker_status_to_str(&WorkerStatus::Offline))
        .bind(offline_before.to_rfc3339())
        .execute(&db.pool)
        .await?;

    let retain_after = now - chrono::Duration::days(7);
    let delete_sql = format!(
        "delete from worker_heartbeats where id in (
             select id from worker_heartbeats where created_at < {}
             order by created_at asc, id asc limit 1000
         )",
        db.placeholder(1)
    );
    sqlx::query(&delete_sql)
        .bind(retain_after.to_rfc3339())
        .execute(&db.pool)
        .await?;
    Ok(())
}
