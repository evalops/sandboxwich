use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
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
use uuid::Uuid;

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
    let scope_sql = format!(
        "select id, labels from workers
         where tenant_id = {} and provider = {}
         order by id asc limit 201",
        state.db.placeholder(1),
        state.db.placeholder(2),
    );
    let worker_cluster = worker.labels.get("cluster");
    let mut scope_worker_ids = Vec::new();
    let scope_rows = sqlx::query(&scope_sql)
        .bind(&ctx.tenant_id)
        .bind(&worker.provider)
        .fetch_all(&state.db.pool)
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
    let sandbox_sql = format!(
        "select id as sandbox_id
         from sandboxes
         where tenant_id = {} and state != 'archived'
         order by id asc limit 201",
        state.db.placeholder(1),
    );
    let mut sandbox_ids = sqlx::query(&sandbox_sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&state.db.pool)
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
         where jl.worker_id in ({scope_placeholders}) and por.resource_namespace = {}
         ) inventory where 1 = 1",
        state.db.placeholder(scope_worker_ids.len() + 1),
    );
    let mut fixed_binds = scope_worker_ids;
    fixed_binds.push(query.namespace.clone());
    let (resources, next_cursor) =
        fetch_keyset_page(&state.db, &sql, &fixed_binds, limit, &cursor, |row| {
            let created_at: String = row.try_get("sandbox_created_at")?;
            let updated_at: String = row.try_get("sandbox_updated_at")?;
            let ttl_seconds: Option<i64> = row.try_get("ttl_seconds")?;
            let expires_at = ttl_seconds
                .map(|ttl| {
                    parse_timestamp(&created_at)
                        .map(|created| created + chrono::Duration::seconds(ttl))
                })
                .transpose()?;
            let state: String = row.try_get("state")?;
            let cleanup_deadline = if matches!(state.as_str(), "archiving" | "archived") {
                Some(parse_timestamp(&updated_at)?)
            } else {
                None
            };
            let resource_kind: String = row.try_get("resource_kind")?;
            Ok(RuntimeResourceInventoryItem {
                sandbox_id: SandboxId(parse_uuid(&row.try_get::<String, _>("sandbox_id")?)?),
                resource_kind: RuntimeResourceKind::parse_db_str(&resource_kind)
                    .map_err(|_| ApiError::internal("invalid runtime resource kind"))?,
                namespace: row.try_get("resource_namespace")?,
                name: row.try_get("resource_name")?,
                uid: row.try_get("resource_uid")?,
                expires_at,
                cleanup_deadline,
            })
        })
        .await?;
    Ok(Json(RuntimeResourceInventoryResponse {
        ok: true,
        provider: worker.provider,
        cluster: worker.labels.get("cluster").cloned(),
        namespace: query.namespace,
        sandbox_ids,
        complete,
        resources,
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
    let ttl_seconds = request.ttl_seconds.unwrap_or(3600);
    if !(1..=86_400).contains(&ttl_seconds) {
        return Err(ApiError::bad_request(
            "guest token ttl_seconds must be between 1 and 86400",
        ));
    }
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(ttl_seconds as i64);
    let token = generate_guest_token();
    let token_hash = hash_worker_token(&token);
    let mut tx = state.db.pool.begin().await?;
    let revoke_sql = format!(
        "update guest_tokens set revoked_at = {}
         where tenant_id = {} and sandbox_id = {} and revoked_at is null",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3)
    );
    sqlx::query(&revoke_sql)
        .bind(now.to_rfc3339())
        .bind(&ctx.tenant_id)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    let insert_sql = format!(
        "insert into guest_tokens
         (id, tenant_id, worker_id, sandbox_id, token_hash, expires_at, revoked_at, created_at)
         values ({})",
        state.db.placeholders(8)
    );
    sqlx::query(&insert_sql)
        .bind(Uuid::now_v7().to_string())
        .bind(&ctx.tenant_id)
        .bind(worker_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(token_hash)
        .bind(expires_at.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(GuestTokenResponse {
        ok: true,
        token,
        tenant_id: ctx.tenant_id,
        worker_id,
        sandbox_id,
        expires_at,
    }))
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
            "update workers set status = {}, capabilities = {}, max_concurrent_jobs = {},
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
                registered_at, last_heartbeat_at from workers
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

pub(crate) async fn drain_worker(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
) -> Result<Json<WorkerResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
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
    Ok(Json(WorkerResponse {
        ok: true,
        worker: fetch_worker(&state.db, worker_id).await?,
        worker_token: None,
    }))
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
    let result = if let Some(max_concurrent_jobs) = request.max_concurrent_jobs {
        let max_concurrent_jobs = validate_max_concurrent_jobs(max_concurrent_jobs)?;
        let sql = format!(
            "update workers
             set status = {}, last_heartbeat_at = {}, labels = {}, max_concurrent_jobs = {}
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
    } else {
        let sql = format!(
            "update workers
             set status = {}, last_heartbeat_at = {}, labels = {}
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
    };

    if result.rows_affected() == 0 {
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
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at
         from workers
         where tenant_id = {}
         order by registered_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&state.db.pool)
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
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at
         from workers
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("worker not found"))?;

    row_to_worker(row)
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
                workers.registered_at, workers.last_heartbeat_at,
                coalesce(sum(case when jobs.kind != 'run_resident_process' then 1 else 0 end), 0) as active_leases
         from workers
         left join job_leases on job_leases.worker_id = workers.id and job_leases.status = 'active'
         left join jobs on jobs.id = job_leases.job_id
         where workers.tenant_id = {}
         group by workers.id, workers.tenant_id, workers.name, workers.status, workers.provider,
                  workers.capabilities, workers.max_concurrent_jobs, workers.labels,
                  workers.registered_at, workers.last_heartbeat_at
         order by workers.registered_at asc, workers.id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(&db.pool)
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

pub(crate) fn guest_supports_uid_isolated_resident_process(health: &GuestHealth) -> bool {
    health.status == GuestStatus::Ready
        && GuestAgentCapabilityReport::from_health_checks(&health.checks)
            .is_some_and(|report| report.supports_uid_isolated_resident_process())
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

pub(crate) async fn insert_worker_heartbeat(
    db: &Database,
    worker_id: WorkerId,
    labels: &str,
    created_at: DateTime<Utc>,
) -> Result<(), ApiError> {
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
