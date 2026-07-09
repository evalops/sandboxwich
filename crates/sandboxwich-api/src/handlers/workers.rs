use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

pub(crate) fn validate_max_concurrent_jobs(max_concurrent_jobs: u32) -> Result<u32, ApiError> {
    if max_concurrent_jobs == 0 {
        return Err(ApiError::bad_request(
            "max_concurrent_jobs must be greater than 0",
        ));
    }
    Ok(max_concurrent_jobs)
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
    let worker = Worker {
        id: WorkerId::new(),
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
    insert_worker(&state.db, &worker, &token_hash).await?;

    Ok(Json(WorkerResponse {
        ok: true,
        worker,
        worker_token: Some(worker_token),
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
        SandboxEventKind::DesktopExpired,
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
         where worker_id = {} and status = 'active'",
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
                coalesce(count(job_leases.id), 0) as active_leases
         from workers
         left join job_leases on job_leases.worker_id = workers.id and job_leases.status = 'active'
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
