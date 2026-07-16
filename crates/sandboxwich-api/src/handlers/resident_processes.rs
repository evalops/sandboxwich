use crate::auth::ensure_sandbox_tenant;
use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::jobs::{add_provision_spec_to_payload, insert_job_on_connection};
use crate::rows::row_to_resident_process;
use crate::state::{AppState, LiveResidentBootstrap, Principal, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn fetch_named_resident_process(
    db: &Database,
    sandbox_id: SandboxId,
    name: &str,
) -> Result<ResidentProcess, ApiError> {
    let sql = format!(
        "select * from resident_processes where sandbox_id = {} and name = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(name)
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("resident process not found"))?;
    row_to_resident_process(row)
}

async fn fetch_resident_process_by_id(
    db: &Database,
    id: ResidentProcessId,
) -> Result<ResidentProcess, ApiError> {
    let sql = format!(
        "select * from resident_processes where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("resident process not found"))?;
    row_to_resident_process(row)
}

fn same_spec(
    current: &ResidentProcess,
    request: &ResidentProcessRequest,
    digest: Option<&str>,
) -> bool {
    current.argv == request.argv
        && current.cwd == request.cwd
        && current.env == request.env
        && current.restart_policy == request.restart_policy
        && current.bootstrap_sha256.as_deref() == digest
        && current.bootstrap_target_file
            == request
                .bootstrap
                .as_ref()
                .map(|value| value.target_file.clone())
        && current.bootstrap_mode == request.bootstrap.as_ref().map(|value| value.mode)
}

pub(crate) async fn put_resident_process(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((sandbox_id, name)): Path<(Uuid, String)>,
    Json(request): Json<ResidentProcessRequest>,
) -> Result<(StatusCode, Json<ResidentProcessResponse>), ApiError> {
    validate_resident_process_request(&request)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    if name != "orb-executor" {
        return Err(ApiError::bad_request(
            "the first resident-process contract supports only orb-executor",
        ));
    }
    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let bootstrap_digest = request
        .bootstrap
        .as_ref()
        .map(|bootstrap| format!("{:x}", Sha256::digest(&bootstrap.content)));

    if let Ok(current) = fetch_named_resident_process(&state.db, sandbox_id, &name).await {
        if request.expected_generation != current.generation {
            return Err(ApiError::conflict_code(
                "resident_process_generation_conflict",
                "resident process generation changed",
            ));
        }
        if same_spec(&current, &request, bootstrap_digest.as_deref()) {
            return Ok((
                StatusCode::OK,
                Json(ResidentProcessResponse {
                    ok: true,
                    resident_process: current,
                    operation: None,
                }),
            ));
        }
        return Err(ApiError::conflict_code(
            "resident_process_spec_conflict",
            "resident process already exists with a different specification",
        ));
    }
    if request.expected_generation != 0 {
        return Err(ApiError::conflict_code(
            "resident_process_generation_conflict",
            "new resident process requires expectedGeneration=0",
        ));
    }

    let now = Utc::now();
    let process = ResidentProcess {
        id: ResidentProcessId::new(),
        sandbox_id,
        tenant_id: sandbox.tenant_id.clone(),
        name,
        argv: request.argv,
        cwd: request.cwd,
        env: request.env,
        bootstrap_sha256: bootstrap_digest.clone(),
        bootstrap_byte_count: request
            .bootstrap
            .as_ref()
            .map(|value| value.content.len() as u64),
        bootstrap_target_file: request
            .bootstrap
            .as_ref()
            .map(|value| value.target_file.clone()),
        bootstrap_mode: request.bootstrap.as_ref().map(|value| value.mode),
        restart_policy: request.restart_policy,
        desired_state: ResidentProcessDesiredState::Running,
        observed_state: ResidentProcessObservedState::Pending,
        generation: 1,
        active_lease_id: None,
        pid: None,
        started_at: None,
        ready_at: None,
        exited_at: None,
        exit_code: None,
        last_error: None,
        created_at: now,
        updated_at: now,
    };
    let mut job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::RunResidentProcess,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "residentProcessId": process.id,
            "generation": process.generation,
            "operation": {
                "kind": OperationKind::RunResidentProcess,
                "resourceId": process.id.0,
            }
        }),
        required_capability: WorkerCapability::RunCommand,
        required_execution_class: sandbox.execution_class.clone(),
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    add_provision_spec_to_payload(&mut job, &sandbox)?;

    if let Some(bootstrap) = request.bootstrap {
        state
            .resident_bootstraps
            .insert(
                process.id,
                LiveResidentBootstrap {
                    content: bootstrap.content,
                    sha256: bootstrap_digest.unwrap_or_default(),
                    target_file: bootstrap.target_file,
                    mode: bootstrap.mode,
                    generation: process.generation,
                },
            )
            .map_err(|_| ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "resident_bootstrap_capacity",
                message: "resident bootstrap capacity is exhausted".into(),
            })?;
    }

    let insert_sql = format!(
        "insert into resident_processes (
            id, sandbox_id, tenant_id, name, argv, cwd, env,
            bootstrap_sha256, bootstrap_byte_count, bootstrap_target_file, bootstrap_mode,
            restart_policy, desired_state, observed_state, generation,
            created_at, updated_at
         ) values ({})",
        state.db.placeholders(17)
    );
    let mut tx = state.db.pool.begin().await?;
    sqlx::query(&insert_sql)
        .bind(process.id.to_string())
        .bind(process.sandbox_id.to_string())
        .bind(&process.tenant_id)
        .bind(&process.name)
        .bind(serde_json::to_string(&process.argv)?)
        .bind(&process.cwd)
        .bind(serde_json::to_string(&process.env)?)
        .bind(&process.bootstrap_sha256)
        .bind(process.bootstrap_byte_count.map(|value| value as i64))
        .bind(&process.bootstrap_target_file)
        .bind(process.bootstrap_mode.map(i64::from))
        .bind(process.restart_policy.as_db_str())
        .bind(process.desired_state.as_db_str())
        .bind(process.observed_state.as_db_str())
        .bind(process.generation as i64)
        .bind(process.created_at.to_rfc3339())
        .bind(process.updated_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    let process_id = process.id.0;
    Ok((
        StatusCode::ACCEPTED,
        Json(ResidentProcessResponse {
            ok: true,
            resident_process: process,
            operation: Some(Operation {
                id: job.id.0,
                kind: OperationKind::RunResidentProcess,
                status: OperationStatus::Queued,
                resource_id: Some(process_id),
                created_at: job.created_at,
                updated_at: job.updated_at,
                error_code: None,
                error_message: None,
            }),
        }),
    ))
}

pub(crate) async fn get_resident_process(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((sandbox_id, name)): Path<(Uuid, String)>,
) -> Result<Json<ResidentProcessResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let process = fetch_named_resident_process(&state.db, sandbox_id, &name).await?;
    if process.tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resident process not found"));
    }
    Ok(Json(ResidentProcessResponse {
        ok: true,
        resident_process: process,
        operation: None,
    }))
}

pub(crate) async fn stop_resident_process(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((sandbox_id, name)): Path<(Uuid, String)>,
) -> Result<Json<ResidentProcessResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let process = fetch_named_resident_process(&state.db, sandbox_id, &name).await?;
    let sql = format!(
        "update resident_processes set desired_state = 'stopped', updated_at = {}
         where id = {} and tenant_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3)
    );
    sqlx::query(&sql)
        .bind(Utc::now().to_rfc3339())
        .bind(process.id.to_string())
        .bind(&ctx.tenant_id)
        .execute(&state.db.pool)
        .await?;
    get_resident_process(State(state), Extension(ctx), Path((sandbox_id.0, name))).await
}

pub(crate) async fn read_resident_process_bootstrap(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(process_id): Path<Uuid>,
    Json(request): Json<ResidentProcessBootstrapReadRequest>,
) -> Result<Json<ResidentProcessBootstrapReadResponse>, ApiError> {
    let process_id = ResidentProcessId(process_id);
    let process = fetch_resident_process_by_id(&state.db, process_id).await?;
    let Principal::Guest {
        sandbox_id,
        worker_id: _,
    } = ctx.principal
    else {
        return Err(ApiError::unauthorized(
            "resident bootstrap requires a guest credential",
        ));
    };
    if process.tenant_id != ctx.tenant_id || process.sandbox_id != sandbox_id {
        return Err(ApiError::not_found("resident process not found"));
    }
    if process.generation != request.generation
        || process.active_lease_id != Some(request.lease_id)
        || process.bootstrap_sha256.as_deref() != Some(request.expected_sha256.as_str())
    {
        return Err(ApiError::conflict_code(
            "resident_bootstrap_fence_mismatch",
            "resident bootstrap request does not match the active lease",
        ));
    }
    let bootstrap = state
        .resident_bootstraps
        .take(&process_id)
        .ok_or_else(|| ApiError {
            status: StatusCode::GONE,
            code: "resident_bootstrap_unavailable",
            message: "resident bootstrap is unavailable or already consumed".into(),
        })?;
    if bootstrap.generation != process.generation || bootstrap.sha256 != request.expected_sha256 {
        return Err(ApiError::conflict_code(
            "resident_bootstrap_fence_mismatch",
            "resident bootstrap cache does not match the active generation",
        ));
    }
    Ok(Json(ResidentProcessBootstrapReadResponse {
        ok: true,
        content: bootstrap.content,
        sha256: bootstrap.sha256,
        target_file: bootstrap.target_file,
        mode: bootstrap.mode,
    }))
}
