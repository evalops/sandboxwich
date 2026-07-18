use crate::activity::bump_sandbox_activity_best_effort;
use crate::auth::{ensure_resident_lease_scope, ensure_sandbox_tenant};
use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::jobs::{add_provision_spec_to_payload, insert_job_on_connection};
use crate::rows::row_to_resident_process;
use crate::state::{
    AppState, LiveResidentBootstrap, Principal, ResidentBootstrapDeliveryError,
    ResidentBootstrapFence, TenantContext,
};
use async_stream::stream;
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::convert::Infallible;
use std::time::Duration;
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

/// Fail-closed gate for issue #176's "sidecar placement primitive": if this
/// sandbox has ever had an `orb-sidecar` resident process configured (a row
/// exists for `(sandbox_id, "orb-sidecar")` -- once configured, this is
/// sticky for the sandbox's lifetime, since a compromised or merely stopped
/// sidecar must not silently lift the requirement it was created to
/// enforce), then reading the *`orb-executor`* workload's one-read bootstrap
/// credential requires that sidecar to be currently observed `Running`.
///
/// This is the one dependent operation v1 gates: sandboxwich's role per
/// evalops/orb#296 is placement plus reusing the one-read bootstrap
/// mechanism to deliver the sidecar's own claim credential, not the
/// egress-proxy/credential-broker tiers (those live in the `orb` repo). The
/// bootstrap read is the single sandboxwich-owned moment where a workload's
/// credential handoff could otherwise proceed silently without its sidecar,
/// so it is what fails loudly here. Other resident-process operations
/// (spawn, observations, stop) for either name are unaffected.
///
/// A missing sidecar row (the sandbox never asked for one) is not a
/// violation -- v1 sidecars are opt-in per sandbox -- so this only returns
/// an error once a sidecar has actually been configured and is not
/// currently healthy.
async fn ensure_sidecar_ready_if_required(
    db: &Database,
    sandbox_id: SandboxId,
    tenant_id: &str,
    process_name: &str,
) -> Result<(), ApiError> {
    if process_name != ORB_EXECUTOR_RESIDENT_PROCESS_NAME {
        return Ok(());
    }
    let sidecar =
        match fetch_named_resident_process(db, sandbox_id, ORB_SIDECAR_RESIDENT_PROCESS_NAME).await
        {
            Ok(sidecar) => sidecar,
            Err(ApiError {
                status: StatusCode::NOT_FOUND,
                ..
            }) => return Ok(()),
            Err(other) => return Err(other),
        };
    if sidecar.tenant_id != tenant_id {
        // Cross-tenant rows should be unreachable given sandbox_id is
        // already tenant-scoped upstream, but never let a foreign row's
        // state gate (or fail to gate) this tenant's bootstrap read.
        return Ok(());
    }
    if sidecar.observed_state != ResidentProcessObservedState::Running {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "resident_sidecar_unavailable",
            message: format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but it is {:?}, \
                 not running; refusing to hand out the orb-executor bootstrap credential",
                sidecar.observed_state
            ),
        });
    }
    let Some(active_lease_id) = sidecar.active_lease_id else {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "resident_sidecar_unavailable",
            message: format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but its running observation has no active lease; refusing to hand out the orb-executor bootstrap credential"
            ),
        });
    };
    let sql = format!(
        "select 1 from job_leases where id = {} and status = 'active' and expires_at > {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let lease_is_live = sqlx::query(&sql)
        .bind(active_lease_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .fetch_optional(&db.pool)
        .await?
        .is_some();
    if !lease_is_live {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "resident_sidecar_unavailable",
            message: format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but its running observation is not backed by a live lease; refusing to hand out the orb-executor bootstrap credential"
            ),
        });
    }
    Ok(())
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
    if !is_supported_resident_process_name(&name) {
        return Err(ApiError::bad_request(
            "the resident-process contract supports only orb-executor and orb-sidecar",
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
    if name == ORB_SIDECAR_RESIDENT_PROCESS_NAME {
        let placement_sql = format!(
            "select w.capabilities
             from sandbox_placements p
             join workers w on w.id = p.worker_id
             where p.sandbox_id = {} and w.tenant_id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2)
        );
        let placed_worker_supports_sidecar = sqlx::query(&placement_sql)
            .bind(sandbox_id.to_string())
            .bind(&sandbox.tenant_id)
            .fetch_optional(&state.db.pool)
            .await?
            .and_then(|row| row.try_get::<String, _>("capabilities").ok())
            .and_then(|raw| serde_json::from_str::<Vec<WorkerCapability>>(&raw).ok())
            .is_some_and(|capabilities| {
                capabilities.contains(&WorkerCapability::ProviderIsolatedResidentProcessV1)
            });
        if !placed_worker_supports_sidecar {
            return Err(ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "resident_sidecar_worker_unsupported",
                message: "orb-sidecar requires its placed worker to advertise provider-isolated resident-process v1 support".into(),
            });
        }
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
            "name": process.name,
            "generation": process.generation,
            "argv": process.argv,
            "cwd": process.cwd,
            "env": process.env,
            "restartPolicy": process.restart_policy,
            "bootstrapSha256": process.bootstrap_sha256,
            "operation": {
                "kind": OperationKind::RunResidentProcess,
                "resourceId": process.id.0,
            }
        }),
        required_capability: if process.name == ORB_SIDECAR_RESIDENT_PROCESS_NAME {
            WorkerCapability::ProviderIsolatedResidentProcessV1
        } else {
            WorkerCapability::RunCommand
        },
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

    let bootstrap_reservation = request
        .bootstrap
        .map(|bootstrap| {
            state.resident_bootstraps.reserve(LiveResidentBootstrap {
                content: bootstrap.content,
                sha256: bootstrap_digest.clone().unwrap_or_default(),
                target_file: bootstrap.target_file,
                mode: bootstrap.mode,
                generation: process.generation,
            })
        })
        .transpose()
        .map_err(|_| ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "resident_bootstrap_capacity",
            message: "resident bootstrap capacity is exhausted".into(),
        })?;

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
    if let Some(reservation) = bootstrap_reservation {
        reservation.publish(process.id);
    }

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
    if !matches!(
        ctx.principal,
        Principal::Guest { .. } | Principal::Worker(_)
    ) {
        return Err(ApiError::unauthorized(
            "resident bootstrap requires a worker or guest credential",
        ));
    }
    if process.tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resident process not found"));
    }
    ensure_resident_lease_scope(&state.db, &process, LeaseId(request.lease_id), &ctx).await?;
    let fence = ResidentBootstrapFence {
        generation: request.generation,
        lease_id: request.lease_id,
        sha256: request.expected_sha256.clone(),
    };
    let delivery = state
        .resident_bootstraps
        .begin_delivery(&process_id, fence.clone())
        .map_err(|error| match error {
            ResidentBootstrapDeliveryError::Unavailable => ApiError {
                status: StatusCode::GONE,
                code: "resident_bootstrap_unavailable",
                message: "resident bootstrap is unavailable or already acknowledged".into(),
            },
            ResidentBootstrapDeliveryError::InFlight => ApiError::conflict_code(
                "resident_bootstrap_delivery_in_flight",
                "resident bootstrap delivery is already in flight",
            ),
            ResidentBootstrapDeliveryError::FenceMismatch => ApiError::conflict_code(
                "resident_bootstrap_fence_mismatch",
                "resident bootstrap was delivered under a different lease fence",
            ),
        })?;
    if delivery.bootstrap().generation != request.generation
        || delivery.bootstrap().sha256 != request.expected_sha256
    {
        return Err(ApiError::conflict_code(
            "resident_bootstrap_fence_mismatch",
            "resident bootstrap cache does not match the active generation",
        ));
    }
    let now = Utc::now();
    let consume_sql = format!(
        "update resident_processes as target
         set bootstrap_consumed_at = coalesce(target.bootstrap_consumed_at, {}),
             bootstrap_delivered_generation = {},
             bootstrap_delivered_lease_id = {},
             bootstrap_delivered_sha256 = {}
         where target.id = {}
           and target.tenant_id = {}
           and target.sandbox_id = {}
           and target.generation = {}
           and target.active_lease_id = {}
           and target.bootstrap_sha256 = {}
           and target.bootstrap_acknowledged_at is null
           and (
             target.bootstrap_consumed_at is null
             or (
               target.bootstrap_delivered_generation = {}
               and target.bootstrap_delivered_lease_id = {}
               and target.bootstrap_delivered_sha256 = {}
             )
           )
           and (
             target.name <> {}
             or not exists (
               select 1 from resident_processes as configured_sidecar
               where configured_sidecar.sandbox_id = target.sandbox_id
                 and configured_sidecar.tenant_id = target.tenant_id
                 and configured_sidecar.name = {}
             )
             or exists (
               select 1
               from resident_processes as ready_sidecar
               join job_leases as live_lease on live_lease.id = ready_sidecar.active_lease_id
               where ready_sidecar.sandbox_id = target.sandbox_id
                 and ready_sidecar.tenant_id = target.tenant_id
                 and ready_sidecar.name = {}
                 and ready_sidecar.observed_state = 'running'
                 and live_lease.status = 'active'
                 and live_lease.expires_at > {}
             )
           )",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6),
        state.db.placeholder(7),
        state.db.placeholder(8),
        state.db.placeholder(9),
        state.db.placeholder(10),
        state.db.placeholder(11),
        state.db.placeholder(12),
        state.db.placeholder(13),
        state.db.placeholder(14),
        state.db.placeholder(15),
        state.db.placeholder(16),
        state.db.placeholder(17),
    );
    let consumed = sqlx::query(&consume_sql)
        .bind(now.to_rfc3339())
        .bind(request.generation as i64)
        .bind(request.lease_id.to_string())
        .bind(&request.expected_sha256)
        .bind(process_id.to_string())
        .bind(&ctx.tenant_id)
        .bind(process.sandbox_id.to_string())
        .bind(request.generation as i64)
        .bind(request.lease_id.to_string())
        .bind(&request.expected_sha256)
        .bind(request.generation as i64)
        .bind(request.lease_id.to_string())
        .bind(&request.expected_sha256)
        .bind(ORB_EXECUTOR_RESIDENT_PROCESS_NAME)
        .bind(ORB_SIDECAR_RESIDENT_PROCESS_NAME)
        .bind(ORB_SIDECAR_RESIDENT_PROCESS_NAME)
        .bind(now.to_rfc3339())
        .execute(&state.db.pool)
        .await?;
    if consumed.rows_affected() != 1 {
        let consumed_sql = format!(
            "select bootstrap_consumed_at, bootstrap_delivered_generation,
                    bootstrap_delivered_lease_id, bootstrap_delivered_sha256,
                    bootstrap_acknowledged_at
             from resident_processes where id = {}",
            state.db.placeholder(1)
        );
        let delivery_row = sqlx::query(&consumed_sql)
            .bind(process_id.to_string())
            .fetch_optional(&state.db.pool)
            .await?;
        let acknowledged_at = delivery_row
            .as_ref()
            .and_then(|row| {
                row.try_get::<Option<String>, _>("bootstrap_acknowledged_at")
                    .ok()
            })
            .flatten();
        if acknowledged_at.is_some() {
            return Err(ApiError {
                status: StatusCode::GONE,
                code: "resident_bootstrap_unavailable",
                message: "resident bootstrap is unavailable or already acknowledged".into(),
            });
        }
        let current = fetch_resident_process_by_id(&state.db, process_id).await?;
        if current.generation != request.generation
            || current.active_lease_id != Some(request.lease_id)
            || current.bootstrap_sha256.as_deref() != Some(request.expected_sha256.as_str())
        {
            return Err(ApiError::conflict_code(
                "resident_bootstrap_fence_mismatch",
                "resident bootstrap request does not match the active lease",
            ));
        }
        if let Some(row) = delivery_row {
            let delivered_generation =
                row.try_get::<Option<i64>, _>("bootstrap_delivered_generation")?;
            let delivered_lease_id =
                row.try_get::<Option<String>, _>("bootstrap_delivered_lease_id")?;
            let delivered_sha256 =
                row.try_get::<Option<String>, _>("bootstrap_delivered_sha256")?;
            if delivered_generation.is_some()
                && (delivered_generation != Some(request.generation as i64)
                    || delivered_lease_id.as_deref() != Some(request.lease_id.to_string().as_str())
                    || delivered_sha256.as_deref() != Some(request.expected_sha256.as_str()))
            {
                return Err(ApiError::conflict_code(
                    "resident_bootstrap_fence_mismatch",
                    "resident bootstrap was delivered under a different lease fence",
                ));
            }
        }
        ensure_sidecar_ready_if_required(
            &state.db,
            process.sandbox_id,
            &current.tenant_id,
            &current.name,
        )
        .await?;
        return Err(ApiError {
            status: StatusCode::GONE,
            code: "resident_bootstrap_unavailable",
            message: "resident bootstrap is unavailable or already consumed".into(),
        });
    }
    let bootstrap = delivery.mark_delivered().map_err(|_| ApiError {
        status: StatusCode::GONE,
        code: "resident_bootstrap_unavailable",
        message: "resident bootstrap was acknowledged while delivery was in flight".into(),
    })?;
    Ok(Json(ResidentProcessBootstrapReadResponse {
        ok: true,
        content: bootstrap.content,
        sha256: bootstrap.sha256,
        target_file: bootstrap.target_file,
        mode: bootstrap.mode,
    }))
}

pub(crate) async fn observe_resident_process(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(process_id): Path<Uuid>,
    Json(request): Json<ResidentProcessObservationRequest>,
) -> Result<Json<ResidentProcessResponse>, ApiError> {
    if request
        .error_message
        .as_ref()
        .is_some_and(|message| message.len() > 1024)
    {
        return Err(ApiError::bad_request(
            "resident process error message exceeds 1024 bytes",
        ));
    }
    let process_id = ResidentProcessId(process_id);
    let process = fetch_resident_process_by_id(&state.db, process_id).await?;
    if !matches!(
        ctx.principal,
        Principal::Guest { .. } | Principal::Worker(_)
    ) {
        return Err(ApiError::unauthorized(
            "resident observations require a worker or guest credential",
        ));
    }
    if process.tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resident process not found"));
    }
    ensure_resident_lease_scope(&state.db, &process, LeaseId(request.lease_id), &ctx).await?;
    if process.generation != request.generation || process.active_lease_id != Some(request.lease_id)
    {
        return Err(ApiError::conflict_code(
            "resident_process_generation_conflict",
            "resident observation does not match the active lease",
        ));
    }
    let now = Utc::now();
    let started_at = matches!(
        request.observed_state,
        ResidentProcessObservedState::Starting | ResidentProcessObservedState::Running
    )
    .then(|| now.to_rfc3339());
    let ready_at =
        (request.observed_state == ResidentProcessObservedState::Running).then(|| now.to_rfc3339());
    let exited_at = matches!(
        request.observed_state,
        ResidentProcessObservedState::Failed
            | ResidentProcessObservedState::Stopped
            | ResidentProcessObservedState::Lost
    )
    .then(|| now.to_rfc3339());
    let last_error = request.error_message.or(request.error_code);
    let sql = format!(
        "update resident_processes
         set bootstrap_acknowledged_at = case
               when {} = 'starting'
                and bootstrap_consumed_at is not null
                and bootstrap_delivered_generation = {}
                and bootstrap_delivered_lease_id = {}
                and bootstrap_delivered_sha256 = bootstrap_sha256
               then coalesce(bootstrap_acknowledged_at, {})
               else bootstrap_acknowledged_at
             end,
             observed_state = {}, pid = {}, exit_code = {}, last_error = {},
             started_at = coalesce(started_at, {}), ready_at = coalesce(ready_at, {}),
             exited_at = {}, updated_at = {}
         where id = {} and generation = {} and active_lease_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6),
        state.db.placeholder(7),
        state.db.placeholder(8),
        state.db.placeholder(9),
        state.db.placeholder(10),
        state.db.placeholder(11),
        state.db.placeholder(12),
        state.db.placeholder(13),
        state.db.placeholder(14),
        state.db.placeholder(15)
    );
    let result = sqlx::query(&sql)
        .bind(request.observed_state.as_db_str())
        .bind(request.generation as i64)
        .bind(request.lease_id.to_string())
        .bind(now.to_rfc3339())
        .bind(request.observed_state.as_db_str())
        .bind(request.pid.map(i64::from))
        .bind(request.exit_code.map(i64::from))
        .bind(last_error)
        .bind(started_at)
        .bind(ready_at)
        .bind(exited_at)
        .bind(now.to_rfc3339())
        .bind(process_id.to_string())
        .bind(request.generation as i64)
        .bind(request.lease_id.to_string())
        .execute(&state.db.pool)
        .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::conflict_code(
            "resident_process_generation_conflict",
            "resident process changed while applying observation",
        ));
    }
    if request.observed_state == ResidentProcessObservedState::Starting
        && let Some(sha256) = process.bootstrap_sha256.as_ref()
    {
        let ack_sql = format!(
            "select bootstrap_acknowledged_at from resident_processes where id = {}",
            state.db.placeholder(1)
        );
        let acknowledged = sqlx::query(&ack_sql)
            .bind(process_id.to_string())
            .fetch_optional(&state.db.pool)
            .await?
            .and_then(|row| {
                row.try_get::<Option<String>, _>("bootstrap_acknowledged_at")
                    .ok()
            })
            .flatten()
            .is_some();
        if acknowledged {
            state.resident_bootstraps.acknowledge(
                &process_id,
                &ResidentBootstrapFence {
                    generation: request.generation,
                    lease_id: request.lease_id,
                    sha256: sha256.clone(),
                },
            );
        }
    }
    // The guest reports observations periodically for as long as the
    // resident process is alive -- a real, repeating heartbeat and one of
    // the idle-TTL activity signals. Best-effort: must not fail this
    // request (the guest's ack) if the bump itself fails.
    bump_sandbox_activity_best_effort(&state.db, process.sandbox_id, now).await;
    let process = fetch_resident_process_by_id(&state.db, process_id).await?;
    Ok(Json(ResidentProcessResponse {
        ok: true,
        resident_process: process,
        operation: None,
    }))
}

pub(crate) async fn resident_process_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((sandbox_id, name)): Path<(Uuid, String)>,
) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let initial = fetch_named_resident_process(&state.db, sandbox_id, &name).await?;
    let db = state.db.clone();
    let process_id = initial.id;
    let tenant_id = ctx.tenant_id;
    let output = stream! {
        let mut last_updated = None;
        loop {
            let process = fetch_resident_process_by_id(&db, process_id).await;
            let Ok(process) = process else { break; };
            if process.tenant_id != tenant_id { break; }
            let event_id = process.updated_at.to_rfc3339();
            if last_updated.as_deref() != Some(event_id.as_str()) {
                let data = serde_json::to_string(&process).unwrap_or_else(|_| "{}".into());
                yield Ok(Event::default().id(event_id.clone()).event("resident_process").data(data));
                last_updated = Some(event_id);
            }
            if matches!(
                process.observed_state,
                ResidentProcessObservedState::Failed
                    | ResidentProcessObservedState::Stopped
                    | ResidentProcessObservedState::Lost
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    Ok(Sse::new(output).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
