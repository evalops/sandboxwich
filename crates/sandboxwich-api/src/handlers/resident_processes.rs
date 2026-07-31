use crate::activity::bump_sandbox_activity_best_effort;
use crate::auth::{ensure_lease_worker_scope, ensure_resident_lease_scope, ensure_sandbox_tenant};
use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::commands::{insert_event, insert_event_on_connection};
use crate::handlers::jobs::{add_provision_spec_to_payload, insert_job_on_connection};
use crate::handlers::resident_attestations::{
    issue_resident_placement_attestation, record_provider_pod_identity,
};
use crate::rows::{parse_timestamp, row_to_job, row_to_resident_process};
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

#[derive(Clone, Copy)]
enum SidecarBootstrapBlockReason {
    NotRunning,
    NoActiveLease,
    InactiveLease,
    ExpiredLease,
}

impl SidecarBootstrapBlockReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotRunning => "not_running",
            Self::NoActiveLease => "no_active_lease",
            Self::InactiveLease => "inactive_lease",
            Self::ExpiredLease => "expired_lease",
        }
    }
}

async fn block_executor_bootstrap(
    db: &Database,
    sidecar: &ResidentProcess,
    reason: SidecarBootstrapBlockReason,
    message: String,
) -> Result<(), ApiError> {
    let telemetry_result = async {
        let mut tx = db.pool.begin().await?;
        insert_event_on_connection(
            db,
            &mut tx,
            sidecar.sandbox_id,
            SandboxEventKind::LifecycleChanged,
            json!({
                "eventType": "sidecar_bootstrap_blocked",
                "reason": reason.as_str(),
                "processName": ORB_SIDECAR_RESIDENT_PROCESS_NAME,
                "generation": sidecar.generation,
            }),
        )
        .await?;
        let sql = format!(
            "insert into sidecar_bootstrap_block_rollups (tenant_id, reason, total)
             values ({})
             on conflict (tenant_id, reason) do update
             set total = sidecar_bootstrap_block_rollups.total + 1",
            db.placeholders(3)
        );
        sqlx::query(&sql)
            .bind(&sidecar.tenant_id)
            .bind(reason.as_str())
            .bind(1_i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<(), ApiError>(())
    }
    .await;
    if let Err(error) = telemetry_result {
        // Telemetry cannot weaken the fail-closed boundary: preserve the
        // original 503. The transaction also ensures an event and its
        // durable metric increment either both persist or both roll back.
        tracing::warn!(
            ?error,
            reason = reason.as_str(),
            process_name = ORB_SIDECAR_RESIDENT_PROCESS_NAME,
            generation = sidecar.generation,
            "failed to persist sidecar bootstrap block event"
        );
    }
    Err(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "resident_sidecar_unavailable",
        message,
    })
}

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

async fn provider_isolation_version(
    db: &Database,
    process_id: ResidentProcessId,
) -> Result<u32, ApiError> {
    let sql = format!(
        "select provider_isolation_version from resident_processes where id = {}",
        db.placeholder(1)
    );
    let version: i64 = sqlx::query_scalar(&sql)
        .bind(process_id.to_string())
        .fetch_one(&db.pool)
        .await?;
    u32::try_from(version)
        .map_err(|_| ApiError::internal("database contains invalid provider isolation version"))
}

fn supported_provider_isolation_version(version: u32) -> bool {
    matches!(
        version,
        PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_V1 | PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION
    )
}

async fn placed_worker_supports_provider_isolated_resident_process(
    db: &Database,
    sandbox_id: SandboxId,
    tenant_id: &str,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select w.labels
         from sandbox_placements p
         join workers w on w.id = p.worker_id
         where p.sandbox_id = {} and w.tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let labels = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(tenant_id)
        .fetch_optional(&db.pool)
        .await?
        .and_then(|row| row.try_get::<String, _>("labels").ok())
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    Ok(labels
        .as_ref()
        .and_then(|labels| labels.get(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL))
        .and_then(serde_json::Value::as_str)
        == Some(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL_VALUE))
}

/// Claim-time readiness probe for an executor job. It is deliberately free
/// of telemetry side effects because guests poll this path: a configured
/// sidecar defers the claim until the provider-isolated row is Running under
/// its current active, unexpired lease. Returning before `try_claim_job`
/// preserves the executor job's attempt budget while the sidecar starts.
pub(crate) async fn executor_sidecar_is_ready_for_claim(
    db: &Database,
    sandbox_id: SandboxId,
    tenant_id: &str,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select rp.tenant_id, rp.provider_isolation_version, rp.desired_state,
                rp.observed_state,
                jl.status as lease_status, jl.expires_at as lease_expires_at
         from resident_processes rp
         left join job_leases jl on jl.id = rp.active_lease_id
         where rp.sandbox_id = {} and rp.name = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(ORB_SIDECAR_RESIDENT_PROCESS_NAME)
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(true);
    };
    let row_tenant_id: String = row.try_get("tenant_id")?;
    let isolation_version: i64 = row.try_get("provider_isolation_version")?;
    let desired_state: String = row.try_get("desired_state")?;
    let observed_state: String = row.try_get("observed_state")?;
    let lease_status: Option<String> = row.try_get("lease_status")?;
    let lease_expires_at: Option<String> = row.try_get("lease_expires_at")?;
    Ok(row_tenant_id == tenant_id
        && u32::try_from(isolation_version).is_ok_and(supported_provider_isolation_version)
        && desired_state == ResidentProcessDesiredState::Running.as_db_str()
        && observed_state == ResidentProcessObservedState::Running.as_db_str()
        && lease_status.as_deref() == Some(LeaseStatus::Active.as_db_str())
        && lease_expires_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?
            .is_some_and(|expires_at| expires_at > Utc::now()))
}

fn ensure_resident_owner_role(
    process: &ResidentProcess,
    ctx: &TenantContext,
) -> Result<(), ApiError> {
    let owns_role = match (&process.name, ctx.principal) {
        (name, Principal::Worker(_)) if name == ORB_SIDECAR_RESIDENT_PROCESS_NAME => true,
        (name, Principal::Guest { sandbox_id, .. })
            if name == ORB_EXECUTOR_RESIDENT_PROCESS_NAME && sandbox_id == process.sandbox_id =>
        {
            true
        }
        _ => false,
    };
    if !owns_role {
        return Err(ApiError::unauthorized(
            "resident process credential does not own this process role",
        ));
    }
    Ok(())
}

async fn delivered_bootstrap_fence(
    db: &Database,
    process_id: ResidentProcessId,
) -> Result<Option<ResidentBootstrapFence>, ApiError> {
    let sql = format!(
        "select bootstrap_delivered_generation, bootstrap_delivered_lease_id,
                bootstrap_delivered_sha256
         from resident_processes where id = {}",
        db.placeholder(1)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(process_id.to_string())
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(None);
    };
    let generation = row.try_get::<Option<i64>, _>("bootstrap_delivered_generation")?;
    let lease_id = row.try_get::<Option<String>, _>("bootstrap_delivered_lease_id")?;
    let sha256 = row.try_get::<Option<String>, _>("bootstrap_delivered_sha256")?;
    match (generation, lease_id, sha256) {
        (Some(generation), Some(lease_id), Some(sha256)) => Ok(Some(ResidentBootstrapFence {
            generation: u64::try_from(generation).map_err(|_| {
                ApiError::internal("database contains invalid delivered bootstrap generation")
            })?,
            lease_id: Uuid::parse_str(&lease_id).map_err(|_| {
                ApiError::internal("database contains invalid delivered bootstrap lease")
            })?,
            sha256,
        })),
        (None, None, None) => Ok(None),
        _ => Err(ApiError::internal(
            "database contains incomplete delivered bootstrap fence",
        )),
    }
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
    if !supported_provider_isolation_version(provider_isolation_version(db, sidecar.id).await?) {
        return block_executor_bootstrap(
            db,
            &sidecar,
            SidecarBootstrapBlockReason::NotRunning,
            format!(
                "sandbox {sandbox_id} has an orb-sidecar resident process that was not admitted under a supported provider-isolation contract; refusing to hand out the orb-executor bootstrap credential"
            ),
        )
        .await;
    }
    if sidecar.desired_state != ResidentProcessDesiredState::Running {
        return block_executor_bootstrap(
            db,
            &sidecar,
            SidecarBootstrapBlockReason::NotRunning,
            format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but it no longer desires Running; refusing to hand out the orb-executor bootstrap credential"
            ),
        )
        .await;
    }
    if sidecar.observed_state != ResidentProcessObservedState::Running {
        return block_executor_bootstrap(
            db,
            &sidecar,
            SidecarBootstrapBlockReason::NotRunning,
            format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but it is {:?}, \
                 not running; refusing to hand out the orb-executor bootstrap credential",
                sidecar.observed_state
            ),
        )
        .await;
    }
    let Some(active_lease_id) = sidecar.active_lease_id else {
        return block_executor_bootstrap(
            db,
            &sidecar,
            SidecarBootstrapBlockReason::NoActiveLease,
            format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but its running observation has no active lease; refusing to hand out the orb-executor bootstrap credential"
            ),
        )
        .await;
    };
    let sql = format!(
        "select status, expires_at from job_leases where id = {}",
        db.placeholder(1)
    );
    let lease = sqlx::query(&sql)
        .bind(active_lease_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    let reason = match lease {
        None => Some(SidecarBootstrapBlockReason::InactiveLease),
        Some(row) => {
            let status: String = row.try_get("status")?;
            let expires_at: String = row.try_get("expires_at")?;
            if status != LeaseStatus::Active.as_db_str() {
                Some(SidecarBootstrapBlockReason::InactiveLease)
            } else if parse_timestamp(&expires_at)? <= Utc::now() {
                Some(SidecarBootstrapBlockReason::ExpiredLease)
            } else {
                None
            }
        }
    };
    if let Some(reason) = reason {
        return block_executor_bootstrap(
            db,
            &sidecar,
            reason,
            format!(
                "sandbox {sandbox_id} requires an orb-sidecar resident process but its running observation is not backed by a live lease; refusing to hand out the orb-executor bootstrap credential"
            ),
        )
        .await;
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

#[utoipa::path(
    put,
    path = "/v1/sandboxes/{sandbox_id}/resident-processes/{name}",
    params(("sandbox_id" = Uuid, Path), ("name" = String, Path, description = "Typed resident name; orb-sidecar requires a non-empty bootstrap")),
    request_body = ResidentProcessRequest,
    responses(
        (status = 200, description = "Existing resident process returned for an idempotent same-spec request", body = ResidentProcessResponse),
        (status = 202, description = "Resident process accepted", body = ResidentProcessResponse),
        (status = 400, description = "Invalid request, including a missing or empty orb-sidecar bootstrap", body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope),
        (status = 503, description = "Bootstrap admission capacity exhausted", body = ErrorEnvelope)
    )
)]
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
    if name == ORB_SIDECAR_RESIDENT_PROCESS_NAME
        && request
            .bootstrap
            .as_ref()
            .is_none_or(|bootstrap| bootstrap.content.is_empty())
    {
        return Err(ApiError::bad_request(
            "orb-sidecar requires a non-empty bootstrap credential",
        ));
    }
    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    if name == ORB_SIDECAR_RESIDENT_PROCESS_NAME
        && !placed_worker_supports_provider_isolated_resident_process(
            &state.db,
            sandbox_id,
            &sandbox.tenant_id,
        )
        .await?
    {
        return Err(ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "resident_sidecar_worker_unsupported",
            message: "orb-sidecar requires its placed worker to advertise provider-isolated resident-process v2 support".into(),
        });
    }
    let bootstrap_digest = request
        .bootstrap
        .as_ref()
        .map(|bootstrap| format!("{:x}", Sha256::digest(&bootstrap.content)));

    if let Ok(current) = fetch_named_resident_process(&state.db, sandbox_id, &name).await {
        if name == ORB_SIDECAR_RESIDENT_PROCESS_NAME
            && !supported_provider_isolation_version(
                provider_isolation_version(&state.db, current.id).await?,
            )
        {
            return Err(ApiError::conflict_code(
                "resident_sidecar_isolation_upgrade_required",
                "the existing orb-sidecar predates supported provider isolation and cannot be reused",
            ));
        }
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

    let bootstrap_reservation = request
        .bootstrap
        .map(|bootstrap| {
            state.resident_bootstraps.reserve(LiveResidentBootstrap {
                tenant_id: process.tenant_id.clone(),
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
            provider_isolation_version,
            created_at, updated_at
         ) values ({})",
        state.db.placeholders(18)
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
        .bind(if process.name == ORB_SIDECAR_RESIDENT_PROCESS_NAME {
            i64::from(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION)
        } else {
            0
        })
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
    let delivered_fence = delivered_bootstrap_fence(&state.db, process.id).await?;
    let now = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let queued_jobs_sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability,
                required_execution_class, priority, attempts, max_attempts, scheduled_at,
                created_at, updated_at, last_error
         from jobs where tenant_id = {} and kind = 'run_resident_process' and status = 'queued'",
        state.db.placeholder(1)
    );
    let queued_jobs = sqlx::query(&queued_jobs_sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&mut *tx)
        .await?;
    let process_id_string = process.id.to_string();
    let queued_job = queued_jobs
        .into_iter()
        .map(row_to_job)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|job| {
            job.payload
                .get("residentProcessId")
                .and_then(serde_json::Value::as_str)
                == Some(process_id_string.as_str())
        });
    let stopped_before_claim = if let Some(job) = queued_job {
        let sql = format!(
            "update jobs set status = 'succeeded', updated_at = {}, last_error = null
             where id = {} and status = 'queued'",
            state.db.placeholder(1),
            state.db.placeholder(2)
        );
        sqlx::query(&sql)
            .bind(now.to_rfc3339())
            .bind(job.id.to_string())
            .execute(&mut *tx)
            .await?
            .rows_affected()
            == 1
    } else {
        false
    };
    let sql = format!(
        "update resident_processes
         set desired_state = 'stopped',
             observed_state = case when {} then 'stopped' else observed_state end,
             exit_code = case when {} then 0 else exit_code end,
             bootstrap_acknowledged_at = case
               when bootstrap_delivered_generation is not null
                and bootstrap_delivered_lease_id is not null
                and bootstrap_delivered_sha256 is not null
               then coalesce(bootstrap_acknowledged_at, {})
               else bootstrap_acknowledged_at
             end,
             updated_at = {}
         where id = {} and tenant_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6)
    );
    sqlx::query(&sql)
        .bind(stopped_before_claim)
        .bind(stopped_before_claim)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(process.id.to_string())
        .bind(&ctx.tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some(sha256) = process.bootstrap_sha256.as_deref() {
        state.resident_bootstraps.reclaim(
            &process.id,
            process.generation,
            sha256,
            delivered_fence.as_ref(),
        );
    }
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
    if process.tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resident process not found"));
    }
    ensure_resident_owner_role(&process, &ctx)?;
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
                 and ready_sidecar.provider_isolation_version in ({}, {})
                 and ready_sidecar.desired_state = 'running'
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
        state.db.placeholder(18),
        state.db.placeholder(19),
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
        .bind(i64::from(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_V1))
        .bind(i64::from(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION))
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
    let placement_attestation = if process.name == ORB_SIDECAR_RESIDENT_PROCESS_NAME
        && provider_isolation_version(&state.db, process.id).await?
            == PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION
    {
        issue_resident_placement_attestation(
            &state,
            &ctx.tenant_id,
            process.sandbox_id,
            process.id,
            request.generation,
            request.lease_id,
        )
        .await?
    } else {
        None
    };
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
        placement_attestation,
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
    if process.tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resident process not found"));
    }
    ensure_resident_owner_role(&process, &ctx)?;
    if request.observed_state == ResidentProcessObservedState::Stopped
        && process.desired_state == ResidentProcessDesiredState::Stopped
        && process.observed_state == ResidentProcessObservedState::Stopped
        && process.generation == request.generation
        && process.active_lease_id.is_none()
    {
        let lease = ensure_lease_worker_scope(&state.db, LeaseId(request.lease_id), &ctx).await?;
        let matching_process = lease
            .job
            .payload
            .get("residentProcessId")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            == Some(process.id.0);
        let matching_generation = lease
            .job
            .payload
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            == Some(request.generation);
        if lease.job.kind == JobKind::RunResidentProcess
            && matching_process
            && matching_generation
            && lease.job.status == JobStatus::Succeeded
        {
            return Ok(Json(ResidentProcessResponse {
                ok: true,
                resident_process: process,
                operation: None,
            }));
        }
    }
    ensure_resident_lease_scope(&state.db, &process, LeaseId(request.lease_id), &ctx).await?;
    if process.generation != request.generation || process.active_lease_id != Some(request.lease_id)
    {
        return Err(ApiError::conflict_code(
            "resident_process_generation_conflict",
            "resident observation does not match the active lease",
        ));
    }
    if process.name == ORB_SIDECAR_RESIDENT_PROCESS_NAME
        && provider_isolation_version(&state.db, process.id).await?
            == PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION
        && matches!(
            request.observed_state,
            ResidentProcessObservedState::Starting | ResidentProcessObservedState::Running
        )
    {
        let pod_name = request.provider_pod_name.as_deref().ok_or_else(|| {
            ApiError::bad_request("provider-isolated sidecar observation requires providerPodName")
        })?;
        let pod_uid = request.provider_pod_uid.as_deref().ok_or_else(|| {
            ApiError::bad_request("provider-isolated sidecar observation requires providerPodUid")
        })?;
        record_provider_pod_identity(
            &state.db,
            &ctx.tenant_id,
            process.id,
            request.generation,
            request.lease_id,
            pod_name,
            pod_uid,
        )
        .await?;
    }
    let now = Utc::now();
    let terminal_failure = matches!(
        request.observed_state,
        ResidentProcessObservedState::Failed | ResidentProcessObservedState::Lost
    ) && process.observed_state != request.observed_state;
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
               when {} in ('starting', 'running', 'failed', 'stopped', 'lost')
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
    if terminal_failure
        && let Err(error) = insert_event(
            &state.db,
            process.sandbox_id,
            SandboxEventKind::LifecycleChanged,
            json!({
                "eventType": "resident_process_terminal_failure",
                "processName": process.name,
                "generation": request.generation,
                "observedState": request.observed_state.as_db_str(),
            }),
        )
        .await
    {
        // The observation is already durable. Returning 500 would invite
        // a retry whose identical state no longer qualifies for an event,
        // so telemetry failure is explicitly non-disruptive.
        tracing::warn!(
            ?error,
            process_name = %process.name,
            generation = request.generation,
            observed_state = request.observed_state.as_db_str(),
            "failed to persist resident terminal failure event"
        );
    }
    if matches!(
        request.observed_state,
        ResidentProcessObservedState::Starting
            | ResidentProcessObservedState::Running
            | ResidentProcessObservedState::Failed
            | ResidentProcessObservedState::Stopped
            | ResidentProcessObservedState::Lost
    ) && let Some(sha256) = process.bootstrap_sha256.as_ref()
    {
        let fence = ResidentBootstrapFence {
            generation: request.generation,
            lease_id: request.lease_id,
            sha256: sha256.clone(),
        };
        if matches!(
            request.observed_state,
            ResidentProcessObservedState::Failed
                | ResidentProcessObservedState::Stopped
                | ResidentProcessObservedState::Lost
        ) {
            state.resident_bootstraps.reclaim(
                &process_id,
                request.generation,
                sha256,
                Some(&fence),
            );
        }
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
            state.resident_bootstraps.acknowledge(&process_id, &fence);
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
