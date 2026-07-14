use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::files::*;
use crate::handlers::leases::*;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::handlers::workers::*;
use crate::pagination::*;
use crate::rows::*;
use crate::state::*;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sha2::Digest;
use sqlx::AnyConnection;
use uuid::Uuid;

pub(crate) async fn create_job(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateJobRequest>,
) -> Result<Json<JobResponse>, ApiError> {
    if request.kind == JobKind::RunCommand {
        validate_run_command_job_input(&request.payload)?;
    }
    if request.kind == JobKind::MaterializeFile {
        validate_materialize_file_job_input(&request.payload)?;
    }
    if request.kind == JobKind::MaterializeFile
        && request.required_capability != WorkerCapability::MaterializeFile
    {
        return Err(ApiError::bad_request(
            "materialize_file requires the materialize_file capability",
        ));
    }
    let now = Utc::now();
    let mut job = Job {
        id: JobId::new(),
        tenant_id: ctx.tenant_id.clone(),
        kind: request.kind,
        status: JobStatus::Queued,
        payload: request.payload,
        required_capability: request.required_capability,
        priority: request.priority.unwrap_or(0),
        attempts: 0,
        max_attempts: request.max_attempts.unwrap_or(3).max(1),
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    validate_job_payload_tenant(&state.db, &job, &ctx).await?;
    enrich_job_payload_with_provision_spec(&state.db, &mut job).await?;
    insert_job(&state.db, &job).await?;
    Ok(Json(JobResponse {
        ok: true,
        job: job.into(),
    }))
}

pub(crate) fn validate_materialize_file_job_input(
    payload: &serde_json::Value,
) -> Result<(), ApiError> {
    let object = payload
        .as_object()
        .ok_or_else(|| ApiError::bad_request("materialization payload must be an object"))?;
    const REQUIRED_KEYS: [&str; 4] = ["sandboxId", "fileId", "destination", "expectedSha256"];
    if object.len() != REQUIRED_KEYS.len()
        || REQUIRED_KEYS.iter().any(|key| !object.contains_key(*key))
    {
        return Err(ApiError::bad_request(
            "materialization payload must contain only sandboxId, fileId, destination, and expectedSha256",
        ));
    }
    let probe = Job {
        id: JobId::new(),
        tenant_id: String::new(),
        kind: JobKind::MaterializeFile,
        status: JobStatus::Queued,
        payload: payload.clone(),
        required_capability: WorkerCapability::MaterializeFile,
        priority: 0,
        attempts: 0,
        max_attempts: 1,
        scheduled_at: Utc::now(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_error: None,
    };
    sandbox_id_from_job(&probe)?;
    file_id_from_job(&probe)?;
    materialization_destination_from_job(&probe)?;
    materialization_digest_from_job(&probe)?;
    Ok(())
}

fn validate_run_command_job_input(payload: &serde_json::Value) -> Result<(), ApiError> {
    let env = payload
        .get("env")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| ApiError::bad_request("job payload env is invalid"))?
        .unwrap_or_default();
    let stdin = payload
        .get("stdin")
        .cloned()
        .map(|value| {
            serde_json::from_value(serde_json::json!({
                "argv": [],
                "cwd": null,
                "env": {},
                "stdin": value,
                "timeout_secs": null
            }))
            .map(|request: AgentCommandRequest| request.stdin)
        })
        .transpose()
        .map_err(|error| {
            if error.to_string().contains("command_stdin_too_large") {
                ApiError::payload_too_large(
                    "command_stdin_too_large",
                    "command stdin exceeds 1048576 bytes",
                )
            } else {
                ApiError::bad_request("job payload stdin is invalid")
            }
        })?
        .flatten();
    validate_command_input(&stdin, &env).map_err(|error| match error {
        CommandExecutionRequestError::StdinTooLarge => ApiError::payload_too_large(
            "command_stdin_too_large",
            "command stdin exceeds 1048576 bytes",
        ),
        CommandExecutionRequestError::EnvironmentContainsNul => {
            ApiError::bad_request(error.to_string())
        }
    })
}

pub(crate) async fn get_job(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobResponse>, ApiError> {
    let job = fetch_job(&state.db, JobId(job_id)).await?;
    ensure_job_tenant(&job, &ctx)?;
    Ok(Json(JobResponse {
        ok: true,
        job: job.into(),
    }))
}

pub(crate) async fn enrich_job_payload_with_provision_spec(
    db: &Database,
    job: &mut Job,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::RunCommand | JobKind::MaterializeFile => {
            let sandbox = fetch_sandbox(db, sandbox_id_from_job(job)?).await?;
            add_provision_spec_to_payload(job, &sandbox)?;
        }
        JobKind::ForkSandbox => {
            let child = fetch_sandbox(db, child_sandbox_id_from_job(job)?).await?;
            add_provision_spec_to_payload(job, &child)?;
        }
        JobKind::RunPrompt
        | JobKind::CreateSnapshot
        | JobKind::StopSandbox
        | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

pub(crate) fn add_provision_spec_to_payload(
    job: &mut Job,
    sandbox: &Sandbox,
) -> Result<(), ApiError> {
    let Some(payload) = job.payload.as_object_mut() else {
        return Err(ApiError::bad_request("job payload must be an object"));
    };
    // This is authoritative control-plane enrichment, not a caller-provided
    // image selector. Profile-bound jobs must stay on the exact worker image
    // that owns the sandbox placement.
    payload.insert("runtimeImage".to_string(), json!(sandbox.template));
    if !payload.contains_key("provisionSpec") {
        payload.insert(
            "provisionSpec".to_string(),
            serde_json::to_value(SandboxProvisionSpec {
                memory_limit: sandbox.memory_limit.clone(),
                network_egress: sandbox.network_egress.clone(),
                workspace_mode: sandbox.workspace_mode.clone(),
                runtime_profile: sandbox.runtime_profile.clone(),
            })?,
        );
    }
    Ok(())
}

pub(crate) async fn validate_job_payload_tenant(
    db: &Database,
    job: &Job,
    ctx: &TenantContext,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
        }
        JobKind::RunCommand => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            let command = fetch_command(db, command_id_from_job(job)?).await?;
            ensure_sandbox_tenant(db, command.sandbox_id, ctx).await?;
        }
        JobKind::MaterializeFile => {
            let sandbox = ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            if sandbox.runtime_profile != SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
                return Err(ApiError::bad_request(
                    "materialize_file requires apex_trusted_supervisor_v1",
                ));
            }
            let file_id = file_id_from_job(job)?;
            let stored = fetch_sandbox_file(db, sandbox.id, file_id).await?;
            let expected = materialization_digest_from_job(job)?;
            let observed = format!("{:x}", sha2::Sha256::digest(&stored.content));
            if expected != observed {
                return Err(ApiError::bad_request(
                    "materialization digest does not match file",
                ));
            }
            materialization_destination_from_job(job)?;
        }
        JobKind::RunPrompt => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
        }
        JobKind::CreateSnapshot => {
            let snapshot = fetch_snapshot(db, snapshot_id_from_job(job)?).await?;
            let sandbox = ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            if snapshot.sandbox_id != sandbox.id {
                return Err(ApiError::bad_request(
                    "snapshot must belong to the referenced sandbox",
                ));
            }
        }
        JobKind::ForkSandbox => {
            ensure_sandbox_tenant(db, parent_sandbox_id_from_job(job)?, ctx).await?;
            ensure_sandbox_tenant(db, child_sandbox_id_from_job(job)?, ctx).await?;
            let snapshot = fetch_snapshot(db, snapshot_id_from_job(job)?).await?;
            ensure_sandbox_tenant(db, snapshot.sandbox_id, ctx).await?;
        }
    }
    Ok(())
}

pub(crate) fn file_id_from_job(job: &Job) -> Result<FileId, ApiError> {
    let value = job
        .payload
        .get("fileId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::bad_request("materialization fileId is required"))?;
    Ok(FileId(Uuid::parse_str(value).map_err(|_| {
        ApiError::bad_request("materialization fileId is invalid")
    })?))
}

pub(crate) fn materialization_digest_from_job(job: &Job) -> Result<&str, ApiError> {
    let value = job
        .payload
        .get("expectedSha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::bad_request("materialization expectedSha256 is required"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ApiError::bad_request(
            "materialization expectedSha256 is invalid",
        ));
    }
    Ok(value)
}

pub(crate) fn materialization_destination_from_job(
    job: &Job,
) -> Result<MaterializeFileDestination, ApiError> {
    serde_json::from_value(
        job.payload
            .get("destination")
            .cloned()
            .ok_or_else(|| ApiError::bad_request("materialization destination is required"))?,
    )
    .map_err(|_| ApiError::bad_request("materialization destination is invalid"))
}

pub(crate) async fn list_jobs(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Query(page): Query<PageParams>,
) -> Result<Json<JobListResponse>, ApiError> {
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;
    let base_sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where tenant_id = {}",
        state.db.placeholder(1)
    );
    let (jobs, next_cursor) = fetch_keyset_page(
        &state.db,
        &base_sql,
        std::slice::from_ref(&ctx.tenant_id),
        limit,
        &cursor,
        row_to_job,
    )
    .await?;

    Ok(Json(JobListResponse {
        ok: true,
        jobs: jobs.into_iter().map(PublicJob::from).collect(),
        next_cursor,
    }))
}

pub(crate) async fn insert_job(db: &Database, job: &Job) -> Result<(), ApiError> {
    let references = job_references(job)?;
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id)
         values ({})",
        db.placeholders(19)
    );
    sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.priority)
        .bind(job.attempts)
        .bind(job.max_attempts)
        .bind(job.scheduled_at.to_rfc3339())
        .bind(job.created_at.to_rfc3339())
        .bind(job.updated_at.to_rfc3339())
        .bind(&job.last_error)
        .bind(references.sandbox_id.map(|id| id.to_string()))
        .bind(references.command_id.map(|id| id.to_string()))
        .bind(references.snapshot_id.map(|id| id.to_string()))
        .bind(references.parent_sandbox_id.map(|id| id.to_string()))
        .bind(references.child_sandbox_id.map(|id| id.to_string()))
        .bind(references.prompt_event_id.map(|id| id.to_string()))
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(crate) async fn insert_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    let references = job_references(job)?;
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id)
         values ({})",
        db.placeholders(19)
    );
    sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.priority)
        .bind(job.attempts)
        .bind(job.max_attempts)
        .bind(job.scheduled_at.to_rfc3339())
        .bind(job.created_at.to_rfc3339())
        .bind(job.updated_at.to_rfc3339())
        .bind(&job.last_error)
        .bind(references.sandbox_id.map(|id| id.to_string()))
        .bind(references.command_id.map(|id| id.to_string()))
        .bind(references.snapshot_id.map(|id| id.to_string()))
        .bind(references.parent_sandbox_id.map(|id| id.to_string()))
        .bind(references.child_sandbox_id.map(|id| id.to_string()))
        .bind(references.prompt_event_id.map(|id| id.to_string()))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

#[derive(Default)]
pub(crate) struct JobReferences {
    pub(crate) sandbox_id: Option<SandboxId>,
    pub(crate) command_id: Option<CommandId>,
    pub(crate) snapshot_id: Option<SnapshotId>,
    pub(crate) parent_sandbox_id: Option<SandboxId>,
    pub(crate) child_sandbox_id: Option<SandboxId>,
    pub(crate) prompt_event_id: Option<EventId>,
}

pub(crate) fn job_references(job: &Job) -> Result<JobReferences, ApiError> {
    let mut references = JobReferences::default();
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
        }
        JobKind::RunCommand => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.command_id = Some(command_id_from_job(job)?);
        }
        JobKind::MaterializeFile => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
        }
        JobKind::RunPrompt => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.prompt_event_id = Some(prompt_event_id_from_job(job)?);
        }
        JobKind::CreateSnapshot => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.snapshot_id = Some(snapshot_id_from_job(job)?);
        }
        JobKind::ForkSandbox => {
            references.parent_sandbox_id = Some(parent_sandbox_id_from_job(job)?);
            references.child_sandbox_id = Some(child_sandbox_id_from_job(job)?);
            references.snapshot_id = Some(snapshot_id_from_job(job)?);
        }
    }
    Ok(references)
}

/// Floor a client-requested lease duration is clamped against. Zero (or
/// negative, once cast) would let a lease expire immediately, so the
/// sweeper could requeue the job before the worker even starts it.
pub(crate) const MIN_LEASE_SECONDS: u64 = 1;

/// Ceiling a client-requested lease duration is clamped against. Without
/// this, a `lease_seconds` value greater than `i64::MAX` wraps to a
/// negative offset when fed to `chrono::Duration::seconds` (an
/// already-expired lease -- the sweeper requeues the job while the first
/// worker is still running it, causing duplicate execution), and values
/// just under that overflow `chrono::Duration::seconds` outright and
/// panic. Mirrors the `effective_command_timeout_secs` clamp in
/// `handlers/commands.rs`.
pub(crate) const MAX_LEASE_SECONDS: u64 = 3600;

/// Default lease duration when a client omits `lease_seconds`.
pub(crate) const DEFAULT_LEASE_SECONDS: u64 = 60;

/// Clamps a client-requested lease duration to
/// `[MIN_LEASE_SECONDS, MAX_LEASE_SECONDS]`, falling back to
/// `DEFAULT_LEASE_SECONDS` when the client omits one. Used by both
/// `try_claim_job` and `renew_lease` so a lease can never be granted (or
/// renewed) for an unbounded -- or, after truncation to `i64`, negative --
/// duration.
pub(crate) fn effective_lease_seconds(requested: Option<u64>) -> u64 {
    requested
        .map(|value| value.clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS))
        .unwrap_or(DEFAULT_LEASE_SECONDS)
}

pub(crate) async fn try_claim_job(
    db: &Database,
    worker: &Worker,
    job: &Job,
    lease_seconds: Option<u64>,
    operation_id: Option<Uuid>,
) -> Result<Option<JobLease>, ApiError> {
    let mut tx = db.pool.begin().await?;
    let claimed = async {
        lock_worker_for_claim_on_connection(db, &mut tx, worker.id).await?;
        let active_leases =
            active_lease_count_for_worker_on_connection(db, &mut tx, worker.id).await?;
        if active_leases >= worker.max_concurrent_jobs {
            return Ok(None);
        }

        let now = Utc::now();
        let attempt = job.attempts + 1;
        let expires_at =
            now + chrono::Duration::seconds(effective_lease_seconds(lease_seconds) as i64);
        let sql = format!(
            "update jobs
             set status = {}, attempts = {}, updated_at = {}
             where id = {} and status = 'queued'",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4)
        );
        let result = sqlx::query(&sql)
            .bind(job_status_to_str(&JobStatus::Leased))
            .bind(attempt)
            .bind(now.to_rfc3339())
            .bind(job.id.to_string())
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }

        let lease = JobLease {
            id: LeaseId::new(),
            job_id: job.id,
            worker_id: worker.id,
            status: LeaseStatus::Active,
            attempt,
            leased_at: now,
            expires_at,
            completed_at: None,
            error: None,
            job: fetch_job_on_connection(db, &mut tx, job.id).await?,
        };
        insert_lease_on_connection(db, &mut tx, &lease).await?;
        bind_sandbox_placement_on_connection(db, &mut tx, &lease.job, worker).await?;
        if let Some(operation_id) = operation_id {
            let sql = format!(
                "insert into lease_claim_operations (worker_id, operation_id, lease_id, created_at)
                 values ({})",
                db.placeholders(4)
            );
            sqlx::query(&sql)
                .bind(worker.id.to_string())
                .bind(operation_id.to_string())
                .bind(lease.id.to_string())
                .bind(now.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }
        apply_claimed_job_on_connection(db, &mut tx, &lease.job).await?;
        let lease = fetch_lease_on_connection(db, &mut tx, lease.id).await?;
        Ok(Some(lease))
    };
    match claimed.await {
        Ok(Some(lease)) => {
            tx.commit().await?;
            Ok(Some(lease))
        }
        Ok(None) => {
            tx.rollback().await?;
            Ok(None)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back lease claim");
            }
            Err(error)
        }
    }
}

async fn bind_sandbox_placement_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    worker: &Worker,
) -> Result<(), ApiError> {
    let sandbox_id = match job.kind {
        JobKind::ProvisionSandbox => Some(sandbox_id_from_job(job)?),
        JobKind::ForkSandbox => Some(child_sandbox_id_from_job(job)?),
        _ => None,
    };
    let Some(sandbox_id) = sandbox_id else {
        return Ok(());
    };
    let now = Utc::now().to_rfc3339();
    let sql = format!(
        "insert into sandbox_placements (sandbox_id, worker_id, provider, cluster, generation, created_at, updated_at)
         values ({})
         on conflict (sandbox_id) do update set worker_id = excluded.worker_id,
           provider = excluded.provider, cluster = excluded.cluster,
           generation = sandbox_placements.generation + 1, updated_at = excluded.updated_at",
        db.placeholders(7)
    );
    sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(worker.id.to_string())
        .bind(&worker.provider)
        .bind(worker.labels.get("cluster"))
        .bind(1_i64)
        .bind(&now)
        .bind(&now)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn lock_worker_for_claim_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    worker_id: WorkerId,
) -> Result<(), ApiError> {
    let sql = format!(
        "update workers
         set last_heartbeat_at = last_heartbeat_at
         where id = {}",
        db.placeholder(1)
    );
    let result = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("worker not found"));
    }
    Ok(())
}

pub(crate) async fn fetch_job(db: &Database, job_id: JobId) -> Result<Job, ApiError> {
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(job_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    row_to_job(row)
}

pub(crate) async fn fetch_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job_id: JobId,
) -> Result<Job, ApiError> {
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(job_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    row_to_job(row)
}

pub(crate) fn uuid_from_job_payload(
    job: &Job,
    key: &'static str,
    missing: &'static str,
) -> Result<Uuid, ApiError> {
    let value = job
        .payload
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::internal(missing))?;
    parse_uuid(value)
}
