use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::files::*;
use crate::handlers::leases::*;
use crate::handlers::sandboxes::*;
use crate::handlers::secrets::{
    fetch_sandbox_secret_mounts, fetch_sandbox_secret_mounts_on_connection,
};
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
use sqlx::Row;
use uuid::Uuid;

pub(crate) async fn create_job(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateJobRequest>,
) -> Result<Json<JobResponse>, ApiError> {
    if request.kind == JobKind::ApexTaskInstructions {
        return Err(ApiError::bad_request(
            "apex_task_instructions jobs can only be created by the live instruction endpoint",
        ));
    }
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
    validate_functional_required_capability(&request.required_capability)?;
    let now = Utc::now();
    let mut job = Job {
        id: JobId::new(),
        tenant_id: ctx.tenant_id.clone(),
        kind: request.kind,
        status: JobStatus::Queued,
        payload: request.payload,
        required_capability: request.required_capability,
        required_execution_class: ExecutionClass::DevelopmentContainer,
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
    const BASE_KEYS: [&str; 4] = ["sandboxId", "fileId", "destination", "expectedSha256"];
    if BASE_KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(ApiError::bad_request(
            "materialization payload is missing a required field",
        ));
    }
    let probe = Job {
        id: JobId::new(),
        tenant_id: String::new(),
        kind: JobKind::MaterializeFile,
        status: JobStatus::Queued,
        payload: payload.clone(),
        required_capability: WorkerCapability::MaterializeFile,
        required_execution_class: ExecutionClass::DevelopmentContainer,
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
    let destination = materialization_destination_from_job(&probe)?;
    materialization_digest_from_job(&probe)?;
    let expected_len = if destination == MaterializeFileDestination::CompilerCacheArchive {
        compiler_cache_identity_from_job(&probe)?;
        BASE_KEYS.len() + 1
    } else {
        BASE_KEYS.len()
    };
    if object.len() != expected_len
        || (destination != MaterializeFileDestination::CompilerCacheArchive
            && object.contains_key("compilerCacheIdentity"))
    {
        return Err(ApiError::bad_request(
            "materialization payload contains fields outside its destination contract",
        ));
    }
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

fn validate_functional_required_capability(capability: &WorkerCapability) -> Result<(), ApiError> {
    match capability {
        WorkerCapability::SandboxedContainer | WorkerCapability::VirtualMachine => {
            Err(ApiError::bad_request(
                "required_capability must be a functional worker capability; isolation is selected by the sandbox execution_class",
            ))
        }
        WorkerCapability::ProvisionSandbox
        | WorkerCapability::RunCommand
        | WorkerCapability::UidIsolatedResidentProcess
        | WorkerCapability::MaterializeFile
        | WorkerCapability::ApexTaskInstructions
        | WorkerCapability::AgentPrompt
        | WorkerCapability::Snapshot
        | WorkerCapability::DesktopStream
        | WorkerCapability::K8sPod
        | WorkerCapability::GvisorSandbox
        | WorkerCapability::FqdnEgress
        | WorkerCapability::ApexTrustedSupervisorV1 => Ok(()),
    }
}

pub(crate) async fn get_job(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobResponse>, ApiError> {
    let job = fetch_job(&state.db, JobId(job_id)).await?;
    ensure_job_tenant(&job, &ctx)?;
    if job
        .payload
        .get(crate::sterile_pool::POOL_JOB_MARKER)
        .is_some()
    {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(Json(JobResponse {
        ok: true,
        job: job.into(),
    }))
}

/// Per-claim-poll cache of sandbox placement inputs so a 200-candidate scan
/// does not re-fetch the same sandbox + secret mounts for every job that
/// points at one sandbox (common when many stop/command jobs share a pool).
///
/// `expected_provision_spec` is the control-plane JSON that
/// [`add_provision_spec_to_payload`] would write, so match checks are a Value
/// equality rather than deserializing full specs per candidate.
#[derive(Clone)]
pub(crate) struct PlacementCacheEntry {
    pub sandbox: Sandbox,
    pub secret_mounts: Vec<SandboxSecretMount>,
    pub expected_provision_spec: serde_json::Value,
    /// The server-owned provider selected for an already-placed sandbox.
    /// `None` is intentional for a pre-placement provision job, where the
    /// request's explicit preference remains authoritative until placement.
    pub provider_preference: Option<ProviderPreference>,
    pub provider_external_id: Option<String>,
    pub provider_routing_scope: Option<String>,
    pub sterile_pool_candidate: Option<SterilePoolCandidateV1>,
}

pub(crate) type PlacementEnrichmentCache =
    std::collections::HashMap<SandboxId, PlacementCacheEntry>;

pub(crate) async fn enrich_job_payload_with_provision_spec(
    db: &Database,
    job: &mut Job,
) -> Result<bool, ApiError> {
    let mut cache = PlacementEnrichmentCache::new();
    enrich_job_payload_with_provision_spec_cached(db, job, &mut cache).await
}

/// Authoritatively align `job` placement fields with the live sandbox.
///
/// Returns `true` when the job was mutated. Claim polls use that signal to
/// skip a no-op writer UPDATE without cloning the full payload JSON for
/// equality (the previous hot path when scanning up to 200 candidates).
pub(crate) async fn enrich_job_payload_with_provision_spec_cached(
    db: &Database,
    job: &mut Job,
    cache: &mut PlacementEnrichmentCache,
) -> Result<bool, ApiError> {
    match job.kind {
        JobKind::ProvisionSandbox
        | JobKind::RunCommand
        | JobKind::RunResidentProcess
        | JobKind::RunPrompt
        | JobKind::CreateSnapshot
        | JobKind::StopSandbox
        | JobKind::ResumeSandbox
        | JobKind::MaterializeFile
        | JobKind::ApexTaskInstructions => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let entry = load_sandbox_placement_inputs(db, sandbox_id, cache).await?;
            Ok(apply_sandbox_placement(job, &entry)?)
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let entry = load_sandbox_placement_inputs(db, child_id, cache).await?;
            Ok(apply_sandbox_placement(job, &entry)?)
        }
        JobKind::DeleteHome => Ok(false),
    }
}

/// Returns `true` when payload or execution class needed repair.
fn apply_sandbox_placement(job: &mut Job, entry: &PlacementCacheEntry) -> Result<bool, ApiError> {
    if placement_matches_sandbox(job, entry) {
        return Ok(false);
    }
    job.required_execution_class = entry.sandbox.execution_class.clone();
    let requested_provider_preference = job
        .payload
        .get("provisionSpec")
        .cloned()
        .and_then(|value| serde_json::from_value::<SandboxProvisionSpec>(value).ok())
        .map(|spec| spec.provider_preference)
        .unwrap_or_default();
    let provider_preference = entry
        .provider_preference
        .clone()
        .unwrap_or(requested_provider_preference);
    add_provision_spec_to_payload_with_identity(
        job,
        &entry.sandbox,
        &entry.secret_mounts,
        provider_preference,
        entry.provider_external_id.clone(),
        entry.provider_routing_scope.clone(),
    )?;
    let payload = job
        .payload
        .as_object_mut()
        .ok_or_else(|| ApiError::internal("job payload is not an object"))?;
    let mut spec: SandboxProvisionSpec = serde_json::from_value(
        payload
            .get("provisionSpec")
            .cloned()
            .ok_or_else(|| ApiError::internal("job provisionSpec is missing"))?,
    )?;
    // Pool candidacy is control-plane state, never a tenant-provided hint.
    // Assigning `None` is important: it strips forged or stale markers from
    // ordinary provision jobs before they can reach a provider.
    spec.sterile_pool_candidate = entry.sterile_pool_candidate.clone();
    payload.insert("provisionSpec".into(), serde_json::to_value(spec)?);
    Ok(true)
}

/// True when the job already carries the control-plane placement that would
/// be written for this sandbox. Forged or partial payloads fail this check
/// and are repaired by [`apply_sandbox_placement`].
pub(crate) fn placement_matches_sandbox(job: &Job, entry: &PlacementCacheEntry) -> bool {
    if job.required_execution_class != entry.sandbox.execution_class {
        return false;
    }
    let Some(image) = job
        .payload
        .get("runtimeImage")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    if image != entry.sandbox.template {
        return false;
    }
    let Some(actual) = job.payload.get("provisionSpec").cloned() else {
        return false;
    };
    let Ok(actual) = serde_json::from_value::<SandboxProvisionSpec>(actual) else {
        return false;
    };
    let Ok(mut expected) =
        serde_json::from_value::<SandboxProvisionSpec>(entry.expected_provision_spec.clone())
    else {
        return false;
    };
    if entry.provider_preference.is_none() {
        expected.provider_preference = actual.provider_preference.clone();
    }
    let Ok(actual) = serde_json::to_value(actual) else {
        return false;
    };
    serde_json::to_value(expected).ok() == Some(actual)
}

/// Test helper: build a cache entry and check placement without a DB.
#[cfg(test)]
pub(crate) fn placement_matches_sandbox_parts(
    job: &Job,
    sandbox: &Sandbox,
    secret_mounts: &[SandboxSecretMount],
) -> bool {
    let Ok(expected) = expected_provision_spec_value(sandbox, secret_mounts) else {
        return false;
    };
    placement_matches_sandbox(
        job,
        &PlacementCacheEntry {
            sandbox: sandbox.clone(),
            secret_mounts: secret_mounts.to_vec(),
            expected_provision_spec: expected,
            provider_preference: None,
            provider_external_id: None,
            provider_routing_scope: None,
            sterile_pool_candidate: None,
        },
    )
}

#[cfg(test)]
fn expected_provision_spec_value(
    sandbox: &Sandbox,
    secret_mounts: &[SandboxSecretMount],
) -> Result<serde_json::Value, ApiError> {
    Ok(serde_json::to_value(SandboxProvisionSpec {
        secret_mounts: secret_mounts.to_vec(),
        execution_class: sandbox.execution_class.clone(),
        memory_limit: sandbox.memory_limit.clone(),
        network_egress: sandbox.network_egress.clone(),
        workspace_mode: sandbox.workspace_mode.clone(),
        runtime_profile: sandbox.runtime_profile.clone(),
        tenant_id: Some(sandbox.tenant_id.clone()),
        ..SandboxProvisionSpec::default()
    })?)
}

async fn load_sandbox_placement_inputs(
    db: &Database,
    sandbox_id: SandboxId,
    cache: &mut PlacementEnrichmentCache,
) -> Result<PlacementCacheEntry, ApiError> {
    if let Some(entry) = cache.get(&sandbox_id) {
        return Ok(entry.clone());
    }
    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    let secret_mounts = fetch_sandbox_secret_mounts(db, sandbox.id).await?;
    let resource_sql = format!(
        "select resource_name, namespace from runtime_resources where sandbox_id = {} and snapshot_id is null and provider = 'cloudflare' order by updated_at desc limit 1",
        db.placeholder(1)
    );
    let identity = sqlx::query(&resource_sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?;
    let provider_external_id = identity
        .as_ref()
        .and_then(|row| row.try_get("resource_name").ok());
    let provider_routing_scope = identity
        .as_ref()
        .and_then(|row| row.try_get("namespace").ok());
    let placement_sql = format!(
        "select provider from sandbox_placements where sandbox_id = {} order by updated_at desc limit 1",
        db.placeholder(1)
    );
    let placement_provider = sqlx::query(&placement_sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .map(|row| row.try_get::<String, _>("provider"))
        .transpose()?;
    let provider_preference = placement_provider
        .as_deref()
        .map(|provider| match provider.to_ascii_lowercase().as_str() {
            "agent_sandbox" => Ok(ProviderPreference::AgentSandbox),
            "cloudflare" => Ok(ProviderPreference::Cloudflare),
            "kubernetes" => Ok(ProviderPreference::Kubernetes),
            other => Err(ApiError::internal(format!(
                "unsupported persisted sandbox placement provider: {other}"
            ))),
        })
        .transpose()?;
    let pool_sql = format!(
        "select release_set_id, runtime_class, policy_digest, release_signature,
                candidate_agent_image, candidate_maestro_image, candidate_service_name
         from sterile_pool_memberships where sandbox_id = {}",
        db.placeholder(1)
    );
    let sterile_pool_candidate = sqlx::query(&pool_sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .map(|row| {
            Ok::<_, ApiError>(SterilePoolCandidateV1 {
                cell_id: SterileCellId(sandbox_id.0),
                release: SterileCellReleaseTrustClassV1 {
                    release_set_id: row.try_get("release_set_id")?,
                    runtime_class: SterileCellRuntimeClass::parse_db_str(
                        row.try_get("runtime_class")?,
                    )
                    .map_err(|error| ApiError::internal(error.to_string()))?,
                    policy_digest: row.try_get("policy_digest")?,
                    signature: row.try_get("release_signature")?,
                },
                agent_image: row.try_get("candidate_agent_image")?,
                maestro_image: row.try_get("candidate_maestro_image")?,
                service_name: row.try_get("candidate_service_name")?,
                pod_name: None,
                pod_uid: None,
            })
        })
        .transpose()?;
    let expected_provision_spec = serde_json::to_value(SandboxProvisionSpec {
        secret_mounts: secret_mounts.clone(),
        execution_class: sandbox.execution_class.clone(),
        memory_limit: sandbox.memory_limit.clone(),
        network_egress: sandbox.network_egress.clone(),
        workspace_mode: sandbox.workspace_mode.clone(),
        runtime_profile: sandbox.runtime_profile.clone(),
        tenant_id: Some(sandbox.tenant_id.clone()),
        provider_external_id: provider_external_id.clone(),
        provider_routing_scope: provider_routing_scope.clone(),
        provider_preference: provider_preference.clone().unwrap_or_default(),
        sterile_pool_candidate: sterile_pool_candidate.clone(),
    })?;
    let entry = PlacementCacheEntry {
        sandbox,
        secret_mounts,
        expected_provision_spec,
        provider_preference,
        provider_external_id,
        provider_routing_scope,
        sterile_pool_candidate,
    };
    cache.insert(sandbox_id, entry.clone());
    Ok(entry)
}

pub(crate) fn add_provision_spec_to_payload(
    job: &mut Job,
    sandbox: &Sandbox,
    secret_mounts: &[SandboxSecretMount],
) -> Result<(), ApiError> {
    add_provision_spec_to_payload_with_identity(
        job,
        sandbox,
        secret_mounts,
        ProviderPreference::Any,
        None,
        None,
    )
}

fn add_provision_spec_to_payload_with_identity(
    job: &mut Job,
    sandbox: &Sandbox,
    secret_mounts: &[SandboxSecretMount],
    provider_preference: ProviderPreference,
    provider_external_id: Option<String>,
    provider_routing_scope: Option<String>,
) -> Result<(), ApiError> {
    let Some(payload) = job.payload.as_object_mut() else {
        return Err(ApiError::bad_request("job payload must be an object"));
    };
    // This is authoritative control-plane enrichment, not a caller-provided
    // image selector. Profile-bound jobs must stay on the exact worker image
    // that owns the sandbox placement.
    payload.insert("runtimeImage".to_string(), json!(sandbox.template));
    payload.insert(
        "provisionSpec".to_string(),
        serde_json::to_value(SandboxProvisionSpec {
            secret_mounts: secret_mounts.to_vec(),
            execution_class: sandbox.execution_class.clone(),
            memory_limit: sandbox.memory_limit.clone(),
            network_egress: sandbox.network_egress.clone(),
            workspace_mode: sandbox.workspace_mode.clone(),
            runtime_profile: sandbox.runtime_profile.clone(),
            provider_preference,
            tenant_id: Some(sandbox.tenant_id.clone()),
            provider_external_id,
            provider_routing_scope,
            sterile_pool_candidate: None,
        })?,
    );
    Ok(())
}

pub(crate) async fn validate_job_payload_tenant(
    db: &Database,
    job: &Job,
    ctx: &TenantContext,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::StopSandbox => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
        }
        JobKind::ResumeSandbox => {
            // Owning the sandbox is not sufficient authority to resume it from
            // an arbitrary snapshot: the snapshot is what the workspace volume
            // is cloned from, so a directly-created resume job goes through the
            // same tenant/ownership/placement claim the resume route uses.
            let sandbox = ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            let now = Utc::now();
            // The same preconditions the resume route enforces. Without them a
            // tenant could queue a restore against its own *running* sandbox,
            // and the provider's failed apply would roll back (delete) that
            // sandbox's live Pod and workspace volume.
            ensure_sandbox_resumable(&sandbox, now)?;
            let mut connection = db.pool.acquire().await?;
            claim_sandbox_resume_snapshot_on_connection(
                db,
                &mut connection,
                &sandbox,
                Some(snapshot_id_from_job(job)?),
                ctx,
                now,
            )
            .await?;
        }
        JobKind::RunCommand => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            let command = fetch_command(db, command_id_from_job(job)?).await?;
            ensure_sandbox_tenant(db, command.sandbox_id, ctx).await?;
        }
        JobKind::RunResidentProcess => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
        }
        JobKind::MaterializeFile => {
            let sandbox = ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            let destination = materialization_destination_from_job(job)?;
            match destination {
                MaterializeFileDestination::CompilerCacheArchive => {
                    if sandbox.runtime_profile != SandboxRuntimeProfile::Unprivileged {
                        return Err(ApiError::bad_request(
                            "compiler-cache materialization requires the unprivileged runtime profile",
                        ));
                    }
                    let identity = compiler_cache_identity_from_job(job)?;
                    // Tenant scope in TenantRepositoryPrivate must come from the
                    // authenticated principal, not a self-declared label that a
                    // downstream shared-cache consumer (Foam) might trust as an
                    // authorization key.
                    bind_compiler_cache_identity_tenant(identity, &ctx.tenant_id)?;
                }
                _ => {
                    if sandbox.runtime_profile != SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
                        return Err(ApiError::bad_request(
                            "APEX materialization requires apex_trusted_supervisor_v1",
                        ));
                    }
                }
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
        }
        JobKind::ApexTaskInstructions => {
            let sandbox = ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            if sandbox.runtime_profile != SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
                return Err(ApiError::bad_request(
                    "apex_task_instructions requires apex_trusted_supervisor_v1",
                ));
            }
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
        JobKind::DeleteHome => {
            crate::handlers::homes::fetch_home(
                db,
                crate::handlers::homes::home_id_from_job(job)?,
                &ctx.tenant_id,
            )
            .await?;
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

pub(crate) fn resident_process_id_from_job(job: &Job) -> Result<ResidentProcessId, ApiError> {
    let value = job
        .payload
        .get("residentProcessId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::bad_request("residentProcessId is required"))?;
    Ok(ResidentProcessId(Uuid::parse_str(value).map_err(|_| {
        ApiError::bad_request("residentProcessId is invalid")
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

pub(crate) fn compiler_cache_identity_from_job(job: &Job) -> Result<&str, ApiError> {
    let identity = job
        .payload
        .get("compilerCacheIdentity")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::bad_request("compilerCacheIdentity is required"))?;
    if identity.is_empty() || identity.len() > MAX_COMPILER_CACHE_IDENTITY_BYTES {
        return Err(ApiError::bad_request(
            "compilerCacheIdentity is empty or exceeds its size bound",
        ));
    }
    Ok(identity)
}

/// Ensure any `TenantRepositoryPrivate` claim in a compiler-cache identity is
/// bound to the authenticated tenant. Repository-shared identities and partial
/// identities without a visibility claim are left alone; full schema validation
/// still happens in the agent at capture/restore time.
pub(crate) fn bind_compiler_cache_identity_tenant(
    identity: &str,
    tenant_id: &str,
) -> Result<(), ApiError> {
    let raw: serde_json::Value = serde_json::from_str(identity)
        .map_err(|_| ApiError::bad_request("compilerCacheIdentity must be valid JSON"))?;
    let Some(visibility) = raw
        .get("namespace")
        .and_then(|namespace| namespace.get("visibility"))
    else {
        return Ok(());
    };
    let kind = visibility
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if kind != "tenant_repository_private" {
        return Ok(());
    }
    let claimed = visibility
        .get("tenant")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if claimed.is_empty() {
        return Err(ApiError::bad_request(
            "compilerCacheIdentity tenant_repository_private visibility requires a tenant",
        ));
    }
    if claimed != tenant_id {
        return Err(ApiError {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "compiler_cache_identity_tenant_mismatch",
            message: "compilerCacheIdentity tenant must match the authenticated tenant".into(),
        });
    }
    Ok(())
}

pub(crate) async fn list_jobs(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Query(page): Query<PageParams>,
) -> Result<Json<JobListResponse>, ApiError> {
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;
    let base_sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, required_execution_class, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where tenant_id = {}
           and not exists (select 1 from sterile_pool_memberships p
                           where p.sandbox_id = jobs.sandbox_id)",
        state.db.placeholder(1)
    );
    let (jobs, next_cursor) = fetch_keyset_page(
        &state.db,
        &base_sql,
        std::slice::from_ref(&ctx.tenant_id),
        limit,
        &cursor,
        job_page_item,
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
         (id, tenant_id, kind, status, payload, required_capability, required_execution_class, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id)
         values ({})",
        db.placeholders(20)
    );
    sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.required_execution_class.as_db_str())
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
         (id, tenant_id, kind, status, payload, required_capability, required_execution_class, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id)
         values ({})",
        db.placeholders(20)
    );
    sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.required_execution_class.as_db_str())
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

/// Inserts a job while allowing the archived-runtime cleanup partial unique
/// index to collapse races between API replicas. Ordinary job insertion keeps
/// its existing error semantics; this helper is only for a deliberately
/// idempotent reconciliation request.
pub(crate) async fn insert_job_on_connection_if_absent(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<bool, ApiError> {
    let references = job_references(job)?;
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, required_execution_class, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id, archived_runtime_cleanup)
         values ({}) on conflict do nothing",
        db.placeholders(21)
    );
    let result = sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.required_execution_class.as_db_str())
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
        .bind(true)
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) const ARCHIVED_RUNTIME_CLEANUP_MARKER: &str = "archivedRuntimeCleanup";

/// Queue provider teardown for an archived sandbox whose runtime rows still
/// describe live resources. The marker is intentionally in the payload (and
/// indexed by a partial unique index) so this remains idempotent after API
/// restarts, worker retries, and concurrent sweeper replicas.
pub(crate) async fn enqueue_archived_runtime_cleanup_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &Sandbox,
    source_payload: Option<&serde_json::Value>,
    reason: &str,
) -> Result<bool, ApiError> {
    let existing_sql = format!(
        "select 1
         from jobs
         where sandbox_id = {} and kind = {} and status in ('queued', 'leased')
         limit 1",
        db.placeholder(1),
        db.placeholder(2)
    );
    if sqlx::query(&existing_sql)
        .bind(sandbox.id.to_string())
        .bind(job_kind_to_str(&JobKind::StopSandbox))
        .fetch_optional(&mut *connection)
        .await?
        .is_some()
    {
        return Ok(false);
    }

    let now = Utc::now();
    let mut job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::StopSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox.id,
            // Cleanup is label-scoped and ignore-not-found, so include the
            // persisted FQDN policy kind even when the original provision
            // completion did not persist that row before the race.
            "deleteGkeFqdnPolicy": true,
            ARCHIVED_RUNTIME_CLEANUP_MARKER: true,
            "cleanupReason": reason,
        }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: sandbox.execution_class.clone(),
        priority: 1000,
        attempts: 0,
        max_attempts: 5,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };

    // Provision jobs written by older API versions may not have carried the
    // enriched spec. Preserve an authoritative spec from the source job when
    // present; otherwise derive it on this same connection so a SQLite write
    // transaction cannot deadlock itself by acquiring a second connection.
    let source_spec = source_payload
        .and_then(|payload| payload.get("provisionSpec"))
        .filter(|spec| spec.is_object())
        .cloned();
    if let Some(spec) = source_spec {
        let payload = job
            .payload
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("archived cleanup payload is not an object"))?;
        payload.insert("provisionSpec".to_string(), spec);
        if let Some(runtime_image) = source_payload.and_then(|payload| payload.get("runtimeImage"))
        {
            payload.insert("runtimeImage".to_string(), runtime_image.clone());
        }
    } else {
        let secret_mounts =
            fetch_sandbox_secret_mounts_on_connection(db, connection, sandbox.id).await?;
        add_provision_spec_to_payload(&mut job, sandbox, &secret_mounts)?;
    }

    insert_job_on_connection_if_absent(db, connection, &job).await
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
        JobKind::ProvisionSandbox | JobKind::StopSandbox => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
        }
        JobKind::ResumeSandbox => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.snapshot_id = Some(snapshot_id_from_job(job)?);
        }
        JobKind::RunCommand => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.command_id = Some(command_id_from_job(job)?);
        }
        JobKind::RunResidentProcess | JobKind::MaterializeFile | JobKind::ApexTaskInstructions => {
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
        JobKind::DeleteHome => {}
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

async fn recheck_sterile_resident_activation_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    if job.kind != JobKind::RunResidentProcess {
        return Ok(());
    }
    let process_id = resident_process_id_from_job(job)?;
    let resident_generation = job
        .payload
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ApiError::internal("resident process job is missing generation"))?;
    let activation = job.payload.get("sterileActivation");
    let (cell_id, lease_id, lease_generation) = match activation {
        None => {
            let sql = format!(
                "select 1 from resident_processes
                 where id = {} and generation = {}
                   and sterile_cell_id is null and sterile_lease_id is null
                   and sterile_lease_generation is null",
                db.placeholder(1),
                db.placeholder(2),
            );
            if sqlx::query(&sql)
                .bind(process_id.to_string())
                .bind(i64::try_from(resident_generation).map_err(|_| {
                    ApiError::internal("resident generation exceeds database range")
                })?)
                .fetch_optional(connection)
                .await?
                .is_none()
            {
                return Err(ApiError::conflict_code(
                    "sterile_resident_activation_fence_mismatch",
                    "ungated resident job does not match its durable activation fence",
                ));
            }
            return Ok(());
        }
        Some(activation) => {
            let cell_id = activation
                .get("cellId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| ApiError::internal("sterile resident job is missing cell id"))?;
            let lease_id = activation
                .get("leaseId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| ApiError::internal("sterile resident job is missing lease id"))?;
            let generation = activation
                .get("generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| ApiError::internal("sterile resident job is missing generation"))?;
            (cell_id, lease_id, generation)
        }
    };
    let sandbox_id = sandbox_id_from_job(job)?;
    if cell_id != sandbox_id.to_string() {
        return Err(ApiError::conflict_code(
            "sterile_resident_activation_fence_mismatch",
            "sterile resident cell does not match the job sandbox",
        ));
    }
    let sql = format!(
        "select 1
         from resident_processes rp
         join sterile_cells sc on sc.id = rp.sterile_cell_id
         where rp.id = {} and rp.tenant_id = {} and rp.generation = {}
           and rp.sterile_cell_id = {} and rp.sterile_lease_id = {}
           and rp.sterile_lease_generation = {}
           and sc.tenant_id = rp.tenant_id and sc.state = 'leased'
           and sc.activated_resident_process_id = rp.id
           and sc.activated_resident_generation = rp.generation
           and sc.lease_id = rp.sterile_lease_id
           and sc.generation = rp.sterile_lease_generation
           and sc.lease_expires_at > {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
    );
    let matched = sqlx::query(&sql)
        .bind(process_id.to_string())
        .bind(&job.tenant_id)
        .bind(
            i64::try_from(resident_generation)
                .map_err(|_| ApiError::internal("resident generation exceeds database range"))?,
        )
        .bind(cell_id)
        .bind(lease_id)
        .bind(
            i64::try_from(lease_generation).map_err(|_| {
                ApiError::internal("sterile lease generation exceeds database range")
            })?,
        )
        .bind(Utc::now().to_rfc3339())
        .fetch_optional(connection)
        .await?;
    if matched.is_none() {
        return Err(ApiError::conflict_code(
            "sterile_resident_activation_fence_mismatch",
            "sterile resident activation is no longer live at job claim",
        ));
    }
    Ok(())
}

async fn quarantine_invalid_sterile_resident_job(db: &Database, job: &Job) -> Result<(), ApiError> {
    let Some(activation) = job.payload.get("sterileActivation") else {
        return Ok(());
    };
    let Some(cell_id) = activation.get("cellId").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let process_id = resident_process_id_from_job(job)?;
    let now = Utc::now().to_rfc3339();
    let mut tx = db.pool.begin().await?;
    let job_sql = format!(
        "update jobs set status = 'dead', last_error = {}, updated_at = {}
         where id = {} and status = 'queued'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let terminalized = sqlx::query(&job_sql)
        .bind("sterile resident activation expired or changed before claim")
        .bind(&now)
        .bind(job.id.to_string())
        .execute(&mut *tx)
        .await?;
    if terminalized.rows_affected() == 1 {
        let process_sql = format!(
            "update resident_processes
             set desired_state = 'stopped', observed_state = 'failed',
                 last_error = {}, updated_at = {}
             where id = {} and sterile_cell_id = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4),
        );
        sqlx::query(&process_sql)
            .bind("sterile resident activation expired or changed before claim")
            .bind(&now)
            .bind(process_id.to_string())
            .bind(cell_id)
            .execute(&mut *tx)
            .await?;
        let cell_sql = format!(
            "update sterile_cells
             set state = 'quarantined', disposition = 'quarantined',
                 destroyed_at = {}, updated_at = {}
             where id = {} and state = 'leased'",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
        );
        sqlx::query(&cell_sql)
            .bind(&now)
            .bind(&now)
            .bind(cell_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Scheduler-side stale activation cleanup. This runs before ordinary worker,
/// provider, health, and capacity eligibility filters so an expired gated job
/// cannot remain queued forever merely because no executor is eligible to
/// reach `try_claim_job`'s transactional fence check.
pub(crate) async fn terminalize_invalid_sterile_resident_job_before_filtering(
    db: &Database,
    job: &Job,
) -> Result<bool, ApiError> {
    if job.kind != JobKind::RunResidentProcess || job.payload.get("sterileActivation").is_none() {
        return Ok(false);
    }
    let mut connection = db.pool.acquire().await?;
    match recheck_sterile_resident_activation_on_connection(db, &mut connection, job).await {
        Ok(()) => Ok(false),
        Err(error) if error.code == "sterile_resident_activation_fence_mismatch" => {
            drop(connection);
            quarantine_invalid_sterile_resident_job(db, job).await?;
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

pub(crate) async fn try_claim_job(
    db: &Database,
    worker: &Worker,
    job: &Job,
    lease_seconds: Option<u64>,
    operation_id: Option<Uuid>,
) -> Result<Option<JobLease>, ApiError> {
    let provider_preference = job
        .payload
        .get("provisionSpec")
        .cloned()
        .and_then(|value| serde_json::from_value::<SandboxProvisionSpec>(value).ok())
        .map(|spec| spec.provider_preference)
        .unwrap_or_default();
    if !crate::handlers::leases::worker_matches_provider_preference(
        &worker.provider,
        &provider_preference,
    ) {
        return Ok(None);
    }
    let mut tx = db.pool.begin().await?;
    let claimed = async {
        if !lock_worker_for_claim_on_connection(db, &mut tx, worker.id).await? {
            return Ok(None);
        }
        if !lock_apex_instruction_placement_on_connection(db, &mut tx, worker, job).await? {
            return Ok(None);
        }
        let active_leases =
            active_lease_count_for_worker_on_connection(db, &mut tx, worker.id).await?;
        if active_leases >= worker.max_concurrent_jobs {
            return Ok(None);
        }
        recheck_sterile_resident_activation_on_connection(db, &mut tx, job).await?;

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

        // Claim only mutates status/attempts/updated_at. Rebuild the leased job
        // in memory instead of a second SELECT (and skip the post-insert lease
        // re-read): every claim pays this path on provision and stop, so the
        // round-trips dominate TTFT under SQLite.
        let mut leased_job = job.clone();
        leased_job.status = JobStatus::Leased;
        leased_job.attempts = attempt;
        leased_job.updated_at = now;
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
            required_execution_class: leased_job.required_execution_class.clone(),
            job: leased_job,
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
        if lease.job.kind == JobKind::RunResidentProcess {
            let sql = format!(
                "update resident_processes
                 set active_lease_id = {}, observed_state = 'starting',
                     provider_pod_name = null, provider_pod_uid = null,
                     last_error_class = null, last_error_code = null, last_error = null,
                     updated_at = {}
                 where id = {} and generation = {} and desired_state = 'running'",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4)
            );
            let generation = lease.job.payload["generation"]
                .as_u64()
                .ok_or_else(|| ApiError::bad_request("resident generation is required"))?;
            let result = sqlx::query(&sql)
                .bind(lease.id.to_string())
                .bind(now.to_rfc3339())
                .bind(resident_process_id_from_job(&lease.job)?.to_string())
                .bind(generation as i64)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(ApiError::conflict_code(
                    "resident_process_generation_conflict",
                    "resident process generation changed before lease claim",
                ));
            }
        }
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
            if error.code == "sterile_resident_activation_fence_mismatch" {
                quarantine_invalid_sterile_resident_job(db, job).await?;
                return Ok(None);
            }
            Err(error)
        }
    }
}

async fn lock_apex_instruction_placement_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    worker: &Worker,
    job: &Job,
) -> Result<bool, ApiError> {
    if job.kind != JobKind::ApexTaskInstructions {
        return Ok(true);
    }
    let Some(target_worker_id) = job
        .payload
        .get("targetWorkerId")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return Ok(false);
    };
    let Some(target_generation) = job
        .payload
        .get("targetPlacementGeneration")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
    else {
        return Ok(false);
    };
    if target_worker_id != worker.id.0 {
        return Ok(false);
    }
    // The no-op update both verifies and locks the exact placement tuple for
    // the remainder of this claim transaction. A concurrent placement move
    // must complete before this check or wait until after the lease commits.
    let sql = format!(
        "update sandbox_placements set updated_at = updated_at
         where sandbox_id = {} and worker_id = {} and generation = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let result = sqlx::query(&sql)
        .bind(sandbox_id_from_job(job)?.to_string())
        .bind(worker.id.to_string())
        .bind(target_generation)
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected() == 1)
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
) -> Result<bool, ApiError> {
    let sql = format!(
        "update workers
         set last_heartbeat_at = last_heartbeat_at
         where id = {} and status in ('registered', 'online')",
        db.placeholder(1)
    );
    let result = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn fetch_job(db: &Database, job_id: JobId) -> Result<Job, ApiError> {
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, required_execution_class, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(job_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    row_to_job(row)
}

/// Connection-scoped job load for callers already holding a write transaction.
/// Claim no longer re-reads after the status CAS; keep this for transactional
/// repair and future lease paths that still need a durable job snapshot.
#[allow(dead_code)]
pub(crate) async fn fetch_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job_id: JobId,
) -> Result<Job, ApiError> {
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, required_execution_class, priority, attempts, max_attempts,
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

#[cfg(test)]
mod placement_match_tests {
    use super::*;
    use chrono::Utc;

    fn sample_sandbox() -> Sandbox {
        let now = Utc::now();
        Sandbox {
            id: SandboxId::new(),
            tenant_id: "t1".into(),
            name: "s".into(),
            state: SandboxState::Running,
            template: "ghcr.io/evalops/ubuntu@sha256:abc".into(),
            memory_limit: MemoryLimit::default(),
            network_egress: NetworkEgress::default(),
            workspace_mode: WorkspaceMode::default(),
            runtime_profile: SandboxRuntimeProfile::default(),
            execution_class: ExecutionClass::DevelopmentContainer,
            created_at: now,
            updated_at: now,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
            last_activity_at: None,
            parent_snapshot_id: None,
        }
    }

    fn base_job(sandbox: &Sandbox) -> Job {
        let now = Utc::now();
        Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id.clone(),
            kind: JobKind::RunCommand,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": sandbox.id.to_string(),
                "runtimeImage": sandbox.template,
                "provisionSpec": SandboxProvisionSpec {
                    memory_limit: sandbox.memory_limit.clone(),
                    network_egress: sandbox.network_egress.clone(),
                    workspace_mode: sandbox.workspace_mode.clone(),
                    runtime_profile: sandbox.runtime_profile.clone(),
                    execution_class: sandbox.execution_class.clone(),
                    tenant_id: Some(sandbox.tenant_id.clone()),
                    secret_mounts: vec![],
                    ..SandboxProvisionSpec::default()
                },
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
        }
    }

    fn entry_for(sandbox: &Sandbox) -> PlacementCacheEntry {
        PlacementCacheEntry {
            expected_provision_spec: expected_provision_spec_value(sandbox, &[]).unwrap(),
            sandbox: sandbox.clone(),
            secret_mounts: vec![],
            provider_preference: None,
            provider_external_id: None,
            provider_routing_scope: None,
            sterile_pool_candidate: None,
        }
    }

    #[test]
    fn placement_matches_when_payload_is_authoritative() {
        let sandbox = sample_sandbox();
        let job = base_job(&sandbox);
        assert!(placement_matches_sandbox(&job, &entry_for(&sandbox)));
        assert!(placement_matches_sandbox_parts(&job, &sandbox, &[]));
    }

    #[test]
    fn placement_rejects_forged_runtime_image() {
        let sandbox = sample_sandbox();
        let mut job = base_job(&sandbox);
        job.payload.as_object_mut().unwrap().insert(
            "runtimeImage".into(),
            json!("ghcr.io/attacker/root@sha256:ff"),
        );
        assert!(!placement_matches_sandbox(&job, &entry_for(&sandbox)));
    }

    #[test]
    fn apply_sandbox_placement_is_idempotent_for_matching_jobs() {
        let sandbox = sample_sandbox();
        let entry = entry_for(&sandbox);
        let mut job = base_job(&sandbox);
        assert!(!apply_sandbox_placement(&mut job, &entry).unwrap());
        // Forged image is repaired and reports a mutation.
        job.payload
            .as_object_mut()
            .unwrap()
            .insert("runtimeImage".into(), json!("evil:latest"));
        assert!(apply_sandbox_placement(&mut job, &entry).unwrap());
        assert_eq!(
            job.payload.get("runtimeImage").and_then(|v| v.as_str()),
            Some(sandbox.template.as_str())
        );
        assert!(!apply_sandbox_placement(&mut job, &entry).unwrap());
    }

    #[test]
    fn apply_sandbox_placement_strips_forged_pool_candidate() {
        let sandbox = sample_sandbox();
        let entry = entry_for(&sandbox);
        let mut job = base_job(&sandbox);
        job.payload["provisionSpec"]["sterile_pool_candidate"] = json!({
            "cell_id": sandbox.id,
            "release": {
                "release_set_id": "forged",
                "runtime_class": "kata_microvm",
                "policy_digest": "sha256:forged",
                "signature": "forged"
            }
        });

        assert!(apply_sandbox_placement(&mut job, &entry).unwrap());
        assert!(job.payload["provisionSpec"]["sterile_pool_candidate"].is_null());
        assert!(placement_matches_sandbox(&job, &entry));
    }

    #[test]
    fn placement_matches_a_concrete_provider_preference() {
        let sandbox = sample_sandbox();
        let mut job = base_job(&sandbox);
        job.payload["provisionSpec"]["provider_preference"] = json!("cloudflare");
        let entry = entry_for(&sandbox);

        assert!(placement_matches_sandbox(&job, &entry));
    }

    #[test]
    fn applied_placement_provider_overrides_command_default_any() {
        let sandbox = sample_sandbox();
        let mut job = base_job(&sandbox);
        job.payload["provisionSpec"]["provider_preference"] = json!("any");
        let mut entry = entry_for(&sandbox);
        entry.provider_preference = Some(ProviderPreference::AgentSandbox);
        entry.expected_provision_spec["provider_preference"] = json!("agent_sandbox");

        assert!(!placement_matches_sandbox(&job, &entry));
        assert!(apply_sandbox_placement(&mut job, &entry).unwrap());
        assert_eq!(
            job.payload["provisionSpec"]["provider_preference"],
            json!("agent_sandbox")
        );
        assert!(placement_matches_sandbox(&job, &entry));
    }
}
