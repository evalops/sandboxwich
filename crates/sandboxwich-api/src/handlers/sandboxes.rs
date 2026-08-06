use crate::auth::*;
use crate::authz::AuthorizationContext;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::homes::claim_home_mount_on_connection;
use crate::handlers::jobs::*;
use crate::handlers::leases::provisioning_operation_from_row;
use crate::handlers::operations::operation_from_job;
use crate::handlers::secrets::*;
use crate::handlers::snapshots::*;
use crate::pagination::*;
use crate::request_id::RequestTrace;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde::Serialize;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) fn provision_spec_from_request(
    request: &CreateSandboxRequest,
    parent: Option<&Sandbox>,
) -> Result<SandboxProvisionSpec, ApiError> {
    let memory_limit = request
        .memory_limit
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.memory_limit.clone()))
        .unwrap_or_default();
    let network_egress = request
        .network_egress
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.network_egress.clone()))
        .unwrap_or_default();
    let workspace_mode = request
        .workspace_mode
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.workspace_mode.clone()))
        .unwrap_or_default();
    let runtime_profile = request
        .runtime_profile
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.runtime_profile.clone()))
        .unwrap_or_default();
    let execution_class = request
        .execution_class
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.execution_class.clone()))
        .unwrap_or_default();
    validate_network_egress(&network_egress)?;
    let effective_template = request
        .template
        .as_deref()
        .or_else(|| parent.map(|sandbox| sandbox.template.as_str()));
    validate_runtime_profile(&runtime_profile, &network_egress, effective_template)?;
    if runtime_profile == SandboxRuntimeProfile::ApexTrustedSupervisorV1
        && execution_class != ExecutionClass::SandboxedContainer
    {
        return Err(ApiError::bad_request(
            "apex_trusted_supervisor_v1 requires sandboxed_container execution_class",
        ));
    }
    Ok(SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        execution_class,
        memory_limit,
        network_egress,
        workspace_mode,
        runtime_profile,
    })
}

pub(crate) fn validate_runtime_profile(
    profile: &SandboxRuntimeProfile,
    network_egress: &NetworkEgress,
    runtime_image: Option<&str>,
) -> Result<(), ApiError> {
    if *profile != SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
        return Ok(());
    }
    if matches!(network_egress, NetworkEgress::AllowAll) {
        return Err(ApiError::bad_request(
            "apex_trusted_supervisor_v1 requires deny-by-default egress",
        ));
    }
    if !runtime_image.is_some_and(immutable_sha256_image) {
        return Err(ApiError::bad_request(
            "apex_trusted_supervisor_v1 requires a digest-pinned runtime image",
        ));
    }
    Ok(())
}

pub(crate) fn validate_network_egress(network_egress: &NetworkEgress) -> Result<(), ApiError> {
    match network_egress {
        NetworkEgress::DenyAll | NetworkEgress::AllowAll => Ok(()),
        NetworkEgress::Allowlist { rules } => {
            for rule in rules {
                let value = rule.value.trim();
                if value.is_empty() {
                    return Err(ApiError::bad_request(
                        "network allow rule value cannot be empty",
                    ));
                }
                if value.len() > 253 {
                    return Err(ApiError::bad_request(
                        "network allow rule value is too long",
                    ));
                }
                if rule.kind == NetworkAllowRuleKind::Cidr && !looks_like_cidr(value) {
                    return Err(ApiError::bad_request(
                        "cidr network allow rule must use CIDR notation",
                    ));
                }
                if rule.kind == NetworkAllowRuleKind::Host && !looks_like_host_rule(value) {
                    return Err(ApiError::bad_request(
                        "host network allow rule must be a lowercase DNS name or one leading-label wildcard",
                    ));
                }
            }
            Ok(())
        }
    }
}

pub(crate) fn looks_like_host_rule(value: &str) -> bool {
    if let Some(base) = value.strip_prefix("*.") {
        return base.contains('.') && !base.contains('*') && looks_like_dns_name(base);
    }
    !value.contains('*') && looks_like_dns_name(value)
}

pub(crate) fn looks_like_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.ends_with('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub(crate) fn provision_capability(
    runtime_profile: &SandboxRuntimeProfile,
    network_egress: &NetworkEgress,
) -> WorkerCapability {
    if *runtime_profile == SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
        return WorkerCapability::ApexTrustedSupervisorV1;
    }
    if network_egress
        .rules()
        .iter()
        .any(|rule| rule.kind == NetworkAllowRuleKind::Host)
    {
        WorkerCapability::FqdnEgress
    } else {
        WorkerCapability::ProvisionSandbox
    }
}

pub(crate) fn execution_capability(execution_class: &ExecutionClass) -> WorkerCapability {
    match execution_class {
        ExecutionClass::DevelopmentContainer => WorkerCapability::ProvisionSandbox,
        ExecutionClass::SandboxedContainer => WorkerCapability::SandboxedContainer,
        ExecutionClass::VirtualMachine => WorkerCapability::VirtualMachine,
    }
}

pub(crate) fn fork_capability(
    runtime_profile: &SandboxRuntimeProfile,
    network_egress: &NetworkEgress,
) -> WorkerCapability {
    if *runtime_profile == SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
        return WorkerCapability::ApexTrustedSupervisorV1;
    }
    if network_egress
        .rules()
        .iter()
        .any(|rule| rule.kind == NetworkAllowRuleKind::Host)
    {
        WorkerCapability::FqdnEgress
    } else {
        WorkerCapability::Snapshot
    }
}

pub(crate) fn looks_like_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => prefix <= 32,
        Ok(std::net::IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

#[utoipa::path(post, path = "/v1/sandboxes", request_body = CreateSandboxRequest, responses((status = 202, description = "Sandbox provisioning accepted", body = SandboxResponse), (status = 400, body = ErrorEnvelope)))]
pub(crate) async fn create_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Extension(authorization): Extension<AuthorizationContext>,
    Extension(trace): Extension<RequestTrace>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    create_sandbox_with_home(state, ctx, request, None, Some(authorization), trace).await
}

pub(crate) async fn create_sandbox_with_home(
    state: AppState,
    ctx: TenantContext,
    request: CreateSandboxRequest,
    home_id: Option<HomeId>,
    authorization: Option<AuthorizationContext>,
    trace: RequestTrace,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let now = Utc::now();
    let managed_home = home_id.is_some();
    let mut provision_spec = provision_spec_from_request(&request, None)?;
    provision_spec.secret_mounts =
        resolve_secret_mounts(&state.db, &ctx.tenant_id, &request.secret_ref_ids).await?;
    if home_id.is_some() && provision_spec.workspace_mode != WorkspaceMode::Persistent {
        return Err(ApiError::bad_request(
            "managed homes require workspace_mode=persistent",
        ));
    }
    let sandbox = Sandbox {
        execution_class: provision_spec.execution_class.clone(),
        id: SandboxId::new(),
        tenant_id: ctx.tenant_id.clone(),
        name: request.name.unwrap_or_else(|| "fresh-sandwich".to_string()),
        state: SandboxState::Planning,
        template: request.template.unwrap_or_else(|| "ubuntu-dev".to_string()),
        memory_limit: provision_spec.memory_limit.clone(),
        network_egress: provision_spec.network_egress.clone(),
        workspace_mode: provision_spec.workspace_mode.clone(),
        runtime_profile: provision_spec.runtime_profile.clone(),
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(Some(3600)),
        max_lifetime_seconds: clamp_optional_lifetime(
            request.max_lifetime_seconds,
            state.sandbox_lifetime.default_max_lifetime_seconds,
            state.sandbox_lifetime.max_max_lifetime_seconds,
        ),
        idle_ttl_seconds: clamp_optional_lifetime(
            request.idle_ttl_seconds,
            state.sandbox_lifetime.default_idle_ttl_seconds,
            state.sandbox_lifetime.max_idle_ttl_seconds,
        ),
        parent_snapshot_id: None,
        last_activity_at: None,
    };

    let mut job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox.id,
            "homeId": home_id,
            "runtimeImage": sandbox.template,
            "provisionSpec": provision_spec
        }),
        required_capability: provision_capability(
            &sandbox.runtime_profile,
            &sandbox.network_egress,
        ),
        required_execution_class: sandbox.execution_class.clone(),
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    if let Some(authorization) = authorization.as_ref() {
        authorization.add_to_payload(&mut job.payload);
    }
    trace.add_to_payload(&mut job.payload);
    // Payload already embeds provisionSpec + runtimeImage from the create
    // request path; re-running add_provision_spec would only re-serialize the
    // same values. Keep the helper call only when secret mounts may have been
    // resolved after the initial payload build (they are set on provision_spec
    // before the json! macro above).
    // Capacity admission: when every online worker has reported an envelope and
    // none can schedule this tier, reject immediately instead of creating a Pod
    // that will only fail after the readiness window.
    reject_if_memory_exceeds_all_envelopes(&state.db, &ctx.tenant_id, &sandbox.memory_limit)
        .await?;
    let mut tx = state.db.pool.begin().await?;
    insert_sandbox_on_connection(&state.db, &mut tx, &sandbox).await?;
    if !provision_spec.secret_mounts.is_empty() {
        insert_sandbox_secret_bindings_on_connection(
            &state.db,
            &mut tx,
            sandbox.id,
            &provision_spec.secret_mounts,
        )
        .await?;
    }
    if let Some(home_id) = home_id {
        claim_home_mount_on_connection(&state.db, &mut tx, home_id, &ctx.tenant_id, sandbox.id)
            .await?;
    }
    // Fresh sandbox row: deny_all / empty allowlist has no rules table rows to
    // clear. Skip the DELETE that every create previously paid for nothing.
    let network_rules = sandbox.network_egress.rules();
    if !network_rules.is_empty() {
        replace_sandbox_network_rules_on_connection(&state.db, &mut tx, sandbox.id, network_rules)
            .await?;
    }
    insert_event_on_connection(
        &state.db,
        &mut tx,
        sandbox.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": sandbox.state,
            "reason": "created",
            "memoryLimit": sandbox.memory_limit,
            "networkEgress": sandbox.network_egress
        }),
    )
    .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    tracing::info!(
        request_id = %trace.request_id,
        trace_id = %trace.trace_id,
        sandbox_id = %sandbox.id,
        job_id = %job.id,
        memory_limit = %sandbox.memory_limit,
        network_egress = %sandbox.network_egress.mode().as_db_str(),
        workspace_mode = %sandbox.workspace_mode.as_db_str(),
        execution_class = %sandbox.execution_class.as_db_str(),
        managed_home,
        "sandbox_create_accepted"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox,
            operation: Some(operation_from_job(&job)?),
            provisioning: None,
            placement: None,
        }),
    ))
}

pub(crate) async fn list_sandboxes(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Query(page): Query<PageParams>,
) -> Result<Response, ApiError> {
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;

    // List embeds denormalized allowlist rules (`network_egress_rules_json`) so
    // the page needs one SELECT. Correlated per-row JSON aggregates and a second
    // batched IN query were both measured slower under 100% allowlist seeds
    // (see scripts/perf-harness.py matrix / allowlist).
    let base_sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, runtime_profile, execution_class,
                created_at, updated_at, ttl_seconds, max_lifetime_seconds, idle_ttl_seconds, last_activity_at, parent_snapshot_id,
                network_egress_rules_json
         from sandboxes
         where tenant_id = {}",
        state.db.placeholder(1)
    );
    let (sandboxes, next_cursor) = fetch_keyset_page(
        &state.db,
        &base_sql,
        std::slice::from_ref(&ctx.tenant_id),
        limit,
        &cursor,
        sandbox_list_page_item,
    )
    .await?;

    Ok(sandbox_list_response(SandboxListResponse {
        ok: true,
        sandboxes,
        next_cursor,
    }))
}

const SANDBOX_LIST_JSON_BYTES_PER_ITEM: usize = 512;

fn sandbox_list_response(response: SandboxListResponse) -> Response {
    let capacity = 128usize.saturating_add(
        response
            .sandboxes
            .len()
            .saturating_mul(SANDBOX_LIST_JSON_BYTES_PER_ITEM),
    );
    json_response_with_capacity(response, capacity)
}

fn json_response_with_capacity<T>(value: T, capacity: usize) -> Response
where
    T: Serialize,
{
    let mut body = Vec::with_capacity(capacity);
    if serde_json::to_writer(&mut body, &value).is_err() {
        // Keep Axum's serialization-error status, headers, and body authoritative.
        return Json(value).into_response();
    }
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

pub(crate) async fn get_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let (sandbox, placement) =
        fetch_sandbox_with_placement_proof(&state.db, SandboxId(sandbox_id)).await?;
    ensure_tenant(&sandbox.tenant_id, &ctx)?;
    let provisioning = fetch_provisioning_operation(&state.db, sandbox.id).await?;
    Ok(Json(SandboxResponse {
        ok: true,
        sandbox,
        operation: None,
        provisioning,
        placement,
    }))
}

/// Load a sandbox and its placement proof in one read-pool round trip.
///
/// Placement is left-joined so planning/archiving/archived sandboxes can still
/// return without a placement row; other states without placement fail closed.
async fn fetch_sandbox_with_placement_proof(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<(Sandbox, Option<SandboxPlacementProof>), ApiError> {
    let sql = format!(
        "select s.id, s.tenant_id, s.name, s.state, s.template, s.memory_limit, s.network_egress_mode,
                s.workspace_mode, s.runtime_profile, s.execution_class, s.created_at, s.updated_at,
                s.ttl_seconds, s.max_lifetime_seconds, s.idle_ttl_seconds, s.last_activity_at,
                s.parent_snapshot_id, p.worker_id as placement_worker_id, p.provider as placement_provider,
                w.labels as placement_labels
           from sandboxes s
           left join sandbox_placements p on p.sandbox_id = s.id
           left join workers w on w.id = p.worker_id
          where s.id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    // Read placement columns before `row_to_sandbox` consumes the row buffer.
    let placement_worker_id: Option<String> = row.try_get("placement_worker_id")?;
    let placement_provider: Option<String> = row.try_get("placement_provider")?;
    let placement_labels: Option<String> = row.try_get("placement_labels")?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress(db, &mut sandbox).await?;

    let placement = match placement_worker_id {
        None => {
            if matches!(
                sandbox.state,
                SandboxState::Planning | SandboxState::Archiving | SandboxState::Archived
            ) {
                None
            } else {
                return Err(ApiError::internal("sandbox placement proof is missing"));
            }
        }
        Some(worker_id) => {
            let provider = placement_provider.unwrap_or_default();
            let labels = placement_labels.unwrap_or_default();
            Some(placement_proof_from_parts(worker_id, provider, labels)?)
        }
    };
    Ok((sandbox, placement))
}

async fn fetch_provisioning_operation(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Option<ProvisioningOperation>, ApiError> {
    let sql = format!(
        "select lease_id, lease_attempt, stage, stage_index, resource_kind,
                resource_namespace, resource_name, resource_uid, observed_generation,
                attempt_count, last_error_class, last_error_code, last_error, updated_at
         from provisioning_operations where sandbox_id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?;
    row.map(|row| provisioning_operation_from_row(sandbox_id, &row))
        .transpose()
}

fn placement_proof_from_parts(
    worker_id: String,
    provider: String,
    labels: String,
) -> Result<SandboxPlacementProof, ApiError> {
    if provider.is_empty() {
        return Err(ApiError::internal("worker placement provider is missing"));
    }
    let labels: HashMap<String, String> = serde_json::from_str(&labels)
        .map_err(|_| ApiError::internal("worker placement labels are invalid"))?;
    let provider_mode = labels
        .get("provider_mode")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ApiError::internal("worker placement provider mode is missing"))?;
    let runtime_image = labels
        .get("runtime_image")
        .filter(|value| immutable_sha256_image(value))
        .cloned()
        .ok_or_else(|| ApiError::internal("worker placement runtime image is not digest-pinned"))?;
    Ok(SandboxPlacementProof {
        worker_id: Uuid::parse_str(&worker_id)
            .map_err(|_| ApiError::internal("worker placement id is invalid"))?,
        provider,
        provider_mode,
        runtime_image,
    })
}

fn immutable_sha256_image(image: &str) -> bool {
    image.rsplit_once('@').is_some_and(|(_, digest)| {
        digest.len() == 71
            && digest.starts_with("sha256:")
            && digest[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

#[utoipa::path(
    get,
    path = "/v1/sandboxes/{sandbox_id}/observed-state",
    params(("sandbox_id" = Uuid, Path)),
    responses((status = 200, body = SandboxObservedState), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn get_sandbox_observed_state(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxObservedState>, ApiError> {
    let sandbox = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    Ok(Json(SandboxObservedState {
        sandbox_id,
        tenant_id: sandbox.tenant_id,
        state: sandbox.state,
        observed_at: Utc::now(),
    }))
}

/// Drives the same stop/teardown a user-initiated `POST .../stop` performs,
/// but parameterized over the `LifecycleChanged` event payload so callers
/// other than the HTTP handler -- currently only the active-lifetime reaper
/// in `reap.rs` -- can record *why* the stop happened (e.g.
/// `"reason": "reaped_max_lifetime"`) while going through the identical
/// state transition, resident-process-stop, guest-token-revoke, and
/// `StopSandbox` job path. There is deliberately no second teardown path: a
/// reaped sandbox becomes `Archiving` exactly like a manually stopped one,
/// then flows into the pre-existing `cleanup_archived_sandboxes` retention
/// sweep once its provider teardown completes.
///
/// Returns `Ok(None)` (rather than proceeding anyway) if the sandbox is no
/// longer in a `STOP_LEGAL_FROM` state by the time the state-transition CAS
/// runs -- i.e. a concurrent actor (another `stop_sandbox_via_job` caller:
/// a racing manual stop, or the reaper) already won the same race. Before
/// this check existed, a CAS-miss here still fell through and enqueued a
/// second `StopSandbox` job, flipped resident processes to `stopped` again,
/// and re-revoked guest tokens -- all no-ops against an already-archiving
/// sandbox, but wasted work and job-queue noise that gets exercised far
/// more routinely now that the reaper is a second, automated caller of this
/// function racing every manual stop.
///
/// Uses `sandbox.tenant_id` (not a caller-supplied tenant context) for every
/// tenant-scoped write, since the reaper acts across all tenants the same
/// way `cleanup_archived_sandboxes` does; the HTTP handler's own
/// `ensure_sandbox_tenant` call already establishes that `sandbox` really
/// belongs to the requesting tenant before this runs.
pub(crate) async fn stop_sandbox_via_job(
    db: &Database,
    resident_bootstraps: &ResidentBootstrapStore,
    sandbox: &Sandbox,
    lifecycle_event_data: serde_json::Value,
    authorization: Option<AuthorizationContext>,
    trace: Option<RequestTrace>,
) -> Result<Option<Job>, ApiError> {
    let sandbox_id = sandbox.id;
    // Pure pre-tx reads: FQDN teardown flag is a single EXISTS, not a full
    // runtime inventory decode; secret mounts stay on the read pool. Run them
    // concurrently so stop admission latency is max(exists, mounts), not sum.
    let (delete_gke_fqdn_policy, secret_mounts) = tokio::try_join!(
        sandbox_has_gke_fqdn_policy(db, sandbox_id),
        fetch_sandbox_secret_mounts(db, sandbox_id),
    )?;
    let now = Utc::now();
    let mut job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::StopSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "deleteGkeFqdnPolicy": delete_gke_fqdn_policy,
        }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: sandbox.execution_class.clone(),
        priority: 100,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    if let Some(trace) = trace {
        trace.add_to_payload(&mut job.payload);
    }
    if let Some(authorization) = authorization.as_ref() {
        authorization.add_to_payload(&mut job.payload);
    }
    add_provision_spec_to_payload(&mut job, sandbox, &secret_mounts)?;
    let mut tx = db.pool.begin().await?;
    let transitioned = set_sandbox_state_on_connection(
        db,
        &mut tx,
        sandbox_id,
        SandboxState::STOP_LEGAL_FROM,
        SandboxState::Archiving,
        lifecycle_event_data,
    )
    .await?;
    if !transitioned {
        // Nothing written on this connection yet besides the failed CAS
        // itself (which affected zero rows) -- rolling back is just
        // hygiene, not undoing real work.
        tx.rollback().await?;
        return Ok(None);
    }
    let resident_bootstraps_sql = format!(
        "select id, generation, bootstrap_sha256,
                bootstrap_delivered_generation, bootstrap_delivered_lease_id,
                bootstrap_delivered_sha256
         from resident_processes
         where sandbox_id = {} and tenant_id = {}
           and bootstrap_sha256 is not null",
        db.placeholder(1),
        db.placeholder(2)
    );
    let resident_bootstrap_identities = sqlx::query(&resident_bootstraps_sql)
        .bind(sandbox_id.to_string())
        .bind(&sandbox.tenant_id)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|row| {
            let id: String = row.try_get("id")?;
            let generation: i64 = row.try_get("generation")?;
            let sha256: String = row.try_get("bootstrap_sha256")?;
            let delivered_generation: Option<i64> =
                row.try_get("bootstrap_delivered_generation")?;
            let delivered_lease_id: Option<String> = row.try_get("bootstrap_delivered_lease_id")?;
            let delivered_sha256: Option<String> = row.try_get("bootstrap_delivered_sha256")?;
            let fence = match (delivered_generation, delivered_lease_id, delivered_sha256) {
                (Some(generation), Some(lease_id), Some(sha256)) => Some(ResidentBootstrapFence {
                    generation: u64::try_from(generation).map_err(|_| {
                        ApiError::internal(
                            "database contains invalid delivered bootstrap generation",
                        )
                    })?,
                    lease_id: Uuid::parse_str(&lease_id).map_err(|_| {
                        ApiError::internal("database contains invalid delivered bootstrap lease")
                    })?,
                    sha256,
                }),
                (None, None, None) => None,
                _ => {
                    return Err(ApiError::internal(
                        "database contains incomplete delivered bootstrap fence",
                    ));
                }
            };
            Ok::<_, ApiError>((
                ResidentProcessId(Uuid::parse_str(&id).map_err(|_| {
                    ApiError::internal("database contains invalid resident process id")
                })?),
                u64::try_from(generation).map_err(|_| {
                    ApiError::internal("database contains invalid resident generation")
                })?,
                sha256,
                fence,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let stop_residents_sql = format!(
        "update resident_processes
         set desired_state = 'stopped',
             bootstrap_acknowledged_at = case
               when bootstrap_delivered_generation is not null
                and bootstrap_delivered_lease_id is not null
                and bootstrap_delivered_sha256 is not null
               then coalesce(bootstrap_acknowledged_at, {})
               else bootstrap_acknowledged_at
             end,
             updated_at = {}
         where sandbox_id = {} and tenant_id = {} and desired_state = 'running'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&stop_residents_sql)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .bind(&sandbox.tenant_id)
        .execute(&mut *tx)
        .await?;
    // Cancel queued non-provision work for this sandbox before inserting the
    // stop job. Provision jobs stay queued so a stop-before-first-claim path can
    // still drain them (they complete into the already-archiving sandbox and
    // enqueue teardown). In-flight *leased* work is fenced via
    // cancel_requested_at so renew returns lease_cancelled and workers abort
    // kubectl waits immediately.
    let cancel_jobs_sql = format!(
        "update jobs
         set status = {}, updated_at = {}, last_error = {},
             cancel_requested_at = {}, cancel_reason = {}
         where tenant_id = {}
           and status = 'queued'
           and kind not in ('stop_sandbox', 'provision_sandbox')
           and (sandbox_id = {} or parent_sandbox_id = {} or child_sandbox_id = {})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9)
    );
    sqlx::query(&cancel_jobs_sql)
        .bind(job_status_to_str(&JobStatus::Cancelled))
        .bind(now.to_rfc3339())
        .bind("sandbox_stopped")
        .bind(now.to_rfc3339())
        .bind("sandbox_stopped")
        .bind(&sandbox.tenant_id)
        .bind(sandbox_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    let cancel_leases_sql = format!(
        "update job_leases
         set cancel_requested_at = {}, cancel_reason = {}
         where status = 'active'
           and cancel_requested_at is null
           and job_id in (
             select id from jobs
             where tenant_id = {}
               and (sandbox_id = {} or parent_sandbox_id = {} or child_sandbox_id = {})
           )",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    sqlx::query(&cancel_leases_sql)
        .bind(now.to_rfc3339())
        .bind("sandbox_stopped")
        .bind(&sandbox.tenant_id)
        .bind(sandbox_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_job_on_connection(db, &mut tx, &job).await?;
    let revoke_sql = format!(
        "update guest_tokens set revoked_at = {}
         where tenant_id = {} and sandbox_id = {} and revoked_at is null",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    sqlx::query(&revoke_sql)
        .bind(now.to_rfc3339())
        .bind(&sandbox.tenant_id)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    // A stopped sandbox has no reachable desktop, so its brokered
    // desktop-access credentials must die with it (mirrors the guest-token
    // revocation above) rather than staying live until their <=900s expiry.
    let revoke_desktop_sql = format!(
        "update desktop_access_credentials set revoked_at = {}
         where tenant_id = {} and sandbox_id = {} and revoked_at is null",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    sqlx::query(&revoke_desktop_sql)
        .bind(now.to_rfc3339())
        .bind(&sandbox.tenant_id)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    for (process_id, generation, sha256, fence) in resident_bootstrap_identities {
        resident_bootstraps.reclaim(&process_id, generation, &sha256, fence.as_ref());
        resident_bootstraps.forget_shared(db, process_id).await;
    }
    Ok(Some(job))
}

pub(crate) async fn stop_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Extension(authorization): Extension<AuthorizationContext>,
    Extension(trace): Extension<RequestTrace>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    let mut sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let now = Utc::now();
    let request_id = trace.request_id.clone();
    let trace_id = trace.trace_id.clone();
    let Some(job) = stop_sandbox_via_job(
        &state.db,
        &state.resident_bootstraps,
        &sandbox,
        json!({"state": SandboxState::Archiving, "reason": "stop_requested"}),
        Some(authorization),
        Some(trace),
    )
    .await?
    else {
        // A concurrent actor (another stop request, or the active-lifetime
        // reaper) already moved this sandbox out of `STOP_LEGAL_FROM` since
        // it was fetched above. Report the conflict honestly instead of
        // returning 202 with a job that was never actually enqueued.
        return Err(sandbox_state_http_conflict(&state.db, sandbox_id).await?);
    };
    sandbox.state = SandboxState::Archiving;
    sandbox.updated_at = now;
    tracing::info!(
        request_id = %request_id,
        trace_id = %trace_id,
        sandbox_id = %sandbox.id,
        job_id = %job.id,
        "sandbox_stop_accepted"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox,
            operation: Some(operation_from_job(&job)?),
            provisioning: None,
            placement: None,
        }),
    ))
}

/// Builds a 409 (or 404, if the sandbox vanished entirely) describing the
/// sandbox's actual current state, for the live `stop_sandbox` handler's
/// CAS-miss path. Deliberately not shared with the `#[cfg(test)]`-only
/// [`sandbox_state_conflict`] below: that one takes the specific
/// `allowed_from`/`next_state` a *particular* action attempted (useful for
/// unit tests exercising one transition at a time), whereas this one only
/// needs to report "someone else already moved it" for the one live route
/// that calls [`stop_sandbox_via_job`] directly.
pub(crate) async fn sandbox_state_http_conflict(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<ApiError, ApiError> {
    Ok(match fetch_sandbox_state(db, sandbox_id).await? {
        None => ApiError::not_found("sandbox not found"),
        Some(actual) => {
            let message = format!(
                "cannot stop sandbox {sandbox_id}: it was concurrently stopped or archived \
                 already (currently {})",
                state_to_str(&actual)
            );
            if matches!(actual, SandboxState::Archiving | SandboxState::Archived) {
                // Stop is an idempotent cleanup operation once teardown has
                // already won the state CAS. Keep the stable code narrow:
                // every other 409 still means the caller attempted an
                // invalid transition and must not be swallowed by a worker.
                ApiError::conflict_code("sandbox_stop_already_in_progress", message)
            } else {
                ApiError::conflict(message)
            }
        }
    })
}

/// Restores a stopped sandbox in place from one of its durable snapshots.
///
/// A resume is deliberately *not* a fork: the sandbox keeps its own id,
/// creation time, placement, and all three lifetime knobs, and the workspace
/// PVC is recreated from the snapshot under the sandbox's own name. That is
/// also why the request carries no placement fields -- there is nothing here
/// a caller could restate, so there is no way to shed a caller-imposed
/// `max_lifetime_seconds` by resuming (which `POST /snapshots/{id}/fork`
/// deliberately does allow; see `docs/capabilities.md`). A sandbox already
/// past its hard cap is refused rather than resumed into an immediate reap.
#[utoipa::path(post, path = "/v1/sandboxes/{sandbox_id}/resume", params(("sandbox_id" = Uuid, Path), ("Idempotency-Key" = Option<String>, Header, description = "Tenant-scoped replay key"), ("X-Request-Id" = Option<String>, Header), ("traceparent" = Option<String>, Header)), request_body = ResumeSandboxRequest, responses((status = 202, description = "Resume accepted with the restored sandbox and asynchronous operation", body = SandboxResponse), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope)))]
pub(crate) async fn resume_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    // Optional so a caller with nothing to say ("restore the latest snapshot")
    // can post an empty body, the way `stop` already accepts one.
    request: Option<Json<ResumeSandboxRequest>>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let Json(request) = request.unwrap_or_default();
    let sandbox_id = SandboxId(sandbox_id);
    let now = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let mut sandbox =
        ensure_sandbox_tenant_on_connection(&state.db, &mut tx, sandbox_id, &ctx.tenant_id).await?;
    ensure_sandbox_resumable(&sandbox, now)?;
    let restore = claim_sandbox_resume_snapshot_on_connection(
        &state.db,
        &mut tx,
        &sandbox,
        request.snapshot_id,
        &ctx,
        now,
    )
    .await?;
    let provision_spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        execution_class: sandbox.execution_class.clone(),
        memory_limit: sandbox.memory_limit.clone(),
        network_egress: sandbox.network_egress.clone(),
        workspace_mode: sandbox.workspace_mode.clone(),
        runtime_profile: sandbox.runtime_profile.clone(),
    };
    let job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ResumeSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "snapshotId": restore.snapshot_id,
            "runtimeImage": sandbox.template,
            "provisionSpec": provision_spec
        }),
        required_capability: fork_capability(&sandbox.runtime_profile, &sandbox.network_egress),
        required_execution_class: sandbox.execution_class.clone(),
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    let next_state = SandboxState::Provisioning;
    let moved = set_sandbox_state_on_connection(
        &state.db,
        &mut tx,
        sandbox_id,
        SandboxState::RESUME_LEGAL_FROM,
        next_state.clone(),
        json!({
            "state": next_state,
            "reason": "resume_requested",
            "restoredFromSnapshotId": restore.snapshot_id
        }),
    )
    .await?;
    if !moved {
        // Lost the race against a concurrent writer. Release the transaction
        // before reading the sandbox again: the pool may hand out a single
        // connection, and this read must not wait on a transaction it owns.
        drop(tx);
        return Err(match fetch_sandbox_state(&state.db, sandbox_id).await? {
            None => ApiError::not_found("sandbox not found"),
            Some(actual) => sandbox_not_resumable(sandbox_id, &actual),
        });
    }
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    sandbox.state = next_state;
    sandbox.updated_at = now;
    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox,
            operation: Some(operation_from_job(&job)?),
            provisioning: None,
            placement: None,
        }),
    ))
}

/// Every precondition a resume has beyond owning the sandbox, checked before
/// the snapshot is claimed so a caller resuming a live sandbox is told that
/// rather than getting a snapshot-shaped error.
///
/// Shared with the `/v1/jobs` path: a directly created `ResumeSandbox` job
/// reaches the same worker code, and running a restore against a *live*
/// sandbox would have the provider apply a cloned-volume PVC over the bound
/// one, fail, and roll back -- deleting the running sandbox's workspace. The
/// state CAS in `resume_sandbox` remains the authority for the racing case.
pub(crate) fn ensure_sandbox_resumable(
    sandbox: &Sandbox,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if !SandboxState::RESUME_LEGAL_FROM.contains(&sandbox.state) {
        return Err(sandbox_not_resumable(sandbox.id, &sandbox.state));
    }
    if sandbox.workspace_mode != WorkspaceMode::Persistent {
        return Err(ApiError::conflict_code(
            "workspace_mode_resume_unsupported",
            "resume requires workspace_mode=persistent",
        ));
    }
    if let Some(max_lifetime_seconds) = sandbox.max_lifetime_seconds
        && let Some(deadline) =
            crate::reap::max_lifetime_expired(sandbox.created_at, max_lifetime_seconds, now)
    {
        // Resuming keeps the original creation time, so a sandbox already past
        // its hard cap would be reaped again by the next sweep. Refuse instead
        // of restoring a sandbox that cannot legally run.
        return Err(ApiError::conflict_code(
            "resume_lifetime_exhausted",
            format!(
                "cannot resume sandbox {}: its max_lifetime_seconds deadline \
                 ({deadline}) has passed; restore the snapshot into a new sandbox instead",
                sandbox.id
            ),
        ));
    }
    Ok(())
}

fn sandbox_not_resumable(sandbox_id: SandboxId, actual: &SandboxState) -> ApiError {
    ApiError::conflict_code(
        "sandbox_not_resumable",
        format!(
            "cannot resume sandbox {sandbox_id}: only an archived sandbox can be resumed \
             (currently {})",
            state_to_str(actual)
        ),
    )
}

#[utoipa::path(post, path = "/v1/sandboxes/{sandbox_id}/fork", params(("sandbox_id" = Uuid, Path), ("Idempotency-Key" = Option<String>, Header, description = "Tenant-scoped replay key"), ("X-Request-Id" = Option<String>, Header), ("traceparent" = Option<String>, Header)), request_body = CreateSandboxRequest, responses((status = 202, description = "Fork accepted with child sandbox and asynchronous operation", body = SandboxResponse), (status = 404, body = ErrorEnvelope)))]
pub(crate) async fn fork_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let parent = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    // A fork copies a workspace, not an entitlement: secret bindings are not
    // inherited, and asking for them here is rejected rather than silently
    // dropped so a caller never believes a forked sandbox holds credentials.
    if !request.secret_ref_ids.is_empty() {
        return Err(ApiError::bad_request(
            "secret references cannot be bound on fork; create a sandbox instead",
        ));
    }
    let provision_spec = provision_spec_from_request(&request, Some(&parent))?;
    if parent.workspace_mode != WorkspaceMode::Persistent
        || provision_spec.workspace_mode != WorkspaceMode::Persistent
    {
        return Err(ApiError::conflict_code(
            "workspace_mode_fork_unsupported",
            "fork requires persistent source and child workspaces",
        ));
    }
    let now = Utc::now();
    let snapshot = Snapshot {
        id: SnapshotId::new(),
        sandbox_id: parent.id,
        status: SnapshotStatus::Pending,
        label: format!("fork-source-{}", now.timestamp_millis()),
        inventory: json!({
            "sourceSandboxId": parent.id,
            "template": parent.template
        }),
        provider_metadata: json!({
            "source": "fork_request"
        }),
        runtime_image: Some(parent.template.clone()),
        provision_spec: Some(SandboxProvisionSpec {
            secret_mounts: Vec::new(),
            execution_class: parent.execution_class.clone(),
            memory_limit: parent.memory_limit.clone(),
            network_egress: parent.network_egress.clone(),
            workspace_mode: parent.workspace_mode.clone(),
            runtime_profile: parent.runtime_profile.clone(),
        }),
        created_at: now,
        ready_at: None,
        expires_at: None,
        error: None,
    };
    let child = Sandbox {
        execution_class: provision_spec.execution_class,
        id: SandboxId::new(),
        tenant_id: parent.tenant_id.clone(),
        name: request
            .name
            .unwrap_or_else(|| format!("{}-fork", parent.name)),
        state: SandboxState::Planning,
        template: request.template.unwrap_or_else(|| parent.template.clone()),
        memory_limit: provision_spec.memory_limit,
        network_egress: provision_spec.network_egress,
        workspace_mode: provision_spec.workspace_mode,
        runtime_profile: provision_spec.runtime_profile,
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(parent.ttl_seconds),
        // Same default/clamp treatment as `create_sandbox`, applied to
        // whichever of the fork request or the parent's own value wins --
        // this keeps a fork's active-lifetime knobs subject to the
        // operator's *current* policy rather than silently inheriting a
        // parent value that policy may since have tightened.
        max_lifetime_seconds: clamp_optional_lifetime(
            request.max_lifetime_seconds.or(parent.max_lifetime_seconds),
            state.sandbox_lifetime.default_max_lifetime_seconds,
            state.sandbox_lifetime.max_max_lifetime_seconds,
        ),
        idle_ttl_seconds: clamp_optional_lifetime(
            request.idle_ttl_seconds.or(parent.idle_ttl_seconds),
            state.sandbox_lifetime.default_idle_ttl_seconds,
            state.sandbox_lifetime.max_idle_ttl_seconds,
        ),
        parent_snapshot_id: Some(snapshot.id),
        last_activity_at: None,
    };

    let job = Job {
        id: JobId::new(),
        tenant_id: parent.tenant_id.clone(),
        kind: JobKind::CreateSnapshot,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": parent.id,
            "snapshotId": snapshot.id,
            "operation": { "kind": OperationKind::ForkSandbox, "resourceId": child.id },
            "runtimeImage": parent.template,
            "provisionSpec": SandboxProvisionSpec {
                secret_mounts: Vec::new(),
                execution_class: parent.execution_class.clone(),
                memory_limit: parent.memory_limit.clone(),
                network_egress: parent.network_egress.clone(),
                workspace_mode: parent.workspace_mode.clone(),
                runtime_profile: parent.runtime_profile.clone(),
            }
        }),
        required_capability: WorkerCapability::Snapshot,
        required_execution_class: parent.execution_class.clone(),
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    let mut tx = state.db.pool.begin().await?;
    insert_snapshot_on_connection(&state.db, &mut tx, &snapshot).await?;
    insert_sandbox_on_connection(&state.db, &mut tx, &child).await?;
    replace_sandbox_network_rules_on_connection(
        &state.db,
        &mut tx,
        child.id,
        child.network_egress.rules(),
    )
    .await?;
    insert_event_on_connection(
        &state.db,
        &mut tx,
        child.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": child.state,
            "reason": "fork_planned",
            "parentSandboxId": parent.id,
            "parentSnapshotId": snapshot.id,
            "memoryLimit": child.memory_limit,
            "networkEgress": child.network_egress
        }),
    )
    .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox: child,
            operation: Some(operation_from_job(&job)?),
            provisioning: None,
            placement: None,
        }),
    ))
}

/// Drives a user-initiated sandbox state change (stop/resume) via a
/// compare-and-swap update. `allowed_from` is the exact set of states this
/// specific action may legally transition out of (e.g.
/// [`SandboxState::RESUME_LEGAL_FROM`]) -- callers must pick the constant for
/// their action rather than deriving one from `next_state` alone, since more
/// than one action can legally target the same state with different
/// preconditions (see [`SandboxState::can_transition_to`]'s docs).
///
/// If the sandbox is not currently in one of `allowed_from`, this returns a
/// 409 Conflict describing the sandbox's actual state rather than silently
/// clobbering it.
#[cfg(test)]
pub(crate) async fn transition_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: SandboxState,
    reason: &'static str,
) -> Result<Json<SandboxResponse>, ApiError> {
    fetch_sandbox(db, sandbox_id).await?;
    let event_state = next_state.clone();
    set_sandbox_state(
        db,
        sandbox_id,
        allowed_from,
        next_state,
        json!({
            "state": event_state,
            "reason": reason
        }),
    )
    .await?;

    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    Ok(Json(SandboxResponse {
        ok: true,
        sandbox,
        operation: None,
        provisioning: None,
        placement: None,
    }))
}

#[cfg(test)]
pub(crate) async fn set_sandbox_state(
    db: &Database,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: SandboxState,
    event_data: serde_json::Value,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let allowed_values: Vec<&str> = allowed_from.iter().map(state_to_str).collect();
    let sql = format!(
        "update sandboxes set state = {}, updated_at = {} where id = {} and state in ({})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        sql_literal_list(&allowed_values)
    );
    let result = sqlx::query(&sql)
        .bind(state)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&db.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(sandbox_state_conflict(db, sandbox_id, allowed_from, &next_state).await?);
    }

    insert_event(
        db,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        event_data,
    )
    .await?;
    Ok(())
}

/// Builds the 404/409 error for a failed user-facing compare-and-swap state
/// update: 404 if the sandbox no longer exists at all, otherwise 409 with the
/// sandbox's actual current state so the caller understands what conflicted.
#[cfg(test)]
pub(crate) async fn sandbox_state_conflict(
    db: &Database,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: &SandboxState,
) -> Result<ApiError, ApiError> {
    let current = fetch_sandbox_state(db, sandbox_id).await?;
    Ok(match current {
        None => ApiError::not_found("sandbox not found"),
        Some(actual) => {
            let allowed = allowed_from
                .iter()
                .map(state_to_str)
                .collect::<Vec<_>>()
                .join(", ");
            ApiError::conflict(format!(
                "cannot transition sandbox {sandbox_id} to {}: sandbox is currently {} (expected one of [{allowed}])",
                state_to_str(next_state),
                state_to_str(&actual),
            ))
        }
    })
}

/// Used by both the `#[cfg(test)]` `sandbox_state_conflict` helper and the
/// live `sandbox_state_http_conflict` (`stop_sandbox`'s CAS-miss path), so
/// -- unlike its two `#[cfg(test)]` siblings above -- this one is not
/// test-only.
pub(crate) async fn fetch_sandbox_state(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Option<SandboxState>, ApiError> {
    let sql = format!(
        "select state from sandboxes where id = {}",
        db.placeholder(1)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
    else {
        return Ok(None);
    };
    let raw: String = row.try_get("state")?;
    Ok(Some(parse_state(&raw)?))
}

/// Drives a worker/job-completion-triggered sandbox state change via a
/// compare-and-swap update, mirroring [`set_sandbox_state`]. Unlike the
/// user-facing routes, a job-completion path must never error out or clobber
/// a sandbox that has moved on since the job started -- e.g. a
/// `ProvisionSandbox`/`ForkSandbox` job completing after the sandbox was
/// concurrently archived must leave it archived, not resurrect it. So on a
/// compare-and-swap miss this logs a warning and returns `Ok(false)` instead
/// of applying the write or raising an error; `Ok(true)` means the CAS won
/// and the `LifecycleChanged` event was recorded.
///
/// Callers that perform further side effects contingent on the transition
/// actually happening (see [`stop_sandbox_via_job`]) must check this return
/// value rather than assuming success -- a `false` here with no further
/// checks is exactly how a concurrent actor winning the same race used to
/// result in a redundant, no-op job/token-revoke/resident-stop sequence.
pub(crate) async fn set_sandbox_state_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: SandboxState,
    event_data: serde_json::Value,
) -> Result<bool, ApiError> {
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let allowed_values: Vec<&str> = allowed_from.iter().map(state_to_str).collect();
    let sql = format!(
        "update sandboxes set state = {}, updated_at = {} where id = {} and state in ({})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        sql_literal_list(&allowed_values)
    );
    let result = sqlx::query(&sql)
        .bind(state)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    if result.rows_affected() == 0 {
        tracing::warn!(
            %sandbox_id,
            next_state = state,
            allowed_from = ?allowed_values,
            "skipping sandbox state transition: sandbox is no longer in an expected \
             predecessor state (likely concurrently stopped/resumed by another request)"
        );
        return Ok(false);
    }

    insert_event_on_connection(
        db,
        connection,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        event_data,
    )
    .await?;
    Ok(true)
}

pub(crate) async fn fetch_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, runtime_profile, execution_class,
                created_at, updated_at, ttl_seconds, max_lifetime_seconds, idle_ttl_seconds, last_activity_at, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress(db, &mut sandbox).await?;
    Ok(sandbox)
}

pub(crate) async fn fetch_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, runtime_profile, execution_class,
                created_at, updated_at, ttl_seconds, max_lifetime_seconds, idle_ttl_seconds, last_activity_at, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress_on_connection(db, connection, &mut sandbox).await?;
    Ok(sandbox)
}

/// Reject create when every online worker has reported a resource envelope and
/// none of those envelopes can schedule `memory_limit`. Workers that have not
/// reported an envelope are treated as "unknown" so rolling upgrades do not
/// brick admission before all workers start heartbeating capacity evidence.
/// True when this sandbox still has the GKE FQDN egress NetworkPolicy row the
/// stop job must delete. Exists-only so stop does not hydrate full inventory.
pub(crate) async fn sandbox_has_gke_fqdn_policy(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let policy_name = format!("sandboxwich-fqdn-egress-{sandbox_id}");
    let sql = format!(
        "select 1 as present from runtime_resources
         where sandbox_id = {}
           and provider = 'kubernetes'
           and resource_kind = {}
           and resource_name = {}
         limit 1",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(runtime_resource_kind_to_str(
            &RuntimeResourceKind::NetworkPolicy,
        ))
        .bind(policy_name)
        .fetch_optional(db.read_pool())
        .await?;
    Ok(row.is_some())
}

pub(crate) async fn reject_if_memory_exceeds_all_envelopes(
    db: &Database,
    tenant_id: &str,
    memory_limit: &MemoryLimit,
) -> Result<(), ApiError> {
    // Fail-open if any online worker has not reported an envelope yet (rolling
    // upgrade). Cheap existence probe before loading every JSON blob.
    let unknown_sql = format!(
        "select 1 as present from workers
         where tenant_id = {} and status = 'online'
           and (resource_envelope is null or resource_envelope = '')
         limit 1",
        db.placeholder(1)
    );
    if sqlx::query(&unknown_sql)
        .bind(tenant_id)
        .fetch_optional(db.read_pool())
        .await?
        .is_some()
    {
        return Ok(());
    }
    let sql = format!(
        "select resource_envelope from workers
         where tenant_id = {} and status = 'online'
           and resource_envelope is not null and resource_envelope <> ''",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(db.read_pool())
        .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let requested = memory_limit.memory_bytes();
    let mut max_ceiling: Option<u64> = None;
    let mut evidence_age: Option<String> = None;
    for row in rows {
        let raw: String = row.try_get("resource_envelope")?;
        // Only need ceiling + evidence for admission; skip full envelope decode.
        let envelope: CapacityEnvelopeView = serde_json::from_str(&raw).map_err(|_| {
            ApiError::internal("database contains invalid worker resource envelope")
        })?;
        match envelope.max_memory_bytes {
            Some(ceiling) if ceiling >= requested => return Ok(()),
            Some(ceiling) => {
                max_ceiling = Some(max_ceiling.unwrap_or(0).max(ceiling));
            }
            None => {}
        }
        evidence_age = Some(envelope.evidence_at);
    }
    Err(ApiError {
        status: StatusCode::CONFLICT,
        code: "capacity_insufficient",
        message: format!(
            "requested memory tier {} ({} bytes) exceeds observed worker capacity (ceiling={} bytes, evidence_at={})",
            memory_limit.as_db_str(),
            requested,
            max_ceiling.unwrap_or(0),
            evidence_age.unwrap_or_else(|| "unknown".into()),
        ),
    })
}

/// Thin parse of the worker envelope JSON for create-time capacity admission.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapacityEnvelopeView {
    #[serde(default)]
    max_memory_bytes: Option<u64>,
    evidence_at: String,
}

pub(crate) async fn ensure_sandbox_tenant_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    tenant_id: &str,
) -> Result<Sandbox, ApiError> {
    let sandbox = fetch_sandbox_on_connection(db, connection, sandbox_id).await?;
    if sandbox.tenant_id != tenant_id {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(sandbox)
}

#[cfg(test)]
pub(crate) async fn insert_sandbox(db: &Database, sandbox: &Sandbox) -> Result<(), ApiError> {
    validate_network_egress(&sandbox.network_egress)?;
    let mut tx = db.pool.begin().await?;
    let inserted = async {
        insert_sandbox_on_connection(db, &mut tx, sandbox).await?;
        replace_sandbox_network_rules_on_connection(
            db,
            &mut tx,
            sandbox.id,
            sandbox.network_egress.rules(),
        )
        .await
    }
    .await;
    match inserted {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back sandbox insert");
            }
            Err(error)
        }
    }
}

pub(crate) async fn insert_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &Sandbox,
) -> Result<(), ApiError> {
    let rules_json = network_egress_rules_json(&sandbox.network_egress)?;
    let sql = format!(
        "insert into sandboxes
         (id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, runtime_profile, execution_class,
          created_at, updated_at, ttl_seconds, max_lifetime_seconds, idle_ttl_seconds, last_activity_at, parent_snapshot_id,
          network_egress_rules_json)
         values ({})",
        db.placeholders(18)
    );
    sqlx::query(&sql)
        .bind(sandbox.id.to_string())
        .bind(&sandbox.tenant_id)
        .bind(&sandbox.name)
        .bind(state_to_str(&sandbox.state))
        .bind(&sandbox.template)
        .bind(memory_limit_to_str(&sandbox.memory_limit))
        .bind(network_egress_mode_to_str(&sandbox.network_egress.mode()))
        .bind(sandbox.workspace_mode.as_db_str())
        .bind(sandbox.runtime_profile.as_db_str())
        .bind(sandbox.execution_class.as_db_str())
        .bind(sandbox.created_at.to_rfc3339())
        .bind(sandbox.updated_at.to_rfc3339())
        .bind(sandbox.ttl_seconds.map(|ttl| ttl as i64))
        .bind(sandbox.max_lifetime_seconds.map(|ttl| ttl as i64))
        .bind(sandbox.idle_ttl_seconds.map(|ttl| ttl as i64))
        .bind(sandbox.last_activity_at.map(|value| value.to_rfc3339()))
        .bind(
            sandbox
                .parent_snapshot_id
                .map(|snapshot| snapshot.0.to_string()),
        )
        .bind(rules_json)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// Serialize allowlist rules for the denormalized list column. Deny/allow-all
/// store null so the list decoder can skip JSON parse. Allowlist always stores
/// a JSON array (possibly empty).
pub(crate) fn network_egress_rules_json(
    network_egress: &NetworkEgress,
) -> Result<Option<String>, ApiError> {
    match network_egress {
        NetworkEgress::Allowlist { rules } => serde_json::to_string(rules)
            .map(Some)
            .map_err(|_| ApiError::internal("failed to serialize network egress allowlist rules")),
        NetworkEgress::DenyAll | NetworkEgress::AllowAll => Ok(None),
    }
}

pub(crate) async fn replace_sandbox_network_rules_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    rules: &[NetworkAllowRule],
) -> Result<(), ApiError> {
    let delete_sql = format!(
        "delete from sandbox_network_egress_rules where sandbox_id = {}",
        db.placeholder(1)
    );
    sqlx::query(&delete_sql)
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    for rule in rules {
        let sql = format!(
            "insert into sandbox_network_egress_rules (id, sandbox_id, kind, value, created_at)
             values ({})",
            db.placeholders(5)
        );
        sqlx::query(&sql)
            .bind(EventId::new().to_string())
            .bind(sandbox_id.to_string())
            .bind(network_allow_rule_kind_to_str(&rule.kind))
            .bind(&rule.value)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *connection)
            .await?;
    }

    // Keep the denormalized list column in lockstep with the normalized table.
    // Empty allowlist stores "[]" (not null) so list never confuses "no rules"
    // with "column not backfilled".
    let rules_json = serde_json::to_string(rules)
        .map_err(|_| ApiError::internal("failed to serialize network egress allowlist rules"))?;
    let update_sql = format!(
        "update sandboxes set network_egress_rules_json = {} where id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&update_sql)
        .bind(Some(rules_json))
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    Ok(())
}

pub(crate) fn sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(job, "sandboxId", "run command job is missing sandbox id").map(SandboxId)
}

pub(crate) fn parent_sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(
        job,
        "parentSandboxId",
        "fork job is missing parent sandbox id",
    )
    .map(SandboxId)
}

pub(crate) fn child_sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(
        job,
        "childSandboxId",
        "fork job is missing child sandbox id",
    )
    .map(SandboxId)
}

pub(crate) async fn hydrate_sandbox_network_egress(
    db: &Database,
    sandbox: &mut Sandbox,
) -> Result<(), ApiError> {
    if !matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
        return Ok(());
    }
    let rules = list_network_allow_rules(db, sandbox.id).await?;
    sandbox.network_egress = NetworkEgress::Allowlist { rules };
    Ok(())
}

pub(crate) async fn hydrate_sandbox_network_egress_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &mut Sandbox,
) -> Result<(), ApiError> {
    if !matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
        return Ok(());
    }
    let rules = list_network_allow_rules_on_connection(db, connection, sandbox.id).await?;
    sandbox.network_egress = NetworkEgress::Allowlist { rules };
    Ok(())
}

pub(crate) async fn list_network_allow_rules(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<NetworkAllowRule>, ApiError> {
    let sql = format!(
        "select kind, value
         from sandbox_network_egress_rules
         where sandbox_id = {}
         order by kind asc, value asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(db.read_pool())
        .await?;
    rows.into_iter().map(row_to_network_allow_rule).collect()
}

pub(crate) async fn list_network_allow_rules_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Vec<NetworkAllowRule>, ApiError> {
    let sql = format!(
        "select kind, value
         from sandbox_network_egress_rules
         where sandbox_id = {}
         order by kind asc, value asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&mut *connection)
        .await?;
    rows.into_iter().map(row_to_network_allow_rule).collect()
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use axum::body::to_bytes;
    use serde::Serializer;

    async fn assert_response_equivalent(expected: Response, actual: Response) {
        assert_eq!(actual.status(), expected.status());
        assert_eq!(actual.headers(), expected.headers());
        let expected = to_bytes(expected.into_body(), usize::MAX).await.unwrap();
        let actual = to_bytes(actual.into_body(), usize::MAX).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn sandbox_list_response_matches_axum_json_bytes_and_headers() {
        let now = Utc::now();
        let response = SandboxListResponse {
            ok: true,
            sandboxes: vec![Sandbox {
                id: SandboxId::new(),
                tenant_id: "tenant-with-\"quotes\"".to_string(),
                name: "sandbox\nname".to_string(),
                state: SandboxState::Ready,
                template: "ubuntu-dev".to_string(),
                memory_limit: MemoryLimit::FourG,
                network_egress: NetworkEgress::Allowlist {
                    rules: vec![NetworkAllowRule {
                        kind: NetworkAllowRuleKind::Host,
                        value: "*.example.test".to_string(),
                    }],
                },
                workspace_mode: WorkspaceMode::Ephemeral,
                runtime_profile: SandboxRuntimeProfile::Unprivileged,
                execution_class: ExecutionClass::DevelopmentContainer,
                created_at: now,
                updated_at: now,
                ttl_seconds: Some(3600),
                max_lifetime_seconds: None,
                idle_ttl_seconds: Some(300),
                last_activity_at: Some(now),
                parent_snapshot_id: None,
            }],
            next_cursor: Some("cursor+/=".to_string()),
        };

        assert_response_equivalent(
            Json(response.clone()).into_response(),
            sandbox_list_response(response),
        )
        .await;
    }

    #[derive(Clone, Copy)]
    struct SerializationFailure;

    impl Serialize for SerializationFailure {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    #[tokio::test]
    async fn presized_json_response_delegates_errors_to_axum_json() {
        assert_response_equivalent(
            Json(SerializationFailure).into_response(),
            json_response_with_capacity(SerializationFailure, 1024),
        )
        .await;
    }
}
