use crate::db::Database;
use crate::error::*;
use crate::identity_mtls::IdentityServiceContext;
use crate::rows::{parse_timestamp, parse_uuid};
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sandboxwich_core::lifecycle_contract::LifecycleReasonCode;
use sandboxwich_core::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{AnyConnection, Row};
use std::collections::BTreeMap;
use std::time::Instant;
use subtle::ConstantTimeEq;
use url::Url;

async fn resident_service_name(
    db: &Database,
    connection: &mut AnyConnection,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
) -> Result<String, ApiError> {
    // The activated resident fence lives on sterile_cells, while the stable
    // Service lives on pool membership. Join both to prevent an unrelated
    // resident from borrowing a candidate's pre-created endpoint.
    let exact_sql = format!(
        "select p.candidate_service_name
         from resident_processes rp
         join sterile_cells c on c.id = rp.sterile_cell_id
         join sterile_pool_memberships p on p.sandbox_id = c.id
         where rp.id = {} and rp.generation = {} and rp.active_lease_id = {}
           and p.state = 'leased' and c.activated_resident_process_id = rp.id
           and c.activated_resident_generation = rp.generation",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    if let Some(service_name) = sqlx::query_scalar::<_, String>(&exact_sql)
        .bind(process_id.to_string())
        .bind(i64::try_from(generation).unwrap_or(i64::MAX))
        .bind(lease_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
    {
        return Ok(service_name);
    }
    Ok(maestro_hosted_runner_service_name(
        process_id, generation, lease_id,
    ))
}
use uuid::Uuid;

const ATTESTATION_VERSION: u32 = 2;
const ATTESTATION_TTL_SECONDS: i64 = 300;
pub(crate) const IDENTITY_METRICS_TENANT_ID: &str = "identity-service";

struct PlacementFence {
    lease_attempt: u64,
    job_id: JobId,
    worker_id: WorkerId,
    placement_generation: u64,
    provider_mode: String,
    runtime_image: String,
    isolation_version: u32,
    lease_expires_at: DateTime<Utc>,
    provider_pod_name: Option<String>,
    provider_pod_uid: Option<String>,
}

struct AttestationRecord {
    id: Uuid,
    tenant_id: String,
    sandbox_id: SandboxId,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
    fence: PlacementFence,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    token_sha256: String,
    consumed_at: Option<DateTime<Utc>>,
    redeem_idempotency_key: Option<Uuid>,
}

fn unavailable() -> ApiError {
    ApiError {
        status: StatusCode::NOT_FOUND,
        code: LifecycleReasonCode::PlacementAttestationNotFound.as_str(),
        message: "placement attestation was not found".into(),
        details: None,
    }
}

fn not_live(message: impl Into<String>) -> ApiError {
    ApiError::conflict_code(
        LifecycleReasonCode::PlacementAttestationNotLive.as_str(),
        message,
    )
}

fn placement_pending() -> ApiError {
    ApiError::conflict_code(
        LifecycleReasonCode::PlacementAttestationPending.as_str(),
        "Maestro hosted runner placement is still being materialized",
    )
}

fn resident_not_ready_error(
    observed_state: &str,
    error_class: Option<ProvisioningErrorClass>,
    error_code: Option<String>,
    last_error: Option<String>,
) -> ApiError {
    let terminal = observed_state == ResidentProcessObservedState::Failed.as_db_str()
        || observed_state == ResidentProcessObservedState::Lost.as_db_str()
        || observed_state == ResidentProcessObservedState::Stopped.as_db_str();
    let has_error = last_error.is_some() || error_class.is_some() || error_code.is_some();
    let message = last_error
        .unwrap_or_else(|| "resident process has not reported a provider error".to_string());
    let code = error_code.as_deref();

    if !terminal {
        if error_class.as_ref() == Some(&ProvisioningErrorClass::RetryableCapacity)
            || code == Some(LifecycleReasonCode::WorkspaceCapacityPending.as_str())
        {
            return ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: LifecycleReasonCode::WorkspaceCapacityPending.as_str(),
                message,
                details: None,
            };
        }
        if has_error {
            return ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: LifecycleReasonCode::ResidentMaterializationPending.as_str(),
                message,
                details: None,
            };
        }
        return placement_pending();
    }

    if error_class.as_ref() == Some(&ProvisioningErrorClass::RetryableCapacity)
        || code == Some(LifecycleReasonCode::WorkspaceCapacityPending.as_str())
    {
        return ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: LifecycleReasonCode::WorkspaceCapacityExhausted.as_str(),
            message,
            details: None,
        };
    }
    if code == Some(LifecycleReasonCode::IdentityExchangeFailed.as_str()) {
        return ApiError {
            status: StatusCode::BAD_GATEWAY,
            code: LifecycleReasonCode::IdentityExchangeFailed.as_str(),
            message,
            details: None,
        };
    }
    if error_class.as_ref() == Some(&ProvisioningErrorClass::TerminalSecurity) {
        if code == Some(LifecycleReasonCode::KubernetesPolicyDenied.as_str()) {
            return ApiError {
                status: StatusCode::FORBIDDEN,
                code: LifecycleReasonCode::KubernetesPolicyDenied.as_str(),
                message,
                details: None,
            };
        }
        if code == Some(LifecycleReasonCode::RuntimeClassBoundaryUnverified.as_str()) {
            return ApiError {
                status: StatusCode::FORBIDDEN,
                code: LifecycleReasonCode::RuntimeClassBoundaryUnverified.as_str(),
                message,
                details: None,
            };
        }
    }
    if error_class.as_ref() == Some(&ProvisioningErrorClass::TerminalContract) {
        if code == Some(LifecycleReasonCode::KubernetesContractInvalid.as_str()) {
            return ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: LifecycleReasonCode::KubernetesContractInvalid.as_str(),
                message,
                details: None,
            };
        }
        if code == Some(LifecycleReasonCode::ResourceContractConflict.as_str()) {
            return ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: LifecycleReasonCode::ResourceContractConflict.as_str(),
                message,
                details: None,
            };
        }
        if code == Some(LifecycleReasonCode::ResourceIdentityConflict.as_str()) {
            return ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: LifecycleReasonCode::ResourceIdentityConflict.as_str(),
                message,
                details: None,
            };
        }
        if code == Some(LifecycleReasonCode::PodUnschedulable.as_str()) {
            return ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: LifecycleReasonCode::PodUnschedulable.as_str(),
                message,
                details: None,
            };
        }
    }
    ApiError {
        status: StatusCode::BAD_GATEWAY,
        code: LifecycleReasonCode::ResidentMaterializationFailed.as_str(),
        message,
        details: None,
    }
}

fn maestro_identity_observation_is_eligible(observed_state: &str) -> bool {
    observed_state == ResidentProcessObservedState::Starting.as_db_str()
        || observed_state == ResidentProcessObservedState::Running.as_db_str()
}

fn maestro_workload_stale_generation() -> ApiError {
    ApiError::conflict_code(
        LifecycleReasonCode::MaestroWorkloadStaleGeneration.as_str(),
        "Maestro workload placement generation is stale",
    )
}

fn validate_maestro_canonical_binding(
    request: &ValidateMaestroWorkloadIdentityRequest,
    env: &BTreeMap<String, String>,
    provider_pod_uid: Uuid,
) -> Result<(), ApiError> {
    if env
        .get("MAESTRO_PLACEMENT_GENERATION")
        .and_then(|value| value.parse::<u64>().ok())
        != Some(request.generation)
    {
        return Err(maestro_workload_stale_generation());
    }
    let binding_matches = env.get("MAESTRO_ORGANIZATION_ID") == Some(&request.organization_id)
        && env.get("MAESTRO_WORKSPACE_ID") == Some(&request.workspace_id)
        && env
            .get("MAESTRO_SANDBOX_ID")
            .and_then(|value| Uuid::parse_str(value).ok())
            == Some(request.sandbox_id.0)
        && env.get("MAESTRO_RUNNER_SESSION_ID") == Some(&request.runner_session_id)
        && provider_pod_uid == request.pod_uid;
    if !binding_matches {
        return Err(not_live(
            "Maestro workload request does not match its canonical binding",
        ));
    }
    Ok(())
}

fn parse_u64(value: i64, field: &'static str) -> Result<u64, ApiError> {
    u64::try_from(value)
        .map_err(|_| ApiError::internal(format!("database contains invalid {field}")))
}

fn parse_labels(raw: &str) -> Result<Value, ApiError> {
    serde_json::from_str(raw)
        .map_err(|_| ApiError::internal("database contains invalid worker labels"))
}

fn label<'a>(labels: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    labels
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::internal(format!("worker is missing required {name} label")))
}

async fn placement_fence_on(
    db: &Database,
    connection: &mut AnyConnection,
    tenant_id: &str,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
) -> Result<PlacementFence, ApiError> {
    let sql = format!(
        "select rp.name, rp.provider_isolation_version, rp.provider_pod_name, rp.provider_pod_uid,
                jl.attempt, jl.job_id, jl.worker_id, j.kind as job_kind, j.payload as job_payload,
                jl.status, jl.expires_at, sp.worker_id as placement_worker_id,
                sp.generation as placement_generation, w.labels
         from resident_processes rp
         join job_leases jl on jl.id = rp.active_lease_id
         join jobs j on j.id = jl.job_id
         join sandbox_placements sp on sp.sandbox_id = rp.sandbox_id
         join workers w on w.id = jl.worker_id
         where rp.id = {} and rp.tenant_id = {} and rp.generation = {}
           and rp.active_lease_id = {} and rp.name in ({}, {})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
    );
    let row = sqlx::query(&sql)
        .bind(process_id.to_string())
        .bind(tenant_id)
        .bind(
            i64::try_from(generation)
                .map_err(|_| ApiError::bad_request("generation is too large"))?,
        )
        .bind(lease_id.to_string())
        .bind(ORB_SIDECAR_RESIDENT_PROCESS_NAME)
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| not_live("resident placement fence is no longer active"))?;
    let status: String = row.try_get("status")?;
    let worker_id: String = row.try_get("worker_id")?;
    let placement_worker_id: String = row.try_get("placement_worker_id")?;
    let lease_expires_at = parse_timestamp(&row.try_get::<String, _>("expires_at")?)?;
    if status != LeaseStatus::Active.as_db_str()
        || worker_id != placement_worker_id
        || lease_expires_at <= Utc::now()
    {
        return Err(not_live("resident placement lease is no longer active"));
    }
    let job_payload: Value = serde_json::from_str(&row.try_get::<String, _>("job_payload")?)
        .map_err(|_| ApiError::internal("resident placement job payload is invalid"))?;
    if row.try_get::<String, _>("job_kind")? != JobKind::RunResidentProcess.as_db_str()
        || job_payload.get("residentProcessId").and_then(Value::as_str)
            != Some(process_id.to_string().as_str())
        || job_payload.get("generation").and_then(Value::as_u64) != Some(generation)
    {
        return Err(not_live(
            "resident placement lease does not match the current process generation",
        ));
    }
    let labels = parse_labels(&row.try_get::<String, _>("labels")?)?;
    let provider_mode = label(&labels, "provider_mode")?.to_string();
    if provider_mode != "apply" {
        return Err(not_live("resident placement is not provider-applied"));
    }
    let process_name: String = row.try_get("name")?;
    let runtime_image_label = if process_name == MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME {
        MAESTRO_HOSTED_RUNNER_IMAGE_LABEL
    } else {
        PROVIDER_ISOLATED_RESIDENT_PROCESS_IMAGE_LABEL
    };
    let runtime_image = label(&labels, runtime_image_label)?.to_string();
    if !runtime_image.contains("@sha256:") {
        return Err(not_live("resident sidecar image is not digest-pinned"));
    }
    let isolation_version = parse_u64(
        row.try_get("provider_isolation_version")?,
        "provider isolation version",
    )? as u32;
    if isolation_version != PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION {
        return Err(not_live(
            "resident placement does not use provider isolation v2",
        ));
    }
    Ok(PlacementFence {
        lease_attempt: parse_u64(row.try_get("attempt")?, "lease attempt")?,
        job_id: JobId(parse_uuid(&row.try_get::<String, _>("job_id")?)?),
        worker_id: WorkerId(parse_uuid(&worker_id)?),
        placement_generation: parse_u64(
            row.try_get("placement_generation")?,
            "placement generation",
        )?,
        provider_mode,
        runtime_image,
        isolation_version,
        lease_expires_at,
        provider_pod_name: row.try_get("provider_pod_name")?,
        provider_pod_uid: row.try_get("provider_pod_uid")?,
    })
}

async fn placement_fence(
    db: &Database,
    tenant_id: &str,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
) -> Result<PlacementFence, ApiError> {
    let mut connection = db.pool.acquire().await?;
    placement_fence_on(
        db,
        &mut connection,
        tenant_id,
        process_id,
        generation,
        lease_id,
    )
    .await
}

struct MaestroUriComponents<'a> {
    organization_id: &'a str,
    workspace_id: &'a str,
    sandbox_id: SandboxId,
    pod_uid: Uuid,
    placement_generation: u64,
    runner_session_id: &'a str,
    runtime_image: &'a str,
    service_name: &'a str,
    resident_process_generation: u64,
    lease_id: Uuid,
    fence: &'a PlacementFence,
}

fn maestro_expected_server_uri_san(binding: &MaestroUriComponents<'_>) -> Result<String, ApiError> {
    let digest = binding
        .runtime_image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| not_live("Maestro runtime image digest is invalid"))?;
    let sandbox_id = binding.sandbox_id.to_string();
    let pod_uid = binding.pod_uid.to_string();
    let placement_generation = binding.placement_generation.to_string();
    let service_port = MAESTRO_HOSTED_RUNNER_CONTAINER_PORT.to_string();
    let process_generation = binding.resident_process_generation.to_string();
    let lease_id = binding.lease_id.to_string();
    let lease_attempt = binding.fence.lease_attempt.to_string();
    let worker_id = binding.fence.worker_id.to_string();
    let mut uri = Url::parse("spiffe://identity.evalops.dev/")
        .map_err(|_| ApiError::internal("Maestro URI SAN base is invalid"))?;
    uri.path_segments_mut()
        .map_err(|_| ApiError::internal("Maestro URI SAN cannot contain path segments"))?
        .extend([
            "maestro",
            "v1",
            "organizations",
            binding.organization_id,
            "workspaces",
            binding.workspace_id,
            "sandboxes",
            &sandbox_id,
            "pods",
            &pod_uid,
            "generations",
            &placement_generation,
            "sessions",
            binding.runner_session_id,
            "images",
            digest,
            "services",
            binding.service_name,
            "ports",
            &service_port,
            "resident-process-generations",
            &process_generation,
            "leases",
            &lease_id,
            "attempts",
            &lease_attempt,
            "workers",
            &worker_id,
        ]);
    Ok(uri.to_string())
}

#[utoipa::path(
    get,
    path = "/v1/sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/connection-binding",
    params(("sandbox_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Live tenant-scoped Maestro connection and exact server certificate binding", body = MaestroHostedRunnerConnectionBindingResponse),
        (status = 404, description = "No tenant-scoped Maestro hosted runner exists", body = ErrorEnvelope),
        (status = 409, description = "The Maestro placement is pending or not live", body = ErrorEnvelope),
        (status = 403, description = "Resident provider policy rejected materialization", body = ErrorEnvelope),
        (status = 422, description = "Resident provider contract rejected materialization", body = ErrorEnvelope),
        (status = 502, description = "Resident process materialization failed", body = ErrorEnvelope),
        (status = 503, description = "Resident process capacity or materialization is pending", body = ErrorEnvelope)
    )
)]
pub(crate) async fn get_maestro_connection_binding(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    axum::extract::Path(sandbox_id): axum::extract::Path<Uuid>,
) -> Result<Json<MaestroHostedRunnerConnectionBindingResponse>, ApiError> {
    let mut connection = state.db.pool.acquire().await?;
    let binding = authoritative_maestro_connection_binding(
        &state.db,
        &mut connection,
        &ctx.tenant_id,
        SandboxId(sandbox_id),
    )
    .await?;
    Ok(Json(binding))
}

pub(crate) async fn authoritative_maestro_connection_binding(
    db: &Database,
    connection: &mut AnyConnection,
    tenant_id: &str,
    sandbox_id: SandboxId,
) -> Result<MaestroHostedRunnerConnectionBindingResponse, ApiError> {
    let sql = format!(
        "select rp.id, rp.generation, rp.active_lease_id, rp.env,
                rp.desired_state, rp.observed_state, rp.provider_pod_uid,
                rp.last_error_class, rp.last_error_code, rp.last_error, w.labels
         from resident_processes rp
         join sandbox_placements sp on sp.sandbox_id = rp.sandbox_id
         join workers w on w.id = sp.worker_id
         where rp.sandbox_id = {} and rp.tenant_id = {} and rp.name = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(tenant_id)
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("Maestro hosted runner not found"))?;
    if row.try_get::<String, _>("desired_state")?
        != ResidentProcessDesiredState::Running.as_db_str()
    {
        return Err(not_live("Maestro hosted runner is not running"));
    }
    let observed_state: String = row.try_get("observed_state")?;
    // The binding is safe to publish once the provider has reported the
    // immutable Pod identity. The runner-host can perform the mTLS identity
    // exchange while the resident is still Starting; transport and runtime
    // identity readiness remain retryable there. Waiting for Running here
    // serialized those two startup phases behind the resident's own boot.
    if !maestro_identity_observation_is_eligible(&observed_state)
        || observed_state == ResidentProcessObservedState::Starting.as_db_str()
    {
        let error_class = row
            .try_get::<Option<String>, _>("last_error_class")?
            .map(|value| ProvisioningErrorClass::parse_db_str(&value))
            .transpose()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let error_code: Option<String> = row.try_get("last_error_code")?;
        let last_error: Option<String> = row.try_get("last_error")?;
        if !maestro_identity_observation_is_eligible(&observed_state)
            || error_class.is_some()
            || error_code.is_some()
            || last_error.is_some()
        {
            return Err(resident_not_ready_error(
                &observed_state,
                error_class,
                error_code,
                last_error,
            ));
        }
    }
    let process_id = ResidentProcessId(parse_uuid(&row.try_get::<String, _>("id")?)?);
    let process_generation = parse_u64(row.try_get("generation")?, "resident generation")?;
    let lease_id = parse_uuid(
        &row.try_get::<String, _>("active_lease_id")
            .map_err(|_| not_live("Maestro hosted runner has no active lease"))?,
    )?;
    let pod_uid = row
        .try_get::<Option<String>, _>("provider_pod_uid")?
        .and_then(|value| Uuid::parse_str(&value).ok())
        .ok_or_else(|| not_live("Maestro placement has no authoritative Pod UID"))?;
    let env: BTreeMap<String, String> = serde_json::from_str(&row.try_get::<String, _>("env")?)
        .map_err(|_| ApiError::internal("Maestro resident environment is invalid"))?;
    // Sandboxwich's authenticated tenant is the control-plane storage scope;
    // the Maestro organization binding is the platform's opaque
    // organization/workspace scope and may legitimately differ from it.
    // Tenant ownership was already enforced by the query above.
    let organization_id = env
        .get("MAESTRO_ORGANIZATION_ID")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| not_live("Maestro organization binding is invalid"))?;
    let workspace_id = env
        .get("MAESTRO_WORKSPACE_ID")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| not_live("Maestro workspace binding is invalid"))?;
    let runner_session_id = env
        .get("MAESTRO_RUNNER_SESSION_ID")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| not_live("Maestro runner session binding is invalid"))?;
    if env
        .get("MAESTRO_SANDBOX_ID")
        .and_then(|value| Uuid::parse_str(value).ok())
        != Some(sandbox_id.0)
    {
        return Err(not_live("Maestro sandbox binding is invalid"));
    }
    let fence = placement_fence_on(
        db,
        connection,
        tenant_id,
        process_id,
        process_generation,
        lease_id,
    )
    .await?;
    let placement_generation = env
        .get("MAESTRO_PLACEMENT_GENERATION")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|generation| *generation == fence.placement_generation)
        .ok_or_else(|| not_live("Maestro placement generation binding is stale"))?;
    if fence
        .provider_pod_uid
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        != Some(pod_uid)
    {
        return Err(not_live("Maestro provider Pod binding is stale"));
    }
    let labels = parse_labels(&row.try_get::<String, _>("labels")?)?;
    let service_namespace = label(&labels, "sandbox_namespace")?.to_string();
    let service_name =
        resident_service_name(db, connection, process_id, process_generation, lease_id).await?;
    let service_host = format!("{service_name}.{service_namespace}.svc.cluster.local");
    let expected_server_uri_san = maestro_expected_server_uri_san(&MaestroUriComponents {
        organization_id,
        workspace_id,
        sandbox_id,
        pod_uid,
        placement_generation,
        runner_session_id,
        runtime_image: &fence.runtime_image,
        service_name: &service_name,
        resident_process_generation: process_generation,
        lease_id,
        fence: &fence,
    })?;
    Ok(MaestroHostedRunnerConnectionBindingResponse {
        ok: true,
        organization_id: organization_id.clone(),
        workspace_id: workspace_id.clone(),
        sandbox_id,
        pod_uid,
        placement_generation,
        runner_session_id: runner_session_id.clone(),
        runtime_image: fence.runtime_image,
        service_namespace,
        service_name,
        service_host,
        service_port: MAESTRO_HOSTED_RUNNER_CONTAINER_PORT,
        expected_server_uri_san,
        resident_process_generation: process_generation,
        lease_id,
        lease_attempt: fence.lease_attempt,
        lease_expires_at_epoch_seconds: fence.lease_expires_at.timestamp(),
        worker_id: fence.worker_id,
    })
}

fn token_for(key: &str, record: &AttestationRecord) -> String {
    let canonical = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        ATTESTATION_VERSION,
        record.id,
        record.tenant_id,
        record.sandbox_id,
        record.process_id,
        record.generation,
        record.lease_id,
        record.fence.lease_attempt,
        record.fence.job_id,
        record.fence.worker_id,
        record.fence.placement_generation,
        record.fence.provider_mode,
        record.fence.runtime_image,
        record.fence.isolation_version,
        record.issued_at.to_rfc3339(),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("validated non-empty placement attestation key");
    mac.update(b"sandboxwich-resident-placement-attestation-v2\0");
    mac.update(canonical.as_bytes());
    format!(
        "swpa2_{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn token_digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn record_from_row(row: &sqlx::any::AnyRow) -> Result<AttestationRecord, ApiError> {
    let consumed_at: Option<String> = row.try_get("consumed_at")?;
    let redeem_key: Option<String> = row.try_get("redeem_idempotency_key")?;
    Ok(AttestationRecord {
        id: parse_uuid(&row.try_get::<String, _>("id")?)?,
        tenant_id: row.try_get("tenant_id")?,
        sandbox_id: SandboxId(parse_uuid(&row.try_get::<String, _>("sandbox_id")?)?),
        process_id: ResidentProcessId(parse_uuid(
            &row.try_get::<String, _>("resident_process_id")?,
        )?),
        generation: parse_u64(
            row.try_get("resident_process_generation")?,
            "resident process generation",
        )?,
        lease_id: parse_uuid(&row.try_get::<String, _>("lease_id")?)?,
        fence: PlacementFence {
            lease_attempt: parse_u64(row.try_get("lease_attempt")?, "lease attempt")?,
            job_id: JobId(parse_uuid(&row.try_get::<String, _>("job_id")?)?),
            worker_id: WorkerId(parse_uuid(&row.try_get::<String, _>("worker_id")?)?),
            placement_generation: parse_u64(
                row.try_get("placement_generation")?,
                "placement generation",
            )?,
            provider_mode: row.try_get("provider_mode")?,
            runtime_image: row.try_get("runtime_image")?,
            isolation_version: u32::try_from(row.try_get::<i64, _>("provider_isolation_version")?)
                .map_err(|_| ApiError::internal("invalid provider isolation version"))?,
            lease_expires_at: parse_timestamp(&row.try_get::<String, _>("lease_expires_at")?)?,
            provider_pod_name: row.try_get("provider_pod_name")?,
            provider_pod_uid: row.try_get("provider_pod_uid")?,
        },
        issued_at: parse_timestamp(&row.try_get::<String, _>("issued_at")?)?,
        expires_at: parse_timestamp(&row.try_get::<String, _>("attestation_expires_at")?)?,
        token_sha256: row.try_get("token_sha256")?,
        consumed_at: consumed_at
            .map(|value| parse_timestamp(&value))
            .transpose()?,
        redeem_idempotency_key: redeem_key.map(|value| parse_uuid(&value)).transpose()?,
    })
}

async fn find_exact_record(
    db: &Database,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
) -> Result<AttestationRecord, ApiError> {
    let sql = format!(
        "select * from resident_placement_attestations
         where resident_process_id = {} and resident_process_generation = {} and lease_id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let row = sqlx::query(&sql)
        .bind(process_id.to_string())
        .bind(
            i64::try_from(generation)
                .map_err(|_| ApiError::bad_request("generation is too large"))?,
        )
        .bind(lease_id.to_string())
        .fetch_one(&db.pool)
        .await?;
    record_from_row(&row)
}

pub(crate) async fn issue_resident_placement_attestation(
    state: &AppState,
    tenant_id: &str,
    sandbox_id: SandboxId,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
) -> Result<Option<ResidentPlacementAttestationBootstrap>, ApiError> {
    let Some(key) = state.placement_attestation_derivation_key.as_deref() else {
        // Preserve mixed-version rollout: an upgraded worker can advertise
        // provider isolation v2 before the API derivation key is installed.
        // Existing non-OIDC sidecars retain the v1 bootstrap contract; OIDC
        // sidecars still fail closed because their required proof file is
        // absent until the operator configures the key.
        return Ok(None);
    };
    let fence = placement_fence(&state.db, tenant_id, process_id, generation, lease_id).await?;
    let issued_at = Utc::now();
    let expires_at =
        (issued_at + Duration::seconds(ATTESTATION_TTL_SECONDS)).min(fence.lease_expires_at);
    if expires_at <= issued_at {
        return Err(not_live("resident placement lease expires too soon"));
    }
    let candidate = AttestationRecord {
        id: Uuid::now_v7(),
        tenant_id: tenant_id.to_string(),
        sandbox_id,
        process_id,
        generation,
        lease_id,
        fence,
        issued_at,
        expires_at,
        token_sha256: String::new(),
        consumed_at: None,
        redeem_idempotency_key: None,
    };
    let token = token_for(key, &candidate);
    let digest = token_digest(&token);
    let issued_at_rfc3339 = candidate.issued_at.to_rfc3339();
    let insert = format!(
        "insert into resident_placement_attestations
         (id, tenant_id, sandbox_id, resident_process_id, resident_process_generation,
          lease_id, lease_attempt, job_id, worker_id, placement_generation,
          provider_pod_name, provider_pod_uid,
          provider_mode, runtime_image, provider_isolation_version, token_sha256,
          issued_at, attestation_expires_at, lease_expires_at, created_at, updated_at)
         values ({})
         on conflict (resident_process_id, resident_process_generation, lease_id) do nothing",
        state.db.placeholders(21),
    );
    sqlx::query(&insert)
        .bind(candidate.id.to_string())
        .bind(tenant_id)
        .bind(sandbox_id.to_string())
        .bind(process_id.to_string())
        .bind(
            i64::try_from(generation)
                .map_err(|_| ApiError::bad_request("generation is too large"))?,
        )
        .bind(lease_id.to_string())
        .bind(
            i64::try_from(candidate.fence.lease_attempt)
                .map_err(|_| ApiError::internal("lease attempt is too large"))?,
        )
        .bind(candidate.fence.job_id.to_string())
        .bind(candidate.fence.worker_id.to_string())
        .bind(
            i64::try_from(candidate.fence.placement_generation)
                .map_err(|_| ApiError::internal("placement generation is too large"))?,
        )
        .bind(&candidate.fence.provider_pod_name)
        .bind(&candidate.fence.provider_pod_uid)
        .bind(&candidate.fence.provider_mode)
        .bind(&candidate.fence.runtime_image)
        .bind(i64::from(candidate.fence.isolation_version))
        .bind(&digest)
        .bind(&issued_at_rfc3339)
        .bind(candidate.expires_at.to_rfc3339())
        .bind(candidate.fence.lease_expires_at.to_rfc3339())
        .bind(&issued_at_rfc3339)
        .bind(&issued_at_rfc3339)
        .execute(&state.db.pool)
        .await?;
    let record = find_exact_record(&state.db, process_id, generation, lease_id).await?;
    let token = token_for(key, &record);
    if token_digest(&token) != record.token_sha256 {
        return Err(ApiError::internal(
            "placement attestation derivation key does not match the persisted record",
        ));
    }
    Ok(Some(ResidentPlacementAttestationBootstrap { token }))
}

pub(crate) async fn record_provider_pod_identity(
    db: &Database,
    tenant_id: &str,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
    pod_name: &str,
    pod_uid: &str,
) -> Result<(), ApiError> {
    if pod_name.is_empty()
        || pod_name.len() > 253
        || pod_uid.is_empty()
        || pod_uid.len() > 253
        || pod_name.chars().any(char::is_whitespace)
        || pod_uid.chars().any(char::is_whitespace)
    {
        return Err(ApiError::bad_request(
            "provider Pod name and UID must be non-empty bounded identifiers",
        ));
    }
    let now = Utc::now().to_rfc3339();
    let process_sql = format!(
        "update resident_processes
         set provider_pod_name = coalesce(provider_pod_name, {}),
             provider_pod_uid = coalesce(provider_pod_uid, {}), updated_at = {}
         where tenant_id = {} and id = {} and generation = {} and active_lease_id = {}
           and (provider_pod_name is null or provider_pod_name = {})
           and (provider_pod_uid is null or provider_pod_uid = {})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9),
    );
    let process_result = sqlx::query(&process_sql)
        .bind(pod_name)
        .bind(pod_uid)
        .bind(&now)
        .bind(tenant_id)
        .bind(process_id.to_string())
        .bind(
            i64::try_from(generation)
                .map_err(|_| ApiError::bad_request("generation is too large"))?,
        )
        .bind(lease_id.to_string())
        .bind(pod_name)
        .bind(pod_uid)
        .execute(&db.pool)
        .await?;
    if process_result.rows_affected() != 1 {
        tracing::warn!(
            tenant_id,
            process_id = %process_id.0,
            generation,
            lease_id = %lease_id,
            provider_pod_name = %pod_name,
            provider_pod_uid = %pod_uid,
            "sandboxwich_resident_placement_fence_rejected"
        );
        return Err(not_live(
            "provider Pod identity does not match the active placement fence",
        ));
    }
    let sql = format!(
        "update resident_placement_attestations
         set provider_pod_name = coalesce(provider_pod_name, {}),
             provider_pod_uid = coalesce(provider_pod_uid, {}), updated_at = {}
         where tenant_id = {} and resident_process_id = {}
           and resident_process_generation = {} and lease_id = {}
           and (provider_pod_name is null or provider_pod_name = {})
           and (provider_pod_uid is null or provider_pod_uid = {})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9),
    );
    let result = sqlx::query(&sql)
        .bind(pod_name)
        .bind(pod_uid)
        .bind(&now)
        .bind(tenant_id)
        .bind(process_id.to_string())
        .bind(
            i64::try_from(generation)
                .map_err(|_| ApiError::bad_request("generation is too large"))?,
        )
        .bind(lease_id.to_string())
        .bind(pod_name)
        .bind(pod_uid)
        .execute(&db.pool)
        .await?;
    if result.rows_affected() > 1 {
        tracing::warn!(
            tenant_id,
            process_id = %process_id.0,
            generation,
            lease_id = %lease_id,
            provider_pod_name = %pod_name,
            provider_pod_uid = %pod_uid,
            "sandboxwich_resident_placement_attestation_corrupt"
        );
        return Err(not_live(
            "provider Pod identity does not match the issued placement fence",
        ));
    }
    Ok(())
}

async fn fetch_record_for_token(
    db: &Database,
    tenant_id: &str,
    token: &str,
) -> Result<AttestationRecord, ApiError> {
    let sql = format!(
        "select * from resident_placement_attestations where tenant_id = {} and token_sha256 = {}",
        db.placeholder(1),
        db.placeholder(2),
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(token_digest(token))
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(unavailable)?;
    record_from_row(&row)
}

async fn fetch_record_by_id(
    db: &Database,
    tenant_id: &str,
    id: Uuid,
) -> Result<AttestationRecord, ApiError> {
    let sql = format!(
        "select * from resident_placement_attestations where tenant_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2),
    );
    let row = sqlx::query(&sql)
        .bind(tenant_id)
        .bind(id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(unavailable)?;
    record_from_row(&row)
}

async fn live_claims(
    db: &Database,
    record: &AttestationRecord,
) -> Result<ResidentPlacementClaims, ApiError> {
    let live = placement_fence(
        db,
        &record.tenant_id,
        record.process_id,
        record.generation,
        record.lease_id,
    )
    .await?;
    if live.job_id != record.fence.job_id
        || live.worker_id != record.fence.worker_id
        || live.placement_generation != record.fence.placement_generation
        || live.provider_mode != record.fence.provider_mode
        || live.runtime_image != record.fence.runtime_image
        || live.isolation_version != record.fence.isolation_version
    {
        return Err(not_live("resident placement fence has changed"));
    }
    let sql = format!(
        "select rp.desired_state, rp.observed_state, rp.provider_pod_uid
         from resident_processes rp
         join resident_placement_attestations a on a.resident_process_id = rp.id
         where a.id = {} and rp.id = {} and rp.tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let row = sqlx::query(&sql)
        .bind(record.id.to_string())
        .bind(record.process_id.to_string())
        .bind(&record.tenant_id)
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(unavailable)?;
    let pod_uid: Option<String> = row.try_get("provider_pod_uid")?;
    if pod_uid != record.fence.provider_pod_uid {
        return Err(not_live("resident provider Pod identity has changed"));
    }
    let pod_uid = pod_uid
        .filter(|value| !value.is_empty())
        .ok_or_else(|| not_live("resident placement has no authoritative provider Pod UID"))?;
    if row.try_get::<String, _>("desired_state")?
        != ResidentProcessDesiredState::Running.as_db_str()
        || row.try_get::<String, _>("observed_state")?
            != ResidentProcessObservedState::Running.as_db_str()
    {
        return Err(not_live("resident sidecar is not running"));
    }
    Ok(ResidentPlacementClaims {
        version: ATTESTATION_VERSION,
        attestation_id: record.id,
        tenant_id: record.tenant_id.clone(),
        sandbox_id: record.sandbox_id,
        resident_process_id: record.process_id,
        resident_process_generation: record.generation,
        lease_id: record.lease_id,
        lease_attempt: live.lease_attempt,
        job_id: live.job_id,
        worker_id: live.worker_id,
        placement_generation: live.placement_generation,
        provider_pod_uid: pod_uid,
        provider_mode: live.provider_mode,
        runtime_image: live.runtime_image,
        provider_isolation_version: live.isolation_version,
        issued_at: record.issued_at,
        attestation_expires_at: record.expires_at,
        lease_expires_at: live.lease_expires_at,
    })
}

#[utoipa::path(
    post,
    path = "/v1/resident-placement-attestations/redeem",
    request_body = RedeemResidentPlacementAttestationRequest,
    responses(
        (status = 200, description = "Placement proof atomically redeemed", body = ResidentPlacementAttestationResponse),
        (status = 404, description = "Unknown, foreign, or distinctly replayed proof", body = ErrorEnvelope),
        (status = 409, description = "Placement fence is no longer live", body = ErrorEnvelope)
    )
)]
pub(crate) async fn redeem_resident_placement_attestation(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<RedeemResidentPlacementAttestationRequest>,
) -> Result<Json<ResidentPlacementAttestationResponse>, ApiError> {
    if request.token.len() > 512 || !request.token.starts_with("swpa2_") {
        return Err(unavailable());
    }
    let key = state
        .placement_attestation_derivation_key
        .as_deref()
        .ok_or_else(|| ApiError::internal("placement attestation validation is not configured"))?;
    let record = fetch_record_for_token(&state.db, &ctx.tenant_id, &request.token).await?;
    let derived = token_for(key, &record);
    if record.expires_at <= Utc::now()
        || !bool::from(derived.as_bytes().ct_eq(request.token.as_bytes()))
    {
        return Err(unavailable());
    }
    // Do not burn a proof that never established a live authoritative fence.
    // The conditional consume below repeats the storage-level portion at the
    // write instant; the final call refreshes the returned lease deadline.
    let _ = live_claims(&state.db, &record).await?;
    match (record.consumed_at, record.redeem_idempotency_key) {
        (Some(_), Some(existing)) if existing == request.idempotency_key => {}
        (Some(_), _) => return Err(unavailable()),
        (None, _) => {
            let sql = format!(
                "update resident_placement_attestations
                 set consumed_at = {}, redeem_idempotency_key = {}, updated_at = {}
                 where id = {} and tenant_id = {} and consumed_at is null
                   and attestation_expires_at > {}
                   and exists (
                     select 1
                     from resident_processes rp
                     join job_leases jl on jl.id = rp.active_lease_id
                     join sandbox_placements sp on sp.sandbox_id = rp.sandbox_id
                     where rp.id = resident_placement_attestations.resident_process_id
                       and rp.tenant_id = resident_placement_attestations.tenant_id
                       and rp.generation = resident_placement_attestations.resident_process_generation
                       and rp.active_lease_id = resident_placement_attestations.lease_id
                       and rp.desired_state = 'running' and rp.observed_state = 'running'
                       and rp.provider_pod_uid = resident_placement_attestations.provider_pod_uid
                       and jl.status = 'active' and jl.expires_at > {}
                       and jl.job_id = resident_placement_attestations.job_id
                       and jl.worker_id = resident_placement_attestations.worker_id
                       and sp.worker_id = resident_placement_attestations.worker_id
                       and sp.generation = resident_placement_attestations.placement_generation
                   )",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3),
                state.db.placeholder(4),
                state.db.placeholder(5),
                state.db.placeholder(6),
                state.db.placeholder(7),
            );
            let now = Utc::now().to_rfc3339();
            let updated = sqlx::query(&sql)
                .bind(&now)
                .bind(request.idempotency_key.to_string())
                .bind(&now)
                .bind(record.id.to_string())
                .bind(&ctx.tenant_id)
                .bind(&now)
                .bind(&now)
                .execute(&state.db.pool)
                .await?;
            if updated.rows_affected() != 1 {
                let raced = fetch_record_by_id(&state.db, &ctx.tenant_id, record.id).await?;
                if raced.redeem_idempotency_key != Some(request.idempotency_key) {
                    return Err(unavailable());
                }
            }
        }
    }
    let claims = live_claims(&state.db, &record).await?;
    Ok(Json(ResidentPlacementAttestationResponse {
        ok: true,
        claims,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/resident-placement-attestations/validate",
    request_body = ValidateResidentPlacementAttestationRequest,
    responses(
        (status = 200, description = "Consumed placement record remains live", body = ResidentPlacementAttestationResponse),
        (status = 404, description = "Unknown, foreign, or unconsumed record", body = ErrorEnvelope),
        (status = 409, description = "Placement fence is no longer live", body = ErrorEnvelope)
    )
)]
pub(crate) async fn validate_resident_placement_attestation(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<ValidateResidentPlacementAttestationRequest>,
) -> Result<Json<ResidentPlacementAttestationResponse>, ApiError> {
    let record = fetch_record_by_id(&state.db, &ctx.tenant_id, request.attestation_id).await?;
    if record.consumed_at.is_none() {
        return Err(unavailable());
    }
    let claims = live_claims(&state.db, &record).await?;
    Ok(Json(ResidentPlacementAttestationResponse {
        ok: true,
        claims,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/maestro-workload-identities/validate",
    request_body = ValidateMaestroWorkloadIdentityRequest,
    responses(
        (status = 200, description = "Maestro workload identity is bound to the live canonical placement", body = MaestroWorkloadIdentityResponse),
        (status = 404, description = "No matching tenant-scoped Maestro placement", body = ErrorEnvelope),
        (status = 409, description = "The workload placement is stale or mismatched", body = ErrorEnvelope)
    )
)]
pub(crate) async fn validate_maestro_workload_identity(
    State(state): State<AppState>,
    Extension(_identity_service): Extension<IdentityServiceContext>,
    Json(request): Json<ValidateMaestroWorkloadIdentityRequest>,
) -> Result<Json<MaestroWorkloadIdentityResponse>, ApiError> {
    let started = Instant::now();
    let result = validate_maestro_workload_identity_inner(&state, request).await;
    let (outcome, reason) = match &result {
        Ok(_) => ("accepted", "validated"),
        Err(error) if error.status.is_server_error() => ("error", "internal"),
        Err(error) if error.status == StatusCode::NOT_FOUND => ("rejected", "not_found"),
        Err(error) if error.status == StatusCode::CONFLICT => ("rejected", "not_live"),
        Err(_) => ("rejected", "invalid_request"),
    };
    state.maestro_observation_sink.try_enqueue(
        IDENTITY_METRICS_TENANT_ID,
        outcome,
        reason,
        started.elapsed().as_millis(),
    );
    result.map(Json)
}

async fn validate_maestro_workload_identity_inner(
    state: &AppState,
    request: ValidateMaestroWorkloadIdentityRequest,
) -> Result<MaestroWorkloadIdentityResponse, ApiError> {
    if request.organization_id.trim().is_empty()
        || request.workspace_id.trim().is_empty()
        || request.runner_session_id.trim().is_empty()
        || request.generation == 0
    {
        return Err(unavailable());
    }
    let sql = format!(
        "select rp.tenant_id, rp.id, rp.generation, rp.active_lease_id, rp.env,
                rp.desired_state, rp.observed_state,
                rp.provider_pod_name, rp.provider_pod_uid, w.labels
         from resident_processes rp
         join job_leases jl on jl.id = rp.active_lease_id
         join workers w on w.id = jl.worker_id
         where rp.sandbox_id = {} and rp.name = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
    );
    let row = sqlx::query(&sql)
        .bind(request.sandbox_id.to_string())
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(unavailable)?;
    let desired_state = row.try_get::<String, _>("desired_state")?;
    let observed_state = row.try_get::<String, _>("observed_state")?;
    // The internal identity exchange is the startup handoff: Maestro cannot
    // become Running until this request succeeds. Canonical binding, Pod UID,
    // and placement-fence checks below still fail closed while Starting is
    // allowed only for this fenced internal route. The public connection
    // binding remains Running-only.
    if desired_state != ResidentProcessDesiredState::Running.as_db_str()
        || !maestro_identity_observation_is_eligible(&observed_state)
    {
        return Err(not_live("Maestro hosted runner is not running"));
    }
    let process_id = ResidentProcessId(parse_uuid(&row.try_get::<String, _>("id")?)?);
    // `organization_id` is a platform binding, not the Sandboxwich database
    // tenant. Use the resident row's authoritative tenant for the placement
    // fence after the canonical organization/workspace binding is checked.
    let tenant_id: String = row.try_get("tenant_id")?;
    let process_generation = parse_u64(row.try_get("generation")?, "resident generation")?;
    let lease_id = parse_uuid(
        &row.try_get::<String, _>("active_lease_id")
            .map_err(|_| not_live("Maestro hosted runner has no active lease"))?,
    )?;
    let env: BTreeMap<String, String> = serde_json::from_str(&row.try_get::<String, _>("env")?)
        .map_err(|_| ApiError::internal("Maestro resident environment is invalid"))?;
    let provider_pod_name: String = row
        .try_get::<Option<String>, _>("provider_pod_name")?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| not_live("Maestro placement has no observed Pod name"))?;
    let provider_pod_uid = row
        .try_get::<Option<String>, _>("provider_pod_uid")?
        .and_then(|value| Uuid::parse_str(&value).ok())
        .ok_or_else(|| not_live("Maestro placement has no authoritative Pod UID"))?;
    validate_maestro_canonical_binding(&request, &env, provider_pod_uid)?;
    let fence = placement_fence(
        &state.db,
        &tenant_id,
        process_id,
        process_generation,
        lease_id,
    )
    .await?;
    if fence.placement_generation != request.generation {
        return Err(maestro_workload_stale_generation());
    }
    if fence
        .provider_pod_uid
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        != Some(request.pod_uid)
        || fence.provider_pod_name.as_deref() != Some(provider_pod_name.as_str())
    {
        return Err(not_live("Maestro placement fence changed"));
    }
    let labels = parse_labels(&row.try_get::<String, _>("labels")?)?;
    let sandbox_namespace = label(&labels, "sandbox_namespace")?.to_string();
    let mut connection = state.db.pool.acquire().await?;
    let service_name = resident_service_name(
        &state.db,
        &mut connection,
        process_id,
        process_generation,
        lease_id,
    )
    .await?;
    Ok(MaestroWorkloadIdentityResponse {
        active: true,
        organization_id: request.organization_id,
        workspace_id: request.workspace_id,
        sandbox_id: request.sandbox_id,
        pod_name: provider_pod_name,
        pod_uid: provider_pod_uid,
        generation: request.generation,
        runner_session_id: request.runner_session_id,
        runtime_image: fence.runtime_image,
        service_account_namespace: sandbox_namespace,
        service_account_name: MAESTRO_HOSTED_RUNNER_SERVICE_ACCOUNT.into(),
        service_name,
        service_port: MAESTRO_HOSTED_RUNNER_CONTAINER_PORT,
        resident_process_generation: process_generation,
        lease_id,
        lease_attempt: fence.lease_attempt,
        lease_expires_at_epoch_seconds: fence.lease_expires_at.timestamp(),
        worker_id: fence.worker_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maestro_binding(
        generation: u64,
    ) -> (
        ValidateMaestroWorkloadIdentityRequest,
        BTreeMap<String, String>,
    ) {
        let sandbox_id = SandboxId::new();
        let pod_uid = Uuid::now_v7();
        let request = ValidateMaestroWorkloadIdentityRequest {
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            sandbox_id,
            pod_uid,
            generation,
            runner_session_id: "session-1".into(),
        };
        let env = BTreeMap::from([
            ("MAESTRO_ORGANIZATION_ID".into(), "org-1".into()),
            ("MAESTRO_WORKSPACE_ID".into(), "workspace-1".into()),
            ("MAESTRO_SANDBOX_ID".into(), sandbox_id.to_string()),
            (
                "MAESTRO_PLACEMENT_GENERATION".into(),
                generation.to_string(),
            ),
            ("MAESTRO_RUNNER_SESSION_ID".into(), "session-1".into()),
        ]);
        (request, env)
    }

    #[test]
    fn maestro_workload_binding_reports_stale_generation_with_stable_code() {
        let (request, mut env) = maestro_binding(7);
        env.insert("MAESTRO_PLACEMENT_GENERATION".into(), "8".into());

        let error = validate_maestro_canonical_binding(&request, &env, request.pod_uid)
            .expect_err("stale generation must be rejected");

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "maestro_workload_stale_generation");
    }

    #[test]
    fn maestro_workload_binding_keeps_non_generation_mismatches_generic() {
        let (mut request, env) = maestro_binding(7);
        request.workspace_id = "workspace-2".into();

        let error = validate_maestro_canonical_binding(&request, &env, request.pod_uid)
            .expect_err("mismatched canonical binding must be rejected");

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "placement_attestation_not_live");
    }

    #[test]
    fn maestro_identity_exchange_accepts_fenced_starting_workloads() {
        assert!(maestro_identity_observation_is_eligible(
            ResidentProcessObservedState::Starting.as_db_str()
        ));
        assert!(maestro_identity_observation_is_eligible(
            ResidentProcessObservedState::Running.as_db_str()
        ));
    }

    #[test]
    fn maestro_identity_exchange_rejects_non_live_workloads() {
        for observed_state in [
            ResidentProcessObservedState::Pending,
            ResidentProcessObservedState::Failed,
            ResidentProcessObservedState::Stopped,
            ResidentProcessObservedState::Lost,
        ] {
            assert!(!maestro_identity_observation_is_eligible(
                observed_state.as_db_str()
            ));
        }
    }

    #[test]
    fn resident_capacity_status_is_typed_while_queued_and_terminal() {
        let queued = resident_not_ready_error(
            ResidentProcessObservedState::Starting.as_db_str(),
            Some(ProvisioningErrorClass::RetryableCapacity),
            Some("workspace_capacity_pending".into()),
            Some("workspace_capacity_pending: exceeded quota".into()),
        );
        assert_eq!(queued.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(queued.code, "workspace_capacity_pending");

        let terminal = resident_not_ready_error(
            ResidentProcessObservedState::Failed.as_db_str(),
            Some(ProvisioningErrorClass::RetryableCapacity),
            Some("workspace_capacity_pending".into()),
            Some("workspace_capacity_pending: exceeded quota".into()),
        );
        assert_eq!(terminal.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(terminal.code, "workspace_capacity_exhausted");
    }

    #[test]
    fn terminal_resident_materialization_never_maps_to_attestation_not_live() {
        for (error_class, error_code) in [
            (Some(ProvisioningErrorClass::RetryableProvider), None),
            (None, None),
            (
                Some(ProvisioningErrorClass::TerminalSecurity),
                Some("kubernetes_policy_denied"),
            ),
        ] {
            let error = resident_not_ready_error(
                ResidentProcessObservedState::Failed.as_db_str(),
                error_class,
                error_code.map(str::to_string),
                Some("provider failed to materialize the resident process".into()),
            );
            assert_ne!(error.code, "placement_attestation_not_live");
        }
    }

    #[test]
    fn live_progress_without_an_error_keeps_pending_distinct_from_materialization_failure() {
        let error = resident_not_ready_error(
            ResidentProcessObservedState::Starting.as_db_str(),
            None,
            None,
            None,
        );
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "placement_attestation_pending");
    }
}
