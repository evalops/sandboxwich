use crate::error::ApiError;
use crate::handlers::resident_attestations::authoritative_maestro_connection_binding;
use crate::rows::parse_timestamp;
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, State};
use chrono::Utc;
use sandboxwich_core::*;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

const BINDING_MISMATCH: &str = "maestro_activation_binding_mismatch";
const REPLAY_MISMATCH: &str = "maestro_activation_replay_mismatch";
const STALE_GENERATION: &str = "maestro_activation_stale_generation";
const EXPIRED_LEASE: &str = "maestro_activation_lease_expired";
const NOT_LIVE: &str = "maestro_activation_not_live";
const PROOF_DIGEST_PREFIX: &str = "sha256:v1:";

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivationProofTupleV1 {
    resident_process_id: ResidentProcessId,
    resident_process_generation: u64,
    lease_id: Uuid,
    lease_attempt: u64,
    job_id: JobId,
    worker_id: WorkerId,
    placement_generation: u64,
    provider_pod_uid: Uuid,
    runtime_image: String,
}

#[derive(Clone, Copy)]
struct ActivationAuthority {
    resident_process_id: ResidentProcessId,
    job_id: JobId,
}

enum ActivationRequest {
    Validate(MaestroHostedRunnerActivationValidationRequest),
    Resolve(MaestroHostedRunnerActivationResolveRequest),
}

impl ActivationRequest {
    fn sandbox_id(&self) -> SandboxId {
        match self {
            Self::Validate(request) => request.sandbox_id,
            Self::Resolve(request) => request.sandbox_id,
        }
    }

    fn activation_id(&self) -> Uuid {
        match self {
            Self::Validate(request) => request.activation_id,
            Self::Resolve(request) => request.activation_id,
        }
    }

    fn caller_tuple_digest(&self) -> Result<Option<String>, ApiError> {
        match self {
            Self::Validate(request) => tuple_sha256(request).map(Some),
            Self::Resolve(_) => Ok(None),
        }
    }

    fn materialize(
        self,
        live: &MaestroHostedRunnerConnectionBindingResponse,
        tenant_id: &str,
    ) -> Result<MaestroHostedRunnerActivationValidationRequest, ApiError> {
        match self {
            Self::Validate(request) => {
                if !binding_matches(&request, live) {
                    let code = if request.placement_generation != live.placement_generation
                        || request.resident_process_generation != live.resident_process_generation
                        || request.lease_attempt != live.lease_attempt
                    {
                        STALE_GENERATION
                    } else {
                        BINDING_MISMATCH
                    };
                    return Err(ApiError::conflict_code(
                        code,
                        "Maestro activation tuple does not exactly match live authority",
                    ));
                }
                Ok(request)
            }
            Self::Resolve(request) => {
                if !resolve_claims_match(&request, live, tenant_id) {
                    let stale = request.placement_generation != live.placement_generation
                        || request.resident_process_generation != live.resident_process_generation
                        || request.lease_attempt != live.lease_attempt;
                    return Err(ApiError::conflict_code(
                        if stale {
                            STALE_GENERATION
                        } else {
                            BINDING_MISMATCH
                        },
                        "Maestro activation claims do not exactly match live authority",
                    ));
                }
                Ok(materialize_validation_request(&request, live))
            }
        }
    }
}

fn tuple_sha256(
    request: &MaestroHostedRunnerActivationValidationRequest,
) -> Result<String, ApiError> {
    let mut tuple = request.clone();
    tuple.activation_id = Uuid::nil();
    let encoded = serde_json::to_vec(&tuple)?;
    let mut hasher = Sha256::new();
    hasher.update(b"sandboxwich-maestro-activation-v1\0");
    hasher.update(encoded);
    Ok(format!("{:x}", hasher.finalize()))
}

fn proof_tuple_digest(
    live: &MaestroHostedRunnerConnectionBindingResponse,
    authority: ActivationAuthority,
) -> Result<String, ApiError> {
    let tuple = ActivationProofTupleV1 {
        resident_process_id: authority.resident_process_id,
        resident_process_generation: live.resident_process_generation,
        lease_id: live.lease_id,
        lease_attempt: live.lease_attempt,
        job_id: authority.job_id,
        worker_id: live.worker_id,
        placement_generation: live.placement_generation,
        provider_pod_uid: live.pod_uid,
        runtime_image: live.runtime_image.clone(),
    };
    digest_proof_tuple(&tuple)
}

fn digest_proof_tuple(tuple: &ActivationProofTupleV1) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(tuple)?;
    let mut hasher = Sha256::new();
    hasher.update(b"sandboxwich-maestro-activation-proof-v1\0");
    hasher.update(encoded);
    Ok(format!("{PROOF_DIGEST_PREFIX}{:x}", hasher.finalize()))
}

fn authority_revision(live: &MaestroHostedRunnerConnectionBindingResponse) -> String {
    format!(
        "maestro-authority:v1:{}:{}:{}",
        live.placement_generation, live.resident_process_generation, live.lease_attempt
    )
}

fn validation_response(
    request: &MaestroHostedRunnerActivationValidationRequest,
    live: &MaestroHostedRunnerConnectionBindingResponse,
    authority: ActivationAuthority,
    tuple_sha256: String,
    validated_at: chrono::DateTime<Utc>,
    replayed: bool,
) -> Result<MaestroHostedRunnerActivationValidationResponse, ApiError> {
    Ok(MaestroHostedRunnerActivationValidationResponse {
        ok: true,
        activation_id: request.activation_id,
        resident_process_id: authority.resident_process_id,
        job_id: authority.job_id,
        tuple_digest: proof_tuple_digest(live, authority)?,
        authority_revision: authority_revision(live),
        tuple_sha256,
        validated_at,
        replayed,
    })
}

fn binding_matches(
    request: &MaestroHostedRunnerActivationValidationRequest,
    live: &MaestroHostedRunnerConnectionBindingResponse,
) -> bool {
    request.organization_id == live.organization_id
        && request.workspace_id == live.workspace_id
        && request.sandbox_id == live.sandbox_id
        && request.pod_uid == live.pod_uid
        && request.placement_generation == live.placement_generation
        && request.runner_session_id == live.runner_session_id
        && request.runtime_image == live.runtime_image
        && request.service_namespace == live.service_namespace
        && request.service_name == live.service_name
        && request.service_host == live.service_host
        && request.service_port == live.service_port
        && request.expected_server_uri_san == live.expected_server_uri_san
        && request.resident_process_generation == live.resident_process_generation
        && request.lease_id == live.lease_id
        && request.lease_attempt == live.lease_attempt
        && request.lease_expires_at_epoch_seconds == live.lease_expires_at_epoch_seconds
        && request.worker_id == live.worker_id
}

fn classify_live_error(error: ApiError) -> ApiError {
    if error.status.is_server_error() {
        return error;
    }
    if error.message.contains("lease is no longer active")
        || error.message.contains("lease expires too soon")
    {
        return ApiError::conflict_code(EXPIRED_LEASE, "Maestro activation lease is expired");
    }
    if error.message.contains("generation")
        || error.message.contains("Pod binding is stale")
        || error.message.contains("process generation")
    {
        return ApiError::conflict_code(STALE_GENERATION, "Maestro activation generation is stale");
    }
    if error.status == axum::http::StatusCode::NOT_FOUND {
        return ApiError {
            status: error.status,
            code: NOT_LIVE,
            message: "Maestro activation authority was not found".into(),
        };
    }
    ApiError::conflict_code(NOT_LIVE, "Maestro activation tuple is not live")
}

#[utoipa::path(
    post,
    path = "/v1/sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/activations/validate",
    params(("sandbox_id" = Uuid, Path)),
    request_body = MaestroHostedRunnerActivationValidationRequest,
    responses(
        (status = 200, description = "Durable proof of an exact live Maestro activation tuple", body = MaestroHostedRunnerActivationValidationResponse),
        (status = 404, description = "No tenant-scoped activation authority exists", body = ErrorEnvelope),
        (status = 409, description = "Activation tuple is stale, expired, replayed with different material, or mismatched", body = ErrorEnvelope)
    )
)]
pub(crate) async fn validate_maestro_activation(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<MaestroHostedRunnerActivationValidationRequest>,
) -> Result<Json<MaestroHostedRunnerActivationValidationResponse>, ApiError> {
    let started = Instant::now();
    let result =
        validate_maestro_activation_inner(&state, &ctx.tenant_id, sandbox_id, request).await;
    let (outcome, reason) = match &result {
        Ok(response) if response.replayed => ("accepted", "replayed"),
        Ok(_) => ("accepted", "validated"),
        Err(error) if error.status.is_server_error() => ("error", "internal"),
        Err(error) => ("rejected", metric_reason(error.code)),
    };
    state.maestro_observation_sink.try_enqueue(
        &ctx.tenant_id,
        outcome,
        reason,
        started.elapsed().as_millis(),
    );
    result.map(Json)
}

async fn validate_maestro_activation_inner(
    state: &AppState,
    tenant_id: &str,
    path_sandbox_id: Uuid,
    request: MaestroHostedRunnerActivationValidationRequest,
) -> Result<MaestroHostedRunnerActivationValidationResponse, ApiError> {
    authoritative_activation_transaction(
        state,
        tenant_id,
        path_sandbox_id,
        ActivationRequest::Validate(request),
    )
    .await
    .map(|(_, proof)| proof)
}

fn live_runtime_image_digest(live: &MaestroHostedRunnerConnectionBindingResponse) -> Option<&str> {
    live.runtime_image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn resolve_claims_match(
    request: &MaestroHostedRunnerActivationResolveRequest,
    live: &MaestroHostedRunnerConnectionBindingResponse,
    tenant_id: &str,
) -> bool {
    let authority_tenant = format!("{}:{}", request.organization_id, request.workspace_id);
    tenant_id == authority_tenant
        && live.organization_id == authority_tenant
        && live.workspace_id == request.workspace_id
        && live.sandbox_id == request.sandbox_id
        && live.pod_uid == request.pod_uid
        && live.placement_generation == request.placement_generation
        && live.runner_session_id == request.runner_session_id
        && live_runtime_image_digest(live) == Some(request.runtime_image_digest.as_str())
        && live.service_name == request.service_name
        && live.service_port == request.service_port
        && live.resident_process_generation == request.resident_process_generation
        && live.lease_id == request.lease_id
        && live.lease_attempt == request.lease_attempt
        && live.worker_id == request.worker_id
}

fn materialize_validation_request(
    request: &MaestroHostedRunnerActivationResolveRequest,
    live: &MaestroHostedRunnerConnectionBindingResponse,
) -> MaestroHostedRunnerActivationValidationRequest {
    MaestroHostedRunnerActivationValidationRequest {
        activation_id: request.activation_id,
        organization_id: live.organization_id.clone(),
        workspace_id: live.workspace_id.clone(),
        sandbox_id: live.sandbox_id,
        pod_uid: live.pod_uid,
        placement_generation: live.placement_generation,
        runner_session_id: live.runner_session_id.clone(),
        runtime_image: live.runtime_image.clone(),
        service_namespace: live.service_namespace.clone(),
        service_name: live.service_name.clone(),
        service_host: live.service_host.clone(),
        service_port: live.service_port,
        expected_server_uri_san: live.expected_server_uri_san.clone(),
        resident_process_generation: live.resident_process_generation,
        lease_id: live.lease_id,
        lease_attempt: live.lease_attempt,
        lease_expires_at_epoch_seconds: live.lease_expires_at_epoch_seconds,
        worker_id: live.worker_id,
    }
}

async fn authoritative_activation_transaction(
    state: &AppState,
    tenant_id: &str,
    path_sandbox_id: Uuid,
    request: ActivationRequest,
) -> Result<
    (
        MaestroHostedRunnerConnectionBindingResponse,
        MaestroHostedRunnerActivationValidationResponse,
    ),
    ApiError,
> {
    let sandbox_id = request.sandbox_id();
    let activation_id = request.activation_id();
    if sandbox_id.0 != path_sandbox_id {
        return Err(ApiError::conflict_code(
            BINDING_MISMATCH,
            "Maestro activation sandbox does not match the request path",
        ));
    }
    let mut transaction = state.db.pool.begin().await?;

    // No-op writes serialize every mutable source of the tuple on SQLite and
    // take the corresponding row locks on PostgreSQL. The canonical read and
    // proof insert therefore share one authoritative point-in-time fence.
    let lock_sql = format!(
        "update resident_processes set updated_at = updated_at
         where tenant_id = {} and sandbox_id = {} and name = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
    );
    if sqlx::query(&lock_sql)
        .bind(tenant_id)
        .bind(sandbox_id.to_string())
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
        != 1
    {
        return Err(ApiError {
            status: axum::http::StatusCode::NOT_FOUND,
            code: NOT_LIVE,
            message: "Maestro activation authority was not found".into(),
        });
    }
    let placement_lock_sql = format!(
        "update sandbox_placements set generation = generation where sandbox_id = {}",
        state.db.placeholder(1),
    );
    if sqlx::query(&placement_lock_sql)
        .bind(sandbox_id.to_string())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
        != 1
    {
        return Err(ApiError::conflict_code(
            NOT_LIVE,
            "Maestro activation placement is not live",
        ));
    }
    let lease_lock_sql = format!(
        "update job_leases set expires_at = expires_at
         where id = (
           select active_lease_id from resident_processes
           where tenant_id = {} and sandbox_id = {} and name = {}
         )",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
    );
    sqlx::query(&lease_lock_sql)
        .bind(tenant_id)
        .bind(sandbox_id.to_string())
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .execute(&mut *transaction)
        .await?;
    let worker_lock_sql = format!(
        "update workers set labels = labels
         where id = (select worker_id from sandbox_placements where sandbox_id = {})",
        state.db.placeholder(1),
    );
    sqlx::query(&worker_lock_sql)
        .bind(sandbox_id.to_string())
        .execute(&mut *transaction)
        .await?;

    let existing_sql = format!(
        "select tuple_sha256, validated_at from maestro_activation_validations
         where tenant_id = {} and activation_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
    );
    let existing = sqlx::query(&existing_sql)
        .bind(tenant_id)
        .bind(activation_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
    // Preserve the legacy validate endpoint's replay precedence: once an
    // activation ID is durable, presenting different full tuple material is
    // a replay mismatch even when that material also disagrees with today's
    // live binding. Resolve cannot compute this digest until it has
    // materialized the authoritative fields below.
    if let (Some(row), Some(caller_digest)) = (&existing, request.caller_tuple_digest()?)
        && row.try_get::<String, _>("tuple_sha256")? != caller_digest
    {
        return Err(ApiError::conflict_code(
            REPLAY_MISMATCH,
            "Maestro activation ID was already used for different tuple material",
        ));
    }

    let live = authoritative_maestro_connection_binding(
        &state.db,
        &mut transaction,
        tenant_id,
        sandbox_id,
    )
    .await
    .map_err(classify_live_error)?;
    let validation = request.materialize(&live, tenant_id)?;
    if Utc::now().timestamp() >= live.lease_expires_at_epoch_seconds {
        return Err(ApiError::conflict_code(
            EXPIRED_LEASE,
            "Maestro activation lease is expired",
        ));
    }
    let digest = tuple_sha256(&validation)?;
    if let Some(row) = &existing
        && row.try_get::<String, _>("tuple_sha256")? != digest
    {
        return Err(ApiError::conflict_code(
            REPLAY_MISMATCH,
            "Maestro activation ID was already used for different tuple material",
        ));
    }

    let authority_sql = format!(
        "select rp.id as resident_process_id, jl.job_id
         from resident_processes rp
         join job_leases jl on jl.id = rp.active_lease_id
         where rp.tenant_id = {} and rp.sandbox_id = {} and rp.name = {}
           and rp.active_lease_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
    );
    let authority_row = sqlx::query(&authority_sql)
        .bind(tenant_id)
        .bind(sandbox_id.to_string())
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .bind(validation.lease_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
    let authority = ActivationAuthority {
        resident_process_id: ResidentProcessId(
            Uuid::parse_str(&authority_row.try_get::<String, _>("resident_process_id")?)
                .map_err(|_| ApiError::internal("invalid authoritative resident process ID"))?,
        ),
        job_id: JobId(
            Uuid::parse_str(&authority_row.try_get::<String, _>("job_id")?)
                .map_err(|_| ApiError::internal("invalid authoritative job ID"))?,
        ),
    };

    let (validated_at, replayed) = if let Some(row) = existing {
        (
            parse_timestamp(&row.try_get::<String, _>("validated_at")?)?,
            true,
        )
    } else {
        let validated_at = Utc::now();
        let insert_sql = format!(
            "insert into maestro_activation_validations
             (tenant_id, activation_id, sandbox_id, tuple_sha256, binding_json, validated_at)
             values ({})",
            state.db.placeholders(6),
        );
        sqlx::query(&insert_sql)
            .bind(tenant_id)
            .bind(activation_id.to_string())
            .bind(sandbox_id.to_string())
            .bind(&digest)
            .bind(serde_json::to_string(&validation)?)
            .bind(validated_at.to_rfc3339())
            .execute(&mut *transaction)
            .await?;
        (validated_at, false)
    };
    let proof = validation_response(
        &validation,
        &live,
        authority,
        digest,
        validated_at,
        replayed,
    )?;
    transaction.commit().await?;
    Ok((live, proof))
}

#[utoipa::path(
    post,
    path = "/v1/sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/activations/resolve",
    params(("sandbox_id" = Uuid, Path)),
    request_body = MaestroHostedRunnerActivationResolveRequest,
    responses(
        (status = 200, description = "Exact locked Maestro binding and durable activation proof", body = MaestroHostedRunnerActivationResolveResponse),
        (status = 404, description = "No tenant-scoped activation authority exists", body = ErrorEnvelope),
        (status = 409, description = "Signed claims are stale, expired, replayed with different material, or mismatched", body = ErrorEnvelope)
    )
)]
pub(crate) async fn resolve_maestro_activation(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<MaestroHostedRunnerActivationResolveRequest>,
) -> Result<Json<MaestroHostedRunnerActivationResolveResponse>, ApiError> {
    let started = Instant::now();
    let result =
        resolve_maestro_activation_inner(&state, &ctx.tenant_id, sandbox_id, request).await;
    let (outcome, reason) = match &result {
        Ok(response) if response.proof.replayed => ("accepted", "replayed"),
        Ok(_) => ("accepted", "validated"),
        Err(error) if error.status.is_server_error() => ("error", "internal"),
        Err(error) => ("rejected", metric_reason(error.code)),
    };
    state.maestro_observation_sink.try_enqueue(
        &ctx.tenant_id,
        outcome,
        reason,
        started.elapsed().as_millis(),
    );
    result.map(Json)
}

async fn resolve_maestro_activation_inner(
    state: &AppState,
    tenant_id: &str,
    path_sandbox_id: Uuid,
    request: MaestroHostedRunnerActivationResolveRequest,
) -> Result<MaestroHostedRunnerActivationResolveResponse, ApiError> {
    let (binding, proof) = authoritative_activation_transaction(
        state,
        tenant_id,
        path_sandbox_id,
        ActivationRequest::Resolve(request),
    )
    .await?;
    Ok(MaestroHostedRunnerActivationResolveResponse { binding, proof })
}

fn metric_reason(code: &str) -> &'static str {
    match code {
        BINDING_MISMATCH => "binding_mismatch",
        REPLAY_MISMATCH => "replay_mismatch",
        STALE_GENERATION => "stale_generation",
        EXPIRED_LEASE => "expired_lease",
        NOT_LIVE => "not_live",
        "not_found" => "not_found",
        "bad_request" => "invalid_request",
        _ => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(value: &str) -> Uuid {
        Uuid::parse_str(value).unwrap()
    }

    #[test]
    fn proof_digest_pins_the_canonical_v1_tuple() {
        let tuple = ActivationProofTupleV1 {
            resident_process_id: ResidentProcessId(uuid("00000000-0000-0000-0000-000000000001")),
            resident_process_generation: 2,
            lease_id: uuid("00000000-0000-0000-0000-000000000003"),
            lease_attempt: 4,
            job_id: JobId(uuid("00000000-0000-0000-0000-000000000005")),
            worker_id: WorkerId(uuid("00000000-0000-0000-0000-000000000006")),
            placement_generation: 7,
            provider_pod_uid: uuid("00000000-0000-0000-0000-000000000008"),
            runtime_image: format!("example@sha256:{}", "a".repeat(64)),
        };

        assert_eq!(
            digest_proof_tuple(&tuple).unwrap(),
            "sha256:v1:5be4e7df19ff91042cf78e8c5fee277b8dd702e149dd838b1ff9977d8327a603"
        );

        let mut different_job = tuple;
        different_job.job_id = JobId(uuid("00000000-0000-0000-0000-000000000009"));
        assert_ne!(
            digest_proof_tuple(&different_job).unwrap(),
            "sha256:v1:5be4e7df19ff91042cf78e8c5fee277b8dd702e149dd838b1ff9977d8327a603"
        );
    }

    #[test]
    fn resolve_claims_fence_every_signed_identity_component() {
        let sandbox_id = SandboxId(uuid("00000000-0000-0000-0000-000000000001"));
        let pod_uid = uuid("00000000-0000-0000-0000-000000000002");
        let lease_id = uuid("00000000-0000-0000-0000-000000000003");
        let worker_id = WorkerId(uuid("00000000-0000-0000-0000-000000000004"));
        let digest = "a".repeat(64);
        let live = MaestroHostedRunnerConnectionBindingResponse {
            ok: true,
            organization_id: "org-1:workspace-1".into(),
            workspace_id: "workspace-1".into(),
            sandbox_id,
            pod_uid,
            placement_generation: 5,
            runner_session_id: "session-1".into(),
            runtime_image: format!("image@sha256:{digest}"),
            service_namespace: "sandboxwich-sandboxes".into(),
            service_name: "maestro-1".into(),
            service_host: "maestro-1.sandboxwich-sandboxes.svc.cluster.local".into(),
            service_port: 8443,
            expected_server_uri_san: "spiffe://identity.evalops.dev/maestro/v1/exact".into(),
            resident_process_generation: 6,
            lease_id,
            lease_attempt: 7,
            lease_expires_at_epoch_seconds: 4_000_000_000,
            worker_id,
        };
        let request = MaestroHostedRunnerActivationResolveRequest {
            activation_id: uuid("00000000-0000-0000-0000-000000000005"),
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            sandbox_id,
            pod_uid,
            placement_generation: 5,
            runner_session_id: "session-1".into(),
            runtime_image_digest: digest,
            service_name: "maestro-1".into(),
            service_port: 8443,
            resident_process_generation: 6,
            lease_id,
            lease_attempt: 7,
            worker_id,
        };
        assert!(resolve_claims_match(&request, &live, "org-1:workspace-1"));

        macro_rules! reject {
            ($change:expr) => {{
                let mut changed = request.clone();
                $change(&mut changed);
                assert!(!resolve_claims_match(&changed, &live, "org-1:workspace-1"));
            }};
        }
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.organization_id =
                "org-2".into()
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.workspace_id =
                "workspace-2".into()
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.sandbox_id =
                SandboxId(Uuid::new_v4())
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.pod_uid =
                Uuid::new_v4()
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.placement_generation +=
                1
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.runner_session_id =
                "session-2".into()
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.runtime_image_digest =
                "b".repeat(64)
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.service_name =
                "maestro-2".into()
        );
        reject!(|value: &mut MaestroHostedRunnerActivationResolveRequest| value.service_port += 1);
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value
                .resident_process_generation +=
                1
        );
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.lease_id =
                Uuid::new_v4()
        );
        reject!(|value: &mut MaestroHostedRunnerActivationResolveRequest| value.lease_attempt += 1);
        reject!(
            |value: &mut MaestroHostedRunnerActivationResolveRequest| value.worker_id =
                WorkerId(Uuid::new_v4())
        );
        assert!(!resolve_claims_match(&request, &live, "other-tenant"));

        for changed in [
            MaestroHostedRunnerActivationResolveRequest {
                placement_generation: request.placement_generation + 1,
                ..request.clone()
            },
            MaestroHostedRunnerActivationResolveRequest {
                resident_process_generation: request.resident_process_generation + 1,
                ..request.clone()
            },
            MaestroHostedRunnerActivationResolveRequest {
                lease_attempt: request.lease_attempt + 1,
                ..request.clone()
            },
        ] {
            let error = ActivationRequest::Resolve(changed)
                .materialize(&live, "org-1:workspace-1")
                .expect_err("generation mismatch must fail closed");
            assert_eq!(error.code, STALE_GENERATION);
        }
    }
}
