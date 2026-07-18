use crate::db::Database;
use crate::error::ApiError;
use crate::rows::{parse_timestamp, parse_uuid};
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sandboxwich_core::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

const ATTESTATION_VERSION: u32 = 2;
const ATTESTATION_TTL_SECONDS: i64 = 300;

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
        code: "placement_attestation_not_found",
        message: "placement attestation was not found".into(),
    }
}

fn not_live(message: impl Into<String>) -> ApiError {
    ApiError::conflict_code("placement_attestation_not_live", message)
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

async fn placement_fence(
    db: &Database,
    tenant_id: &str,
    process_id: ResidentProcessId,
    generation: u64,
    lease_id: Uuid,
) -> Result<PlacementFence, ApiError> {
    let sql = format!(
        "select rp.provider_isolation_version, rp.provider_pod_name, rp.provider_pod_uid,
                jl.attempt, jl.job_id, jl.worker_id,
                jl.status, jl.expires_at, sp.worker_id as placement_worker_id,
                sp.generation as placement_generation, w.labels
         from resident_processes rp
         join job_leases jl on jl.id = rp.active_lease_id
         join sandbox_placements sp on sp.sandbox_id = rp.sandbox_id
         join workers w on w.id = jl.worker_id
         where rp.id = {} and rp.tenant_id = {} and rp.generation = {}
           and rp.active_lease_id = {} and rp.name = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
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
        .fetch_optional(&db.pool)
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
    let labels = parse_labels(&row.try_get::<String, _>("labels")?)?;
    let provider_mode = label(&labels, "provider_mode")?.to_string();
    if provider_mode != "apply" {
        return Err(not_live("resident placement is not provider-applied"));
    }
    let runtime_image = label(&labels, PROVIDER_ISOLATED_RESIDENT_PROCESS_IMAGE_LABEL)?.to_string();
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
