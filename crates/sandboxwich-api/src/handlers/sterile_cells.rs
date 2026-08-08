use crate::auth::{constant_time_eq, ensure_worker_scope, ensure_worker_tenant, hash_worker_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::idempotency::SkipIdempotencyResponsePersist;
use crate::rows::{parse_timestamp, parse_uuid};
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sandboxwich_core::*;
use sha2::Sha256;
use sqlx::{Any, Row, Transaction};
use std::sync::Arc;
use uuid::Uuid;

const DEFAULT_LEASE_SECONDS: u64 = 120;
const MAX_LEASE_SECONDS: u64 = 300;
const RELEASE_SIGNATURE_PREFIX: &str = "swrs1_";
const LEASE_ATTESTATION_PREFIX: &str = "swla1_";

fn require_enabled(state: &AppState) -> Result<Arc<str>, ApiError> {
    state
        .sterile_cell_signing_key
        .clone()
        .ok_or_else(|| ApiError::not_found("resource not found"))
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn validate_release(key: &str, release: &SterileCellReleaseTrustClassV1) -> Result<(), ApiError> {
    if !valid_identifier(&release.release_set_id)
        || release.policy_digest.len() != 64
        || !release
            .policy_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad_request(
            "release_set_id or policy_digest is invalid",
        ));
    }
    let canonical = format!(
        "sandboxwich-sterile-release-v1\0{}\0{}\0{}",
        release.release_set_id,
        release.runtime_class.as_db_str(),
        release.policy_digest.to_ascii_lowercase(),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| ApiError::internal("sterile-cell signing key is invalid"))?;
    mac.update(canonical.as_bytes());
    let expected = format!(
        "{RELEASE_SIGNATURE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    if !constant_time_eq(expected.as_bytes(), release.signature.as_bytes()) {
        return Err(ApiError::forbidden(
            "sterile-cell release trust class signature is invalid",
        ));
    }
    Ok(())
}

fn validate_binding(value: &str, field: &'static str) -> Result<(), ApiError> {
    if !valid_identifier(value) {
        return Err(ApiError::bad_request(format!("{field} is invalid")));
    }
    Ok(())
}

fn lease_token(key: &str, lease: &SterileCellLeaseV1) -> Result<String, ApiError> {
    let canonical = format!(
        "sandboxwich-sterile-lease-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        lease.lease_id,
        lease.cell_id,
        lease.generation,
        lease.release.release_set_id,
        lease.release.runtime_class.as_db_str(),
        lease.release.policy_digest,
        lease.organization_id,
        lease.workspace_id,
        lease.thread_id,
        lease.runner_session_id,
        lease.expires_at.to_rfc3339(),
        lease.release.signature,
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| ApiError::internal("sterile-cell signing key is invalid"))?;
    mac.update(canonical.as_bytes());
    Ok(format!(
        "{LEASE_ATTESTATION_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn release_from_row(row: &sqlx::any::AnyRow) -> Result<SterileCellReleaseTrustClassV1, ApiError> {
    Ok(SterileCellReleaseTrustClassV1 {
        release_set_id: row.try_get("release_set_id")?,
        runtime_class: SterileCellRuntimeClass::parse_db_str(row.try_get("runtime_class")?)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        policy_digest: row.try_get("policy_digest")?,
        signature: row.try_get("release_signature")?,
    })
}

fn cell_from_row(row: &sqlx::any::AnyRow) -> Result<SterileCellV1, ApiError> {
    let disposition: Option<String> = row.try_get("disposition")?;
    Ok(SterileCellV1 {
        cell_id: SterileCellId(parse_uuid(row.try_get("id")?)?),
        worker_id: WorkerId(parse_uuid(row.try_get("worker_id")?)?),
        provider_cell_id: row.try_get("provider_cell_id")?,
        state: SterileCellState::parse_db_str(row.try_get("state")?)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        generation: u64::try_from(row.try_get::<i64, _>("generation")?)
            .map_err(|_| ApiError::internal("invalid sterile-cell generation"))?,
        release: release_from_row(row)?,
        expires_at: parse_timestamp(row.try_get("cell_expires_at")?)?,
        disposition: disposition
            .map(|value| SterileCellDisposition::parse_db_str(&value))
            .transpose()
            .map_err(|error| ApiError::internal(error.to_string()))?,
    })
}

fn lease_from_row(row: &sqlx::any::AnyRow) -> Result<SterileCellLeaseV1, ApiError> {
    Ok(SterileCellLeaseV1 {
        lease_id: parse_uuid(row.try_get("lease_id")?)?,
        cell_id: SterileCellId(parse_uuid(row.try_get("id")?)?),
        generation: u64::try_from(row.try_get::<i64, _>("generation")?)
            .map_err(|_| ApiError::internal("invalid sterile-cell generation"))?,
        release: release_from_row(row)?,
        organization_id: row.try_get("organization_id")?,
        workspace_id: row.try_get("workspace_id")?,
        thread_id: row.try_get("thread_id")?,
        runner_session_id: row.try_get("runner_session_id")?,
        expires_at: parse_timestamp(row.try_get("lease_expires_at")?)?,
    })
}

#[utoipa::path(
    post,
    path = "/v1/workers/{worker_id}/sterile-cells/prepare",
    params(("worker_id" = Uuid, Path)),
    request_body = PrepareSterileCellRequestV1,
    responses((status = 200, body = SterileCellResponseV1), (status = 403, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn prepare_sterile_cell(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Json(request): Json<PrepareSterileCellRequestV1>,
) -> Result<Json<SterileCellResponseV1>, ApiError> {
    let key = require_enabled(&state)?;
    let worker_id = WorkerId(worker_id);
    ensure_worker_scope(&ctx, worker_id)?;
    let worker = ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    validate_release(&key, &request.release)?;
    if request.expires_at <= Utc::now() {
        return Err(ApiError::bad_request(
            "sterile-cell expiry must be in the future",
        ));
    }
    validate_binding(&request.provider_cell_id, "provider_cell_id")?;
    let required_capability = match request.release.runtime_class {
        SterileCellRuntimeClass::KataMicrovm => WorkerCapability::VirtualMachine,
        SterileCellRuntimeClass::GvisorLowerRisk => WorkerCapability::SandboxedContainer,
    };
    if !worker.capabilities.contains(&required_capability) {
        return Err(ApiError::forbidden(
            "worker does not advertise the signed sterile-cell runtime class",
        ));
    }
    let now = Utc::now().to_rfc3339();
    let sql = format!(
        "insert into sterile_cells
         (id, worker_id, provider_cell_id, state, generation, release_set_id,
          runtime_class, policy_digest, release_signature, tenant_id,
          cell_expires_at, created_at, updated_at) values ({})",
        state.db.placeholders(13),
    );
    sqlx::query(&sql)
        .bind(request.cell_id.to_string())
        .bind(worker_id.to_string())
        .bind(&request.provider_cell_id)
        .bind(SterileCellState::Ready.as_db_str())
        .bind(1_i64)
        .bind(&request.release.release_set_id)
        .bind(request.release.runtime_class.as_db_str())
        .bind(request.release.policy_digest.to_ascii_lowercase())
        .bind(&request.release.signature)
        .bind(&worker.tenant_id)
        .bind(request.expires_at.to_rfc3339())
        .bind(&now)
        .bind(&now)
        .execute(&state.db.pool)
        .await?;
    let cell = fetch_cell(&state.db, request.cell_id).await?;
    Ok(Json(SterileCellResponseV1 { ok: true, cell }))
}

async fn fetch_cell(db: &Database, cell_id: SterileCellId) -> Result<SterileCellV1, ApiError> {
    let sql = format!(
        "select * from sterile_cells where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(cell_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    cell_from_row(&row)
}

enum ClaimAttempt {
    Claimed(Box<SterileCellLeaseV1>, String),
    Contended,
    Empty,
}

async fn claim_once(
    state: &AppState,
    key: &str,
    ctx: &TenantContext,
    request: &ClaimSterileCellRequestV1,
    lease_expires_at: DateTime<Utc>,
) -> Result<ClaimAttempt, ApiError> {
    let mut transaction = state.db.pool.begin().await?;
    let select = format!(
        "select id, cell_expires_at, generation from sterile_cells
         where tenant_id = {} and state = 'ready' and release_set_id = {}
         and runtime_class = {} and policy_digest = {} and release_signature = {}
         and cell_expires_at > {} order by created_at asc, id asc limit 1",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6),
    );
    let Some(row) = sqlx::query(&select)
        .bind(&ctx.tenant_id)
        .bind(&request.release.release_set_id)
        .bind(request.release.runtime_class.as_db_str())
        .bind(request.release.policy_digest.to_ascii_lowercase())
        .bind(&request.release.signature)
        .bind(lease_expires_at.to_rfc3339())
        .fetch_optional(&mut *transaction)
        .await?
    else {
        transaction.commit().await?;
        return Ok(ClaimAttempt::Empty);
    };
    let cell_id = SterileCellId(parse_uuid(row.try_get("id")?)?);
    let cell_expiry = parse_timestamp(row.try_get("cell_expires_at")?)?;
    let lease_expires_at = lease_expires_at.min(cell_expiry);
    if lease_expires_at <= Utc::now() {
        quarantine_expired_ready(&state.db, &mut transaction, cell_id).await?;
        transaction.commit().await?;
        return Ok(ClaimAttempt::Contended);
    }
    let generation = u64::try_from(row.try_get::<i64, _>("generation")?)
        .map_err(|_| ApiError::internal("invalid sterile-cell generation"))?
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("sterile-cell generation overflow"))?;
    let lease = SterileCellLeaseV1 {
        lease_id: Uuid::now_v7(),
        cell_id,
        generation,
        release: request.release.clone(),
        organization_id: request.organization_id.clone(),
        workspace_id: request.workspace_id.clone(),
        thread_id: request.thread_id.clone(),
        runner_session_id: request.runner_session_id.clone(),
        expires_at: lease_expires_at,
    };
    let token = lease_token(key, &lease)?;
    let now = Utc::now().to_rfc3339();
    let update = format!(
        "update sterile_cells set state = 'leased', generation = {}, tenant_id = {},
         organization_id = {}, workspace_id = {}, thread_id = {}, runner_session_id = {},
         lease_id = {}, lease_attestation_sha256 = {}, lease_expires_at = {},
         ever_tenant_exposed = 1, leased_at = {}, updated_at = {}
         where id = {} and tenant_id = {} and state = 'ready'
         and generation = {} and ever_tenant_exposed = 0",
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
    );
    let updated = sqlx::query(&update)
        .bind(i64::try_from(generation).map_err(|_| ApiError::bad_request("generation too large"))?)
        .bind(&ctx.tenant_id)
        .bind(&request.organization_id)
        .bind(&request.workspace_id)
        .bind(&request.thread_id)
        .bind(&request.runner_session_id)
        .bind(lease.lease_id.to_string())
        .bind(hash_worker_token(&token))
        .bind(lease.expires_at.to_rfc3339())
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string())
        .bind(&ctx.tenant_id)
        .bind(
            i64::try_from(generation - 1)
                .map_err(|_| ApiError::bad_request("generation too large"))?,
        )
        .execute(&mut *transaction)
        .await?;
    if updated.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(ClaimAttempt::Contended);
    }
    transaction.commit().await?;
    Ok(ClaimAttempt::Claimed(Box::new(lease), token))
}

async fn quarantine_expired_ready(
    db: &Database,
    transaction: &mut Transaction<'_, Any>,
    cell_id: SterileCellId,
) -> Result<(), ApiError> {
    let sql = format!(
        "update sterile_cells set state = 'quarantined', disposition = 'quarantined',
         destroyed_at = {}, updated_at = {} where id = {} and state = 'ready'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let now = Utc::now().to_rfc3339();
    sqlx::query(&sql)
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/v1/sterile-cells/claim",
    request_body = ClaimSterileCellRequestV1,
    responses((status = 200, body = ClaimSterileCellResponseV1), (status = 403, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn claim_sterile_cell(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<ClaimSterileCellRequestV1>,
) -> Result<Response, ApiError> {
    let key = require_enabled(&state)?;
    validate_release(&key, &request.release)?;
    validate_binding(&request.organization_id, "organization_id")?;
    validate_binding(&request.workspace_id, "workspace_id")?;
    validate_binding(&request.thread_id, "thread_id")?;
    validate_binding(&request.runner_session_id, "runner_session_id")?;
    let lease_seconds = request
        .lease_seconds
        .unwrap_or(DEFAULT_LEASE_SECONDS)
        .clamp(1, MAX_LEASE_SECONDS);
    let lease_expires_at = Utc::now()
        + Duration::seconds(
            i64::try_from(lease_seconds)
                .map_err(|_| ApiError::bad_request("lease_seconds is too large"))?,
        );
    for _ in 0..4 {
        match claim_once(&state, &key, &ctx, &request, lease_expires_at).await? {
            ClaimAttempt::Claimed(lease, token) => {
                return Ok(secret_claim_response(ClaimSterileCellResponseV1 {
                    ok: true,
                    lease: Some(*lease),
                    lease_attestation: Some(token),
                }));
            }
            ClaimAttempt::Empty => {
                return Ok(secret_claim_response(ClaimSterileCellResponseV1 {
                    ok: true,
                    lease: None,
                    lease_attestation: None,
                }));
            }
            ClaimAttempt::Contended => {}
        }
    }
    Ok(secret_claim_response(ClaimSterileCellResponseV1 {
        ok: true,
        lease: None,
        lease_attestation: None,
    }))
}

fn secret_claim_response(body: ClaimSterileCellResponseV1) -> Response {
    let mut response = Json(body).into_response();
    response
        .extensions_mut()
        .insert(SkipIdempotencyResponsePersist);
    response
}

#[utoipa::path(
    post,
    path = "/v1/sterile-cell-leases/{lease_id}/validate",
    params(("lease_id" = Uuid, Path)),
    request_body = ValidateSterileCellLeaseRequestV1,
    responses((status = 200, body = ValidateSterileCellLeaseResponseV1), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope))
)]
pub(crate) async fn validate_sterile_cell_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<ValidateSterileCellLeaseRequestV1>,
) -> Result<Json<ValidateSterileCellLeaseResponseV1>, ApiError> {
    require_enabled(&state)?;
    let sql = format!(
        "select id, state, generation, release_set_id, runtime_class, policy_digest,
         release_signature, lease_id, organization_id, workspace_id, thread_id,
         runner_session_id, lease_expires_at, lease_attestation_sha256
         from sterile_cells where lease_id = {} and tenant_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .bind(&ctx.tenant_id)
        .fetch_optional(state.db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    let lease = lease_from_row(&row)?;
    let digest: String = row.try_get("lease_attestation_sha256")?;
    let valid = lease.lease_id == lease_id
        && lease.generation == request.generation
        && lease.organization_id == request.organization_id
        && lease.workspace_id == request.workspace_id
        && lease.thread_id == request.thread_id
        && lease.runner_session_id == request.runner_session_id
        && constant_time_eq(
            digest.as_bytes(),
            hash_worker_token(&request.lease_attestation).as_bytes(),
        );
    if !valid {
        return Err(ApiError::conflict(
            "sterile-cell lease attestation does not match the live lease fence",
        ));
    }
    let state_value: String = row.try_get("state")?;
    if state_value != SterileCellState::Leased.as_db_str() || lease.expires_at <= Utc::now() {
        quarantine_lease(&state.db, lease.cell_id).await?;
        return Err(ApiError::conflict("sterile-cell lease is no longer live"));
    }
    Ok(Json(ValidateSterileCellLeaseResponseV1 { ok: true, lease }))
}

async fn quarantine_lease(db: &Database, cell_id: SterileCellId) -> Result<(), ApiError> {
    let sql = format!(
        "update sterile_cells set state = 'quarantined', disposition = 'quarantined',
         destroyed_at = {}, updated_at = {} where id = {} and state in ('ready', 'leased')",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let now = Utc::now().to_rfc3339();
    sqlx::query(&sql)
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/v1/workers/{worker_id}/sterile-cells/{cell_id}/destroy",
    params(("worker_id" = Uuid, Path), ("cell_id" = Uuid, Path)),
    request_body = DestroySterileCellRequestV1,
    responses((status = 200, body = SterileCellResponseV1), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope))
)]
pub(crate) async fn destroy_sterile_cell(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((worker_id, cell_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DestroySterileCellRequestV1>,
) -> Result<Json<SterileCellResponseV1>, ApiError> {
    require_enabled(&state)?;
    let worker_id = WorkerId(worker_id);
    let cell_id = SterileCellId(cell_id);
    ensure_worker_scope(&ctx, worker_id)?;
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let sql = format!(
        "select * from sterile_cells where id = {} and worker_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
    );
    let row = sqlx::query(&sql)
        .bind(cell_id.to_string())
        .bind(worker_id.to_string())
        .fetch_optional(state.db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    let current = cell_from_row(&row)?;
    let current_lease_id = row
        .try_get::<Option<String>, _>("lease_id")?
        .and_then(|value| Uuid::parse_str(&value).ok());
    if matches!(
        current.state,
        SterileCellState::Destroyed | SterileCellState::Quarantined
    ) {
        if current.generation == request.generation
            && current_lease_id == Some(request.lease_id)
            && current.disposition == Some(request.disposition)
        {
            return Ok(Json(SterileCellResponseV1 {
                ok: true,
                cell: current,
            }));
        }
        return Err(ApiError::conflict(
            "sterile-cell cleanup fence does not match the terminal cell",
        ));
    }
    if current.state != SterileCellState::Leased
        || current.generation != request.generation
        || current_lease_id != Some(request.lease_id)
    {
        quarantine_lease(&state.db, cell_id).await?;
        return Err(ApiError::conflict(
            "sterile-cell cleanup fence is ambiguous; cell was quarantined",
        ));
    }
    let state_value = match request.disposition {
        SterileCellDisposition::Destroyed => SterileCellState::Destroyed,
        SterileCellDisposition::Quarantined => SterileCellState::Quarantined,
    };
    let update = format!(
        "update sterile_cells set state = {}, disposition = {}, destroyed_at = {}, updated_at = {}
         where id = {} and worker_id = {} and state = 'leased' and generation = {} and lease_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6),
        state.db.placeholder(7),
        state.db.placeholder(8),
    );
    let now = Utc::now().to_rfc3339();
    let updated = sqlx::query(&update)
        .bind(state_value.as_db_str())
        .bind(request.disposition.as_db_str())
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string())
        .bind(worker_id.to_string())
        .bind(
            i64::try_from(request.generation)
                .map_err(|_| ApiError::bad_request("generation too large"))?,
        )
        .bind(request.lease_id.to_string())
        .execute(&state.db.pool)
        .await?;
    if updated.rows_affected() != 1 {
        quarantine_lease(&state.db, cell_id).await?;
        return Err(ApiError::conflict(
            "sterile-cell cleanup fence changed; cell was quarantined",
        ));
    }
    Ok(Json(SterileCellResponseV1 {
        ok: true,
        cell: fetch_cell(&state.db, cell_id).await?,
    }))
}

pub(crate) async fn quarantine_expired_sterile_cells(db: &Database) -> Result<u64, ApiError> {
    let now = Utc::now().to_rfc3339();
    let ready = quarantine_expired_state(db, "ready", "cell_expires_at", &now).await?;
    let leased_cell = quarantine_expired_state(db, "leased", "cell_expires_at", &now).await?;
    let leased_lease = quarantine_expired_state(db, "leased", "lease_expires_at", &now).await?;
    Ok(ready + leased_cell + leased_lease)
}

async fn quarantine_expired_state(
    db: &Database,
    state: &'static str,
    expiry_column: &'static str,
    now: &str,
) -> Result<u64, ApiError> {
    debug_assert!(matches!(state, "ready" | "leased"));
    debug_assert!(matches!(
        expiry_column,
        "cell_expires_at" | "lease_expires_at"
    ));
    let sql = format!(
        "update sterile_cells set state = 'quarantined', disposition = 'quarantined',
         destroyed_at = {}, updated_at = {}
         where state = '{state}' and {expiry_column} is not null and {expiry_column} <= {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let result = sqlx::query(&sql)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&db.pool)
        .await?;
    Ok(result.rows_affected())
}
