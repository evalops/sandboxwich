use crate::auth::{constant_time_eq, ensure_worker_scope, ensure_worker_tenant, hash_worker_token};
use crate::db::Database;
use crate::error::ApiError;
use crate::idempotency::SkipIdempotencyResponsePersist;
use crate::rows::{parse_timestamp, parse_uuid};
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sandboxwich_core::*;
use sha2::{Digest as _, Sha256};
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

pub(crate) fn validate_release(
    key: &str,
    release: &SterileCellReleaseTrustClassV1,
) -> Result<(), ApiError> {
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

fn claim_request_digest(request: &ClaimSterileCellRequestV1) -> String {
    let requested_lease_seconds = request
        .lease_seconds
        .map_or_else(|| "none".to_string(), |seconds| seconds.to_string());
    let canonical = format!(
        "sandboxwich-sterile-claim-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        request.release.release_set_id,
        request.release.runtime_class.as_db_str(),
        request.release.policy_digest,
        request.release.signature,
        request.organization_id,
        request.workspace_id,
        request.thread_id,
        request.runner_session_id,
        requested_lease_seconds,
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
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

#[utoipa::path(
    get,
    path = "/v1/workers/{worker_id}/sterile-cells/{cell_id}",
    params(("worker_id" = Uuid, Path), ("cell_id" = Uuid, Path)),
    responses((status = 200, body = WorkerSterileCellLookupResponseV1), (status = 403, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn get_worker_sterile_cell(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((worker_id, cell_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<WorkerSterileCellLookupResponseV1>, ApiError> {
    require_enabled(&state)?;
    let worker_id = WorkerId(worker_id);
    let cell_id = SterileCellId(cell_id);
    ensure_worker_scope(&ctx, worker_id)?;
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let sql = format!(
        "select cells.*, claims.claim_id as claim_locator_id
         from sterile_cells cells
         left join sterile_cell_claims claims on claims.cell_id = cells.id
         where cells.id = {} and cells.worker_id = {} and cells.tenant_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
    );
    let row = sqlx::query(&sql)
        .bind(cell_id.to_string())
        .bind(worker_id.to_string())
        .bind(&ctx.tenant_id)
        .fetch_optional(state.db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    let claim_id = row.try_get::<Option<String>, _>("claim_locator_id")?;
    let lease_id = row.try_get::<Option<String>, _>("lease_id")?;
    let lease_expires_at = row.try_get::<Option<String>, _>("lease_expires_at")?;
    let claim = if let Some(claim_id) = claim_id {
        let (Some(lease_id), Some(expires_at)) = (lease_id, lease_expires_at) else {
            return Err(ApiError::internal(
                "sterile-cell claim locator is incomplete",
            ));
        };
        Some(SterileCellClaimLocatorV1 {
            claim_id: parse_uuid(&claim_id)?,
            lease_id: parse_uuid(&lease_id)?,
            generation: u64::try_from(row.try_get::<i64, _>("generation")?)
                .map_err(|_| ApiError::internal("invalid sterile-cell generation"))?,
            expires_at: parse_timestamp(&expires_at)?,
        })
    } else {
        None
    };
    Ok(Json(WorkerSterileCellLookupResponseV1 {
        ok: true,
        cell: cell_from_row(&row)?,
        claim,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/workers/{worker_id}/sterile-cells/{cell_id}/retire",
    params(("worker_id" = Uuid, Path), ("cell_id" = Uuid, Path)),
    request_body = RetireSterileCellRequestV1,
    responses((status = 200, body = SterileCellResponseV1), (status = 403, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope))
)]
pub(crate) async fn retire_ready_sterile_cell(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((worker_id, cell_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RetireSterileCellRequestV1>,
) -> Result<Json<SterileCellResponseV1>, ApiError> {
    require_enabled(&state)?;
    let worker_id = WorkerId(worker_id);
    let cell_id = SterileCellId(cell_id);
    ensure_worker_scope(&ctx, worker_id)?;
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let current = fetch_worker_cell(&state.db, worker_id, cell_id, &ctx.tenant_id).await?;
    if current.state == SterileCellState::Quarantined
        && current.generation == 1
        && request.generation == 1
        && current.disposition == Some(SterileCellDisposition::Quarantined)
    {
        return Ok(Json(SterileCellResponseV1 {
            ok: true,
            cell: current,
        }));
    }
    if request.generation != 1
        || current.generation != 1
        || current.state != SterileCellState::Ready
    {
        return Err(ApiError::conflict(
            "only a ready generation-1 sterile cell can be retired",
        ));
    }
    let sql = format!(
        "update sterile_cells set state = 'quarantined', disposition = 'quarantined',
         destroyed_at = {}, updated_at = {}
         where id = {} and worker_id = {} and tenant_id = {}
         and state = 'ready' and generation = 1 and ever_tenant_exposed = 0",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
    );
    let now = Utc::now().to_rfc3339();
    let updated = sqlx::query(&sql)
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string())
        .bind(worker_id.to_string())
        .bind(&ctx.tenant_id)
        .execute(&state.db.pool)
        .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "sterile-cell state changed before ready-cell retirement",
        ));
    }
    Ok(Json(SterileCellResponseV1 {
        ok: true,
        cell: fetch_worker_cell(&state.db, worker_id, cell_id, &ctx.tenant_id).await?,
    }))
}

async fn fetch_worker_cell(
    db: &Database,
    worker_id: WorkerId,
    cell_id: SterileCellId,
    tenant_id: &str,
) -> Result<SterileCellV1, ApiError> {
    let sql = format!(
        "select * from sterile_cells where id = {} and worker_id = {} and tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
    );
    let row = sqlx::query(&sql)
        .bind(cell_id.to_string())
        .bind(worker_id.to_string())
        .bind(tenant_id)
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    cell_from_row(&row)
}

enum ClaimAttempt {
    Claimed(Box<SterileCellLeaseV1>, String),
    Contended,
    Empty,
    NoLongerLive,
}

async fn recover_claim(
    state: &AppState,
    key: &str,
    transaction: &mut Transaction<'_, Any>,
    ctx: &TenantContext,
    claim_id: Uuid,
    request_digest: &str,
) -> Result<Option<ClaimAttempt>, ApiError> {
    let select = format!(
        "select claims.request_sha256, claims.cell_id as claim_cell_id,
         claims.lease_id as claim_lease_id, cells.*
         from sterile_cell_claims claims
         left join sterile_cells cells on cells.id = claims.cell_id
         where claims.tenant_id = {} and claims.claim_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
    );
    let Some(row) = sqlx::query(&select)
        .bind(&ctx.tenant_id)
        .bind(claim_id.to_string())
        .fetch_optional(&mut **transaction)
        .await?
    else {
        return Ok(None);
    };
    let stored_digest: String = row.try_get("request_sha256")?;
    if !constant_time_eq(stored_digest.as_bytes(), request_digest.as_bytes()) {
        return Err(ApiError::conflict(
            "claim_id was already used for a different sterile-cell claim",
        ));
    }
    if row.try_get::<Option<String>, _>("claim_cell_id")?.is_none() {
        return Ok(Some(ClaimAttempt::Empty));
    }
    let lease = lease_from_row(&row)?;
    let claim_lease_id: &str = row.try_get("claim_lease_id")?;
    if parse_uuid(claim_lease_id)? != lease.lease_id {
        return Err(ApiError::internal(
            "sterile-cell claim and lease locators do not match",
        ));
    }
    let state_value: String = row.try_get("state")?;
    if state_value != SterileCellState::Leased.as_db_str() || lease.expires_at <= Utc::now() {
        if state_value == SterileCellState::Leased.as_db_str() {
            let now = Utc::now().to_rfc3339();
            let update = format!(
                "update sterile_cells set state = 'quarantined', disposition = 'quarantined',
                 destroyed_at = {}, updated_at = {} where id = {} and state = 'leased'",
                state.db.placeholder(1),
                state.db.placeholder(2),
                state.db.placeholder(3),
            );
            sqlx::query(&update)
                .bind(&now)
                .bind(&now)
                .bind(lease.cell_id.to_string())
                .execute(&mut **transaction)
                .await?;
        }
        return Ok(Some(ClaimAttempt::NoLongerLive));
    }
    let token = lease_token(key, &lease)?;
    let stored_attestation_digest: &str = row.try_get("lease_attestation_sha256")?;
    if !constant_time_eq(
        stored_attestation_digest.as_bytes(),
        hash_worker_token(&token).as_bytes(),
    ) {
        return Err(ApiError::conflict(
            "live sterile-cell lease attestation cannot be regenerated",
        ));
    }
    Ok(Some(ClaimAttempt::Claimed(Box::new(lease), token)))
}

async fn claim_once(
    state: &AppState,
    key: &str,
    ctx: &TenantContext,
    request: &ClaimSterileCellRequestV1,
    lease_expires_at: DateTime<Utc>,
) -> Result<ClaimAttempt, ApiError> {
    let mut transaction = state.db.pool.begin().await?;
    let claim_fence = request
        .claim_id
        .map(|claim_id| (claim_id, claim_request_digest(request)));
    if let Some((claim_id, request_digest)) = &claim_fence {
        if let Some(recovered) =
            recover_claim(state, key, &mut transaction, ctx, *claim_id, request_digest).await?
        {
            transaction.commit().await?;
            if matches!(recovered, ClaimAttempt::NoLongerLive) {
                return Err(ApiError::conflict(
                    "claim_id refers to a sterile-cell lease that is no longer live",
                ));
            }
            return Ok(recovered);
        }
        let insert_claim = format!(
            "insert into sterile_cell_claims
             (tenant_id, claim_id, request_sha256, created_at) values ({})
             on conflict (tenant_id, claim_id) do nothing",
            state.db.placeholders(4),
        );
        let inserted = sqlx::query(&insert_claim)
            .bind(&ctx.tenant_id)
            .bind(claim_id.to_string())
            .bind(request_digest)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *transaction)
            .await?;
        if inserted.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(ClaimAttempt::Contended);
        }
    }
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
    crate::sterile_pool::record_pool_claim_on_connection(
        &state.db,
        &mut transaction,
        cell_id,
        lease.lease_id,
        generation,
    )
    .await?;
    if let Some((claim_id, request_digest)) = claim_fence {
        let link_claim = format!(
            "update sterile_cell_claims set cell_id = {}, lease_id = {}
             where tenant_id = {} and claim_id = {} and request_sha256 = {}
             and cell_id is null and lease_id is null",
            state.db.placeholder(1),
            state.db.placeholder(2),
            state.db.placeholder(3),
            state.db.placeholder(4),
            state.db.placeholder(5),
        );
        let linked = sqlx::query(&link_claim)
            .bind(cell_id.to_string())
            .bind(lease.lease_id.to_string())
            .bind(&ctx.tenant_id)
            .bind(claim_id.to_string())
            .bind(&request_digest)
            .execute(&mut *transaction)
            .await?;
        if linked.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(ClaimAttempt::Contended);
        }
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
            ClaimAttempt::NoLongerLive => unreachable!("claim_once returns an error instead"),
        }
    }
    if request.claim_id.is_some() {
        Err(ApiError::conflict_code(
            "sterile_cell_claim_contended",
            "sterile-cell claim is contended; retry with the same claim_id",
        ))
    } else {
        Ok(secret_claim_response(ClaimSterileCellResponseV1 {
            ok: true,
            lease: None,
            lease_attestation: None,
        }))
    }
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
    let validated = validate_live_lease_fence(
        &state.db,
        &ctx,
        lease_id,
        request.generation,
        &request.organization_id,
        &request.workspace_id,
        &request.thread_id,
        &request.runner_session_id,
        &request.lease_attestation,
    )
    .await?;
    Ok(Json(ValidateSterileCellLeaseResponseV1 {
        ok: true,
        lease: validated.lease,
    }))
}

struct ValidatedLiveLease {
    lease: SterileCellLeaseV1,
    worker_id: WorkerId,
}

#[allow(clippy::too_many_arguments)]
async fn validate_live_lease_fence(
    db: &Database,
    ctx: &TenantContext,
    lease_id: Uuid,
    generation: u64,
    organization_id: &str,
    workspace_id: &str,
    thread_id: &str,
    runner_session_id: &str,
    lease_attestation: &str,
) -> Result<ValidatedLiveLease, ApiError> {
    let sql = format!(
        "select id, worker_id, state, generation, release_set_id, runtime_class, policy_digest,
         release_signature, lease_id, organization_id, workspace_id, thread_id,
         runner_session_id, lease_expires_at, lease_attestation_sha256
         from sterile_cells where lease_id = {} and tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2),
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .bind(&ctx.tenant_id)
        .fetch_optional(db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    let lease = lease_from_row(&row)?;
    let digest: String = row.try_get("lease_attestation_sha256")?;
    let valid = lease.lease_id == lease_id
        && lease.generation == generation
        && lease.organization_id == organization_id
        && lease.workspace_id == workspace_id
        && lease.thread_id == thread_id
        && lease.runner_session_id == runner_session_id
        && constant_time_eq(
            digest.as_bytes(),
            hash_worker_token(lease_attestation).as_bytes(),
        );
    if !valid {
        return Err(ApiError::conflict(
            "sterile-cell lease attestation does not match the live lease fence",
        ));
    }
    let state_value: String = row.try_get("state")?;
    if state_value != SterileCellState::Leased.as_db_str() || lease.expires_at <= Utc::now() {
        quarantine_lease(db, lease.cell_id).await?;
        return Err(ApiError::conflict("sterile-cell lease is no longer live"));
    }
    let worker_id: &str = row.try_get("worker_id")?;
    Ok(ValidatedLiveLease {
        lease,
        worker_id: WorkerId(parse_uuid(worker_id)?),
    })
}

#[utoipa::path(
    post,
    path = "/v1/sterile-cell-leases/{lease_id}/release",
    params(("lease_id" = Uuid, Path)),
    request_body = ReleaseSterileCellLeaseRequestV1,
    responses((status = 202, body = SterileCellLeaseStatusResponseV1), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope))
)]
pub(crate) async fn release_sterile_cell_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<ReleaseSterileCellLeaseRequestV1>,
) -> Result<(StatusCode, Json<SterileCellLeaseStatusResponseV1>), ApiError> {
    require_enabled(&state)?;
    let validated = validate_live_lease_fence(
        &state.db,
        &ctx,
        lease_id,
        request.generation,
        &request.organization_id,
        &request.workspace_id,
        &request.thread_id,
        &request.runner_session_id,
        &request.lease_attestation,
    )
    .await?;
    let cell_id = validated.lease.cell_id;
    let mut tx = state.db.pool.begin().await?;
    match crate::sterile_pool::enqueue_pool_stop_on_connection(
        &state.db,
        &mut tx,
        validated.worker_id,
        cell_id,
        lease_id,
        request.generation,
        request.disposition,
    )
    .await
    {
        Ok(true) => tx.commit().await?,
        Ok(false) => {
            tx.rollback().await?;
            return Err(ApiError::not_found("resource not found"));
        }
        Err(error) => {
            if error.status == StatusCode::CONFLICT {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            return Err(error);
        }
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(SterileCellLeaseStatusResponseV1 {
            ok: true,
            status: SterileCellLeaseStatusV1 {
                lease_id,
                cell_id,
                generation: request.generation,
                state: SterileCellState::Leased,
                disposition: None,
            },
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/v1/sterile-cell-leases/{lease_id}",
    params(("lease_id" = Uuid, Path)),
    responses((status = 200, body = SterileCellLeaseStatusResponseV1), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn get_sterile_cell_lease_status(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
) -> Result<Json<SterileCellLeaseStatusResponseV1>, ApiError> {
    require_enabled(&state)?;
    let sql = format!(
        "select id, generation, state, disposition from sterile_cells
         where lease_id = {} and tenant_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .bind(&ctx.tenant_id)
        .fetch_optional(state.db.read_pool())
        .await?
        .ok_or_else(|| ApiError::not_found("resource not found"))?;
    let state_value: &str = row.try_get("state")?;
    let disposition: Option<String> = row.try_get("disposition")?;
    Ok(Json(SterileCellLeaseStatusResponseV1 {
        ok: true,
        status: SterileCellLeaseStatusV1 {
            lease_id,
            cell_id: SterileCellId(parse_uuid(row.try_get("id")?)?),
            generation: u64::try_from(row.try_get::<i64, _>("generation")?)
                .map_err(|_| ApiError::internal("invalid sterile-cell generation"))?,
            state: SterileCellState::parse_db_str(state_value)
                .map_err(|error| ApiError::internal(error.to_string()))?,
            disposition: disposition
                .map(|value| SterileCellDisposition::parse_db_str(&value))
                .transpose()
                .map_err(|error| ApiError::internal(error.to_string()))?,
        },
    }))
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
    if crate::sterile_pool::sandbox_has_pool_membership(&state.db, SandboxId(cell_id.0)).await? {
        return Err(ApiError::conflict(
            "pool-created cells must be released before provider-confirmed destruction",
        ));
    }
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

#[utoipa::path(
    post,
    path = "/v1/workers/{worker_id}/sterile-cells/{cell_id}/release",
    params(("worker_id" = Uuid, Path), ("cell_id" = Uuid, Path)),
    request_body = DestroySterileCellRequestV1,
    responses((status = 202, body = SterileCellResponseV1), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope))
)]
pub(crate) async fn release_sterile_pool_cell(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((worker_id, cell_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<DestroySterileCellRequestV1>,
) -> Result<(StatusCode, Json<SterileCellResponseV1>), ApiError> {
    require_enabled(&state)?;
    let worker_id = WorkerId(worker_id);
    let cell_id = SterileCellId(cell_id);
    ensure_worker_scope(&ctx, worker_id)?;
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let current = fetch_worker_cell(&state.db, worker_id, cell_id, &ctx.tenant_id).await?;
    if current.state != SterileCellState::Leased {
        return Err(ApiError::conflict(
            "only a live leased pool cell can be released",
        ));
    }
    let mut tx = state.db.pool.begin().await?;
    match crate::sterile_pool::enqueue_pool_stop_on_connection(
        &state.db,
        &mut tx,
        worker_id,
        cell_id,
        request.lease_id,
        request.generation,
        request.disposition,
    )
    .await
    {
        Ok(true) => {
            tx.commit().await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(SterileCellResponseV1 {
                    ok: true,
                    cell: current,
                }),
            ))
        }
        Ok(false) => {
            tx.rollback().await?;
            Err(ApiError::not_found("resource not found"))
        }
        Err(error) => {
            if error.status == StatusCode::CONFLICT {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            Err(error)
        }
    }
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
         where state = '{state}' and {expiry_column} is not null and {expiry_column} <= {}
           and not exists (
             select 1 from sterile_pool_memberships p where p.sandbox_id = sterile_cells.id
           )",
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
