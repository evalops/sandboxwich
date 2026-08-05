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
    if let Err(error) = record_observation(
        &state,
        &ctx.tenant_id,
        outcome,
        reason,
        started.elapsed().as_millis(),
    )
    .await
    {
        tracing::warn!(error = ?error, outcome, reason, "maestro_activation_metric_write_failed");
    }
    result.map(Json)
}

async fn validate_maestro_activation_inner(
    state: &AppState,
    tenant_id: &str,
    path_sandbox_id: Uuid,
    request: MaestroHostedRunnerActivationValidationRequest,
) -> Result<MaestroHostedRunnerActivationValidationResponse, ApiError> {
    if request.sandbox_id.0 != path_sandbox_id {
        return Err(ApiError::conflict_code(
            BINDING_MISMATCH,
            "Maestro activation sandbox does not match the request path",
        ));
    }
    let digest = tuple_sha256(&request)?;
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
    let locked = sqlx::query(&lock_sql)
        .bind(tenant_id)
        .bind(request.sandbox_id.to_string())
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .execute(&mut *transaction)
        .await?;
    if locked.rows_affected() != 1 {
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
        .bind(request.sandbox_id.to_string())
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
        .bind(request.sandbox_id.to_string())
        .bind(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME)
        .execute(&mut *transaction)
        .await?;
    let worker_lock_sql = format!(
        "update workers set labels = labels
         where id = (select worker_id from sandbox_placements where sandbox_id = {})",
        state.db.placeholder(1),
    );
    sqlx::query(&worker_lock_sql)
        .bind(request.sandbox_id.to_string())
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
        .bind(request.activation_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
    if let Some(row) = &existing
        && row.try_get::<String, _>("tuple_sha256")? != digest
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
        request.sandbox_id,
    )
    .await
    .map_err(classify_live_error)?;
    if !binding_matches(&request, &live) {
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
    if Utc::now().timestamp() >= live.lease_expires_at_epoch_seconds {
        return Err(ApiError::conflict_code(
            EXPIRED_LEASE,
            "Maestro activation lease is expired",
        ));
    }

    if let Some(row) = existing {
        let validated_at = parse_timestamp(&row.try_get::<String, _>("validated_at")?)?;
        transaction.commit().await?;
        return Ok(MaestroHostedRunnerActivationValidationResponse {
            ok: true,
            activation_id: request.activation_id,
            tuple_sha256: digest,
            validated_at,
            replayed: true,
        });
    }

    let validated_at = Utc::now();
    let insert_sql = format!(
        "insert into maestro_activation_validations
         (tenant_id, activation_id, sandbox_id, tuple_sha256, binding_json, validated_at)
         values ({})",
        state.db.placeholders(6)
    );
    sqlx::query(&insert_sql)
        .bind(tenant_id)
        .bind(request.activation_id.to_string())
        .bind(request.sandbox_id.to_string())
        .bind(&digest)
        .bind(serde_json::to_string(&request)?)
        .bind(validated_at.to_rfc3339())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(MaestroHostedRunnerActivationValidationResponse {
        ok: true,
        activation_id: request.activation_id,
        tuple_sha256: digest,
        validated_at,
        replayed: false,
    })
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

async fn record_observation(
    state: &AppState,
    tenant_id: &str,
    outcome: &str,
    reason: &str,
    elapsed_ms: u128,
) -> Result<(), ApiError> {
    const BUCKETS_MS: [u128; 8] = [
        1_000, 5_000, 15_000, 30_000, 60_000, 120_000, 300_000, 900_000,
    ];
    let elapsed_ms = i64::try_from(elapsed_ms).unwrap_or(i64::MAX);
    let buckets = BUCKETS_MS.map(|limit| i64::from((elapsed_ms as u128) <= limit));
    let sql = format!(
        "insert into maestro_activation_validation_metrics
         (tenant_id, outcome, reason, sample_count, sum_ms, b0, b1, b2, b3, b4, b5, b6, b7)
         values ({})
         on conflict (tenant_id, outcome, reason) do update set
           sample_count = maestro_activation_validation_metrics.sample_count + excluded.sample_count,
           sum_ms = maestro_activation_validation_metrics.sum_ms + excluded.sum_ms,
           b0 = maestro_activation_validation_metrics.b0 + excluded.b0,
           b1 = maestro_activation_validation_metrics.b1 + excluded.b1,
           b2 = maestro_activation_validation_metrics.b2 + excluded.b2,
           b3 = maestro_activation_validation_metrics.b3 + excluded.b3,
           b4 = maestro_activation_validation_metrics.b4 + excluded.b4,
           b5 = maestro_activation_validation_metrics.b5 + excluded.b5,
           b6 = maestro_activation_validation_metrics.b6 + excluded.b6,
           b7 = maestro_activation_validation_metrics.b7 + excluded.b7",
        state.db.placeholders(13)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(outcome)
        .bind(reason)
        .bind(1_i64)
        .bind(elapsed_ms)
        .bind(buckets[0])
        .bind(buckets[1])
        .bind(buckets[2])
        .bind(buckets[3])
        .bind(buckets[4])
        .bind(buckets[5])
        .bind(buckets[6])
        .bind(buckets[7])
        .execute(&state.db.pool)
        .await?;
    Ok(())
}
