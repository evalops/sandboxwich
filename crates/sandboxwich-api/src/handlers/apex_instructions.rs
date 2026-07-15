use crate::auth::{ensure_lease_worker_scope, ensure_sandbox_tenant};
use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::jobs::{add_provision_spec_to_payload, insert_job_on_connection};
use crate::state::{
    APEX_INSTRUCTION_READ_TIMEOUT, ApexInstructionDelivery, ApexWaiterGuard, ApexWaiterInsertError,
    AppState, TenantContext,
};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::sync::oneshot;
use uuid::Uuid;

const APEX_INSTRUCTION_MAX_BYTES: u64 = 1024 * 1024;
const APEX_INSTRUCTION_READ_TTL_SECONDS: i64 = 35;

#[derive(Debug)]
struct InstructionReadRow {
    request_id: Uuid,
    sandbox_id: SandboxId,
    lease_id: Option<Uuid>,
    lease_attempt: u64,
    provider_apply_id: Uuid,
    expected_sha256: String,
    expected_byte_count: u64,
    claim_lease_generation: u64,
    state: String,
    expires_at: DateTime<Utc>,
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::internal(format!("invalid {field} in database")))
}

fn parse_u64(value: i64, field: &'static str) -> Result<u64, ApiError> {
    u64::try_from(value).map_err(|_| ApiError::internal(format!("invalid {field} in database")))
}

fn read_row(row: sqlx::any::AnyRow) -> Result<InstructionReadRow, ApiError> {
    let lease_id: Option<String> = row.try_get("lease_id")?;
    let expires_at: String = row.try_get("expires_at")?;
    Ok(InstructionReadRow {
        request_id: parse_uuid(&row.try_get::<String, _>("request_id")?, "request_id")?,
        sandbox_id: SandboxId(parse_uuid(
            &row.try_get::<String, _>("sandbox_id")?,
            "sandbox_id",
        )?),
        lease_id: lease_id
            .as_deref()
            .map(|value| parse_uuid(value, "lease_id"))
            .transpose()?,
        lease_attempt: parse_u64(row.try_get("lease_attempt")?, "lease_attempt")?,
        provider_apply_id: parse_uuid(
            &row.try_get::<String, _>("provider_apply_id")?,
            "provider_apply_id",
        )?,
        expected_sha256: row.try_get("expected_sha256")?,
        expected_byte_count: parse_u64(row.try_get("expected_byte_count")?, "expected_byte_count")?,
        claim_lease_generation: parse_u64(
            row.try_get("claim_lease_generation")?,
            "claim_lease_generation",
        )?,
        state: row.try_get("state")?,
        expires_at: DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|_| ApiError::internal("invalid instruction expiry in database"))?
            .with_timezone(&Utc),
    })
}

async fn fetch_read_by_key(
    db: &Database,
    tenant_id: &str,
    idempotency_key: &str,
) -> Result<Option<InstructionReadRow>, ApiError> {
    let sql = format!(
        "select request_id, sandbox_id, lease_id, lease_attempt, provider_apply_id,
                expected_sha256, expected_byte_count, claim_lease_generation, state, expires_at
         from apex_instruction_reads where tenant_id = {} and idempotency_key = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(idempotency_key)
        .fetch_optional(&db.pool)
        .await?
        .map(read_row)
        .transpose()
}

fn unavailable_response(row: InstructionReadRow) -> ApexTaskInstructionsReadResponse {
    ApexTaskInstructionsReadResponse {
        ok: true,
        request_id: row.request_id,
        sandbox_id: row.sandbox_id,
        lease_id: row.lease_id,
        lease_attempt: row.lease_attempt,
        provider_apply_id: row.provider_apply_id,
        sha256: row.expected_sha256,
        byte_count: row.expected_byte_count,
        output_base64: None,
        output_unavailable: true,
    }
}

fn validate_request(request: &ApexTaskInstructionsReadRequest) -> Result<(), ApiError> {
    if request.expected_sha256.len() != 64
        || !request
            .expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ApiError::bad_request(
            "expectedSha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    if !(1..=APEX_INSTRUCTION_MAX_BYTES).contains(&request.expected_byte_count) {
        return Err(ApiError::bad_request(
            "expectedByteCount must be between 1 and 1048576",
        ));
    }
    if request.claim_lease_generation == 0 {
        return Err(ApiError::bad_request(
            "claimLeaseGeneration must be greater than zero",
        ));
    }
    Ok(())
}

fn decode_callback_output(
    encoded: &str,
    expected_sha256: &str,
    expected_byte_count: u64,
    reported_sha256: &str,
    reported_byte_count: u64,
) -> Result<Vec<u8>, ApiError> {
    if encoded.len() > ((APEX_INSTRUCTION_MAX_BYTES as usize).div_ceil(3) * 4) + 4 {
        return Err(ApiError::payload_too_large(
            "apex_instruction_too_large",
            "instruction callback exceeds 1048576 bytes",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ApiError::bad_request("instruction callback output is invalid"))?;
    let observed_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let observed_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if bytes.len() > APEX_INSTRUCTION_MAX_BYTES as usize
        || observed_count != expected_byte_count
        || reported_byte_count != expected_byte_count
        || observed_sha256 != expected_sha256
        || reported_sha256 != expected_sha256
    {
        return Err(ApiError::conflict("instruction callback output mismatch"));
    }
    Ok(bytes)
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get("idempotency-key")
        .ok_or_else(|| ApiError::bad_request("idempotency-key is required"))?
        .to_str()
        .map_err(|_| ApiError::bad_request("idempotency-key is invalid"))?;
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request("idempotency-key is invalid"));
    }
    Ok(value)
}

async fn mark_unavailable(db: &Database, request_id: Uuid) -> Result<(), ApiError> {
    let sql = format!(
        "update apex_instruction_reads set state = 'unavailable', completed_at = {}
         where request_id = {} and state in ('pending', 'completed')",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&sql)
        .bind(Utc::now().to_rfc3339())
        .bind(request_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(crate) async fn read_apex_task_instructions(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ApexTaskInstructionsReadRequest>,
) -> Result<Json<ApexTaskInstructionsReadResponse>, ApiError> {
    validate_request(&request)?;
    let key = idempotency_key(&headers)?.to_owned();
    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    if sandbox.runtime_profile != SandboxRuntimeProfile::ApexTrustedSupervisorV1
        || sandbox.state != SandboxState::Ready
    {
        return Err(ApiError::conflict(
            "APEX instruction reads require a ready trusted-supervisor sandbox",
        ));
    }
    if let Some(row) = fetch_read_by_key(&state.db, &ctx.tenant_id, &key).await? {
        if row.sandbox_id != sandbox_id
            || row.expected_sha256 != request.expected_sha256
            || row.expected_byte_count != request.expected_byte_count
            || row.claim_lease_generation != request.claim_lease_generation
        {
            return Err(ApiError::conflict("instruction read idempotency conflict"));
        }
        if row.state == "pending" && row.expires_at > Utc::now() {
            return Err(ApiError::conflict(
                "instruction read is already in progress",
            ));
        }
        if row.state == "pending" {
            mark_unavailable(&state.db, row.request_id).await?;
        }
        return Ok(Json(unavailable_response(row)));
    }

    let callback_base = state.apex_callback_base_url.as_deref().ok_or_else(|| {
        ApiError::not_implemented(
            "apex_instruction_callback_unconfigured",
            "APEX instruction callback URL is not configured on this API instance",
        )
    })?;
    let placement_sql = format!(
        "select worker_id, generation from sandbox_placements where sandbox_id = {}",
        state.db.placeholder(1)
    );
    let placement = sqlx::query(&placement_sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(|| ApiError::conflict("sandbox provider placement is unavailable"))?;
    let worker_id = parse_uuid(&placement.try_get::<String, _>("worker_id")?, "worker_id")?;
    let placement_generation = parse_u64(
        placement.try_get("generation")?,
        "sandbox placement generation",
    )?;

    let request_id = Uuid::now_v7();
    let provider_apply_id = Uuid::now_v7();
    let callback_nonce = Uuid::now_v7();
    let job_id = JobId::new();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(APEX_INSTRUCTION_READ_TTL_SECONDS);
    let callback_url = format!(
        "{}/v1/workers/{worker_id}/apex-instruction-callbacks/{callback_nonce}",
        callback_base.trim_end_matches('/')
    );
    let mut job = Job {
        id: job_id,
        tenant_id: ctx.tenant_id.clone(),
        kind: JobKind::ApexTaskInstructions,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "requestId": request_id,
            "providerApplyId": provider_apply_id,
            "callbackNonce": callback_nonce,
            "callbackUrl": callback_url,
            "targetWorkerId": worker_id,
            "targetPlacementGeneration": placement_generation,
            "expectedSha256": request.expected_sha256,
            "expectedByteCount": request.expected_byte_count,
            "claimLeaseGeneration": request.claim_lease_generation,
        }),
        required_capability: WorkerCapability::ApexTaskInstructions,
        required_execution_class: sandbox.execution_class.clone(),
        priority: 100,
        attempts: 0,
        // The fixed provider read is a one-time capability. Once claimed it
        // must become terminal on callback failure, worker loss, or expiry;
        // only a fresh tenant claim key may execute the reader again.
        max_attempts: 1,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    add_provision_spec_to_payload(&mut job, &sandbox)?;
    let (sender, receiver) = oneshot::channel();
    match state.apex_waiters.try_insert(callback_nonce, sender) {
        Ok(()) => {}
        Err(ApexWaiterInsertError::Full) => {
            return Err(ApiError::too_many_requests(
                "apex_instruction_waiters_full",
                "this API instance has too many concurrent instruction reads",
            ));
        }
        Err(ApexWaiterInsertError::Duplicate) => {
            return Err(ApiError::internal("instruction callback nonce collision"));
        }
    }
    let _guard = ApexWaiterGuard::new(state.apex_waiters.clone(), callback_nonce);

    let mut tx = state.db.pool.begin().await?;
    let insert_read_sql = format!(
        "insert into apex_instruction_reads
         (id, tenant_id, sandbox_id, job_id, idempotency_key, callback_nonce,
          claim_lease_generation, request_id, lease_id, lease_attempt, provider_apply_id,
          expected_sha256, expected_byte_count, observed_sha256, observed_byte_count,
          state, created_at, completed_at, expires_at) values ({})",
        state.db.placeholders(19)
    );
    sqlx::query(&insert_read_sql)
        .bind(Uuid::now_v7().to_string())
        .bind(&ctx.tenant_id)
        .bind(sandbox_id.to_string())
        .bind(job_id.to_string())
        .bind(&key)
        .bind(callback_nonce.to_string())
        .bind(
            i64::try_from(request.claim_lease_generation)
                .map_err(|_| ApiError::bad_request("claimLeaseGeneration is too large"))?,
        )
        .bind(request_id.to_string())
        .bind(Option::<String>::None)
        .bind(0_i64)
        .bind(provider_apply_id.to_string())
        .bind(&request.expected_sha256)
        .bind(i64::try_from(request.expected_byte_count).expect("1 MiB fits i64"))
        .bind(Option::<String>::None)
        .bind(Option::<i64>::None)
        .bind("pending")
        .bind(now.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(expires_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    let delivery = match tokio::time::timeout(APEX_INSTRUCTION_READ_TIMEOUT, receiver).await {
        Ok(Ok(delivery)) => delivery,
        Ok(Err(_)) | Err(_) => {
            mark_unavailable(&state.db, request_id).await?;
            let row = fetch_read_by_key(&state.db, &ctx.tenant_id, &key)
                .await?
                .ok_or_else(|| ApiError::internal("instruction read disappeared"))?;
            return Ok(Json(unavailable_response(row)));
        }
    };
    Ok(Json(ApexTaskInstructionsReadResponse {
        ok: true,
        request_id: delivery.request_id,
        sandbox_id: delivery.sandbox_id,
        lease_id: Some(delivery.lease_id),
        lease_attempt: delivery.lease_attempt,
        provider_apply_id: delivery.provider_apply_id,
        sha256: delivery.sha256,
        byte_count: u64::try_from(delivery.bytes.len()).expect("bounded output fits u64"),
        output_base64: Some(base64::engine::general_purpose::STANDARD.encode(delivery.bytes)),
        output_unavailable: false,
    }))
}

pub(crate) async fn deliver_apex_task_instructions(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((worker_id, callback_nonce)): Path<(Uuid, Uuid)>,
    Json(request): Json<ApexTaskInstructionsCallbackRequest>,
) -> Result<Json<ApexTaskInstructionsCallbackResponse>, ApiError> {
    let lease = ensure_lease_worker_scope(&state.db, LeaseId(request.lease_id), &ctx).await?;
    if lease.worker_id.0 != worker_id || lease.status != LeaseStatus::Active {
        return Err(ApiError::not_found("instruction callback not found"));
    }
    if lease.job.kind != JobKind::ApexTaskInstructions
        || lease.attempt <= 0
        || u64::try_from(lease.attempt).ok() != Some(request.lease_attempt)
        || lease
            .job
            .payload
            .get("requestId")
            .and_then(serde_json::Value::as_str)
            != Some(request.request_id.to_string().as_str())
        || lease
            .job
            .payload
            .get("providerApplyId")
            .and_then(serde_json::Value::as_str)
            != Some(request.provider_apply_id.to_string().as_str())
        || lease
            .job
            .payload
            .get("callbackNonce")
            .and_then(serde_json::Value::as_str)
            != Some(callback_nonce.to_string().as_str())
    {
        return Err(ApiError::not_found("instruction callback not found"));
    }
    let expected_sha256 = lease
        .job
        .payload
        .get("expectedSha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::internal("instruction job digest is missing"))?;
    let expected_byte_count = lease
        .job
        .payload
        .get("expectedByteCount")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ApiError::internal("instruction job byte count is missing"))?;
    let encoded = request
        .output_base64
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("instruction callback output is required"))?;
    let bytes = decode_callback_output(
        encoded,
        expected_sha256,
        expected_byte_count,
        &request.sha256,
        request.byte_count,
    )?;
    let observed_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let observed_sha256 = format!("{:x}", Sha256::digest(&bytes));

    let sender = state.apex_waiters.take(&callback_nonce);
    let output_unavailable = sender.is_none();
    let next_state = if output_unavailable {
        "unavailable"
    } else {
        "completed"
    };
    let sql = format!(
        "update apex_instruction_reads
         set lease_id = {}, lease_attempt = {}, observed_sha256 = {}, observed_byte_count = {},
             state = {}, completed_at = {}
         where request_id = {} and callback_nonce = {}
           and (state = 'pending' or (state = 'unavailable' and lease_id is null))",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6),
        state.db.placeholder(7),
        state.db.placeholder(8),
    );
    let updated = sqlx::query(&sql)
        .bind(request.lease_id.to_string())
        .bind(i64::try_from(request.lease_attempt).map_err(|_| {
            ApiError::bad_request("instruction callback lease attempt is too large")
        })?)
        .bind(&observed_sha256)
        .bind(i64::try_from(observed_count).expect("1 MiB fits i64"))
        .bind(next_state)
        .bind(Utc::now().to_rfc3339())
        .bind(request.request_id.to_string())
        .bind(callback_nonce.to_string())
        .execute(&state.db.pool)
        .await?;
    if updated.rows_affected() == 0 {
        let replay_sql = format!(
            "select lease_id, lease_attempt, provider_apply_id, observed_sha256,
                    observed_byte_count, state
             from apex_instruction_reads
             where request_id = {} and callback_nonce = {}",
            state.db.placeholder(1),
            state.db.placeholder(2),
        );
        let replay = sqlx::query(&replay_sql)
            .bind(request.request_id.to_string())
            .bind(callback_nonce.to_string())
            .fetch_optional(&state.db.pool)
            .await?
            .ok_or_else(|| ApiError::not_found("instruction callback not found"))?;
        let persisted_lease_id: Option<String> = replay.try_get("lease_id")?;
        let persisted_attempt: i64 = replay.try_get("lease_attempt")?;
        let persisted_provider_apply_id: String = replay.try_get("provider_apply_id")?;
        let persisted_sha256: Option<String> = replay.try_get("observed_sha256")?;
        let persisted_count: Option<i64> = replay.try_get("observed_byte_count")?;
        let persisted_state: String = replay.try_get("state")?;
        let exact_replay = persisted_lease_id.as_deref()
            == Some(request.lease_id.to_string().as_str())
            && u64::try_from(persisted_attempt).ok() == Some(request.lease_attempt)
            && persisted_provider_apply_id == request.provider_apply_id.to_string()
            && persisted_sha256.as_deref() == Some(observed_sha256.as_str())
            && persisted_count.and_then(|value| u64::try_from(value).ok()) == Some(observed_count)
            && matches!(persisted_state.as_str(), "completed" | "unavailable");
        if !exact_replay {
            return Err(ApiError::not_found("instruction callback not found"));
        }
        return Ok(Json(ApexTaskInstructionsCallbackResponse {
            ok: true,
            output_unavailable: persisted_state == "unavailable",
        }));
    }
    if let Some(sender) = sender {
        let delivery = ApexInstructionDelivery {
            bytes,
            sha256: observed_sha256,
            request_id: request.request_id,
            sandbox_id: sandboxwich_core::SandboxId(
                lease
                    .job
                    .payload
                    .get("sandboxId")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or_else(|| ApiError::internal("instruction sandbox lineage is invalid"))?,
            ),
            lease_id: request.lease_id,
            lease_attempt: request.lease_attempt,
            provider_apply_id: request.provider_apply_id,
        };
        if sender.send(delivery).is_err() {
            mark_unavailable(&state.db, request.request_id).await?;
            return Ok(Json(ApexTaskInstructionsCallbackResponse {
                ok: true,
                output_unavailable: true,
            }));
        }
    }
    Ok(Json(ApexTaskInstructionsCallbackResponse {
        ok: true,
        output_unavailable,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::db::{connect_database, migrate_database};
    use crate::handlers::jobs::insert_job;
    use crate::handlers::jobs::{fetch_job, try_claim_job};
    use crate::handlers::leases::{
        complete_lease_in_transaction, expire_lease_if_still_active, fail_lease_in_transaction,
        insert_lease_on_connection,
    };
    use crate::handlers::sandboxes::{insert_sandbox, sandbox_id_from_job};
    use crate::handlers::workers::insert_worker;
    use crate::routes::APEX_CALLBACK_BODY_LIMIT_BYTES;
    use crate::state::{ApexInstructionWaiters, Principal};
    use std::collections::BTreeMap;
    use std::time::Duration;

    const TEST_TENANT_TOKEN: &str = "tenant-token";
    const TEST_WORKER_TOKEN: &str = "sbw_wtok_test-worker-token";

    #[test]
    fn exact_one_mib_callback_fits_wire_limit_and_decodes_exactly() {
        let bytes = vec![b'x'; APEX_INSTRUCTION_MAX_BYTES as usize];
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let request = ApexTaskInstructionsCallbackRequest {
            request_id: Uuid::nil(),
            lease_id: Uuid::nil(),
            lease_attempt: 1,
            provider_apply_id: Uuid::nil(),
            sha256: digest.clone(),
            byte_count: APEX_INSTRUCTION_MAX_BYTES,
            output_base64: Some(encoded.clone()),
        };
        assert!(serde_json::to_vec(&request).unwrap().len() <= APEX_CALLBACK_BODY_LIMIT_BYTES);
        assert_eq!(
            decode_callback_output(
                &encoded,
                &digest,
                APEX_INSTRUCTION_MAX_BYTES,
                &digest,
                APEX_INSTRUCTION_MAX_BYTES,
            )
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn decoded_callback_over_one_mib_is_rejected() {
        let bytes = vec![b'x'; APEX_INSTRUCTION_MAX_BYTES as usize + 1];
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let error = decode_callback_output(
            &encoded,
            &digest,
            APEX_INSTRUCTION_MAX_BYTES + 1,
            &digest,
            APEX_INSTRUCTION_MAX_BYTES + 1,
        )
        .unwrap_err();
        assert!(matches!(
            error.status,
            axum::http::StatusCode::PAYLOAD_TOO_LARGE | axum::http::StatusCode::CONFLICT
        ));
    }

    async fn callback_fixture(
        expires_at: DateTime<Utc>,
    ) -> (
        AppState,
        TenantContext,
        Worker,
        JobLease,
        Uuid,
        Uuid,
        Uuid,
        Vec<u8>,
    ) {
        let path =
            std::env::temp_dir().join(format!("sandboxwich-apex-callback-{}.db", Uuid::now_v7()));
        let db = connect_database(&format!("sqlite://{}", path.display()), 1)
            .await
            .unwrap();
        migrate_database(&db).await.unwrap();
        let now = Utc::now();
        let sandbox = Sandbox {
            id: SandboxId::new(),
            tenant_id: "tenant-apex".into(),
            name: "apex".into(),
            state: SandboxState::Ready,
            template: format!("image@sha256:{}", "a".repeat(64)),
            memory_limit: MemoryLimit::FourG,
            network_egress: NetworkEgress::DenyAll,
            workspace_mode: WorkspaceMode::Persistent,
            runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
            execution_class: ExecutionClass::SandboxedContainer,
            created_at: now,
            updated_at: now,
            ttl_seconds: None,
            parent_snapshot_id: None,
        };
        insert_sandbox(&db, &sandbox).await.unwrap();
        let worker = Worker {
            id: WorkerId::new(),
            tenant_id: sandbox.tenant_id.clone(),
            name: "worker".into(),
            status: WorkerStatus::Online,
            provider: "kubernetes".into(),
            capabilities: vec![WorkerCapability::ApexTaskInstructions],
            max_concurrent_jobs: 4,
            labels: BTreeMap::new(),
            registered_at: now,
            last_heartbeat_at: Some(now),
        };
        insert_worker(
            &db,
            &worker,
            &crate::auth::hash_worker_token(TEST_WORKER_TOKEN),
        )
        .await
        .unwrap();
        sqlx::query(
            "insert into sandbox_placements
             (sandbox_id, worker_id, provider, cluster, generation, created_at, updated_at)
             values (?, ?, 'kubernetes', 'test', 1, ?, ?)",
        )
        .bind(sandbox.id.to_string())
        .bind(worker.id.to_string())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();
        let request_id = Uuid::now_v7();
        let provider_apply_id = Uuid::now_v7();
        let callback_nonce = Uuid::now_v7();
        let bytes = b"PRIVATE_SENTINEL".to_vec();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let job = Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id.clone(),
            kind: JobKind::ApexTaskInstructions,
            status: JobStatus::Leased,
            payload: json!({
                "sandboxId": sandbox.id,
                "requestId": request_id,
                "providerApplyId": provider_apply_id,
                "callbackNonce": callback_nonce,
                "expectedSha256": digest,
                "expectedByteCount": bytes.len(),
                "claimLeaseGeneration": 3,
            }),
            required_capability: WorkerCapability::ApexTaskInstructions,
            required_execution_class: ExecutionClass::SandboxedContainer,
            priority: 100,
            attempts: 1,
            max_attempts: 3,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        };
        insert_job(&db, &job).await.unwrap();
        let lease = JobLease {
            id: LeaseId::new(),
            job_id: job.id,
            worker_id: worker.id,
            status: LeaseStatus::Active,
            attempt: 1,
            leased_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            completed_at: None,
            error: None,
            required_execution_class: ExecutionClass::SandboxedContainer,
            job,
        };
        let mut tx = db.pool.begin().await.unwrap();
        insert_lease_on_connection(&db, &mut tx, &lease)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sqlx::query(
            "insert into apex_instruction_reads
             (id, tenant_id, sandbox_id, job_id, idempotency_key, callback_nonce,
              claim_lease_generation, request_id, lease_id, lease_attempt, provider_apply_id,
              expected_sha256, expected_byte_count, observed_sha256, observed_byte_count,
              state, created_at, completed_at, expires_at)
             values (?, ?, ?, ?, ?, ?, 3, ?, NULL, 0, ?, ?, ?, NULL, NULL, 'pending', ?, NULL, ?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(&sandbox.tenant_id)
        .bind(sandbox.id.to_string())
        .bind(lease.job_id.to_string())
        .bind("claim-3")
        .bind(callback_nonce.to_string())
        .bind(request_id.to_string())
        .bind(provider_apply_id.to_string())
        .bind(&digest)
        .bind(i64::try_from(bytes.len()).unwrap())
        .bind(now.to_rfc3339())
        .bind(expires_at.to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();
        let state = AppState {
            db,
            auth: AuthConfig {
                shared_token: Some(TEST_TENANT_TOKEN.into()),
                tenant_tokens: Vec::new(),
                operator_token: None,
                allow_insecure_no_auth: true,
            },
            default_tenant_id: sandbox.tenant_id.clone(),
            apex_callback_base_url: Some("http://127.0.0.1:3217".into()),
            // An empty fresh registry models restart or a callback routed to
            // the wrong API replica while durable lineage survives.
            apex_waiters: ApexInstructionWaiters::default(),
        };
        let ctx = TenantContext {
            tenant_id: sandbox.tenant_id,
            principal: Principal::Worker(worker.id),
        };
        (
            state,
            ctx,
            worker,
            lease,
            request_id,
            provider_apply_id,
            callback_nonce,
            bytes,
        )
    }

    #[tokio::test]
    async fn wrong_instance_or_restart_never_replays_callback_body() {
        let (state, ctx, worker, lease, request_id, provider_apply_id, nonce, bytes) =
            callback_fixture(Utc::now() + chrono::Duration::seconds(35)).await;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let request = ApexTaskInstructionsCallbackRequest {
            request_id,
            lease_id: lease.id.0,
            lease_attempt: 1,
            provider_apply_id,
            sha256: digest,
            byte_count: u64::try_from(bytes.len()).unwrap(),
            output_base64: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        };
        let response = deliver_apex_task_instructions(
            State(state.clone()),
            Extension(ctx.clone()),
            Path((worker.id.0, nonce)),
            Json(request.clone()),
        )
        .await
        .unwrap()
        .0;
        assert!(response.output_unavailable);
        let replay = deliver_apex_task_instructions(
            State(state.clone()),
            Extension(ctx),
            Path((worker.id.0, nonce)),
            Json(request),
        )
        .await
        .unwrap()
        .0;
        assert!(replay.output_unavailable);
        let row = sqlx::query("select state, observed_sha256, observed_byte_count from apex_instruction_reads where request_id = ?")
            .bind(request_id.to_string())
            .fetch_one(&state.db.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("state"), "unavailable");
        assert_eq!(
            row.get::<i64, _>("observed_byte_count"),
            i64::try_from(bytes.len()).unwrap()
        );
        assert!(
            !row.get::<String, _>("observed_sha256")
                .contains("PRIVATE_SENTINEL")
        );
        let payload = sqlx::query("select payload from jobs where id = ?")
            .bind(lease.job_id.to_string())
            .fetch_one(&state.db.pool)
            .await
            .unwrap()
            .get::<String, _>("payload");
        assert!(!payload.contains("PRIVATE_SENTINEL"));
    }

    #[tokio::test]
    async fn expired_read_returns_unavailable_without_new_job_or_waiter() {
        let (state, _ctx, _worker, lease, request_id, provider_apply_id, _nonce, bytes) =
            callback_fixture(Utc::now() - chrono::Duration::seconds(1)).await;
        let tenant_ctx = TenantContext {
            tenant_id: lease.job.tenant_id.clone(),
            principal: Principal::Tenant,
        };
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", "claim-3".parse().unwrap());
        let response = read_apex_task_instructions(
            State(state.clone()),
            Extension(tenant_ctx),
            Path(sandbox_id_from_job(&lease.job).unwrap().0),
            headers,
            Json(ApexTaskInstructionsReadRequest {
                expected_sha256: format!("{:x}", Sha256::digest(&bytes)),
                expected_byte_count: u64::try_from(bytes.len()).unwrap(),
                claim_lease_generation: 3,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.provider_apply_id, provider_apply_id);
        assert!(response.output_unavailable);
        assert!(response.output_base64.is_none());
        let jobs = sqlx::query("select count(*) as count from jobs")
            .fetch_one(&state.db.pool)
            .await
            .unwrap()
            .get::<i64, _>("count");
        assert_eq!(jobs, 1, "expired replay must not queue another read job");
    }

    async fn run_live_http_read(
        client: &reqwest::Client,
        base_url: &str,
        state: &AppState,
        worker: &Worker,
        sandbox_id: SandboxId,
        claim: (&str, u64),
        bytes: &[u8],
    ) -> (ApexTaskInstructionsReadResponse, Job, JobLease) {
        let (key, generation) = claim;
        let digest = format!("{:x}", Sha256::digest(bytes));
        let request = ApexTaskInstructionsReadRequest {
            expected_sha256: digest.clone(),
            expected_byte_count: u64::try_from(bytes.len()).unwrap(),
            claim_lease_generation: generation,
        };
        let public_client = client.clone();
        let public_url = format!("{base_url}/v1/sandboxes/{sandbox_id}/apex-task-instructions");
        let public_key = key.to_string();
        let public = tokio::spawn(async move {
            public_client
                .post(public_url)
                .bearer_auth(TEST_TENANT_TOKEN)
                .header("x-sandboxwich-tenant", "tenant-apex")
                .header("idempotency-key", public_key)
                .json(&request)
                .send()
                .await
                .unwrap()
        });

        let job_id = loop {
            let row = sqlx::query(
                "select job_id from apex_instruction_reads
                 where tenant_id = ? and idempotency_key = ?",
            )
            .bind("tenant-apex")
            .bind(key)
            .fetch_optional(&state.db.pool)
            .await
            .unwrap();
            if let Some(row) = row {
                break JobId(Uuid::parse_str(&row.get::<String, _>("job_id")).unwrap());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let job = fetch_job(&state.db, job_id).await.unwrap();
        let lease = try_claim_job(&state.db, worker, &job, Some(60), None)
            .await
            .unwrap()
            .unwrap();
        let callback_url = job
            .payload
            .get("callbackUrl")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        let callback = ApexTaskInstructionsCallbackRequest {
            request_id: Uuid::parse_str(job.payload["requestId"].as_str().unwrap()).unwrap(),
            lease_id: lease.id.0,
            lease_attempt: u64::try_from(lease.attempt).unwrap(),
            provider_apply_id: Uuid::parse_str(job.payload["providerApplyId"].as_str().unwrap())
                .unwrap(),
            sha256: digest,
            byte_count: u64::try_from(bytes.len()).unwrap(),
            output_base64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        };
        let callback_response = client
            .post(callback_url)
            .bearer_auth(TEST_WORKER_TOKEN)
            .header("x-sandboxwich-tenant", "tenant-apex")
            .json(&callback)
            .send()
            .await
            .unwrap();
        let callback_status = callback_response.status();
        let callback_body = callback_response.text().await.unwrap();
        assert!(
            callback_status.is_success(),
            "callback failed with {callback_status}: {callback_body}"
        );
        assert!(
            !serde_json::from_str::<ApexTaskInstructionsCallbackResponse>(&callback_body)
                .unwrap()
                .output_unavailable
        );
        let public_response = public.await.unwrap();
        assert!(public_response.status().is_success());
        (
            public_response
                .json::<ApexTaskInstructionsReadResponse>()
                .await
                .unwrap(),
            job,
            lease,
        )
    }

    #[tokio::test]
    async fn actual_router_live_read_is_ephemeral_replay_safe_and_fresh_key_reacquires() {
        let (mut state, _ctx, worker, seeded_lease, _, _, _, _) =
            callback_fixture(Utc::now() + chrono::Duration::seconds(35)).await;
        let sandbox_id = sandbox_id_from_job(&seeded_lease.job).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        state.apex_callback_base_url = Some(base_url.clone());
        let router = crate::routes::app(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let bytes = b"PRIVATE_SENTINEL";

        let (first, first_job, first_lease) = run_live_http_read(
            &client,
            &base_url,
            &state,
            &worker,
            sandbox_id,
            ("live-claim-4", 4),
            bytes,
        )
        .await;
        assert!(!first.output_unavailable);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(first.output_base64.as_deref().unwrap())
                .unwrap(),
            bytes
        );
        assert_eq!(
            first_job.max_attempts, 1,
            "a private one-time read must never be leased twice"
        );

        // Model a successful first callback whose HTTP response was lost. The
        // exact authenticated replay must acknowledge the already-delivered
        // state so the worker can complete this lease without rereading.
        let callback_replay = ApexTaskInstructionsCallbackRequest {
            request_id: first.request_id,
            lease_id: first_lease.id.0,
            lease_attempt: u64::try_from(first_lease.attempt).unwrap(),
            provider_apply_id: first.provider_apply_id,
            sha256: first.sha256.clone(),
            byte_count: first.byte_count,
            output_base64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        };
        let callback_replay = client
            .post(first_job.payload["callbackUrl"].as_str().unwrap())
            .bearer_auth(TEST_WORKER_TOKEN)
            .header("x-sandboxwich-tenant", "tenant-apex")
            .json(&callback_replay)
            .send()
            .await
            .unwrap();
        assert!(callback_replay.status().is_success());
        let callback_replay = callback_replay
            .json::<ApexTaskInstructionsCallbackResponse>()
            .await
            .unwrap();
        assert!(
            !callback_replay.output_unavailable,
            "an exact callback replay must return the persisted successful acknowledgement"
        );
        complete_lease_in_transaction(
            &state.db,
            first_lease.id,
            WorkerJobResult::ApexTaskInstructions {
                request_id: first.request_id,
                sandbox_id,
                lease_id: first_lease.id,
                lease_attempt: first_lease.attempt,
                provider_apply_id: first.provider_apply_id,
                sha256: first.sha256.clone(),
                byte_count: first.byte_count,
                output_unavailable: callback_replay.output_unavailable,
            },
        )
        .await
        .unwrap();

        let replay = client
            .post(format!(
                "{base_url}/v1/sandboxes/{sandbox_id}/apex-task-instructions"
            ))
            .bearer_auth(TEST_TENANT_TOKEN)
            .header("x-sandboxwich-tenant", "tenant-apex")
            .header("idempotency-key", "live-claim-4")
            .json(&ApexTaskInstructionsReadRequest {
                expected_sha256: format!("{:x}", Sha256::digest(bytes)),
                expected_byte_count: u64::try_from(bytes.len()).unwrap(),
                claim_lease_generation: 4,
            })
            .send()
            .await
            .unwrap();
        assert!(replay.status().is_success());
        let replay = replay
            .json::<ApexTaskInstructionsReadResponse>()
            .await
            .unwrap();
        assert!(replay.output_unavailable);
        assert!(replay.output_base64.is_none());

        let changed = client
            .post(format!(
                "{base_url}/v1/sandboxes/{sandbox_id}/apex-task-instructions"
            ))
            .bearer_auth(TEST_TENANT_TOKEN)
            .header("x-sandboxwich-tenant", "tenant-apex")
            .header("idempotency-key", "live-claim-4")
            .json(&ApexTaskInstructionsReadRequest {
                expected_sha256: "f".repeat(64),
                expected_byte_count: u64::try_from(bytes.len()).unwrap(),
                claim_lease_generation: 4,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(changed.status(), reqwest::StatusCode::CONFLICT);

        let race_request = ApexTaskInstructionsReadRequest {
            expected_sha256: format!("{:x}", Sha256::digest(bytes)),
            expected_byte_count: u64::try_from(bytes.len()).unwrap(),
            claim_lease_generation: 6,
        };
        let race_url = format!("{base_url}/v1/sandboxes/{sandbox_id}/apex-task-instructions");
        let race_calls = (0..2)
            .map(|_| {
                let client = client.clone();
                let url = race_url.clone();
                let request = race_request.clone();
                tokio::spawn(async move {
                    client
                        .post(url)
                        .bearer_auth(TEST_TENANT_TOKEN)
                        .header("x-sandboxwich-tenant", "tenant-apex")
                        .header("idempotency-key", "live-race-6")
                        .json(&request)
                        .send()
                        .await
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let race_job_id = loop {
            let row = sqlx::query(
                "select job_id from apex_instruction_reads where idempotency_key = 'live-race-6'",
            )
            .fetch_optional(&state.db.pool)
            .await
            .unwrap();
            if let Some(row) = row {
                break JobId(Uuid::parse_str(&row.get::<String, _>("job_id")).unwrap());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let race_job = fetch_job(&state.db, race_job_id).await.unwrap();
        let race_lease = try_claim_job(&state.db, &worker, &race_job, Some(60), None)
            .await
            .unwrap()
            .unwrap();
        let race_callback = ApexTaskInstructionsCallbackRequest {
            request_id: Uuid::parse_str(race_job.payload["requestId"].as_str().unwrap()).unwrap(),
            lease_id: race_lease.id.0,
            lease_attempt: u64::try_from(race_lease.attempt).unwrap(),
            provider_apply_id: Uuid::parse_str(
                race_job.payload["providerApplyId"].as_str().unwrap(),
            )
            .unwrap(),
            sha256: race_request.expected_sha256.clone(),
            byte_count: race_request.expected_byte_count,
            output_base64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
        };
        let callback = client
            .post(race_job.payload["callbackUrl"].as_str().unwrap())
            .bearer_auth(TEST_WORKER_TOKEN)
            .header("x-sandboxwich-tenant", "tenant-apex")
            .json(&race_callback)
            .send()
            .await
            .unwrap();
        assert!(callback.status().is_success());
        let mut race_statuses = Vec::new();
        for call in race_calls {
            race_statuses.push(call.await.unwrap().status());
        }
        race_statuses.sort();
        assert_eq!(
            race_statuses,
            vec![reqwest::StatusCode::OK, reqwest::StatusCode::CONFLICT]
        );
        let race_jobs = sqlx::query(
            "select count(*) as count from apex_instruction_reads where idempotency_key = 'live-race-6'",
        )
        .fetch_one(&state.db.pool)
        .await
        .unwrap()
        .get::<i64, _>("count");
        assert_eq!(
            race_jobs, 1,
            "same-key race must converge to one durable job"
        );

        let (fresh, fresh_job, fresh_lease) = run_live_http_read(
            &client,
            &base_url,
            &state,
            &worker,
            sandbox_id,
            ("live-claim-5", 5),
            bytes,
        )
        .await;
        assert!(!fresh.output_unavailable);
        assert_ne!(fresh.request_id, first.request_id);

        let mut callback_failure_invocations = 1_u64;
        fail_lease_in_transaction(
            &state.db,
            fresh_lease.id,
            true,
            "simulated lost callback response",
        )
        .await
        .unwrap();
        let failed_job = fetch_job(&state.db, fresh_job.id).await.unwrap();
        if failed_job.status == JobStatus::Queued
            && try_claim_job(&state.db, &worker, &failed_job, Some(60), None)
                .await
                .unwrap()
                .is_some()
        {
            callback_failure_invocations += 1;
        }
        assert_eq!(
            callback_failure_invocations, 1,
            "callback failure must not execute the one-time provider read again"
        );

        let (_expiry, expiry_job, expiry_lease) = run_live_http_read(
            &client,
            &base_url,
            &state,
            &worker,
            sandbox_id,
            ("live-claim-expiry-7", 7),
            bytes,
        )
        .await;
        let mut expiry_invocations = 1_u64;
        expire_lease_if_still_active(
            &state.db,
            expiry_lease.id,
            expiry_lease.expires_at + chrono::Duration::seconds(1),
        )
        .await
        .unwrap();
        let expired_job = fetch_job(&state.db, expiry_job.id).await.unwrap();
        if expired_job.status == JobStatus::Queued
            && try_claim_job(&state.db, &worker, &expired_job, Some(60), None)
                .await
                .unwrap()
                .is_some()
        {
            expiry_invocations += 1;
        }
        assert_eq!(
            expiry_invocations, 1,
            "lease expiry must not execute the one-time provider read again"
        );

        let sentinel_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let durable = sqlx::query(
            "select r.expected_sha256, r.observed_sha256, j.payload
             from apex_instruction_reads r join jobs j on j.id = r.job_id
             where r.idempotency_key in ('live-claim-4', 'live-claim-5')",
        )
        .fetch_all(&state.db.pool)
        .await
        .unwrap();
        assert_eq!(durable.len(), 2);
        for row in durable {
            for field in [
                row.get::<String, _>("expected_sha256"),
                row.get::<String, _>("observed_sha256"),
                row.get::<String, _>("payload"),
            ] {
                assert!(!field.contains("PRIVATE_SENTINEL"));
                assert!(!field.contains(&sentinel_base64));
            }
        }
        let cached = sqlx::query(
            "select count(*) as count from idempotency_records
             where idempotency_key in ('live-claim-4', 'live-claim-5')",
        )
        .fetch_one(&state.db.pool)
        .await
        .unwrap()
        .get::<i64, _>("count");
        assert_eq!(cached, 0, "live response must bypass response persistence");
        assert!(!first_job.payload.to_string().contains("PRIVATE_SENTINEL"));
        server.abort();
    }

    #[tokio::test]
    async fn instruction_claim_is_bound_to_exact_worker_and_placement_generation() {
        let (state, _ctx, worker, seeded_lease, _, _, _, bytes) =
            callback_fixture(Utc::now() + chrono::Duration::seconds(35)).await;
        let sandbox_id = sandbox_id_from_job(&seeded_lease.job).unwrap();
        let tenant_ctx = TenantContext {
            tenant_id: worker.tenant_id.clone(),
            principal: Principal::Tenant,
        };
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", "placement-fence-8".parse().unwrap());
        let read_state = state.clone();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let read = tokio::spawn(async move {
            read_apex_task_instructions(
                State(read_state),
                Extension(tenant_ctx),
                Path(sandbox_id.0),
                headers,
                Json(ApexTaskInstructionsReadRequest {
                    expected_sha256: digest,
                    expected_byte_count: u64::try_from(bytes.len()).unwrap(),
                    claim_lease_generation: 8,
                }),
            )
            .await
        });
        let job = loop {
            if let Some(row) =
                sqlx::query("select job_id from apex_instruction_reads where idempotency_key = ?")
                    .bind("placement-fence-8")
                    .fetch_optional(&state.db.pool)
                    .await
                    .unwrap()
            {
                let id = JobId(Uuid::parse_str(&row.get::<String, _>("job_id")).unwrap());
                break fetch_job(&state.db, id).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        let other_worker = Worker {
            id: WorkerId::new(),
            tenant_id: worker.tenant_id.clone(),
            name: "same-cluster-worker".into(),
            status: WorkerStatus::Online,
            provider: worker.provider.clone(),
            capabilities: worker.capabilities.clone(),
            max_concurrent_jobs: 4,
            labels: worker.labels.clone(),
            registered_at: Utc::now(),
            last_heartbeat_at: Some(Utc::now()),
        };
        insert_worker(
            &state.db,
            &other_worker,
            &crate::auth::hash_worker_token("sbw_wtok_other-worker"),
        )
        .await
        .unwrap();

        assert!(
            try_claim_job(&state.db, &other_worker, &job, Some(60), None)
                .await
                .unwrap()
                .is_none(),
            "a same-provider worker must not claim another worker's private read"
        );

        sqlx::query(
            "update sandbox_placements
             set worker_id = ?, generation = generation + 1, updated_at = ?
             where sandbox_id = ?",
        )
        .bind(other_worker.id.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&state.db.pool)
        .await
        .unwrap();
        assert!(
            try_claim_job(&state.db, &worker, &job, Some(60), None)
                .await
                .unwrap()
                .is_none(),
            "the original worker must fail closed after placement generation changes"
        );
        assert!(
            try_claim_job(&state.db, &other_worker, &job, Some(60), None)
                .await
                .unwrap()
                .is_none(),
            "a replacement worker cannot inherit an already-issued private read"
        );
        read.abort();
    }
}
