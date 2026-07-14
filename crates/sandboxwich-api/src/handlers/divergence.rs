use crate::auth::*;
use crate::error::*;
use crate::handlers::commands::insert_event_on_connection;
use crate::handlers::jobs::{add_provision_spec_to_payload, insert_job_on_connection};
use crate::handlers::sandboxes::{
    fetch_sandbox, fetch_sandbox_on_connection, hydrate_sandbox_network_egress_on_connection,
    set_sandbox_state_on_connection,
};
use crate::state::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::Row;
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

pub(crate) const LIMACHARLIE_SOURCE: &str = "limacharlie";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimaCharlieConfig {
    pub organization_id: String,
    pub sensor_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterFailure {
    Transient(String),
    Permanent(String),
}

pub trait SensorObservationAdapter: Send + Sync {
    fn poll<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SensorObservation>, AdapterFailure>> + Send + 'a>>;
}

struct WebhookBatchAdapter {
    config: LimaCharlieConfig,
    observations: Vec<SensorObservation>,
}

impl SensorObservationAdapter for WebhookBatchAdapter {
    fn poll<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SensorObservation>, AdapterFailure>> + Send + 'a>>
    {
        Box::pin(async {
            if self.config.organization_id != LIMACHARLIE_SOURCE {
                return Err(AdapterFailure::Permanent(
                    "unsupported sensor observation source".to_string(),
                ));
            }
            if self.config.sensor_tag.trim().is_empty() {
                return Err(AdapterFailure::Transient(
                    "sensor adapter tag is temporarily unavailable".to_string(),
                ));
            }
            Ok(self.observations.clone())
        })
    }
}

#[utoipa::path(post, path = "/v1/sandboxes/{sandbox_id}/tool-call-ledger", tag = "divergence", request_body = ToolCallLedgerEntryRequest, responses((status = 200)))]
pub(crate) async fn append_tool_call_ledger(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<ToolCallLedgerEntryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    validate_ledger(&request)?;
    let now = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let sql = format!(
        "insert into tool_call_ledger
         (id, tenant_id, sandbox_id, external_id, session_id, receipt_id, started_at, ended_at, created_at)
         values ({})
         on conflict (tenant_id, external_id) do nothing",
        (1..=9).map(|i| state.db.placeholder(i)).collect::<Vec<_>>().join(", ")
    );
    let ledger_id = Uuid::now_v7();
    let inserted = sqlx::query(&sql)
        .bind(ledger_id.to_string())
        .bind(&ctx.tenant_id)
        .bind(sandbox_id.to_string())
        .bind(&request.external_id)
        .bind(&request.session_id)
        .bind(&request.receipt_id)
        .bind(request.started_at.to_rfc3339())
        .bind(request.ended_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    for scope in request
        .scopes
        .iter()
        .filter(|_| inserted.rows_affected() == 1)
    {
        let sql = format!(
            "insert into tool_call_receipt_scopes (ledger_id, activity_class, resource_prefix)
             values ({}, {}, {}) on conflict do nothing",
            state.db.placeholder(1),
            state.db.placeholder(2),
            state.db.placeholder(3)
        );
        sqlx::query(&sql)
            .bind(ledger_id.to_string())
            .bind(scope.activity_class.as_db_str())
            .bind(&scope.resource_prefix)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"ok": true, "externalId": request.external_id})))
}

fn validate_ledger(request: &ToolCallLedgerEntryRequest) -> Result<(), ApiError> {
    if request.external_id.trim().is_empty()
        || request.session_id.trim().is_empty()
        || request.receipt_id.trim().is_empty()
        || request.started_at > request.ended_at
        || request.scopes.is_empty()
        || request.scopes.iter().any(|s| s.resource_prefix.is_empty())
    {
        return Err(ApiError::bad_request(
            "invalid typed tool-call ledger entry",
        ));
    }
    Ok(())
}

#[utoipa::path(post, path = "/v1/divergence/reconcile", tag = "divergence", request_body = DivergenceReconcileRequest, responses((status = 200, body = DivergenceReconcileResponse)))]
pub(crate) async fn reconcile_divergence(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    headers: HeaderMap,
    Json(request): Json<DivergenceReconcileRequest>,
) -> Result<Json<DivergenceReconcileResponse>, ApiError> {
    // Reconciliation is tenant-scoped and also operator-gated because a
    // confirmed divergence can stop a sandbox.
    ensure_operator_authorized_for(
        &state,
        &headers,
        "divergence reconciliation",
        "/divergence/reconcile",
    )?;
    let adapter = WebhookBatchAdapter {
        config: LimaCharlieConfig {
            organization_id: request.source,
            sensor_tag: "sandboxwich-webhook".to_string(),
        },
        observations: request.observations,
    };
    Ok(Json(reconcile_with_adapter(&state, &ctx, &adapter).await?))
}

pub(crate) async fn reconcile_with_adapter(
    state: &AppState,
    ctx: &TenantContext,
    adapter: &dyn SensorObservationAdapter,
) -> Result<DivergenceReconcileResponse, ApiError> {
    let observations = match adapter.poll().await {
        Ok(value) => value,
        Err(AdapterFailure::Transient(_message)) => {
            let retry_after = Utc::now() + Duration::seconds(30);
            return Ok(DivergenceReconcileResponse {
                ok: false,
                observations_ingested: 0,
                observations_matched: 0,
                findings_created: vec![],
                retry_after: Some(retry_after),
            });
        }
        Err(AdapterFailure::Permanent(message)) => return Err(ApiError::bad_request(message)),
    };
    let mut matched = 0;
    let mut findings = Vec::new();
    for observation in &observations {
        let sandbox = fetch_sandbox(&state.db, observation.sandbox_id).await?;
        ensure_tenant(&sandbox.tenant_id, ctx)?;
        validate_observation(observation)?;
        persist_observation(state, ctx, observation).await?;
        match correlate(state, ctx, observation).await? {
            None => matched += 1,
            Some(finding) => findings.push(finding),
        }
    }
    Ok(DivergenceReconcileResponse {
        ok: true,
        observations_ingested: observations.len() as u64,
        observations_matched: matched,
        findings_created: findings,
        retry_after: None,
    })
}

fn validate_observation(value: &SensorObservation) -> Result<(), ApiError> {
    if value.external_id.trim().is_empty()
        || value.session_id.trim().is_empty()
        || value.resource.trim().is_empty()
    {
        return Err(ApiError::bad_request("invalid typed sensor observation"));
    }
    Ok(())
}

async fn persist_observation(
    state: &AppState,
    ctx: &TenantContext,
    value: &SensorObservation,
) -> Result<(), ApiError> {
    let sql = format!("insert into sensor_observations
        (id, tenant_id, external_id, sandbox_id, session_id, activity_class, resource, observed_at, created_at)
        values ({}) on conflict (tenant_id, external_id) do nothing",
        (1..=9).map(|i| state.db.placeholder(i)).collect::<Vec<_>>().join(", "));
    sqlx::query(&sql)
        .bind(Uuid::now_v7().to_string())
        .bind(&ctx.tenant_id)
        .bind(&value.external_id)
        .bind(value.sandbox_id.to_string())
        .bind(&value.session_id)
        .bind(value.activity_class.as_db_str())
        .bind(&value.resource)
        .bind(value.observed_at.to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db.pool)
        .await?;
    Ok(())
}

async fn correlate(
    state: &AppState,
    ctx: &TenantContext,
    observation: &SensorObservation,
) -> Result<Option<DivergenceFinding>, ApiError> {
    let sql = format!("select id, receipt_id from tool_call_ledger where tenant_id = {} and sandbox_id = {}
        and session_id = {} and started_at <= {} and ended_at >= {} order by started_at desc limit 1",
        state.db.placeholder(1), state.db.placeholder(2), state.db.placeholder(3),
        state.db.placeholder(4), state.db.placeholder(5));
    let ledger = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .bind(observation.sandbox_id.to_string())
        .bind(&observation.session_id)
        .bind(observation.observed_at.to_rfc3339())
        .bind(observation.observed_at.to_rfc3339())
        .fetch_optional(&state.db.pool)
        .await?;
    let (kind, receipt_id, ledger_id) = if let Some(row) = ledger {
        let ledger_id: String = row.try_get("id")?;
        let receipt_id: String = row.try_get("receipt_id")?;
        let sql = format!(
            "select 1 from tool_call_receipt_scopes where ledger_id = {} and activity_class = {}
            and substr({}, 1, length(resource_prefix)) = resource_prefix limit 1",
            state.db.placeholder(1),
            state.db.placeholder(2),
            state.db.placeholder(3)
        );
        let scoped = sqlx::query(&sql)
            .bind(&ledger_id)
            .bind(observation.activity_class.as_db_str())
            .bind(&observation.resource)
            .fetch_optional(&state.db.pool)
            .await?
            .is_some();
        if scoped {
            mark_observation(state, ctx, observation, "matched").await?;
            return Ok(None);
        }
        (
            DivergenceKind::ReceiptScopeMismatch,
            Some(receipt_id),
            Some(ledger_id),
        )
    } else {
        (DivergenceKind::UnaccountedActivity, None, None)
    };
    let finding = DivergenceFinding {
        id: Uuid::now_v7(),
        sandbox_id: observation.sandbox_id,
        observation_external_id: observation.external_id.clone(),
        session_id: observation.session_id.clone(),
        receipt_id,
        kind,
        activity_class: observation.activity_class.clone(),
        resource: observation.resource.clone(),
        status: DivergenceFindingStatus::Open,
        detected_at: Utc::now(),
    };
    let sql = format!("insert into divergence_findings
        (id, tenant_id, sandbox_id, observation_external_id, session_id, receipt_id, kind, activity_class, resource, status, detected_at)
        values ({}) on conflict (tenant_id, observation_external_id) do nothing",
        (1..=11).map(|i| state.db.placeholder(i)).collect::<Vec<_>>().join(", "));
    let sandbox = fetch_sandbox(&state.db, finding.sandbox_id).await?;
    ensure_tenant(&sandbox.tenant_id, ctx)?;
    let mut tx = state.db.pool.begin().await?;
    let inserted = sqlx::query(&sql)
        .bind(finding.id.to_string())
        .bind(&ctx.tenant_id)
        .bind(finding.sandbox_id.to_string())
        .bind(&finding.observation_external_id)
        .bind(&finding.session_id)
        .bind(&finding.receipt_id)
        .bind(finding.kind.as_db_str())
        .bind(finding.activity_class.as_db_str())
        .bind(&finding.resource)
        .bind(finding.status.as_db_str())
        .bind(finding.detected_at.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    if inserted.rows_affected() == 0 {
        tx.commit().await?;
        return Ok(None);
    }
    if let Some(ledger_id) = ledger_id {
        let sql = format!(
            "update tool_call_ledger set revoked_at = {} where id = {} and revoked_at is null",
            state.db.placeholder(1),
            state.db.placeholder(2)
        );
        sqlx::query(&sql)
            .bind(finding.detected_at.to_rfc3339())
            .bind(ledger_id)
            .execute(&mut *tx)
            .await?;
    }
    mark_observation_on_connection(state, &mut tx, ctx, observation, "divergent").await?;
    if SandboxState::STOP_LEGAL_FROM.contains(&sandbox.state) {
        request_divergence_stop_on_connection(state, &mut tx, ctx, &finding).await?;
    }
    insert_event_on_connection(
        &state.db,
        &mut tx,
        finding.sandbox_id,
        SandboxEventKind::DivergenceDetected,
        json!({
            "findingId": finding.id,
            "kind": finding.kind,
            "observationExternalId": finding.observation_external_id,
            "activityClass": finding.activity_class,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Some(finding))
}

async fn request_divergence_stop_on_connection(
    state: &AppState,
    connection: &mut sqlx::AnyConnection,
    ctx: &TenantContext,
    finding: &DivergenceFinding,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let mut sandbox =
        fetch_sandbox_on_connection(&state.db, connection, finding.sandbox_id).await?;
    hydrate_sandbox_network_egress_on_connection(&state.db, connection, &mut sandbox).await?;
    let mut job = Job {
        id: JobId::new(),
        tenant_id: ctx.tenant_id.clone(),
        kind: JobKind::StopSandbox,
        status: JobStatus::Queued,
        payload: json!({"sandboxId": finding.sandbox_id, "divergenceFindingId": finding.id}),
        required_capability: WorkerCapability::ProvisionSandbox,
        priority: 100,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    add_provision_spec_to_payload(&mut job, &sandbox)?;
    set_sandbox_state_on_connection(
        &state.db,
        connection,
        finding.sandbox_id,
        SandboxState::STOP_LEGAL_FROM,
        SandboxState::Archiving,
        json!({"state": SandboxState::Archiving, "reason": "divergence_detected", "findingId": finding.id}),
    )
    .await?;
    insert_job_on_connection(&state.db, connection, &job).await?;
    Ok(())
}

async fn mark_observation(
    state: &AppState,
    ctx: &TenantContext,
    value: &SensorObservation,
    status: &str,
) -> Result<(), ApiError> {
    let mut connection = state.db.pool.acquire().await?;
    mark_observation_on_connection(state, &mut connection, ctx, value, status).await
}

async fn mark_observation_on_connection(
    state: &AppState,
    connection: &mut sqlx::AnyConnection,
    ctx: &TenantContext,
    value: &SensorObservation,
    status: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "update sensor_observations set reconciliation_status = {}, attempts = attempts + 1,
        next_attempt_at = null, last_error = null where tenant_id = {} and external_id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3)
    );
    sqlx::query(&sql)
        .bind(status)
        .bind(&ctx.tenant_id)
        .bind(&value.external_id)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

#[utoipa::path(get, path = "/v1/sandboxes/{sandbox_id}/divergence-findings", tag = "divergence", responses((status = 200, body = DivergenceFindingListResponse)))]
pub(crate) async fn list_divergence_findings(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<DivergenceFindingListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let sql = format!("select id, sandbox_id, observation_external_id, session_id, receipt_id, kind,
        activity_class, resource, status, detected_at from divergence_findings where tenant_id = {} and sandbox_id = {}
        order by detected_at, id", state.db.placeholder(1), state.db.placeholder(2));
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .bind(sandbox_id.to_string())
        .fetch_all(&state.db.pool)
        .await?;
    let findings = rows
        .into_iter()
        .map(|row| -> Result<_, ApiError> {
            Ok(DivergenceFinding {
                id: Uuid::parse_str(row.try_get("id")?)
                    .map_err(|error| ApiError::internal(format!("invalid finding id: {error}")))?,
                sandbox_id,
                observation_external_id: row.try_get("observation_external_id")?,
                session_id: row.try_get("session_id")?,
                receipt_id: row.try_get("receipt_id")?,
                kind: parse_divergence_kind(row.try_get("kind")?)?,
                activity_class: parse_activity_class(row.try_get("activity_class")?)?,
                resource: row.try_get("resource")?,
                status: parse_finding_status(row.try_get("status")?)?,
                detected_at: chrono::DateTime::parse_from_rfc3339(row.try_get("detected_at")?)
                    .map_err(|error| {
                        ApiError::internal(format!("invalid finding timestamp: {error}"))
                    })?
                    .with_timezone(&Utc),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(DivergenceFindingListResponse { ok: true, findings }))
}

fn parse_activity_class(value: &str) -> Result<ActivityClass, ApiError> {
    match value {
        "process_spawn" => Ok(ActivityClass::ProcessSpawn),
        "network_connect" => Ok(ActivityClass::NetworkConnect),
        "file_write" => Ok(ActivityClass::FileWrite),
        _ => Err(ApiError::internal("invalid activity class")),
    }
}

fn parse_divergence_kind(value: &str) -> Result<DivergenceKind, ApiError> {
    match value {
        "unaccounted_activity" => Ok(DivergenceKind::UnaccountedActivity),
        "receipt_scope_mismatch" => Ok(DivergenceKind::ReceiptScopeMismatch),
        _ => Err(ApiError::internal("invalid divergence kind")),
    }
}

fn parse_finding_status(value: &str) -> Result<DivergenceFindingStatus, ApiError> {
    match value {
        "open" => Ok(DivergenceFindingStatus::Open),
        "resolved" => Ok(DivergenceFindingStatus::Resolved),
        _ => Err(ApiError::internal("invalid finding status")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use crate::db::{connect_database, migrate_database};

    struct FakeAdapter(Result<Vec<SensorObservation>, AdapterFailure>);

    impl SensorObservationAdapter for FakeAdapter {
        fn poll<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SensorObservation>, AdapterFailure>> + Send + 'a>>
        {
            Box::pin(async move { self.0.clone() })
        }
    }

    async fn state() -> AppState {
        let path =
            std::env::temp_dir().join(format!("sandboxwich-divergence-{}.db", Uuid::now_v7()));
        let db = connect_database(&format!("sqlite://{}", path.display()), 1)
            .await
            .unwrap();
        migrate_database(&db).await.unwrap();
        AppState {
            db,
            auth: AuthConfig {
                shared_token: None,
                tenant_tokens: vec![],
                operator_token: None,
                allow_insecure_no_auth: true,
            },
            default_tenant_id: "default".to_string(),
        }
    }

    #[tokio::test]
    async fn fake_adapter_distinguishes_retryable_and_permanent_failures() {
        let state = state().await;
        let ctx = TenantContext {
            tenant_id: "default".to_string(),
            principal: Principal::Tenant,
        };
        let transient = reconcile_with_adapter(
            &state,
            &ctx,
            &FakeAdapter(Err(AdapterFailure::Transient("rate limited".to_string()))),
        )
        .await
        .unwrap();
        assert!(!transient.ok);
        assert!(transient.retry_after.is_some());

        let permanent = reconcile_with_adapter(
            &state,
            &ctx,
            &FakeAdapter(Err(AdapterFailure::Permanent("bad mapping".to_string()))),
        )
        .await;
        assert!(permanent.is_err());
    }
}
