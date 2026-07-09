use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::commands::command_id_from_job;
use crate::handlers::jobs::{fetch_job, job_references};
use crate::rows::job_status_to_str;
use crate::state::{AppState, TenantContext};
use async_stream::stream;
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use sandboxwich_core::*;
use std::convert::Infallible;
use std::time::Duration;
use uuid::Uuid;

pub(crate) fn operation_from_job(job: &Job) -> Result<Operation, ApiError> {
    let references = job_references(job)?;
    let kind = match job.kind {
        JobKind::ProvisionSandbox => OperationKind::ProvisionSandbox,
        JobKind::StopSandbox => OperationKind::StopSandbox,
        JobKind::ResumeSandbox => OperationKind::ResumeSandbox,
        JobKind::RunCommand => OperationKind::RunCommand,
        JobKind::CreateSnapshot => OperationKind::CreateSnapshot,
        JobKind::ForkSandbox => OperationKind::ForkSandbox,
        JobKind::RunPrompt => {
            return Err(ApiError::not_implemented(
                "agent_prompt_unavailable",
                "agent prompt execution is not implemented",
            ));
        }
    };
    let status = match job.status {
        JobStatus::Queued => OperationStatus::Queued,
        JobStatus::Leased => OperationStatus::Running,
        JobStatus::Succeeded => OperationStatus::Succeeded,
        JobStatus::Failed | JobStatus::Dead => OperationStatus::Failed,
        JobStatus::Cancelled => OperationStatus::Cancelled,
    };
    Ok(Operation {
        id: job.id.0,
        kind,
        status,
        resource_id: references
            .command_id
            .map(|id| id.0)
            .or_else(|| references.snapshot_id.map(|id| id.0))
            .or_else(|| references.child_sandbox_id.map(|id| id.0))
            .or_else(|| references.sandbox_id.map(|id| id.0)),
        created_at: job.created_at,
        updated_at: job.updated_at,
        error_code: job
            .last_error
            .as_ref()
            .map(|_| "operation_failed".to_string()),
        error_message: job.last_error.clone(),
    })
}

async fn tenant_operation(db: &Database, id: Uuid, ctx: &TenantContext) -> Result<Job, ApiError> {
    let job = fetch_job(db, JobId(id)).await?;
    if job.tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("operation not found"));
    }
    Ok(job)
}

#[utoipa::path(get, path = "/v1/operations/{operation_id}", tag = "operations", params(("operation_id" = Uuid, Path)), responses((status = 200, body = OperationResponse), (status = 404, body = ErrorEnvelope)))]
pub(crate) async fn get_operation(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<OperationResponse>, ApiError> {
    let operation = operation_from_job(&tenant_operation(&state.db, id, &ctx).await?)?;
    Ok(Json(OperationResponse {
        ok: true,
        operation,
    }))
}

#[utoipa::path(post, path = "/v1/operations/{operation_id}/cancel", tag = "operations", params(("operation_id" = Uuid, Path)), responses((status = 200, body = OperationResponse), (status = 409, body = ErrorEnvelope)))]
pub(crate) async fn cancel_operation(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<OperationResponse>, ApiError> {
    let job = tenant_operation(&state.db, id, &ctx).await?;
    if job.status != JobStatus::Queued {
        return Err(ApiError::conflict_code(
            "operation_not_cancellable",
            "only queued operations can be cancelled",
        ));
    }
    if job.kind != JobKind::RunCommand {
        return Err(ApiError::conflict_code(
            "operation_not_cancellable",
            "this operation cannot be cancelled safely",
        ));
    }
    let sql = format!(
        "update jobs set status = {}, updated_at = {} where id = {} and status = 'queued'",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3)
    );
    let now = chrono::Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let result = sqlx::query(&sql)
        .bind(job_status_to_str(&JobStatus::Cancelled))
        .bind(now.to_rfc3339())
        .bind(job.id.to_string())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::conflict_code(
            "operation_not_cancellable",
            "operation is no longer cancellable",
        ));
    }
    let command_id = command_id_from_job(&job)?;
    let command_sql = format!(
        "update commands set status = {}, finished_at = {} where id = {} and status = 'queued'",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3)
    );
    sqlx::query(&command_sql)
        .bind(CommandStatus::Failed.as_db_str())
        .bind(now.to_rfc3339())
        .bind(command_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    get_operation(State(state), Extension(ctx), Path(id)).await
}

pub(crate) async fn operation_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    tenant_operation(&state.db, id, &ctx).await?;
    let last_id = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let db = state.db.clone();
    let tenant = ctx.tenant_id;
    let output = stream! {
        let mut last = last_id;
        loop {
            let job = fetch_job(&db, JobId(id)).await;
            let Ok(job) = job else { break; };
            if job.tenant_id != tenant { break; }
            let event_id = job.updated_at.to_rfc3339();
            if last.as_deref() != Some(event_id.as_str()) {
                let operation = match operation_from_job(&job) { Ok(value) => value, Err(_) => break };
                let data = serde_json::to_string(&operation).unwrap_or_else(|_| "{}".to_string());
                yield Ok(Event::default().id(event_id.clone()).event("operation").data(data));
                last = Some(event_id);
            }
            if matches!(job.status, JobStatus::Succeeded | JobStatus::Failed | JobStatus::Dead | JobStatus::Cancelled) { break; }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    Ok(Sse::new(output).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
