use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::jobs::insert_job_on_connection;
use crate::handlers::operations::operation_from_job;
use crate::handlers::sandboxes::create_sandbox_with_home;
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use sandboxwich_core::*;
use sqlx::{AnyConnection, Row};
use uuid::Uuid;

#[utoipa::path(post, path = "/v1/homes", request_body = CreateHomeRequest, responses((status = 201, body = HomeResponse)))]
pub(crate) async fn create_home(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(_request): Json<CreateHomeRequest>,
) -> Result<(StatusCode, Json<HomeResponse>), ApiError> {
    let now = Utc::now();
    let home = Home {
        id: HomeId::new(),
        tenant_id: ctx.tenant_id,
        state: HomeState::Ready,
        created_at: now,
        updated_at: now,
        error: None,
    };
    let sql = format!(
        "insert into homes (id, tenant_id, state, created_at, updated_at, error) values ({})",
        state.db.placeholders(6)
    );
    sqlx::query(&sql)
        .bind(home.id.to_string())
        .bind(&home.tenant_id)
        .bind(home.state.as_db_str())
        .bind(home.created_at.to_rfc3339())
        .bind(home.updated_at.to_rfc3339())
        .bind(&home.error)
        .execute(&state.db.pool)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(HomeResponse {
            ok: true,
            home,
            operation: None,
        }),
    ))
}

#[utoipa::path(get, path = "/v1/homes/{home_id}", params(("home_id" = Uuid, Path)), responses((status = 200, body = HomeResponse), (status = 404)))]
pub(crate) async fn get_home(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(home_id): Path<Uuid>,
) -> Result<Json<HomeResponse>, ApiError> {
    let home = fetch_home(&state.db, HomeId(home_id), &ctx.tenant_id).await?;
    Ok(Json(HomeResponse {
        ok: true,
        home,
        operation: None,
    }))
}

#[utoipa::path(post, path = "/v1/homes/{home_id}/sandboxes", params(("home_id" = Uuid, Path)), request_body = CreateSandboxRequest, responses((status = 202, body = SandboxResponse), (status = 404), (status = 409)))]
pub(crate) async fn create_home_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(home_id): Path<Uuid>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    create_sandbox_with_home(state, ctx, request, Some(HomeId(home_id))).await
}

#[utoipa::path(delete, path = "/v1/homes/{home_id}", params(("home_id" = Uuid, Path)), responses((status = 202, body = HomeResponse), (status = 404), (status = 409)))]
pub(crate) async fn delete_home(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(home_id): Path<Uuid>,
) -> Result<(StatusCode, Json<HomeResponse>), ApiError> {
    let home_id = HomeId(home_id);
    let now = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let active_sql = format!(
        "select 1 from sandbox_home_mounts where home_id = {} and tenant_id = {} limit 1",
        state.db.placeholder(1),
        state.db.placeholder(2)
    );
    if sqlx::query(&active_sql)
        .bind(home_id.to_string())
        .bind(&ctx.tenant_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
    {
        return Err(ApiError::conflict_code(
            "home_has_live_sandbox",
            "home cannot be deleted while a sandbox is mounted",
        ));
    }
    let update_sql = format!(
        "update homes set state = {}, updated_at = {}, error = null where id = {} and tenant_id = {} and state in ('ready', 'delete_failed')",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4)
    );
    let updated = sqlx::query(&update_sql)
        .bind(HomeState::Deleting.as_db_str())
        .bind(now.to_rfc3339())
        .bind(home_id.to_string())
        .bind(&ctx.tenant_id)
        .execute(&mut *tx)
        .await?;
    if updated.rows_affected() == 0 {
        let exists_sql = format!(
            "select 1 from homes where id = {} and tenant_id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2)
        );
        let exists = sqlx::query(&exists_sql)
            .bind(home_id.to_string())
            .bind(&ctx.tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        return Err(if exists {
            ApiError::conflict_code(
                "home_delete_in_progress",
                "home deletion is already in progress",
            )
        } else {
            ApiError::not_found("home not found")
        });
    }
    let job = Job {
        id: JobId::new(),
        tenant_id: ctx.tenant_id.clone(),
        kind: JobKind::DeleteHome,
        status: JobStatus::Queued,
        payload: serde_json::json!({ "homeId": home_id }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;
    let home = fetch_home(&state.db, home_id, &ctx.tenant_id).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(HomeResponse {
            ok: true,
            home,
            operation: Some(operation_from_job(&job)?),
        }),
    ))
}

pub(crate) fn home_id_from_job(job: &Job) -> Result<HomeId, ApiError> {
    let value = job
        .payload
        .get("homeId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::internal("home job is missing homeId"))?;
    Ok(HomeId(Uuid::parse_str(value).map_err(|_| {
        ApiError::internal("home job has invalid homeId")
    })?))
}

pub(crate) async fn mark_home_delete_failed_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    home_id: HomeId,
    error: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "update homes set state = {}, updated_at = {}, error = {} where id = {} and state = 'deleting'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(HomeState::DeleteFailed.as_db_str())
        .bind(Utc::now().to_rfc3339())
        .bind(error)
        .bind(home_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn fetch_home(
    db: &Database,
    home_id: HomeId,
    tenant_id: &str,
) -> Result<Home, ApiError> {
    let sql = format!(
        "select id, tenant_id, state, created_at, updated_at, error from homes where id = {} and tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(home_id.to_string())
        .bind(tenant_id)
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("home not found"))?;
    row_to_home(row)
}

fn row_to_home(row: sqlx::any::AnyRow) -> Result<Home, ApiError> {
    let id: String = row.try_get("id")?;
    let state: String = row.try_get("state")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    Ok(Home {
        id: HomeId(Uuid::parse_str(&id).map_err(|_| ApiError::internal("invalid home id"))?),
        tenant_id: row.try_get("tenant_id")?,
        state: HomeState::parse_db_str(&state)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        created_at: created_at
            .parse()
            .map_err(|_| ApiError::internal("invalid home created_at"))?,
        updated_at: updated_at
            .parse()
            .map_err(|_| ApiError::internal("invalid home updated_at"))?,
        error: row.try_get("error")?,
    })
}

pub(crate) async fn claim_home_mount_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    home_id: HomeId,
    tenant_id: &str,
    sandbox_id: SandboxId,
) -> Result<(), ApiError> {
    let cleanup_sql = format!(
        "delete from sandbox_home_mounts where home_id = {} and sandbox_id in (select id from sandboxes where state in ('archived', 'error'))",
        db.placeholder(1)
    );
    sqlx::query(&cleanup_sql)
        .bind(home_id.to_string())
        .execute(&mut *connection)
        .await?;

    let home_sql = format!(
        "select state from homes where id = {} and tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let state = sqlx::query(&home_sql)
        .bind(home_id.to_string())
        .bind(tenant_id)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("home not found"))?
        .try_get::<String, _>("state")?;
    if state != HomeState::Ready.as_db_str() {
        return Err(ApiError::conflict_code(
            "home_not_ready",
            "home is not ready to mount",
        ));
    }

    let insert_sql = format!(
        "insert into sandbox_home_mounts (sandbox_id, home_id, tenant_id, created_at) values ({})",
        db.placeholders(4)
    );
    sqlx::query(&insert_sql)
        .bind(sandbox_id.to_string())
        .bind(home_id.to_string())
        .bind(tenant_id)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *connection)
        .await
        .map_err(|_| {
            ApiError::conflict_code("home_already_mounted", "home already has a live sandbox")
        })?;
    Ok(())
}
