use crate::auth::ensure_operator_authorized_for;
use crate::authz::AuthorizationContext;
use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::jobs::insert_job_on_connection;
use crate::handlers::operations::operation_from_job;
use crate::handlers::sandboxes::create_sandbox_with_home;
use crate::request_id::RequestTrace;
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use sandboxwich_core::*;
use serde::Serialize;
use serde_json::json;
use sqlx::{AnyConnection, Row};
use utoipa::ToSchema;
use uuid::Uuid;

const HOME_MOUNT_RECLAIMABLE_STATES_SQL: &str = "'archived', 'error'";
const HOME_MOUNT_CLAIM_SAVEPOINT: &str = "sandbox_home_mount_claim";

#[utoipa::path(post, path = "/v1/homes", request_body = CreateHomeRequest, responses((status = 201, body = HomeResponse), (status = 200, body = HomeResponse)))]
pub(crate) async fn create_home(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateHomeRequest>,
) -> Result<(StatusCode, Json<HomeResponse>), ApiError> {
    let external_key = request
        .external_key
        .as_deref()
        .map(validate_home_external_key)
        .transpose()?;
    if let Some(key) = external_key
        && let Some(existing) = fetch_home_by_external_key(&state.db, key, &ctx.tenant_id).await?
    {
        let mounted_sandbox = fetch_home_mount(&state.db, existing.id, &ctx.tenant_id).await?;
        return Ok((
            StatusCode::OK,
            Json(HomeResponse {
                ok: true,
                home: existing,
                operation: None,
                mounted_sandbox,
            }),
        ));
    }
    let now = Utc::now();
    let home = Home {
        id: HomeId::new(),
        tenant_id: ctx.tenant_id.clone(),
        state: HomeState::Ready,
        created_at: now,
        updated_at: now,
        error: None,
        external_key: external_key.map(str::to_string),
    };
    let sql = format!(
        "insert into homes (id, tenant_id, state, created_at, updated_at, error, external_key) values ({})",
        state.db.placeholders(7)
    );
    let inserted = sqlx::query(&sql)
        .bind(home.id.to_string())
        .bind(&home.tenant_id)
        .bind(home.state.as_db_str())
        .bind(home.created_at.to_rfc3339())
        .bind(home.updated_at.to_rfc3339())
        .bind(&home.error)
        .bind(&home.external_key)
        .execute(&state.db.pool)
        .await;
    if let Err(insert_error) = inserted {
        // Two concurrent creates with the same external key race on the
        // unique index; the loser re-resolves the winner's home instead of
        // surfacing the constraint violation. Any other insert failure (or a
        // failure without an external key to re-resolve by) propagates.
        if let Some(key) = &home.external_key
            && let Some(existing) =
                fetch_home_by_external_key(&state.db, key, &ctx.tenant_id).await?
        {
            let mounted_sandbox = fetch_home_mount(&state.db, existing.id, &ctx.tenant_id).await?;
            return Ok((
                StatusCode::OK,
                Json(HomeResponse {
                    ok: true,
                    home: existing,
                    operation: None,
                    mounted_sandbox,
                }),
            ));
        }
        return Err(insert_error.into());
    }
    Ok((
        StatusCode::CREATED,
        Json(HomeResponse {
            ok: true,
            home,
            operation: None,
            mounted_sandbox: None,
        }),
    ))
}

const HOME_EXTERNAL_KEY_MAX_LEN: usize = 128;

/// External keys are caller-derived identifiers (e.g. a hash of a tenant
/// principal), not free text: bounded length, restricted charset, no
/// whitespace. Fail-closed validation keeps them safe to index, log, and
/// echo back verbatim.
fn validate_home_external_key(raw: &str) -> Result<&str, ApiError> {
    if raw.is_empty() || raw.len() > HOME_EXTERNAL_KEY_MAX_LEN {
        return Err(ApiError::bad_request(format!(
            "external_key must be 1..={HOME_EXTERNAL_KEY_MAX_LEN} characters"
        )));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
    {
        return Err(ApiError::bad_request(
            "external_key may only contain ASCII alphanumerics, '.', '_', ':', and '-'",
        ));
    }
    Ok(raw)
}

#[utoipa::path(get, path = "/v1/homes/{home_id}", params(("home_id" = Uuid, Path)), responses((status = 200, body = HomeResponse), (status = 404)))]
pub(crate) async fn get_home(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(home_id): Path<Uuid>,
) -> Result<Json<HomeResponse>, ApiError> {
    let home = fetch_home(&state.db, HomeId(home_id), &ctx.tenant_id).await?;
    let mounted_sandbox = fetch_home_mount(&state.db, home.id, &ctx.tenant_id).await?;
    Ok(Json(HomeResponse {
        ok: true,
        home,
        operation: None,
        mounted_sandbox,
    }))
}

#[utoipa::path(post, path = "/v1/homes/{home_id}/sandboxes", params(("home_id" = Uuid, Path)), request_body = CreateSandboxRequest, responses((status = 202, body = SandboxResponse), (status = 404), (status = 409)))]
pub(crate) async fn create_home_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Extension(authorization): Extension<AuthorizationContext>,
    Extension(trace): Extension<RequestTrace>,
    Path(home_id): Path<Uuid>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    create_sandbox_with_home(
        state,
        ctx,
        request,
        Some(HomeId(home_id)),
        Some(authorization),
        trace,
    )
    .await
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
            mounted_sandbox: None,
        }),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HomeMountReconciliationResponse {
    pub(crate) ok: bool,
    pub(crate) removed_mounts: u64,
}

/// Remove only mount rows whose sandbox lifecycle is already terminal. This
/// is an idempotent, operator-gated repair for rows left behind by an
/// interrupted teardown; it never changes a sandbox or home state and never
/// touches a live mount.
#[utoipa::path(
    post,
    path = "/v1/operator/home-mounts/reconcile",
    tag = "operator",
    responses(
        (status = 200, body = HomeMountReconciliationResponse),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub(crate) async fn reconcile_home_mounts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<HomeMountReconciliationResponse>, ApiError> {
    ensure_operator_authorized_for(
        &state,
        &headers,
        "home mount reconciliation",
        "/home-mounts/reconcile",
    )?;
    let sql = format!(
        "delete from sandbox_home_mounts
         where sandbox_id in (
             select id from sandboxes where state in ({HOME_MOUNT_RECLAIMABLE_STATES_SQL})
         )"
    );
    let result = sqlx::query(&sql).execute(&state.db.pool).await?;
    let removed_mounts = result.rows_affected();
    tracing::info!(removed_mounts, "home mount reconciliation completed");
    Ok(Json(HomeMountReconciliationResponse {
        ok: true,
        removed_mounts,
    }))
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
        "select id, tenant_id, state, created_at, updated_at, error, external_key from homes where id = {} and tenant_id = {}",
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

async fn fetch_home_by_external_key(
    db: &Database,
    external_key: &str,
    tenant_id: &str,
) -> Result<Option<Home>, ApiError> {
    let sql = format!(
        "select id, tenant_id, state, created_at, updated_at, error, external_key from homes where tenant_id = {} and external_key = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&sql)
        .bind(tenant_id)
        .bind(external_key)
        .fetch_optional(&db.pool)
        .await?
        .map(row_to_home)
        .transpose()
}

/// Reports the sandbox currently holding this home's mount, if any, with its
/// live state. Deliberately unfiltered: `archiving` remains provider-owned,
/// while an `archived`/`error` row may still await lazy cleanup in
/// `claim_home_mount_on_connection`. Reporting every row keeps the caller's
/// view aligned with the claim boundary.
async fn fetch_home_mount(
    db: &Database,
    home_id: HomeId,
    tenant_id: &str,
) -> Result<Option<HomeMount>, ApiError> {
    let sql = format!(
        "select m.sandbox_id, s.state from sandbox_home_mounts m join sandboxes s on s.id = m.sandbox_id where m.home_id = {} and m.tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(home_id.to_string())
        .bind(tenant_id)
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(None);
    };
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let state: String = row.try_get("state")?;
    Ok(Some(HomeMount {
        sandbox_id: SandboxId(
            Uuid::parse_str(&sandbox_id)
                .map_err(|_| ApiError::internal("invalid mounted sandbox id"))?,
        ),
        sandbox_state: SandboxState::parse_db_str(&state)
            .map_err(|error| ApiError::internal(error.to_string()))?,
    }))
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
        external_key: row.try_get("external_key")?,
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
        "delete from sandbox_home_mounts where home_id = {} and sandbox_id in (select id from sandboxes where state in ({HOME_MOUNT_RECLAIMABLE_STATES_SQL}))",
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

    if let Some(mount) = fetch_home_mount_on_connection(db, connection, home_id, tenant_id).await? {
        return Err(home_mount_conflict(Some(mount)));
    }

    let insert_sql = format!(
        "insert into sandbox_home_mounts (sandbox_id, home_id, tenant_id, created_at) values ({})",
        db.placeholders(4)
    );
    sqlx::query(&format!("savepoint {HOME_MOUNT_CLAIM_SAVEPOINT}"))
        .execute(&mut *connection)
        .await?;
    match sqlx::query(&insert_sql)
        .bind(sandbox_id.to_string())
        .bind(home_id.to_string())
        .bind(tenant_id)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *connection)
        .await
    {
        Ok(_) => {
            sqlx::query(&format!("release savepoint {HOME_MOUNT_CLAIM_SAVEPOINT}"))
                .execute(&mut *connection)
                .await?;
            Ok(())
        }
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            sqlx::query(&format!(
                "rollback to savepoint {HOME_MOUNT_CLAIM_SAVEPOINT}"
            ))
            .execute(&mut *connection)
            .await?;
            sqlx::query(&format!("release savepoint {HOME_MOUNT_CLAIM_SAVEPOINT}"))
                .execute(&mut *connection)
                .await?;
            let mount = fetch_home_mount_on_connection(db, connection, home_id, tenant_id).await?;
            Err(home_mount_conflict(mount))
        }
        Err(error) => {
            let _ = sqlx::query(&format!(
                "rollback to savepoint {HOME_MOUNT_CLAIM_SAVEPOINT}"
            ))
            .execute(&mut *connection)
            .await;
            let _ = sqlx::query(&format!("release savepoint {HOME_MOUNT_CLAIM_SAVEPOINT}"))
                .execute(&mut *connection)
                .await;
            Err(error.into())
        }
    }
}

async fn fetch_home_mount_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    home_id: HomeId,
    tenant_id: &str,
) -> Result<Option<HomeMount>, ApiError> {
    let sql = format!(
        "select m.sandbox_id, s.state
         from sandbox_home_mounts m
         join sandboxes s on s.id = m.sandbox_id
         where m.home_id = {} and m.tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(home_id.to_string())
        .bind(tenant_id)
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(None);
    };
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let state: String = row.try_get("state")?;
    Ok(Some(HomeMount {
        sandbox_id: SandboxId(
            Uuid::parse_str(&sandbox_id)
                .map_err(|_| ApiError::internal("invalid mounted sandbox id"))?,
        ),
        sandbox_state: SandboxState::parse_db_str(&state)
            .map_err(|error| ApiError::internal(error.to_string()))?,
    }))
}

fn home_mount_conflict(mount: Option<HomeMount>) -> ApiError {
    let details = mount
        .as_ref()
        .map(|mount| {
            json!({
                "mountedSandboxId": mount.sandbox_id,
                "mountedSandboxState": mount.sandbox_state,
                "reclaimable": mount.sandbox_state.clone().is_home_mount_reclaimable(),
            })
        })
        .unwrap_or_else(|| json!({ "reclaimable": false }));
    ApiError::conflict_code_with_details(
        "home_already_mounted",
        "home already has a mounted sandbox",
        details,
    )
}
