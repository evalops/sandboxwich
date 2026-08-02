//! Tenant-scoped secret *references*.
//!
//! The control plane records where long-lived user and model credentials
//! live; it never records, transports, or returns the credentials
//! themselves. Every row here is a locator plus its scope
//! (`tenant_id` = platform organization, `workspace_id`), and every read and
//! mutation is filtered on that scope.

use crate::db::Database;
use crate::error::ApiError;
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use sandboxwich_core::*;
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListSecretRefsParams {
    /// Optional workspace narrowing. The organization scope is always taken
    /// from the authenticated principal and can never be widened here.
    pub(crate) workspace_id: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/secret-refs",
    request_body = CreateSecretRefRequest,
    responses(
        (status = 201, body = SecretRefResponse),
        (status = 400, body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope)
    )
)]
pub(crate) async fn create_secret_ref(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateSecretRefRequest>,
) -> Result<(StatusCode, Json<SecretRefResponse>), ApiError> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let now = Utc::now();
    let secret_ref = SecretRef {
        id: SecretRefId::new(),
        tenant_id: ctx.tenant_id.clone(),
        workspace_id: request.workspace_id,
        name: request.name,
        source: request.source,
        delivery: request.delivery,
        state: SecretRefState::Active,
        created_at: now,
        updated_at: now,
        revoked_at: None,
    };
    let sql = format!(
        "insert into secret_refs (
             id, tenant_id, workspace_id, name, backend, source_object_name,
             source_object_key, delivery, state, created_at, updated_at, revoked_at
         ) values ({})",
        state.db.placeholders(12)
    );
    sqlx::query(&sql)
        .bind(secret_ref.id.to_string())
        .bind(&secret_ref.tenant_id)
        .bind(&secret_ref.workspace_id)
        .bind(&secret_ref.name)
        .bind(secret_ref.source.backend.as_db_str())
        .bind(&secret_ref.source.object_name)
        .bind(&secret_ref.source.object_key)
        .bind(secret_ref.delivery.as_db_str())
        .bind(secret_ref.state.as_db_str())
        .bind(secret_ref.created_at.to_rfc3339())
        .bind(secret_ref.updated_at.to_rfc3339())
        .bind(Option::<String>::None)
        .execute(&state.db.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::conflict_code(
                    "secret_ref_name_conflict",
                    "an active secret reference with this name already exists in the workspace",
                )
            } else {
                ApiError::from(error)
            }
        })?;
    Ok((
        StatusCode::CREATED,
        Json(SecretRefResponse {
            ok: true,
            secret_ref,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/v1/secret-refs",
    responses((status = 200, body = SecretRefListResponse))
)]
pub(crate) async fn list_secret_refs(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Query(params): Query<ListSecretRefsParams>,
) -> Result<Json<SecretRefListResponse>, ApiError> {
    let mut sql = format!(
        "select {SECRET_REF_COLUMNS} from secret_refs where tenant_id = {}",
        state.db.placeholder(1)
    );
    if params.workspace_id.is_some() {
        sql.push_str(&format!(" and workspace_id = {}", state.db.placeholder(2)));
    }
    sql.push_str(" order by created_at desc, id desc");
    let mut query = sqlx::query(&sql).bind(&ctx.tenant_id);
    if let Some(workspace_id) = &params.workspace_id {
        query = query.bind(workspace_id);
    }
    let secret_refs = query
        .fetch_all(&state.db.pool)
        .await?
        .into_iter()
        .map(row_to_secret_ref)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(SecretRefListResponse {
        ok: true,
        secret_refs,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/secret-refs/{secret_ref_id}",
    params(("secret_ref_id" = Uuid, Path)),
    responses((status = 200, body = SecretRefResponse), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn get_secret_ref(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(secret_ref_id): Path<Uuid>,
) -> Result<Json<SecretRefResponse>, ApiError> {
    let secret_ref =
        fetch_secret_ref(&state.db, SecretRefId(secret_ref_id), &ctx.tenant_id).await?;
    Ok(Json(SecretRefResponse {
        ok: true,
        secret_ref,
    }))
}

/// Revocation is a state transition, not a delete: the row stays queryable so
/// an operator can see that a credential reference existed and when it was
/// withdrawn. A revoked reference can never be bound to a sandbox again.
#[utoipa::path(
    delete,
    path = "/v1/secret-refs/{secret_ref_id}",
    params(("secret_ref_id" = Uuid, Path)),
    responses((status = 200, body = SecretRefResponse), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn revoke_secret_ref(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(secret_ref_id): Path<Uuid>,
) -> Result<Json<SecretRefResponse>, ApiError> {
    let secret_ref_id = SecretRefId(secret_ref_id);
    let now = Utc::now();
    let sql = format!(
        "update secret_refs set state = {}, updated_at = {}, revoked_at = {}
         where id = {} and tenant_id = {} and state = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5),
        state.db.placeholder(6)
    );
    sqlx::query(&sql)
        .bind(SecretRefState::Revoked.as_db_str())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(secret_ref_id.to_string())
        .bind(&ctx.tenant_id)
        .bind(SecretRefState::Active.as_db_str())
        .execute(&state.db.pool)
        .await?;
    // Re-read rather than trusting the update's row count: revocation is
    // idempotent, and an already-revoked reference must still return its
    // durable record instead of a spurious 404.
    let secret_ref = fetch_secret_ref(&state.db, secret_ref_id, &ctx.tenant_id).await?;
    Ok(Json(SecretRefResponse {
        ok: true,
        secret_ref,
    }))
}

const SECRET_REF_COLUMNS: &str = "id, tenant_id, workspace_id, name, backend, source_object_name, \
     source_object_key, delivery, state, created_at, updated_at, revoked_at";

pub(crate) async fn fetch_secret_ref(
    db: &Database,
    secret_ref_id: SecretRefId,
    tenant_id: &str,
) -> Result<SecretRef, ApiError> {
    let sql = format!(
        "select {SECRET_REF_COLUMNS} from secret_refs where id = {} and tenant_id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(secret_ref_id.to_string())
        .bind(tenant_id)
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("secret reference not found"))?;
    row_to_secret_ref(row)
}

fn row_to_secret_ref(row: sqlx::any::AnyRow) -> Result<SecretRef, ApiError> {
    let id: String = row.try_get("id")?;
    let backend: String = row.try_get("backend")?;
    let delivery: String = row.try_get("delivery")?;
    let state: String = row.try_get("state")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let revoked_at: Option<String> = row.try_get("revoked_at")?;
    Ok(SecretRef {
        id: SecretRefId(
            Uuid::parse_str(&id).map_err(|_| ApiError::internal("invalid secret reference id"))?,
        ),
        tenant_id: row.try_get("tenant_id")?,
        workspace_id: row.try_get("workspace_id")?,
        name: row.try_get("name")?,
        source: SecretSource {
            backend: SecretBackend::parse_db_str(&backend)
                .map_err(|error| ApiError::internal(error.to_string()))?,
            object_name: row.try_get("source_object_name")?,
            object_key: row.try_get("source_object_key")?,
        },
        delivery: SecretDelivery::parse_db_str(&delivery)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        state: SecretRefState::parse_db_str(&state)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        created_at: created_at
            .parse()
            .map_err(|_| ApiError::internal("invalid secret reference created_at"))?,
        updated_at: updated_at
            .parse()
            .map_err(|_| ApiError::internal("invalid secret reference updated_at"))?,
        revoked_at: revoked_at
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ApiError::internal("invalid secret reference revoked_at"))
            })
            .transpose()?,
    })
}

/// Resolves the references a sandbox create asked to bind into material-free
/// delivery instructions.
///
/// Fail-closed in every direction: an unknown, foreign, or revoked reference
/// fails the create rather than producing a sandbox that silently lacks a
/// credential, and all bound references must live in one workspace, because a
/// sandbox that mounts two workspaces' credentials side by side is a
/// workspace-isolation hole regardless of how the guest behaves.
pub(crate) async fn resolve_secret_mounts(
    db: &Database,
    tenant_id: &str,
    secret_ref_ids: &[SecretRefId],
) -> Result<Vec<SandboxSecretMount>, ApiError> {
    validate_secret_ref_bindings(secret_ref_ids)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let mut mounts = Vec::with_capacity(secret_ref_ids.len());
    let mut workspace_id: Option<String> = None;
    for secret_ref_id in secret_ref_ids {
        let secret_ref = fetch_secret_ref(db, *secret_ref_id, tenant_id).await?;
        if secret_ref.state != SecretRefState::Active {
            return Err(ApiError::bad_request(format!(
                "secret reference {secret_ref_id} is revoked"
            )));
        }
        match &workspace_id {
            Some(existing) if *existing != secret_ref.workspace_id => {
                return Err(ApiError::bad_request(
                    "all bound secret references must belong to one workspace",
                ));
            }
            Some(_) => {}
            None => workspace_id = Some(secret_ref.workspace_id.clone()),
        }
        mounts.push(SandboxSecretMount::from_ref(&secret_ref));
    }
    Ok(mounts)
}

pub(crate) async fn insert_sandbox_secret_bindings_on_connection(
    db: &Database,
    connection: &mut sqlx::AnyConnection,
    sandbox_id: SandboxId,
    mounts: &[SandboxSecretMount],
) -> Result<(), ApiError> {
    let now = Utc::now().to_rfc3339();
    for mount in mounts {
        let sql = format!(
            "insert into sandbox_secret_bindings (
                 sandbox_id, secret_ref_id, name, backend, source_object_name,
                 source_object_key, delivery, mount_dir, file_path, env_file_variable, created_at
             ) values ({})",
            db.placeholders(11)
        );
        sqlx::query(&sql)
            .bind(sandbox_id.to_string())
            .bind(mount.secret_ref_id.to_string())
            .bind(&mount.name)
            .bind(mount.source.backend.as_db_str())
            .bind(&mount.source.object_name)
            .bind(&mount.source.object_key)
            .bind(mount.delivery.as_db_str())
            .bind(&mount.mount_dir)
            .bind(&mount.file_path)
            .bind(&mount.env_file_variable)
            .bind(&now)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// Bindings snapshotted at create time, in a stable order. Every job that
/// re-derives a sandbox's provisioning spec reads them from here, so a
/// long-lived sandbox keeps the exact spec its Pod was provisioned with.
pub(crate) async fn fetch_sandbox_secret_mounts(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<SandboxSecretMount>, ApiError> {
    let mut connection = db.pool.acquire().await?;
    fetch_sandbox_secret_mounts_on_connection(db, &mut connection, sandbox_id).await
}

/// Same read against a caller-held connection. Callers already inside a
/// transaction must use this: taking a second SQLite connection while holding
/// a write transaction deadlocks against the database lock.
pub(crate) async fn fetch_sandbox_secret_mounts_on_connection(
    db: &Database,
    connection: &mut sqlx::AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Vec<SandboxSecretMount>, ApiError> {
    let sql = format!(
        "select secret_ref_id, name, backend, source_object_name, source_object_key,
                delivery, mount_dir, file_path, env_file_variable
         from sandbox_secret_bindings where sandbox_id = {}
         order by name asc",
        db.placeholder(1)
    );
    sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&mut *connection)
        .await?
        .into_iter()
        .map(row_to_secret_mount)
        .collect()
}

fn row_to_secret_mount(row: sqlx::any::AnyRow) -> Result<SandboxSecretMount, ApiError> {
    let secret_ref_id: String = row.try_get("secret_ref_id")?;
    let backend: String = row.try_get("backend")?;
    let delivery: String = row.try_get("delivery")?;
    Ok(SandboxSecretMount {
        secret_ref_id: SecretRefId(
            Uuid::parse_str(&secret_ref_id)
                .map_err(|_| ApiError::internal("invalid secret binding id"))?,
        ),
        name: row.try_get("name")?,
        source: SecretSource {
            backend: SecretBackend::parse_db_str(&backend)
                .map_err(|error| ApiError::internal(error.to_string()))?,
            object_name: row.try_get("source_object_name")?,
            object_key: row.try_get("source_object_key")?,
        },
        delivery: SecretDelivery::parse_db_str(&delivery)
            .map_err(|error| ApiError::internal(error.to_string()))?,
        mount_dir: row.try_get("mount_dir")?,
        file_path: row.try_get("file_path")?,
        env_file_variable: row.try_get("env_file_variable")?,
    })
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}
