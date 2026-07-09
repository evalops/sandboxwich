use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::workers::*;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use uuid::Uuid;

pub(crate) async fn request_ssh_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<RequestSshKeyRequest>,
) -> Result<Json<SshKeyResponse>, ApiError> {
    if request.public_key.trim().is_empty() {
        return Err(ApiError::bad_request("public_key is required"));
    }
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let now = Utc::now();
    let ssh_key = SshKey {
        id: SshKeyId::new(),
        sandbox_id,
        public_key: request.public_key,
        principal: request.principal.unwrap_or_else(|| "default".to_string()),
        status: SshKeyStatus::Requested,
        requested_at: now,
        updated_at: now,
        applied_at: None,
        error: None,
    };
    insert_ssh_key(&state.db, &ssh_key).await?;

    Ok(Json(SshKeyResponse { ok: true, ssh_key }))
}

pub(crate) async fn list_ssh_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SshKeyListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let sql = format!(
        "select id, sandbox_id, public_key, principal, status, requested_at, updated_at, applied_at, error
         from ssh_keys
         where sandbox_id = {}
         order by requested_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&state.db.pool)
        .await?;
    let ssh_keys = rows
        .into_iter()
        .map(row_to_ssh_key)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(SshKeyListResponse { ok: true, ssh_keys }))
}

pub(crate) async fn create_ssh_access(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<SshAccessRequest>,
) -> Result<Json<SshAccessResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let guest_health = fetch_guest_health(&state.db, sandbox_id).await?;
    let ssh_access = mint_ssh_access(sandbox_id, guest_health.as_ref(), request)?;
    Ok(Json(SshAccessResponse {
        ok: true,
        ssh_access,
    }))
}

pub(crate) async fn update_ssh_key_status(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(ssh_key_id): Path<Uuid>,
    Json(request): Json<UpdateSshKeyStatusRequest>,
) -> Result<Json<SshKeyResponse>, ApiError> {
    let ssh_key_id = SshKeyId(ssh_key_id);
    let ssh_key = fetch_ssh_key(&state.db, ssh_key_id).await?;
    ensure_sandbox_tenant(&state.db, ssh_key.sandbox_id, &ctx).await?;
    let now = Utc::now();
    let applied_at = if request.status == SshKeyStatus::Applied {
        Some(now.to_rfc3339())
    } else {
        None
    };
    let sql = format!(
        "update ssh_keys
         set status = {}, updated_at = {}, applied_at = {}, error = {}
         where id = {}",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3),
        state.db.placeholder(4),
        state.db.placeholder(5)
    );
    sqlx::query(&sql)
        .bind(ssh_key_status_to_str(&request.status))
        .bind(now.to_rfc3339())
        .bind(applied_at)
        .bind(request.error)
        .bind(ssh_key_id.to_string())
        .execute(&state.db.pool)
        .await?;
    let ssh_key = fetch_ssh_key(&state.db, ssh_key_id).await?;

    Ok(Json(SshKeyResponse { ok: true, ssh_key }))
}

pub(crate) async fn fetch_ssh_key(db: &Database, ssh_key_id: SshKeyId) -> Result<SshKey, ApiError> {
    let sql = format!(
        "select id, sandbox_id, public_key, principal, status, requested_at, updated_at, applied_at, error
         from ssh_keys
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(ssh_key_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("ssh key not found"))?;

    row_to_ssh_key(row)
}

pub(crate) fn validate_broker(broker: String) -> Result<String, ApiError> {
    let broker = broker.trim();
    if broker.is_empty() {
        return Err(ApiError::bad_request("desktop broker is required"));
    }
    Ok(broker.to_string())
}

pub(crate) fn sanitize_broker_url(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        return Err(ApiError::bad_request("desktop broker_url cannot be empty"));
    }
    if !(value.starts_with("https://") || value.starts_with("http://")) {
        return Err(ApiError::bad_request(
            "desktop broker_url must start with http:// or https://",
        ));
    }
    if value.contains('?') || value.contains('#') || value.contains('@') {
        return Err(ApiError::bad_request(
            "desktop broker_url must not include credentials, query, or fragment data",
        ));
    }
    Ok(Some(value.to_string()))
}

pub(crate) fn mint_ssh_access(
    sandbox_id: SandboxId,
    guest_health: Option<&GuestHealth>,
    request: SshAccessRequest,
) -> Result<SshAccess, ApiError> {
    let now = Utc::now();
    let ttl_seconds = request.ttl_seconds.unwrap_or(300);
    if ttl_seconds == 0 {
        return Err(ApiError::bad_request(
            "ssh access ttl_seconds must be greater than 0",
        ));
    }
    let ttl_seconds = ttl_seconds.min(900);
    let expires_at = expires_at_from_ttl(now, Some(ttl_seconds))?
        .ok_or_else(|| ApiError::internal("failed to calculate ssh access expiry"))?;
    let principal = request
        .principal
        .filter(|principal| !principal.trim().is_empty())
        .unwrap_or_else(|| "sandboxwich".to_string());
    let ssh = guest_health
        .and_then(|health| health.checks.get("ssh"))
        .and_then(|value| value.as_object());
    let host = ssh
        .and_then(|ssh| ssh.get("host"))
        .and_then(|value| value.as_str())
        .unwrap_or("127.0.0.1")
        .to_string();
    let port = ssh
        .and_then(|ssh| ssh.get("port"))
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .filter(|port| *port > 0)
        .unwrap_or(22);
    let username = ssh
        .and_then(|ssh| ssh.get("username"))
        .and_then(|value| value.as_str())
        .unwrap_or("ubuntu")
        .to_string();

    Ok(SshAccess {
        sandbox_id,
        host: host.clone(),
        port,
        username: username.clone(),
        principal,
        command: format!("ssh -p {port} {username}@{host}"),
        scp_command_prefix: format!("scp -P {port}"),
        expires_at,
        connection_metadata: json!({
            "source": "guest_health",
            "guestStatus": guest_health.map(|health| &health.status),
            "sandboxId": sandbox_id
        }),
    })
}

pub(crate) async fn insert_ssh_key(db: &Database, ssh_key: &SshKey) -> Result<(), ApiError> {
    let sql = format!(
        "insert into ssh_keys
         (id, sandbox_id, public_key, principal, status, requested_at, updated_at, applied_at, error)
         values ({})",
        db.placeholders(9)
    );
    sqlx::query(&sql)
        .bind(ssh_key.id.to_string())
        .bind(ssh_key.sandbox_id.to_string())
        .bind(&ssh_key.public_key)
        .bind(&ssh_key.principal)
        .bind(ssh_key_status_to_str(&ssh_key.status))
        .bind(ssh_key.requested_at.to_rfc3339())
        .bind(ssh_key.updated_at.to_rfc3339())
        .bind(ssh_key.applied_at.map(|time| time.to_rfc3339()))
        .bind(&ssh_key.error)
        .execute(&db.pool)
        .await?;
    Ok(())
}
