use crate::activity::*;
use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::ssh::*;
use crate::idempotency::SkipIdempotencyResponsePersist;
use crate::reconcile::list_runtime_resources_for_sandbox;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use uuid::Uuid;

pub(crate) async fn create_desktop_session(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateDesktopSessionRequest>,
) -> Result<Json<DesktopSessionResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let desktop_session = desktop_session_from_request(sandbox_id, request)?;
    insert_desktop_session(&state.db, &desktop_session).await?;
    insert_desktop_event(
        &state.db,
        &desktop_session,
        SandboxEventKind::DesktopRequested,
    )
    .await?;

    Ok(Json(DesktopSessionResponse {
        ok: true,
        desktop_session,
    }))
}

pub(crate) async fn list_desktop_sessions(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<DesktopSessionListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let desktop_sessions = list_desktop_sessions_for_sandbox(&state.db, sandbox_id).await?;
    Ok(Json(DesktopSessionListResponse {
        ok: true,
        desktop_sessions,
    }))
}

pub(crate) async fn get_desktop_session(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(desktop_session_id): Path<Uuid>,
) -> Result<Json<DesktopSessionResponse>, ApiError> {
    let desktop_session =
        fetch_desktop_session(&state.db, DesktopSessionId(desktop_session_id)).await?;
    ensure_sandbox_tenant(&state.db, desktop_session.sandbox_id, &ctx).await?;
    Ok(Json(DesktopSessionResponse {
        ok: true,
        desktop_session,
    }))
}

pub(crate) async fn update_desktop_session_status(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(desktop_session_id): Path<Uuid>,
    Json(request): Json<UpdateDesktopSessionRequest>,
) -> Result<Json<DesktopSessionResponse>, ApiError> {
    let desktop_session_id = DesktopSessionId(desktop_session_id);
    let current = fetch_desktop_session(&state.db, desktop_session_id).await?;
    ensure_sandbox_tenant(&state.db, current.sandbox_id, &ctx).await?;
    let updated = updated_desktop_session(current, request)?;
    update_desktop_session(&state.db, &updated).await?;
    insert_desktop_event(
        &state.db,
        &updated,
        desktop_event_kind_for_status(&updated.status),
    )
    .await?;
    // A session that can no longer be connected to must not leave a live
    // desktop-access credential behind (see the `sbw_dtok_` rotate-by-revocation
    // contract); revoke them the moment it reaches a terminal state.
    if is_terminal_desktop_status(&updated.status) {
        revoke_desktop_access_credentials_for_session(&state.db, updated.id, Utc::now()).await?;
    }

    Ok(Json(DesktopSessionResponse {
        ok: true,
        desktop_session: updated,
    }))
}

pub(crate) async fn create_desktop_access(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(desktop_session_id): Path<Uuid>,
    Json(request): Json<DesktopAccessRequest>,
) -> Result<Response, ApiError> {
    let desktop_session =
        fetch_desktop_session(&state.db, DesktopSessionId(desktop_session_id)).await?;
    ensure_sandbox_tenant(&state.db, desktop_session.sandbox_id, &ctx).await?;
    // Fail closed: `mint_desktop_access` rejects a non-`Ready` or expired
    // session, so no credential row is ever written for a session a caller
    // cannot legitimately connect to.
    let mut access = mint_desktop_access(&desktop_session, request.ttl_seconds)?;
    access.transport = resolve_desktop_transport(&state.db, desktop_session.sandbox_id).await?;
    let credential = mint_desktop_access_credential(
        &state.db,
        &ctx.tenant_id,
        &desktop_session,
        access.expires_at,
    )
    .await?;
    // Minting desktop access is the moment a caller is about to actually use
    // the sandbox's desktop -- one of the idle-TTL activity signals.
    // Best-effort: must not fail this request if the bump itself fails.
    bump_sandbox_activity_best_effort(&state.db, desktop_session.sandbox_id, Utc::now()).await;
    // The body carries the one-time raw credential, so it must never be
    // persisted for idempotent replay (see `SkipIdempotencyResponsePersist`).
    let mut response = Json(DesktopAccessResponse {
        ok: true,
        access,
        credential,
    })
    .into_response();
    response
        .extensions_mut()
        .insert(SkipIdempotencyResponsePersist);
    Ok(response)
}

/// Resolves the sandbox's live brokered desktop tunnel: its persisted
/// `runtime_resources` row of kind `Service` / purpose `Desktop` (rendered by
/// the Kubernetes provider in front of the guest's noVNC bridge). Returns
/// `None` when no usable row exists yet (or it has been torn down), leaving the
/// access record metadata-only exactly as before.
///
/// A sandbox can carry more than one desktop `Service` row (e.g. re-reconciled
/// under a second cluster/namespace), so selection is deliberate rather than
/// list-order: prefer a `Ready` resource, then the most recently reconciled
/// one. Fail closed on the port -- a row whose `service_port` was never
/// recorded is skipped rather than reported with a fabricated default, so a
/// caller is never handed a port the desktop is not actually listening on.
pub(crate) async fn resolve_desktop_transport(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Option<DesktopTransport>, ApiError> {
    let resources = list_runtime_resources_for_sandbox(db, sandbox_id).await?;
    let mut candidates: Vec<RuntimeResource> = resources
        .into_iter()
        .filter(|resource| {
            resource.resource_kind == RuntimeResourceKind::Service
                && resource.purpose == RuntimeResourcePurpose::Desktop
                && resource.service_port.is_some()
                && !matches!(
                    resource.status,
                    RuntimeResourceStatus::Deleted | RuntimeResourceStatus::Destroyed
                )
        })
        .collect();
    candidates.sort_by(|a, b| {
        let a_ready = a.status == RuntimeResourceStatus::Ready;
        let b_ready = b.status == RuntimeResourceStatus::Ready;
        b_ready
            .cmp(&a_ready)
            .then_with(|| b.updated_at.cmp(&a.updated_at))
    });
    let Some(resource) = candidates.into_iter().next() else {
        return Ok(None);
    };
    let Some(service_port) = resource.service_port else {
        return Ok(None);
    };
    Ok(Some(DesktopTransport {
        kind: DesktopTransportKind::NovncWebsocket,
        runtime_resource_id: resource.id,
        service_name: resource.resource_name,
        namespace: resource.namespace,
        cluster: resource.cluster,
        service_port,
        ready: resource.status == RuntimeResourceStatus::Ready,
        status: resource.status,
    }))
}

/// Mints the one-time, sandbox-bound brokered-transport credential for a
/// desktop access record. The raw token is returned once and never persisted
/// (only its SHA-256 hash is stored); minting revokes the session's previous
/// live credential so a session has at most one usable credential at a time
/// (rotate-by-revocation, mirroring `mint_guest_token`). `expires_at` is the
/// already-clamped access expiry, so the credential never outlives the
/// session or the caller's requested TTL ceiling.
pub(crate) async fn mint_desktop_access_credential(
    db: &Database,
    tenant_id: &str,
    desktop_session: &DesktopSession,
    expires_at: DateTime<Utc>,
) -> Result<DesktopAccessCredential, ApiError> {
    let now = Utc::now();
    let token = generate_desktop_token();
    let token_hash = hash_worker_token(&token);
    let id = DesktopAccessCredentialId::new();
    let mut tx = db.pool.begin().await?;
    let revoke_sql = format!(
        "update desktop_access_credentials set revoked_at = {}
         where tenant_id = {} and desktop_session_id = {} and revoked_at is null",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    sqlx::query(&revoke_sql)
        .bind(now.to_rfc3339())
        .bind(tenant_id)
        .bind(desktop_session.id.to_string())
        .execute(&mut *tx)
        .await?;
    let insert_sql = format!(
        "insert into desktop_access_credentials
         (id, tenant_id, sandbox_id, desktop_session_id, token_hash, expires_at, revoked_at, created_at)
         values ({})",
        db.placeholders(8)
    );
    sqlx::query(&insert_sql)
        .bind(id.to_string())
        .bind(tenant_id)
        .bind(desktop_session.sandbox_id.to_string())
        .bind(desktop_session.id.to_string())
        .bind(token_hash)
        .bind(expires_at.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(DesktopAccessCredential {
        id,
        token,
        sandbox_id: desktop_session.sandbox_id,
        session_id: desktop_session.id,
        expires_at,
    })
}

/// Revokes every live brokered desktop-access credential bound to a desktop
/// session. Called when the session reaches a terminal state
/// (`Closed`/`Failed`/`Expired`) so its `sbw_dtok_` credential stops being
/// valid immediately instead of lingering until its `<=900s` expiry -- the
/// desktop it grants access to no longer exists. Idempotent: only touches rows
/// still `revoked_at is null`.
pub(crate) async fn revoke_desktop_access_credentials_for_session_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    desktop_session_id: DesktopSessionId,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update desktop_access_credentials set revoked_at = {}
         where desktop_session_id = {} and revoked_at is null",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&sql)
        .bind(now.to_rfc3339())
        .bind(desktop_session_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// Pool-backed variant of
/// [`revoke_desktop_access_credentials_for_session_on_connection`].
pub(crate) async fn revoke_desktop_access_credentials_for_session(
    db: &Database,
    desktop_session_id: DesktopSessionId,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let mut connection = db.pool.acquire().await?;
    revoke_desktop_access_credentials_for_session_on_connection(
        db,
        &mut connection,
        desktop_session_id,
        now,
    )
    .await
}

/// Whether a desktop session status is terminal -- the session can no longer be
/// connected to, so its access credentials should be revoked.
pub(crate) fn is_terminal_desktop_status(status: &DesktopSessionStatus) -> bool {
    matches!(
        status,
        DesktopSessionStatus::Closed | DesktopSessionStatus::Failed | DesktopSessionStatus::Expired
    )
}

pub(crate) fn desktop_session_from_request(
    sandbox_id: SandboxId,
    request: CreateDesktopSessionRequest,
) -> Result<DesktopSession, ApiError> {
    let now = Utc::now();
    Ok(DesktopSession {
        id: DesktopSessionId::new(),
        sandbox_id,
        status: DesktopSessionStatus::Pending,
        broker: validate_broker(
            request
                .broker
                .unwrap_or_else(|| "sandboxwich-broker".to_string()),
        )?,
        broker_url: sanitize_broker_url(request.broker_url)?,
        access_mode: request.access_mode.unwrap_or(DesktopAccessMode::Browser),
        connection_metadata: request.connection_metadata.unwrap_or_else(|| json!({})),
        created_at: now,
        updated_at: now,
        expires_at: expires_at_from_ttl(now, request.ttl_seconds.or(Some(3600)))?,
        error: None,
    })
}

pub(crate) fn updated_desktop_session(
    current: DesktopSession,
    request: UpdateDesktopSessionRequest,
) -> Result<DesktopSession, ApiError> {
    let now = Utc::now();
    let expires_at = match request.ttl_seconds {
        Some(ttl) => expires_at_from_ttl(now, Some(ttl))?,
        None => current.expires_at,
    };
    Ok(DesktopSession {
        id: current.id,
        sandbox_id: current.sandbox_id,
        status: request.status,
        broker: match request.broker {
            Some(broker) => validate_broker(broker)?,
            None => current.broker,
        },
        broker_url: match request.broker_url {
            Some(broker_url) => sanitize_broker_url(Some(broker_url))?,
            None => current.broker_url,
        },
        access_mode: request.access_mode.unwrap_or(current.access_mode),
        connection_metadata: request
            .connection_metadata
            .unwrap_or(current.connection_metadata),
        created_at: current.created_at,
        updated_at: now,
        expires_at,
        error: request.error,
    })
}

pub(crate) async fn insert_desktop_session(
    db: &Database,
    desktop_session: &DesktopSession,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into desktop_sessions
         (id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
          created_at, updated_at, expires_at, error)
         values ({})",
        db.placeholders(11)
    );
    sqlx::query(&sql)
        .bind(desktop_session.id.to_string())
        .bind(desktop_session.sandbox_id.to_string())
        .bind(desktop_session_status_to_str(&desktop_session.status))
        .bind(&desktop_session.broker)
        .bind(&desktop_session.broker_url)
        .bind(desktop_access_mode_to_str(&desktop_session.access_mode))
        .bind(serde_json::to_string(&desktop_session.connection_metadata)?)
        .bind(desktop_session.created_at.to_rfc3339())
        .bind(desktop_session.updated_at.to_rfc3339())
        .bind(desktop_session.expires_at.map(|time| time.to_rfc3339()))
        .bind(&desktop_session.error)
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(crate) async fn fetch_desktop_session(
    db: &Database,
    desktop_session_id: DesktopSessionId,
) -> Result<DesktopSession, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
                created_at, updated_at, expires_at, error
         from desktop_sessions
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(desktop_session_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("desktop session not found"))?;

    row_to_desktop_session(row)
}

pub(crate) async fn list_desktop_sessions_for_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<DesktopSession>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
                created_at, updated_at, expires_at, error
         from desktop_sessions
         where sandbox_id = {}
         order by updated_at desc, created_at desc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;

    rows.into_iter().map(row_to_desktop_session).collect()
}

pub(crate) async fn update_desktop_session(
    db: &Database,
    desktop_session: &DesktopSession,
) -> Result<(), ApiError> {
    let sql = format!(
        "update desktop_sessions
         set status = {}, broker = {}, broker_url = {}, access_mode = {},
             connection_metadata = {}, updated_at = {}, expires_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9)
    );
    let result = sqlx::query(&sql)
        .bind(desktop_session_status_to_str(&desktop_session.status))
        .bind(&desktop_session.broker)
        .bind(&desktop_session.broker_url)
        .bind(desktop_access_mode_to_str(&desktop_session.access_mode))
        .bind(serde_json::to_string(&desktop_session.connection_metadata)?)
        .bind(desktop_session.updated_at.to_rfc3339())
        .bind(desktop_session.expires_at.map(|time| time.to_rfc3339()))
        .bind(&desktop_session.error)
        .bind(desktop_session.id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("desktop session not found"));
    }
    Ok(())
}

pub(crate) async fn expire_due_desktop_sessions(
    db: &Database,
) -> Result<Vec<DesktopSession>, ApiError> {
    let now = Utc::now();
    let rows = sqlx::query(
        "select id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
                created_at, updated_at, expires_at, error
         from desktop_sessions
         where status in ('pending', 'ready') and expires_at is not null
         order by expires_at asc, id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let mut expired = Vec::new();
    for row in rows {
        let desktop_session = row_to_desktop_session(row)?;
        let Some(expires_at) = desktop_session.expires_at else {
            continue;
        };
        if expires_at > now {
            continue;
        }

        let mut tx = db.pool.begin().await?;
        let expired_session = async {
            let won_transition =
                expire_active_desktop_session_on_connection(db, &mut tx, desktop_session.id, now)
                    .await?;
            if !won_transition {
                // The session's TTL was extended (or its status/broker/etc. was
                // otherwise updated), or another caller already expired it,
                // since this sweep's SELECT was taken. A blind full-row
                // overwrite here would clobber that concurrent update, so skip
                // side effects entirely instead.
                return Ok(None);
            }
            let expired_session =
                fetch_desktop_session_on_connection(db, &mut tx, desktop_session.id).await?;
            // An expired session is terminal: kill its access credentials in the
            // same transaction so none outlives the session it is bound to.
            revoke_desktop_access_credentials_for_session_on_connection(
                db,
                &mut tx,
                desktop_session.id,
                now,
            )
            .await?;
            insert_desktop_event_on_connection(
                db,
                &mut tx,
                &expired_session,
                SandboxEventKind::DesktopExpired,
            )
            .await?;
            Ok(Some(expired_session))
        }
        .await;
        match expired_session {
            Ok(Some(expired_session)) => {
                tx.commit().await?;
                expired.push(expired_session);
            }
            Ok(None) => {
                tx.commit().await?;
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back desktop session expiration");
                }
                return Err(error);
            }
        }
    }

    Ok(expired)
}

/// Guarded, atomic `pending`/`ready` -> `expired` transition for a desktop
/// session that a sweep has observed as due. Returns `true` only if this call
/// performed the transition (`rows_affected() == 1`); returns `false` if the
/// session's TTL was extended (via `update_desktop_session_status`) or it was
/// already expired by another caller since the sweep's SELECT was taken. This
/// only touches `status`, `updated_at`, and `error` (unlike the previous
/// implementation, which blindly overwrote every column from the sweep's
/// stale in-memory copy via `update_desktop_session`), so a concurrent update
/// to e.g. `connection_metadata` is not lost either. Mirrors
/// `expire_active_lease_on_connection`'s guard against the renewal-vs-expiry
/// race.
pub(crate) async fn expire_active_desktop_session_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    desktop_session_id: DesktopSessionId,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let sql = format!(
        "update desktop_sessions
         set status = {}, updated_at = {}, error = {}
         where id = {} and status in ('pending', 'ready')
           and expires_at is not null and expires_at <= {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5)
    );
    let result = sqlx::query(&sql)
        .bind(desktop_session_status_to_str(
            &DesktopSessionStatus::Expired,
        ))
        .bind(now.to_rfc3339())
        .bind("desktop session expired")
        .bind(desktop_session_id.to_string())
        .bind(now.to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(result.rows_affected() == 1)
}

pub(crate) async fn fetch_desktop_session_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    desktop_session_id: DesktopSessionId,
) -> Result<DesktopSession, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, broker, broker_url, access_mode, connection_metadata,
                created_at, updated_at, expires_at, error
         from desktop_sessions
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(desktop_session_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("desktop session not found"))?;

    row_to_desktop_session(row)
}

pub(crate) async fn insert_desktop_event(
    db: &Database,
    desktop_session: &DesktopSession,
    kind: SandboxEventKind,
) -> Result<SandboxEvent, ApiError> {
    insert_event(
        db,
        desktop_session.sandbox_id,
        kind,
        json!({
            "desktopSessionId": desktop_session.id,
            "status": desktop_session.status,
            "broker": desktop_session.broker,
            "accessMode": desktop_session.access_mode,
            "connectionMetadata": desktop_session.connection_metadata,
            "expiresAt": desktop_session.expires_at,
            "error": desktop_session.error
        }),
    )
    .await
}

pub(crate) async fn insert_desktop_event_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    desktop_session: &DesktopSession,
    kind: SandboxEventKind,
) -> Result<SandboxEvent, ApiError> {
    insert_event_on_connection(
        db,
        connection,
        desktop_session.sandbox_id,
        kind,
        json!({
            "desktopSessionId": desktop_session.id,
            "status": desktop_session.status,
            "broker": desktop_session.broker,
            "accessMode": desktop_session.access_mode,
            "connectionMetadata": desktop_session.connection_metadata,
            "expiresAt": desktop_session.expires_at,
            "error": desktop_session.error
        }),
    )
    .await
}

pub(crate) fn desktop_event_kind_for_status(status: &DesktopSessionStatus) -> SandboxEventKind {
    match status {
        DesktopSessionStatus::Pending => SandboxEventKind::DesktopRequested,
        DesktopSessionStatus::Ready => SandboxEventKind::DesktopReady,
        DesktopSessionStatus::Failed => SandboxEventKind::DesktopFailed,
        DesktopSessionStatus::Closed => SandboxEventKind::DesktopClosed,
        DesktopSessionStatus::Expired => SandboxEventKind::DesktopExpired,
    }
}

pub(crate) fn mint_desktop_access(
    desktop_session: &DesktopSession,
    ttl_seconds: Option<u64>,
) -> Result<DesktopAccess, ApiError> {
    if desktop_session.status != DesktopSessionStatus::Ready {
        return Err(ApiError::bad_request("desktop session is not ready"));
    }

    let now = Utc::now();
    let ttl_seconds = ttl_seconds.unwrap_or(300);
    if ttl_seconds == 0 {
        return Err(ApiError::bad_request(
            "desktop access ttl_seconds must be greater than 0",
        ));
    }
    let ttl_seconds = ttl_seconds.min(900);
    let mut expires_at = expires_at_from_ttl(now, Some(ttl_seconds))?
        .ok_or_else(|| ApiError::internal("failed to calculate desktop access expiry"))?;
    if let Some(session_expires_at) = desktop_session.expires_at {
        if session_expires_at <= now {
            return Err(ApiError::bad_request("desktop session has expired"));
        }
        if session_expires_at < expires_at {
            expires_at = session_expires_at;
        }
    }

    Ok(DesktopAccess {
        session_id: desktop_session.id,
        sandbox_id: desktop_session.sandbox_id,
        broker: desktop_session.broker.clone(),
        access_mode: desktop_session.access_mode.clone(),
        access_url: desktop_access_url(desktop_session),
        expires_at,
        connection_metadata: desktop_session.connection_metadata.clone(),
        // Resolved from persisted runtime resources by the caller after minting.
        transport: None,
    })
}

pub(crate) fn desktop_access_url(desktop_session: &DesktopSession) -> String {
    let mode = desktop_access_mode_to_str(&desktop_session.access_mode);
    match &desktop_session.broker_url {
        Some(broker_url) => format!(
            "{broker_url}/sessions/{}/connect/{mode}",
            desktop_session.id
        ),
        None => format!(
            "sandboxwich://desktop/{}/connect/{mode}",
            desktop_session.id
        ),
    }
}
