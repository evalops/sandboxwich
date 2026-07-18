use crate::activity::*;
use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::ssh::*;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
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
) -> Result<Json<DesktopAccessResponse>, ApiError> {
    let desktop_session =
        fetch_desktop_session(&state.db, DesktopSessionId(desktop_session_id)).await?;
    ensure_sandbox_tenant(&state.db, desktop_session.sandbox_id, &ctx).await?;
    let access = mint_desktop_access(&desktop_session, request.ttl_seconds)?;
    // Minting desktop access is the moment a caller is about to actually use
    // the sandbox's desktop -- one of the idle-TTL activity signals.
    // Best-effort: must not fail this request if the bump itself fails.
    bump_sandbox_activity_best_effort(&state.db, desktop_session.sandbox_id, Utc::now()).await;
    Ok(Json(DesktopAccessResponse { ok: true, access }))
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
