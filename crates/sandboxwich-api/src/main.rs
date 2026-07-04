use std::net::SocketAddr;

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use sandboxwich_core::{
    CommandId, CommandListResponse, CommandRequest, CommandResponse, CommandRun, CommandStatus,
    CreateSandboxRequest, ErrorEnvelope, EventId, EventListResponse, HealthResponse,
    PromptQueuedResponse, PromptRequest, Sandbox, SandboxEvent, SandboxEventKind, SandboxId,
    SandboxListResponse, SandboxResponse, SandboxState, SnapshotId,
};
use serde_json::json;
use sqlx::{
    Any, AnyPool, QueryBuilder, Row, Sqlite,
    any::{AnyPoolOptions, AnyRow},
    migrate::MigrateDatabase,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    pool: AnyPool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind = std::env::var("SANDBOXWICH_BIND").unwrap_or_else(|_| "127.0.0.1:3217".to_string());
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid SANDBOXWICH_BIND value: {bind}"))?;

    let database_url = std::env::var("SANDBOXWICH_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://sandboxwich.db".to_string());
    let pool = connect_database(&database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, %database_url, "sandboxwich-api listening");
    axum::serve(listener, app(AppState { pool }))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn connect_database(database_url: &str) -> anyhow::Result<AnyPool> {
    sqlx::any::install_default_drivers();
    if database_url.starts_with("sqlite:")
        && !Sqlite::database_exists(database_url).await.unwrap_or(false)
    {
        Sqlite::create_database(database_url).await?;
    }

    Ok(AnyPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?)
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/sandboxes", get(list_sandboxes).post(create_sandbox))
        .route("/sandboxes/{sandbox_id}", get(get_sandbox))
        .route("/sandboxes/{sandbox_id}/stop", post(stop_sandbox))
        .route("/sandboxes/{sandbox_id}/resume", post(resume_sandbox))
        .route("/sandboxes/{sandbox_id}/fork", post(fork_sandbox))
        .route(
            "/sandboxes/{sandbox_id}/commands",
            get(list_commands).post(queue_command),
        )
        .route("/sandboxes/{sandbox_id}/prompt", post(queue_prompt))
        .route("/sandboxes/{sandbox_id}/events", get(list_events))
        .route("/commands/{command_id}", get(get_command))
        .with_state(state)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install shutdown signal handler");
    }
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "sandboxwich-api".to_string(),
    })
}

async fn create_sandbox(
    State(state): State<AppState>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let now = Utc::now();
    let sandbox = Sandbox {
        id: SandboxId::new(),
        name: request.name.unwrap_or_else(|| "fresh-sandwich".to_string()),
        state: SandboxState::Ready,
        template: request.template.unwrap_or_else(|| "ubuntu-dev".to_string()),
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(Some(3600)),
        parent_snapshot_id: None,
    };

    insert_sandbox(&state.pool, &sandbox).await?;
    insert_event(
        &state.pool,
        sandbox.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": sandbox.state,
            "reason": "created"
        }),
    )
    .await?;

    Ok(Json(SandboxResponse { ok: true, sandbox }))
}

async fn list_sandboxes(
    State(state): State<AppState>,
) -> Result<Json<SandboxListResponse>, ApiError> {
    let rows = sqlx::query(
        "select id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         order by created_at asc",
    )
    .fetch_all(&state.pool)
    .await?;

    let sandboxes = rows
        .into_iter()
        .map(row_to_sandbox)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(SandboxListResponse {
        ok: true,
        sandboxes,
    }))
}

async fn get_sandbox(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sandbox = fetch_sandbox(&state.pool, SandboxId(sandbox_id)).await?;
    Ok(Json(SandboxResponse { ok: true, sandbox }))
}

async fn stop_sandbox(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    transition_sandbox(
        &state.pool,
        SandboxId(sandbox_id),
        SandboxState::Archived,
        "stopped",
    )
    .await
}

async fn resume_sandbox(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    transition_sandbox(
        &state.pool,
        SandboxId(sandbox_id),
        SandboxState::Ready,
        "resumed",
    )
    .await
}

async fn fork_sandbox(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let parent = fetch_sandbox(&state.pool, SandboxId(sandbox_id)).await?;
    let now = Utc::now();
    let child = Sandbox {
        id: SandboxId::new(),
        name: request
            .name
            .unwrap_or_else(|| format!("{}-fork", parent.name)),
        state: SandboxState::Ready,
        template: request.template.unwrap_or(parent.template),
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(parent.ttl_seconds),
        parent_snapshot_id: Some(SnapshotId::new()),
    };

    insert_sandbox(&state.pool, &child).await?;
    insert_event(
        &state.pool,
        child.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": child.state,
            "reason": "forked",
            "parentSandboxId": parent.id
        }),
    )
    .await?;

    Ok(Json(SandboxResponse {
        ok: true,
        sandbox: child,
    }))
}

async fn queue_command(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CommandRequest>,
) -> Result<Json<CommandResponse>, ApiError> {
    if request.argv.is_empty() {
        return Err(ApiError::bad_request("argv must contain at least one item"));
    }

    let sandbox_id = SandboxId(sandbox_id);
    fetch_sandbox(&state.pool, sandbox_id).await?;

    let now = Utc::now();
    let command = CommandRun {
        id: CommandId::new(),
        sandbox_id,
        status: CommandStatus::Finished,
        argv: request.argv,
        cwd: request.cwd,
        exit_code: Some(0),
        stdout: "dry-run: worker backend is not connected yet\n".to_string(),
        stderr: String::new(),
        created_at: now,
        finished_at: Some(now),
    };

    insert_command(&state.pool, &command).await?;
    insert_event(
        &state.pool,
        sandbox_id,
        SandboxEventKind::CommandQueued,
        json!({
            "commandId": command.id,
            "argv": command.argv
        }),
    )
    .await?;
    insert_event(
        &state.pool,
        sandbox_id,
        SandboxEventKind::CommandFinished,
        json!({
            "commandId": command.id,
            "exitCode": command.exit_code,
            "stdout": command.stdout
        }),
    )
    .await?;

    Ok(Json(CommandResponse { ok: true, command }))
}

async fn list_commands(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<CommandListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    fetch_sandbox(&state.pool, sandbox_id).await?;

    let mut query = QueryBuilder::<Any>::new(
        "select id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at
         from commands
         where sandbox_id = ",
    );
    query
        .push_bind(sandbox_id.to_string())
        .push(" order by created_at asc, id asc");

    let rows = query.build().fetch_all(&state.pool).await?;
    let commands = rows
        .into_iter()
        .map(row_to_command)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(CommandListResponse { ok: true, commands }))
}

async fn get_command(
    State(state): State<AppState>,
    Path(command_id): Path<Uuid>,
) -> Result<Json<CommandResponse>, ApiError> {
    let command = fetch_command(&state.pool, CommandId(command_id)).await?;
    Ok(Json(CommandResponse { ok: true, command }))
}

async fn queue_prompt(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<PromptRequest>,
) -> Result<Json<PromptQueuedResponse>, ApiError> {
    if request.instructions.trim().is_empty() {
        return Err(ApiError::bad_request("instructions are required"));
    }

    let sandbox_id = SandboxId(sandbox_id);
    fetch_sandbox(&state.pool, sandbox_id).await?;

    let event = insert_event(
        &state.pool,
        sandbox_id,
        SandboxEventKind::PromptQueued,
        json!({
            "engine": request.engine,
            "model": request.model,
            "effort": request.effort,
            "instructions": request.instructions
        }),
    )
    .await?;

    Ok(Json(PromptQueuedResponse { ok: true, event }))
}

async fn list_events(
    State(state): State<AppState>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<EventListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    fetch_sandbox(&state.pool, sandbox_id).await?;

    let mut query = QueryBuilder::<Any>::new(
        "select id, sandbox_id, kind, data, created_at
         from sandbox_events
         where sandbox_id = ",
    );
    query
        .push_bind(sandbox_id.to_string())
        .push(" order by created_at asc, id asc");
    let rows = query.build().fetch_all(&state.pool).await?;

    let events = rows
        .into_iter()
        .map(row_to_event)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(EventListResponse { ok: true, events }))
}

async fn transition_sandbox(
    pool: &AnyPool,
    sandbox_id: SandboxId,
    next_state: SandboxState,
    reason: &'static str,
) -> Result<Json<SandboxResponse>, ApiError> {
    fetch_sandbox(pool, sandbox_id).await?;
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let mut query = QueryBuilder::<Any>::new("update sandboxes set state = ");
    query
        .push_bind(state)
        .push(", updated_at = ")
        .push_bind(now.to_rfc3339())
        .push(" where id = ")
        .push_bind(sandbox_id.to_string());
    let result = query.build().execute(pool).await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("sandbox not found"));
    }

    insert_event(
        pool,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": next_state,
            "reason": reason
        }),
    )
    .await?;

    let sandbox = fetch_sandbox(pool, sandbox_id).await?;
    Ok(Json(SandboxResponse { ok: true, sandbox }))
}

async fn fetch_sandbox(pool: &AnyPool, sandbox_id: SandboxId) -> Result<Sandbox, ApiError> {
    let mut query = QueryBuilder::<Any>::new(
        "select id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where id = ",
    );
    query.push_bind(sandbox_id.to_string());
    let row = query
        .build()
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    row_to_sandbox(row)
}

async fn fetch_command(pool: &AnyPool, command_id: CommandId) -> Result<CommandRun, ApiError> {
    let mut query = QueryBuilder::<Any>::new(
        "select id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at
         from commands
         where id = ",
    );
    query.push_bind(command_id.0.to_string());
    let row = query
        .build()
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::not_found("command not found"))?;

    row_to_command(row)
}

async fn insert_sandbox(pool: &AnyPool, sandbox: &Sandbox) -> Result<(), ApiError> {
    let mut query = QueryBuilder::<Any>::new(
        "insert into sandboxes
         (id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values (",
    );
    query
        .push_bind(sandbox.id.to_string())
        .push(", ")
        .push_bind(&sandbox.name)
        .push(", ")
        .push_bind(state_to_str(&sandbox.state))
        .push(", ")
        .push_bind(&sandbox.template)
        .push(", ")
        .push_bind(sandbox.created_at.to_rfc3339())
        .push(", ")
        .push_bind(sandbox.updated_at.to_rfc3339())
        .push(", ")
        .push_bind(sandbox.ttl_seconds.map(|ttl| ttl as i64))
        .push(", ")
        .push_bind(
            sandbox
                .parent_snapshot_id
                .map(|snapshot| snapshot.0.to_string()),
        )
        .push(")");

    query.build().execute(pool).await?;
    Ok(())
}

async fn insert_command(pool: &AnyPool, command: &CommandRun) -> Result<(), ApiError> {
    let mut query = QueryBuilder::<Any>::new(
        "insert into commands
         (id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at)
         values (",
    );
    query
        .push_bind(command.id.0.to_string())
        .push(", ")
        .push_bind(command.sandbox_id.to_string())
        .push(", ")
        .push_bind(command_status_to_str(&command.status))
        .push(", ")
        .push_bind(serde_json::to_string(&command.argv)?)
        .push(", ")
        .push_bind(&command.cwd)
        .push(", ")
        .push_bind(command.exit_code)
        .push(", ")
        .push_bind(&command.stdout)
        .push(", ")
        .push_bind(&command.stderr)
        .push(", ")
        .push_bind(command.created_at.to_rfc3339())
        .push(", ")
        .push_bind(command.finished_at.map(|time| time.to_rfc3339()))
        .push(")");

    query.build().execute(pool).await?;
    Ok(())
}

async fn insert_event(
    pool: &AnyPool,
    sandbox_id: SandboxId,
    kind: SandboxEventKind,
    data: serde_json::Value,
) -> Result<SandboxEvent, ApiError> {
    let event = SandboxEvent {
        id: EventId::new(),
        sandbox_id,
        kind,
        data,
        created_at: Utc::now(),
    };

    let mut query = QueryBuilder::<Any>::new(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values (",
    );
    query
        .push_bind(event.id.0.to_string())
        .push(", ")
        .push_bind(event.sandbox_id.to_string())
        .push(", ")
        .push_bind(event_kind_to_str(&event.kind))
        .push(", ")
        .push_bind(serde_json::to_string(&event.data)?)
        .push(", ")
        .push_bind(event.created_at.to_rfc3339())
        .push(")");

    query.build().execute(pool).await?;

    Ok(event)
}

fn row_to_sandbox(row: AnyRow) -> Result<Sandbox, ApiError> {
    let id: String = row.try_get("id")?;
    let state: String = row.try_get("state")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let ttl_seconds: Option<i64> = row.try_get("ttl_seconds")?;
    let parent_snapshot_id: Option<String> = row.try_get("parent_snapshot_id")?;

    Ok(Sandbox {
        id: SandboxId(parse_uuid(&id)?),
        name: row.try_get("name")?,
        state: parse_state(&state)?,
        template: row.try_get("template")?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        ttl_seconds: ttl_seconds.map(|ttl| ttl as u64),
        parent_snapshot_id: parent_snapshot_id
            .map(|snapshot| parse_uuid(&snapshot).map(SnapshotId))
            .transpose()?,
    })
}

fn row_to_event(row: AnyRow) -> Result<SandboxEvent, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let kind: String = row.try_get("kind")?;
    let data: String = row.try_get("data")?;
    let created_at: String = row.try_get("created_at")?;

    Ok(SandboxEvent {
        id: EventId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        kind: parse_event_kind(&kind)?,
        data: serde_json::from_str(&data)?,
        created_at: parse_timestamp(&created_at)?,
    })
}

fn row_to_command(row: AnyRow) -> Result<CommandRun, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let argv: String = row.try_get("argv")?;
    let created_at: String = row.try_get("created_at")?;
    let finished_at: Option<String> = row.try_get("finished_at")?;

    Ok(CommandRun {
        id: CommandId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_command_status(&status)?,
        argv: serde_json::from_str(&argv)?,
        cwd: row.try_get("cwd")?,
        exit_code: row.try_get("exit_code")?,
        stdout: row.try_get("stdout")?,
        stderr: row.try_get("stderr")?,
        created_at: parse_timestamp(&created_at)?,
        finished_at: finished_at.map(|time| parse_timestamp(&time)).transpose()?,
    })
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::internal("database contains invalid uuid"))
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| ApiError::internal("database contains invalid timestamp"))
}

fn state_to_str(state: &SandboxState) -> &'static str {
    match state {
        SandboxState::Provisioning => "provisioning",
        SandboxState::Ready => "ready",
        SandboxState::Running => "running",
        SandboxState::Idle => "idle",
        SandboxState::Archiving => "archiving",
        SandboxState::Archived => "archived",
        SandboxState::Error => "error",
    }
}

fn parse_state(value: &str) -> Result<SandboxState, ApiError> {
    match value {
        "provisioning" => Ok(SandboxState::Provisioning),
        "ready" => Ok(SandboxState::Ready),
        "running" => Ok(SandboxState::Running),
        "idle" => Ok(SandboxState::Idle),
        "archiving" => Ok(SandboxState::Archiving),
        "archived" => Ok(SandboxState::Archived),
        "error" => Ok(SandboxState::Error),
        _ => Err(ApiError::internal(
            "database contains invalid sandbox state",
        )),
    }
}

fn command_status_to_str(status: &CommandStatus) -> &'static str {
    match status {
        CommandStatus::Queued => "queued",
        CommandStatus::Running => "running",
        CommandStatus::Finished => "finished",
        CommandStatus::Failed => "failed",
    }
}

fn parse_command_status(value: &str) -> Result<CommandStatus, ApiError> {
    match value {
        "queued" => Ok(CommandStatus::Queued),
        "running" => Ok(CommandStatus::Running),
        "finished" => Ok(CommandStatus::Finished),
        "failed" => Ok(CommandStatus::Failed),
        _ => Err(ApiError::internal(
            "database contains invalid command status",
        )),
    }
}

fn event_kind_to_str(kind: &SandboxEventKind) -> &'static str {
    match kind {
        SandboxEventKind::LifecycleChanged => "lifecycle_changed",
        SandboxEventKind::CommandQueued => "command_queued",
        SandboxEventKind::CommandStarted => "command_started",
        SandboxEventKind::CommandOutput => "command_output",
        SandboxEventKind::CommandFinished => "command_finished",
        SandboxEventKind::PromptQueued => "prompt_queued",
        SandboxEventKind::PromptFinished => "prompt_finished",
        SandboxEventKind::DesktopReady => "desktop_ready",
    }
}

fn parse_event_kind(value: &str) -> Result<SandboxEventKind, ApiError> {
    match value {
        "lifecycle_changed" => Ok(SandboxEventKind::LifecycleChanged),
        "command_queued" => Ok(SandboxEventKind::CommandQueued),
        "command_started" => Ok(SandboxEventKind::CommandStarted),
        "command_output" => Ok(SandboxEventKind::CommandOutput),
        "command_finished" => Ok(SandboxEventKind::CommandFinished),
        "prompt_queued" => Ok(SandboxEventKind::PromptQueued),
        "prompt_finished" => Ok(SandboxEventKind::PromptFinished),
        "desktop_ready" => Ok(SandboxEventKind::DesktopReady),
        _ => Err(ApiError::internal("database contains invalid event kind")),
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database error");
        Self::internal("database operation failed")
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "json persistence error");
        Self::internal("json persistence failed")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope::new(self.code, self.message)),
        )
            .into_response()
    }
}
