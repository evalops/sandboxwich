use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::jobs::*;
use crate::pagination::*;
use crate::rows::*;
use crate::state::*;
use crate::util::*;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

pub(crate) const MAX_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_COMMAND_OUTPUT_CHUNKS: i64 = 4_096;
pub(crate) const MAX_COMMAND_OUTPUT_CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MATERIALIZED_OUTPUT_CHUNKS: i64 = 64;
pub(crate) const MATERIALIZED_CHUNK_CHARS: usize = 64 * 1024;

pub(crate) fn validate_command_output_bounds(
    existing_chunks: i64,
    existing_bytes: i64,
    new_chunk_bytes: usize,
) -> Result<(), ApiError> {
    if new_chunk_bytes > MAX_COMMAND_OUTPUT_CHUNK_BYTES {
        return Err(ApiError::bad_request("command output chunk exceeds 2 MiB"));
    }
    if existing_chunks >= MAX_COMMAND_OUTPUT_CHUNKS {
        return Err(ApiError::bad_request("command output exceeds 4096 chunks"));
    }
    let new_chunk_bytes = i64::try_from(new_chunk_bytes)
        .map_err(|_| ApiError::bad_request("command output chunk is too large"))?;
    if existing_bytes.saturating_add(new_chunk_bytes) > MAX_COMMAND_OUTPUT_BYTES as i64 {
        return Err(ApiError::bad_request("command output exceeds 4 MiB"));
    }
    Ok(())
}

/// Clamps a client-requested command execution timeout to
/// `(0, MAX_COMMAND_TIMEOUT_SECS]`, falling back to
/// `DEFAULT_COMMAND_TIMEOUT_SECS` when the client omits one. This is what
/// stands between a client and requesting an effectively-unbounded command
/// execution (or, via `Some(0)`, one that always times out immediately):
/// every `RunCommand` job's payload carries the result of this function as
/// `timeoutSecs`, which `sandboxwich-agent`'s `execute_streaming` and
/// `sandboxwich-worker`'s `kubectl exec` wrapper both bound their command
/// execution to.
pub(crate) fn effective_command_timeout_secs(requested: Option<u64>) -> u64 {
    requested
        .map(|value| value.clamp(1, MAX_COMMAND_TIMEOUT_SECS))
        .unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECS)
}

#[utoipa::path(post, path = "/v1/sandboxes/{sandbox_id}/commands", params(("sandbox_id" = Uuid, Path)), responses((status = 202, description = "Command accepted with an Operation resource"), (status = 400, body = ErrorEnvelope)))]
pub(crate) async fn queue_command(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CommandRequest>,
) -> Result<(StatusCode, Json<QueueCommandResponse>), ApiError> {
    if request.argv.is_empty() {
        return Err(ApiError::bad_request("argv must contain at least one item"));
    }

    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let now = Utc::now();
    let env = request.env;
    let timeout_secs = effective_command_timeout_secs(request.timeout_secs);
    let command = CommandRun {
        id: CommandId::new(),
        sandbox_id,
        status: CommandStatus::Queued,
        argv: request.argv,
        cwd: request.cwd,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        created_at: now,
        finished_at: None,
    };

    let job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id,
        kind: JobKind::RunCommand,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "commandId": command.id,
            "argv": command.argv,
            "cwd": command.cwd,
            "env": env,
            "timeoutSecs": timeout_secs,
            "provisionSpec": SandboxProvisionSpec {
                memory_limit: sandbox.memory_limit.clone(),
                network_egress: sandbox.network_egress.clone(),
            }
        }),
        required_capability: WorkerCapability::RunCommand,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };

    insert_command(&state.db, &command).await?;
    insert_job(&state.db, &job).await?;
    insert_event(
        &state.db,
        sandbox_id,
        SandboxEventKind::CommandQueued,
        json!({
            "commandId": command.id,
            "argv": command.argv
        }),
    )
    .await?;
    let command_id = command.id;
    Ok((
        StatusCode::ACCEPTED,
        Json(QueueCommandResponse {
            ok: true,
            command,
            queued_job: QueuedCommandJob {
                id: job.id,
                sandbox_id,
                command_id,
                kind: JobKind::RunCommand,
                status: JobStatus::Queued,
                required_capability: WorkerCapability::RunCommand,
            },
            operation: Operation {
                id: job.id.0,
                kind: OperationKind::RunCommand,
                status: OperationStatus::Queued,
                resource_id: Some(command_id.0),
                created_at: job.created_at,
                updated_at: job.updated_at,
                error_code: None,
                error_message: None,
            },
        }),
    ))
}

pub(crate) async fn list_commands(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Query(page): Query<PageParams>,
) -> Result<Json<CommandListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;

    let base_sql = format!(
        "select id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at
         from commands
         where sandbox_id = {}",
        state.db.placeholder(1)
    );
    let (commands, next_cursor) = fetch_keyset_page(
        &state.db,
        &base_sql,
        &[sandbox_id.to_string()],
        limit,
        &cursor,
        row_to_command,
    )
    .await?;

    Ok(Json(CommandListResponse {
        ok: true,
        commands,
        next_cursor,
    }))
}

pub(crate) async fn get_command(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(command_id): Path<Uuid>,
) -> Result<Json<CommandResponse>, ApiError> {
    let command = fetch_command(&state.db, CommandId(command_id)).await?;
    ensure_sandbox_tenant(&state.db, command.sandbox_id, &ctx).await?;
    Ok(Json(CommandResponse { ok: true, command }))
}

pub(crate) async fn list_command_output(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(command_id): Path<Uuid>,
    Query(page): Query<PageParams>,
) -> Result<Json<CommandOutputListResponse>, ApiError> {
    let command_id = CommandId(command_id);
    let command = fetch_command(&state.db, command_id).await?;
    ensure_sandbox_tenant(&state.db, command.sandbox_id, &ctx).await?;
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;
    let (chunks, next_cursor) =
        list_command_output_chunks(&state.db, command_id, limit, &cursor).await?;
    Ok(Json(CommandOutputListResponse {
        ok: true,
        complete: matches!(
            command.status,
            CommandStatus::Finished | CommandStatus::Failed
        ),
        chunks,
        next_cursor,
    }))
}

#[utoipa::path(post, path = "/v1/sandboxes/{sandbox_id}/prompt", params(("sandbox_id" = Uuid, Path)), responses((status = 501, body = ErrorEnvelope)))]
pub(crate) async fn queue_prompt(
    State(_state): State<AppState>,
    Extension(_ctx): Extension<TenantContext>,
    Path(_sandbox_id): Path<Uuid>,
    Json(_request): Json<PromptRequest>,
) -> Result<Json<PromptQueuedResponse>, ApiError> {
    Err(ApiError::not_implemented(
        "agent_prompt_unavailable",
        "agent prompt execution is not implemented",
    ))
}

pub(crate) async fn list_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Query(page): Query<PageParams>,
) -> Result<Json<EventListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;

    let base_sql = format!(
        "select id, sandbox_id, kind, data, created_at
         from sandbox_events
         where sandbox_id = {}",
        state.db.placeholder(1)
    );
    let (events, next_cursor) = fetch_keyset_page(
        &state.db,
        &base_sql,
        &[sandbox_id.to_string()],
        limit,
        &cursor,
        row_to_event,
    )
    .await?;

    Ok(Json(EventListResponse {
        ok: true,
        events,
        next_cursor,
    }))
}

pub(crate) async fn fetch_command(
    db: &Database,
    command_id: CommandId,
) -> Result<CommandRun, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at
         from commands
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(command_id.0.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("command not found"))?;

    let mut command = row_to_command(row)?;
    // Chunks are the canonical streaming representation. Materialize the
    // compatibility stdout/stderr fields on reads without rewriting an
    // ever-growing aggregate for every append. This view is explicitly
    // bounded to 64 x 64Ki-character slices; callers needing every byte use
    // the paginated /commands/{id}/output endpoint.
    let sql = format!(
        "select stream, substr(chunk, 1, {MATERIALIZED_CHUNK_CHARS}) as chunk
         from command_output_chunks where command_id = {}
         order by stream asc, sequence asc limit {}",
        db.placeholder(1),
        MATERIALIZED_OUTPUT_CHUNKS,
    );
    let rows = sqlx::query(&sql)
        .bind(command_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    if !rows.is_empty() {
        command.stdout.clear();
        command.stderr.clear();
        for row in rows {
            let stream: String = row.try_get("stream")?;
            let chunk: String = row.try_get("chunk")?;
            match parse_command_output_stream(&stream)? {
                CommandOutputStream::Stdout => command.stdout.push_str(&chunk),
                CommandOutputStream::Stderr => command.stderr.push_str(&chunk),
            }
        }
    }
    Ok(command)
}

pub(crate) async fn list_command_output_chunks(
    db: &Database,
    command_id: CommandId,
    limit: u32,
    cursor: &Option<(PageDirection, PageCursor)>,
) -> Result<(Vec<CommandOutputChunk>, Option<String>), ApiError> {
    let base_sql = format!(
        "select id, command_id, stream, sequence, chunk, annotations, created_at
         from command_output_chunks
         where command_id = {}",
        db.placeholder(1)
    );
    fetch_keyset_page(
        db,
        &base_sql,
        &[command_id.to_string()],
        limit,
        cursor,
        row_to_command_output_chunk,
    )
    .await
}

pub(crate) async fn append_command_output_chunk(
    db: &Database,
    command_id: CommandId,
    sandbox_id: SandboxId,
    stream: CommandOutputStream,
    chunk: String,
    annotations: Vec<CommandOutputAnnotation>,
    operation: Option<(LeaseId, Uuid)>,
) -> Result<CommandOutputChunk, ApiError> {
    let mut tx = db.pool.begin().await?;
    if let Some((lease_id, operation_id)) = operation {
        let sql = format!(
            "select chunk_id from command_output_operations where lease_id = {} and operation_id = {}",
            db.placeholder(1),
            db.placeholder(2)
        );
        if let Some(row) = sqlx::query(&sql)
            .bind(lease_id.to_string())
            .bind(operation_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
        {
            let chunk_id: String = row.try_get("chunk_id")?;
            let chunk = fetch_output_chunk_on_connection(db, &mut tx, &chunk_id).await?;
            tx.commit().await?;
            return Ok(chunk);
        }
    }
    let appended = append_command_output_chunk_on_connection(
        db,
        &mut tx,
        command_id,
        sandbox_id,
        stream,
        chunk,
        annotations,
    )
    .await;
    match appended {
        Ok(chunk) => {
            if let Some((lease_id, operation_id)) = operation {
                let sql = format!(
                    "insert into command_output_operations (lease_id, operation_id, chunk_id, created_at) values ({})",
                    db.placeholders(4)
                );
                sqlx::query(&sql)
                    .bind(lease_id.to_string())
                    .bind(operation_id.to_string())
                    .bind(chunk.id.to_string())
                    .bind(chunk.created_at.to_rfc3339())
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            Ok(chunk)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back command output append");
            }
            Err(error)
        }
    }
}

async fn fetch_output_chunk_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    chunk_id: &str,
) -> Result<CommandOutputChunk, ApiError> {
    let sql = format!(
        "select id, command_id, stream, sequence, chunk, annotations, created_at
         from command_output_chunks where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(chunk_id)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| {
            ApiError::internal("output idempotency record references a missing chunk")
        })?;
    row_to_command_output_chunk(row)
}

pub(crate) async fn append_command_output_chunk_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    sandbox_id: SandboxId,
    stream: CommandOutputStream,
    chunk: String,
    annotations: Vec<CommandOutputAnnotation>,
) -> Result<CommandOutputChunk, ApiError> {
    lock_command_output_for_append_on_connection(db, connection, command_id).await?;
    let byte_length = match db.dialect {
        SqlDialect::Postgres => "octet_length(chunk)",
        SqlDialect::Sqlite => "length(cast(chunk as blob))",
    };
    let bounds_sql = format!(
        "select count(*) as chunk_count, coalesce(sum({byte_length}), 0) as byte_count
         from command_output_chunks where command_id = {}",
        db.placeholder(1)
    );
    let bounds = sqlx::query(&bounds_sql)
        .bind(command_id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    validate_command_output_bounds(
        bounds.try_get("chunk_count")?,
        bounds.try_get("byte_count")?,
        chunk.len(),
    )?;
    let sequence =
        next_command_output_sequence_on_connection(db, connection, command_id, &stream).await?;
    let now = Utc::now();
    let output_chunk = CommandOutputChunk {
        id: CommandOutputChunkId::new(),
        command_id,
        stream,
        sequence,
        chunk,
        annotations,
        created_at: now,
    };
    let sql = format!(
        "insert into command_output_chunks (id, command_id, stream, sequence, chunk, annotations, created_at)
         values ({})",
        db.placeholders(7)
    );
    sqlx::query(&sql)
        .bind(output_chunk.id.to_string())
        .bind(output_chunk.command_id.to_string())
        .bind(command_output_stream_to_str(&output_chunk.stream))
        .bind(count_to_i64(output_chunk.sequence)?)
        .bind(&output_chunk.chunk)
        .bind(serde_json::to_string(&output_chunk.annotations)?)
        .bind(output_chunk.created_at.to_rfc3339())
        .execute(&mut *connection)
        .await?;

    insert_event_on_connection(
        db,
        connection,
        sandbox_id,
        SandboxEventKind::CommandOutput,
        json!({
            "commandId": command_id,
            "stream": output_chunk.stream,
            "sequence": output_chunk.sequence
        }),
    )
    .await?;

    Ok(output_chunk)
}

pub(crate) async fn lock_command_output_for_append_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
) -> Result<(), ApiError> {
    let sql = format!(
        "update commands
         set id = id
         where id = {}",
        db.placeholder(1)
    );
    let result = sqlx::query(&sql)
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("command not found"));
    }
    Ok(())
}

pub(crate) async fn next_command_output_sequence_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
) -> Result<u64, ApiError> {
    let sql = format!(
        "select coalesce(max(sequence), 0) as max_sequence
         from command_output_chunks
         where command_id = {} and stream = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(command_id.to_string())
        .bind(command_output_stream_to_str(stream))
        .fetch_one(&mut *connection)
        .await?;
    let max_sequence: i64 = row.try_get("max_sequence")?;
    let next = max_sequence
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("command output sequence overflow"))?;
    u64::try_from(next)
        .map_err(|_| ApiError::internal("database contains invalid command output sequence"))
}

pub(crate) async fn reset_command_for_retry_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
) -> Result<(), ApiError> {
    let delete_sql = format!(
        "delete from command_output_chunks
         where command_id = {}",
        db.placeholder(1)
    );
    sqlx::query(&delete_sql)
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;

    let update_sql = format!(
        "update commands
         set status = {}, stdout = '', stderr = '', exit_code = {}, finished_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let result = sqlx::query(&update_sql)
        .bind(command_status_to_str(&CommandStatus::Queued))
        .bind(Option::<i32>::None)
        .bind(Option::<String>::None)
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("command not found"));
    }
    Ok(())
}

pub(crate) async fn insert_command(db: &Database, command: &CommandRun) -> Result<(), ApiError> {
    let sql = format!(
        "insert into commands
         (id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at)
         values ({})",
        db.placeholders(10)
    );
    sqlx::query(&sql)
        .bind(command.id.0.to_string())
        .bind(command.sandbox_id.to_string())
        .bind(command_status_to_str(&command.status))
        .bind(serde_json::to_string(&command.argv)?)
        .bind(&command.cwd)
        .bind(command.exit_code)
        .bind(&command.stdout)
        .bind(&command.stderr)
        .bind(command.created_at.to_rfc3339())
        .bind(command.finished_at.map(|time| time.to_rfc3339()))
        .execute(&db.pool)
        .await?;
    Ok(())
}

pub(crate) fn command_id_from_job(job: &Job) -> Result<CommandId, ApiError> {
    uuid_from_job_payload(job, "commandId", "run command job is missing command id").map(CommandId)
}

pub(crate) fn prompt_event_id_from_job(job: &Job) -> Result<EventId, ApiError> {
    uuid_from_job_payload(
        job,
        "promptEventId",
        "prompt job is missing prompt event id",
    )
    .map(EventId)
}

pub(crate) async fn insert_event(
    db: &Database,
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

    let sql = format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values ({})",
        db.placeholders(5)
    );
    sqlx::query(&sql)
        .bind(event.id.0.to_string())
        .bind(event.sandbox_id.to_string())
        .bind(event_kind_to_str(&event.kind))
        .bind(serde_json::to_string(&event.data)?)
        .bind(event.created_at.to_rfc3339())
        .execute(&db.pool)
        .await?;

    Ok(event)
}

pub(crate) async fn insert_event_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
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

    let sql = format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values ({})",
        db.placeholders(5)
    );
    sqlx::query(&sql)
        .bind(event.id.0.to_string())
        .bind(event.sandbox_id.to_string())
        .bind(event_kind_to_str(&event.kind))
        .bind(serde_json::to_string(&event.data)?)
        .bind(event.created_at.to_rfc3339())
        .execute(&mut *connection)
        .await?;

    Ok(event)
}
