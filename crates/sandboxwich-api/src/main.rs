use std::net::SocketAddr;

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Extension, Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use sandboxwich_core::{
    AppendCommandOutputRequest, ArchivedSandboxCleanupSkip, CapacityResponse, ClaimLeaseRequest,
    ClaimLeaseResponse, CleanupRun, CleanupRunId, CleanupRunStatus, CommandId, CommandListResponse,
    CommandOutputChunk, CommandOutputChunkId, CommandOutputChunkResponse,
    CommandOutputListResponse, CommandOutputStream, CommandRequest, CommandResponse, CommandRun,
    CommandStatus, CompleteLeaseRequest, CreateDesktopSessionRequest, CreateJobRequest,
    CreateSandboxRequest, CreateSnapshotRequest, DesktopAccess, DesktopAccessMode,
    DesktopAccessRequest, DesktopAccessResponse, DesktopSession, DesktopSessionId,
    DesktopSessionListResponse, DesktopSessionResponse, DesktopSessionStatus, ErrorEnvelope,
    EventId, EventListResponse, FailLeaseRequest, GuestHealth, GuestHealthResponse, GuestStatus,
    HealthResponse, Job, JobId, JobKind, JobLease, JobListResponse, JobResponse, JobStatus,
    LeaseId, LeaseResponse, LeaseStatus, PromptQueuedResponse, PromptRequest,
    ProviderRuntimeResource, ReconcileRuntimeResourcesRequest, ReconcileRuntimeResourcesResponse,
    RegisterWorkerRequest, RenewLeaseRequest, RequestSshKeyRequest, RuntimeResource,
    RuntimeResourceId, RuntimeResourceKind, RuntimeResourceListResponse, RuntimeResourcePurpose,
    RuntimeResourceStatus, Sandbox, SandboxEvent, SandboxEventKind, SandboxId, SandboxListResponse,
    SandboxResponse, SandboxState, Snapshot, SnapshotCleanupResponse, SnapshotId,
    SnapshotListResponse, SnapshotResponse, SnapshotStatus, SshAccess, SshAccessRequest,
    SshAccessResponse, SshKey, SshKeyId, SshKeyListResponse, SshKeyResponse, SshKeyStatus,
    UpdateDesktopSessionRequest, UpdateGuestHealthRequest, UpdateSshKeyStatusRequest, Worker,
    WorkerCapability, WorkerCapacity, WorkerHeartbeatRequest, WorkerId, WorkerJobResult,
    WorkerListResponse, WorkerResponse, WorkerStatus,
};
use serde_json::json;
use sqlx::{
    AnyConnection, AnyPool, Row, Sqlite,
    any::{AnyPoolOptions, AnyRow},
    migrate::MigrateDatabase,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: Database,
    auth_token: Option<String>,
    default_tenant_id: String,
}

#[derive(Clone, Debug)]
struct TenantContext {
    tenant_id: String,
}

#[derive(Clone)]
struct Database {
    pool: AnyPool,
    dialect: SqlDialect,
}

#[derive(Clone, Copy)]
enum SqlDialect {
    Postgres,
    Sqlite,
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
    let auth_token = std::env::var("SANDBOXWICH_API_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty());
    let default_tenant_id = std::env::var("SANDBOXWICH_DEFAULT_TENANT")
        .ok()
        .filter(|tenant| !tenant.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());
    let db = connect_database(&database_url).await?;
    sqlx::migrate!("./migrations").run(&db.pool).await?;
    ensure_database_constraints(&db).await?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, %database_url, "sandboxwich-api listening");
    axum::serve(
        listener,
        app(AppState {
            db,
            auth_token,
            default_tenant_id,
        }),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn connect_database(database_url: &str) -> anyhow::Result<Database> {
    sqlx::any::install_default_drivers();
    let dialect = SqlDialect::from_url(database_url)?;
    if matches!(dialect, SqlDialect::Sqlite)
        && !Sqlite::database_exists(database_url).await.unwrap_or(false)
    {
        Sqlite::create_database(database_url).await?;
    }

    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    Ok(Database { pool, dialect })
}

async fn ensure_database_constraints(db: &Database) -> anyhow::Result<()> {
    match db.dialect {
        SqlDialect::Postgres => ensure_postgres_constraints(db).await,
        SqlDialect::Sqlite => ensure_sqlite_constraints(db).await,
    }
}

async fn ensure_postgres_constraints(db: &Database) -> anyhow::Result<()> {
    for statement in [
        r#"
        do $$
        begin
            alter table sandboxes drop constraint if exists sandboxes_state_check;
            alter table sandboxes add constraint sandboxes_state_check
                check (state in ('planning', 'provisioning', 'ready', 'running', 'idle', 'archiving', 'archived', 'error'));
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'commands_status_check'
            ) then
                alter table commands add constraint commands_status_check
                    check (status in ('queued', 'running', 'finished', 'failed'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            alter table sandbox_events drop constraint if exists sandbox_events_kind_check;
            alter table sandbox_events add constraint sandbox_events_kind_check
                check (kind in (
                    'lifecycle_changed',
                    'command_queued',
                    'command_started',
                    'command_output',
                    'command_finished',
                    'prompt_queued',
                    'prompt_started',
                    'prompt_finished',
                    'desktop_requested',
                    'desktop_ready',
                    'desktop_failed',
                    'desktop_closed',
                    'desktop_expired'
                ));
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'workers_status_check'
            ) then
                alter table workers add constraint workers_status_check
                    check (status in ('registered', 'online', 'draining', 'offline'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'jobs_kind_check'
            ) then
                alter table jobs add constraint jobs_kind_check
                    check (kind in (
                        'provision_sandbox',
                        'stop_sandbox',
                        'resume_sandbox',
                        'run_command',
                        'run_prompt',
                        'create_snapshot',
                        'fork_sandbox'
                    ));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'jobs_status_check'
            ) then
                alter table jobs add constraint jobs_status_check
                    check (status in ('queued', 'leased', 'succeeded', 'failed', 'dead'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'job_leases_status_check'
            ) then
                alter table job_leases add constraint job_leases_status_check
                    check (status in ('active', 'completed', 'failed', 'expired'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'guest_health_status_check'
            ) then
                alter table guest_health add constraint guest_health_status_check
                    check (status in ('pending', 'ready', 'unreachable', 'unhealthy', 'terminated'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'snapshots_status_check'
            ) then
                alter table snapshots add constraint snapshots_status_check
                    check (status in ('pending', 'ready', 'failed', 'expired'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'desktop_sessions_status_check'
            ) then
                alter table desktop_sessions add constraint desktop_sessions_status_check
                    check (status in ('pending', 'ready', 'failed', 'closed', 'expired'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'desktop_sessions_access_mode_check'
            ) then
                alter table desktop_sessions add constraint desktop_sessions_access_mode_check
                    check (access_mode in ('browser', 'vnc', 'rdp'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'ssh_keys_status_check'
            ) then
                alter table ssh_keys add constraint ssh_keys_status_check
                    check (status in ('requested', 'applied', 'failed', 'revoked'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'runtime_resources_kind_check'
            ) then
                alter table runtime_resources add constraint runtime_resources_kind_check
                    check (resource_kind in ('pod', 'persistent_volume_claim', 'service', 'volume_snapshot'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'runtime_resources_purpose_check'
            ) then
                alter table runtime_resources add constraint runtime_resources_purpose_check
                    check (purpose in ('runtime', 'workspace', 'ssh', 'desktop', 'snapshot'));
            end if;
        end $$;
        "#,
        r#"
        do $$
        begin
            if not exists (
                select 1 from pg_constraint where conname = 'runtime_resources_status_check'
            ) then
                alter table runtime_resources add constraint runtime_resources_status_check
                    check (status in ('planned', 'applied', 'ready', 'failed', 'deleted'));
            end if;
        end $$;
        "#,
    ] {
        sqlx::query(statement).execute(&db.pool).await?;
    }

    Ok(())
}

async fn ensure_sqlite_constraints(db: &Database) -> anyhow::Result<()> {
    for statement in [
        r#"
        drop trigger if exists validate_sandboxes_state_insert;
        "#,
        r#"
        drop trigger if exists validate_sandboxes_state_update;
        "#,
        r#"
        drop trigger if exists validate_sandbox_events_kind_insert;
        "#,
        r#"
        drop trigger if exists validate_sandbox_events_kind_update;
        "#,
        r#"
        create trigger if not exists validate_sandboxes_state_insert
        before insert on sandboxes
        for each row
        when new.state not in ('planning', 'provisioning', 'ready', 'running', 'idle', 'archiving', 'archived', 'error')
        begin
            select raise(abort, 'invalid sandbox state');
        end;
        "#,
        r#"
        create trigger if not exists validate_sandboxes_state_update
        before update of state on sandboxes
        for each row
        when new.state not in ('planning', 'provisioning', 'ready', 'running', 'idle', 'archiving', 'archived', 'error')
        begin
            select raise(abort, 'invalid sandbox state');
        end;
        "#,
        r#"
        create trigger if not exists validate_commands_status_insert
        before insert on commands
        for each row
        when new.status not in ('queued', 'running', 'finished', 'failed')
        begin
            select raise(abort, 'invalid command status');
        end;
        "#,
        r#"
        create trigger if not exists validate_commands_status_update
        before update of status on commands
        for each row
        when new.status not in ('queued', 'running', 'finished', 'failed')
        begin
            select raise(abort, 'invalid command status');
        end;
        "#,
        r#"
        create trigger if not exists validate_sandbox_events_kind_insert
        before insert on sandbox_events
        for each row
        when new.kind not in (
            'lifecycle_changed',
            'command_queued',
            'command_started',
            'command_output',
            'command_finished',
            'prompt_queued',
            'prompt_started',
            'prompt_finished',
            'desktop_requested',
            'desktop_ready',
            'desktop_failed',
            'desktop_closed',
            'desktop_expired'
        )
        begin
            select raise(abort, 'invalid event kind');
        end;
        "#,
        r#"
        create trigger if not exists validate_sandbox_events_kind_update
        before update of kind on sandbox_events
        for each row
        when new.kind not in (
            'lifecycle_changed',
            'command_queued',
            'command_started',
            'command_output',
            'command_finished',
            'prompt_queued',
            'prompt_started',
            'prompt_finished',
            'desktop_requested',
            'desktop_ready',
            'desktop_failed',
            'desktop_closed',
            'desktop_expired'
        )
        begin
            select raise(abort, 'invalid event kind');
        end;
        "#,
        r#"
        create trigger if not exists validate_workers_status_insert
        before insert on workers
        for each row
        when new.status not in ('registered', 'online', 'draining', 'offline')
        begin
            select raise(abort, 'invalid worker status');
        end;
        "#,
        r#"
        create trigger if not exists validate_workers_status_update
        before update of status on workers
        for each row
        when new.status not in ('registered', 'online', 'draining', 'offline')
        begin
            select raise(abort, 'invalid worker status');
        end;
        "#,
        r#"
        create trigger if not exists validate_jobs_kind_insert
        before insert on jobs
        for each row
        when new.kind not in ('provision_sandbox', 'stop_sandbox', 'resume_sandbox', 'run_command', 'run_prompt', 'create_snapshot', 'fork_sandbox')
        begin
            select raise(abort, 'invalid job kind');
        end;
        "#,
        r#"
        create trigger if not exists validate_jobs_kind_update
        before update of kind on jobs
        for each row
        when new.kind not in ('provision_sandbox', 'stop_sandbox', 'resume_sandbox', 'run_command', 'run_prompt', 'create_snapshot', 'fork_sandbox')
        begin
            select raise(abort, 'invalid job kind');
        end;
        "#,
        r#"
        create trigger if not exists validate_jobs_status_insert
        before insert on jobs
        for each row
        when new.status not in ('queued', 'leased', 'succeeded', 'failed', 'dead')
        begin
            select raise(abort, 'invalid job status');
        end;
        "#,
        r#"
        create trigger if not exists validate_jobs_status_update
        before update of status on jobs
        for each row
        when new.status not in ('queued', 'leased', 'succeeded', 'failed', 'dead')
        begin
            select raise(abort, 'invalid job status');
        end;
        "#,
        r#"
        create trigger if not exists validate_job_leases_status_insert
        before insert on job_leases
        for each row
        when new.status not in ('active', 'completed', 'failed', 'expired')
        begin
            select raise(abort, 'invalid lease status');
        end;
        "#,
        r#"
        create trigger if not exists validate_job_leases_status_update
        before update of status on job_leases
        for each row
        when new.status not in ('active', 'completed', 'failed', 'expired')
        begin
            select raise(abort, 'invalid lease status');
        end;
        "#,
        r#"
        create trigger if not exists validate_guest_health_status_insert
        before insert on guest_health
        for each row
        when new.status not in ('pending', 'ready', 'unreachable', 'unhealthy', 'terminated')
        begin
            select raise(abort, 'invalid guest status');
        end;
        "#,
        r#"
        create trigger if not exists validate_guest_health_status_update
        before update of status on guest_health
        for each row
        when new.status not in ('pending', 'ready', 'unreachable', 'unhealthy', 'terminated')
        begin
            select raise(abort, 'invalid guest status');
        end;
        "#,
        r#"
        create trigger if not exists validate_snapshots_status_insert
        before insert on snapshots
        for each row
        when new.status not in ('pending', 'ready', 'failed', 'expired')
        begin
            select raise(abort, 'invalid snapshot status');
        end;
        "#,
        r#"
        create trigger if not exists validate_snapshots_status_update
        before update of status on snapshots
        for each row
        when new.status not in ('pending', 'ready', 'failed', 'expired')
        begin
            select raise(abort, 'invalid snapshot status');
        end;
        "#,
        r#"
        create trigger if not exists validate_desktop_sessions_status_insert
        before insert on desktop_sessions
        for each row
        when new.status not in ('pending', 'ready', 'failed', 'closed', 'expired')
        begin
            select raise(abort, 'invalid desktop session status');
        end;
        "#,
        r#"
        create trigger if not exists validate_desktop_sessions_status_update
        before update of status on desktop_sessions
        for each row
        when new.status not in ('pending', 'ready', 'failed', 'closed', 'expired')
        begin
            select raise(abort, 'invalid desktop session status');
        end;
        "#,
        r#"
        create trigger if not exists validate_desktop_sessions_access_mode_insert
        before insert on desktop_sessions
        for each row
        when new.access_mode not in ('browser', 'vnc', 'rdp')
        begin
            select raise(abort, 'invalid desktop access mode');
        end;
        "#,
        r#"
        create trigger if not exists validate_desktop_sessions_access_mode_update
        before update of access_mode on desktop_sessions
        for each row
        when new.access_mode not in ('browser', 'vnc', 'rdp')
        begin
            select raise(abort, 'invalid desktop access mode');
        end;
        "#,
        r#"
        create trigger if not exists validate_ssh_keys_status_insert
        before insert on ssh_keys
        for each row
        when new.status not in ('requested', 'applied', 'failed', 'revoked')
        begin
            select raise(abort, 'invalid ssh key status');
        end;
        "#,
        r#"
        create trigger if not exists validate_ssh_keys_status_update
        before update of status on ssh_keys
        for each row
        when new.status not in ('requested', 'applied', 'failed', 'revoked')
        begin
            select raise(abort, 'invalid ssh key status');
        end;
        "#,
        r#"
        create trigger if not exists validate_runtime_resources_kind_insert
        before insert on runtime_resources
        for each row
        when new.resource_kind not in ('pod', 'persistent_volume_claim', 'service', 'volume_snapshot')
        begin
            select raise(abort, 'invalid runtime resource kind');
        end;
        "#,
        r#"
        create trigger if not exists validate_runtime_resources_kind_update
        before update of resource_kind on runtime_resources
        for each row
        when new.resource_kind not in ('pod', 'persistent_volume_claim', 'service', 'volume_snapshot')
        begin
            select raise(abort, 'invalid runtime resource kind');
        end;
        "#,
        r#"
        create trigger if not exists validate_runtime_resources_purpose_insert
        before insert on runtime_resources
        for each row
        when new.purpose not in ('runtime', 'workspace', 'ssh', 'desktop', 'snapshot')
        begin
            select raise(abort, 'invalid runtime resource purpose');
        end;
        "#,
        r#"
        create trigger if not exists validate_runtime_resources_purpose_update
        before update of purpose on runtime_resources
        for each row
        when new.purpose not in ('runtime', 'workspace', 'ssh', 'desktop', 'snapshot')
        begin
            select raise(abort, 'invalid runtime resource purpose');
        end;
        "#,
        r#"
        create trigger if not exists validate_runtime_resources_status_insert
        before insert on runtime_resources
        for each row
        when new.status not in ('planned', 'applied', 'ready', 'failed', 'deleted')
        begin
            select raise(abort, 'invalid runtime resource status');
        end;
        "#,
        r#"
        create trigger if not exists validate_runtime_resources_status_update
        before update of status on runtime_resources
        for each row
        when new.status not in ('planned', 'applied', 'ready', 'failed', 'deleted')
        begin
            select raise(abort, 'invalid runtime resource status');
        end;
        "#,
    ] {
        sqlx::query(statement).execute(&db.pool).await?;
    }

    Ok(())
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/sandboxes", get(list_sandboxes).post(create_sandbox))
        .route("/sandboxes/{sandbox_id}", get(get_sandbox))
        .route(
            "/sandboxes/{sandbox_id}/runtime-resources",
            get(list_runtime_resources),
        )
        .route("/sandboxes/{sandbox_id}/stop", post(stop_sandbox))
        .route("/sandboxes/{sandbox_id}/resume", post(resume_sandbox))
        .route("/sandboxes/{sandbox_id}/fork", post(fork_sandbox))
        .route(
            "/sandboxes/{sandbox_id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route(
            "/sandboxes/{sandbox_id}/desktop",
            get(list_desktop_sessions),
        )
        .route(
            "/sandboxes/{sandbox_id}/desktop-sessions",
            get(list_desktop_sessions).post(create_desktop_session),
        )
        .route(
            "/sandboxes/{sandbox_id}/commands",
            get(list_commands).post(queue_command),
        )
        .route("/sandboxes/{sandbox_id}/prompt", post(queue_prompt))
        .route("/sandboxes/{sandbox_id}/events", get(list_events))
        .route(
            "/desktop-sessions/{desktop_session_id}",
            get(get_desktop_session),
        )
        .route(
            "/desktop-sessions/{desktop_session_id}/status",
            post(update_desktop_session_status),
        )
        .route(
            "/desktop-sessions/{desktop_session_id}/access",
            post(create_desktop_access),
        )
        .route("/snapshots/cleanup", post(cleanup_snapshots))
        .route("/snapshots/{snapshot_id}", get(get_snapshot))
        .route("/commands/{command_id}", get(get_command))
        .route("/commands/{command_id}/output", get(list_command_output))
        .route("/workers", get(list_workers))
        .route("/capacity", get(get_capacity))
        .route("/workers/register", post(register_worker))
        .route("/workers/{worker_id}/heartbeat", post(heartbeat_worker))
        .route(
            "/workers/{worker_id}/runtime-resources/reconcile",
            post(reconcile_runtime_resources),
        )
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/workers/{worker_id}/leases/claim", post(claim_lease))
        .route("/leases/{lease_id}/renew", post(renew_lease))
        .route("/leases/{lease_id}/output", post(append_lease_output))
        .route("/leases/{lease_id}/complete", post(complete_lease))
        .route("/leases/{lease_id}/fail", post(fail_lease))
        .route(
            "/sandboxes/{sandbox_id}/guest-health",
            get(get_guest_health).post(update_guest_health),
        )
        .route(
            "/sandboxes/{sandbox_id}/ssh-keys",
            get(list_ssh_keys).post(request_ssh_key),
        )
        .route(
            "/sandboxes/{sandbox_id}/ssh-access",
            post(create_ssh_access),
        )
        .route("/ssh-keys/{ssh_key_id}/status", post(update_ssh_key_status))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_and_tenant))
}

async fn auth_and_tenant(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(expected_token) = &state.auth_token {
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected_token);
        if !authorized {
            return ApiError::unauthorized("valid bearer token is required").into_response();
        }
    }

    let tenant_id = request
        .headers()
        .get("x-sandboxwich-tenant")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|tenant| !tenant.is_empty())
        .unwrap_or(&state.default_tenant_id)
        .to_string();
    request.extensions_mut().insert(TenantContext { tenant_id });

    next.run(request).await
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

fn ensure_tenant(resource_tenant_id: &str, ctx: &TenantContext) -> Result<(), ApiError> {
    if resource_tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(())
}

async fn ensure_sandbox_tenant(
    db: &Database,
    sandbox_id: SandboxId,
    ctx: &TenantContext,
) -> Result<Sandbox, ApiError> {
    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    ensure_tenant(&sandbox.tenant_id, ctx)?;
    Ok(sandbox)
}

async fn ensure_worker_tenant(
    db: &Database,
    worker_id: WorkerId,
    ctx: &TenantContext,
) -> Result<Worker, ApiError> {
    let worker = fetch_worker(db, worker_id).await?;
    ensure_tenant(&worker.tenant_id, ctx)?;
    Ok(worker)
}

fn ensure_job_tenant(job: &Job, ctx: &TenantContext) -> Result<(), ApiError> {
    ensure_tenant(&job.tenant_id, ctx)
}

async fn ensure_lease_tenant(
    db: &Database,
    lease_id: LeaseId,
    ctx: &TenantContext,
) -> Result<JobLease, ApiError> {
    let lease = fetch_lease(db, lease_id).await?;
    ensure_job_tenant(&lease.job, ctx)?;
    Ok(lease)
}

async fn create_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let now = Utc::now();
    let sandbox = Sandbox {
        id: SandboxId::new(),
        tenant_id: ctx.tenant_id.clone(),
        name: request.name.unwrap_or_else(|| "fresh-sandwich".to_string()),
        state: SandboxState::Ready,
        template: request.template.unwrap_or_else(|| "ubuntu-dev".to_string()),
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(Some(3600)),
        parent_snapshot_id: None,
    };

    insert_sandbox(&state.db, &sandbox).await?;
    insert_event(
        &state.db,
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
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<SandboxListResponse>, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where tenant_id = {}
         order by created_at asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&state.db.pool)
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
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sandbox = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    Ok(Json(SandboxResponse { ok: true, sandbox }))
}

async fn list_runtime_resources(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<RuntimeResourceListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let resources = list_runtime_resources_for_sandbox(&state.db, sandbox_id).await?;
    Ok(Json(RuntimeResourceListResponse {
        ok: true,
        resources,
    }))
}

async fn stop_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    transition_sandbox(
        &state.db,
        SandboxId(sandbox_id),
        SandboxState::Archived,
        "stopped",
    )
    .await
}

async fn resume_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    transition_sandbox(
        &state.db,
        SandboxId(sandbox_id),
        SandboxState::Ready,
        "resumed",
    )
    .await
}

async fn fork_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let parent = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    let now = Utc::now();
    let snapshot = Snapshot {
        id: SnapshotId::new(),
        sandbox_id: parent.id,
        status: SnapshotStatus::Pending,
        label: format!("fork-source-{}", now.timestamp_millis()),
        inventory: json!({
            "sourceSandboxId": parent.id,
            "template": parent.template
        }),
        provider_metadata: json!({
            "source": "fork_request"
        }),
        created_at: now,
        ready_at: None,
        expires_at: expires_at_from_ttl(now, request.ttl_seconds)?,
        error: None,
    };
    insert_snapshot(&state.db, &snapshot).await?;

    let child = Sandbox {
        id: SandboxId::new(),
        tenant_id: parent.tenant_id.clone(),
        name: request
            .name
            .unwrap_or_else(|| format!("{}-fork", parent.name)),
        state: SandboxState::Planning,
        template: request.template.unwrap_or(parent.template),
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(parent.ttl_seconds),
        parent_snapshot_id: Some(snapshot.id),
    };

    insert_sandbox(&state.db, &child).await?;
    insert_event(
        &state.db,
        child.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": child.state,
            "reason": "fork_planned",
            "parentSandboxId": parent.id,
            "parentSnapshotId": snapshot.id
        }),
    )
    .await?;
    insert_job(
        &state.db,
        &Job {
            id: JobId::new(),
            tenant_id: parent.tenant_id.clone(),
            kind: JobKind::CreateSnapshot,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": parent.id,
                "snapshotId": snapshot.id
            }),
            required_capability: WorkerCapability::Snapshot,
            priority: 0,
            attempts: 0,
            max_attempts: 3,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        },
    )
    .await?;

    Ok(Json(SandboxResponse {
        ok: true,
        sandbox: child,
    }))
}

async fn create_snapshot(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateSnapshotRequest>,
) -> Result<Json<SnapshotResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let snapshot = pending_snapshot_from_request(sandbox_id, request)?;
    let scheduled_at = snapshot.created_at;
    insert_snapshot(&state.db, &snapshot).await?;
    insert_event(
        &state.db,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "reason": "snapshot_created",
            "snapshotId": snapshot.id,
            "snapshotStatus": snapshot.status
        }),
    )
    .await?;
    insert_job(
        &state.db,
        &Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id,
            kind: JobKind::CreateSnapshot,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": sandbox_id,
                "snapshotId": snapshot.id
            }),
            required_capability: WorkerCapability::Snapshot,
            priority: 0,
            attempts: 0,
            max_attempts: 3,
            scheduled_at,
            created_at: scheduled_at,
            updated_at: scheduled_at,
            last_error: None,
        },
    )
    .await?;

    Ok(Json(SnapshotResponse { ok: true, snapshot }))
}

async fn list_snapshots(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SnapshotListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    expire_due_snapshots(&state.db).await?;
    let snapshots = list_snapshots_for_sandbox(&state.db, sandbox_id).await?;
    Ok(Json(SnapshotListResponse {
        ok: true,
        snapshots,
    }))
}

async fn get_snapshot(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(snapshot_id): Path<Uuid>,
) -> Result<Json<SnapshotResponse>, ApiError> {
    expire_due_snapshots(&state.db).await?;
    let snapshot = fetch_snapshot(&state.db, SnapshotId(snapshot_id)).await?;
    ensure_sandbox_tenant(&state.db, snapshot.sandbox_id, &ctx).await?;
    Ok(Json(SnapshotResponse { ok: true, snapshot }))
}

async fn cleanup_snapshots(
    State(state): State<AppState>,
) -> Result<Json<SnapshotCleanupResponse>, ApiError> {
    let cleanup = run_cleanup_controller(&state.db).await?;
    Ok(Json(SnapshotCleanupResponse {
        ok: true,
        cleanup_run: cleanup.cleanup_run,
        expired: cleanup.expired,
        archived_sandboxes_deleted: cleanup.archived_sandboxes_deleted,
        archived_sandboxes: cleanup.archived_sandboxes,
        archived_sandboxes_skipped: cleanup.archived_sandboxes_skipped,
        runtime_resources_deleted: cleanup.runtime_resources_deleted,
    }))
}

async fn create_desktop_session(
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

async fn list_desktop_sessions(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<DesktopSessionListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    expire_due_desktop_sessions(&state.db).await?;
    let desktop_sessions = list_desktop_sessions_for_sandbox(&state.db, sandbox_id).await?;
    Ok(Json(DesktopSessionListResponse {
        ok: true,
        desktop_sessions,
    }))
}

async fn get_desktop_session(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(desktop_session_id): Path<Uuid>,
) -> Result<Json<DesktopSessionResponse>, ApiError> {
    expire_due_desktop_sessions(&state.db).await?;
    let desktop_session =
        fetch_desktop_session(&state.db, DesktopSessionId(desktop_session_id)).await?;
    ensure_sandbox_tenant(&state.db, desktop_session.sandbox_id, &ctx).await?;
    Ok(Json(DesktopSessionResponse {
        ok: true,
        desktop_session,
    }))
}

async fn update_desktop_session_status(
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

async fn create_desktop_access(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(desktop_session_id): Path<Uuid>,
    Json(request): Json<DesktopAccessRequest>,
) -> Result<Json<DesktopAccessResponse>, ApiError> {
    expire_due_desktop_sessions(&state.db).await?;
    let desktop_session =
        fetch_desktop_session(&state.db, DesktopSessionId(desktop_session_id)).await?;
    ensure_sandbox_tenant(&state.db, desktop_session.sandbox_id, &ctx).await?;
    let access = mint_desktop_access(&desktop_session, request.ttl_seconds)?;
    Ok(Json(DesktopAccessResponse { ok: true, access }))
}

async fn queue_command(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CommandRequest>,
) -> Result<Json<CommandResponse>, ApiError> {
    if request.argv.is_empty() {
        return Err(ApiError::bad_request("argv must contain at least one item"));
    }

    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let now = Utc::now();
    let env = request.env;
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

    insert_command(&state.db, &command).await?;
    insert_job(
        &state.db,
        &Job {
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
            }),
            required_capability: WorkerCapability::RunCommand,
            priority: 0,
            attempts: 0,
            max_attempts: 3,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        },
    )
    .await?;
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
    Ok(Json(CommandResponse { ok: true, command }))
}

async fn list_commands(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<CommandListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let sql = format!(
        "select id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at
         from commands
         where sandbox_id = {}
         order by created_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&state.db.pool)
        .await?;
    let commands = rows
        .into_iter()
        .map(row_to_command)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(CommandListResponse { ok: true, commands }))
}

async fn get_command(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(command_id): Path<Uuid>,
) -> Result<Json<CommandResponse>, ApiError> {
    let command = fetch_command(&state.db, CommandId(command_id)).await?;
    ensure_sandbox_tenant(&state.db, command.sandbox_id, &ctx).await?;
    Ok(Json(CommandResponse { ok: true, command }))
}

async fn list_command_output(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(command_id): Path<Uuid>,
) -> Result<Json<CommandOutputListResponse>, ApiError> {
    let command_id = CommandId(command_id);
    let command = fetch_command(&state.db, command_id).await?;
    ensure_sandbox_tenant(&state.db, command.sandbox_id, &ctx).await?;
    let chunks = list_command_output_chunks(&state.db, command_id).await?;
    Ok(Json(CommandOutputListResponse { ok: true, chunks }))
}

async fn queue_prompt(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<PromptRequest>,
) -> Result<Json<PromptQueuedResponse>, ApiError> {
    if request.instructions.trim().is_empty() {
        return Err(ApiError::bad_request("instructions are required"));
    }

    let sandbox_id = SandboxId(sandbox_id);
    let sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let event = insert_event(
        &state.db,
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
    let now = Utc::now();
    insert_job(
        &state.db,
        &Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id,
            kind: JobKind::RunPrompt,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": sandbox_id,
                "promptEventId": event.id,
                "instructions": request.instructions,
                "engine": request.engine,
                "model": request.model,
                "effort": request.effort
            }),
            required_capability: WorkerCapability::AgentPrompt,
            priority: 0,
            attempts: 0,
            max_attempts: 3,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        },
    )
    .await?;

    Ok(Json(PromptQueuedResponse { ok: true, event }))
}

async fn list_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<EventListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let sql = format!(
        "select id, sandbox_id, kind, data, created_at
         from sandbox_events
         where sandbox_id = {}
         order by created_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&state.db.pool)
        .await?;

    let events = rows
        .into_iter()
        .map(row_to_event)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(EventListResponse { ok: true, events }))
}

fn validate_max_concurrent_jobs(max_concurrent_jobs: u32) -> Result<u32, ApiError> {
    if max_concurrent_jobs == 0 {
        return Err(ApiError::bad_request(
            "max_concurrent_jobs must be greater than 0",
        ));
    }
    Ok(max_concurrent_jobs)
}

async fn register_worker(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<RegisterWorkerRequest>,
) -> Result<Json<WorkerResponse>, ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::bad_request("worker name is required"));
    }
    if request.provider.trim().is_empty() {
        return Err(ApiError::bad_request("worker provider is required"));
    }
    if request.capabilities.is_empty() {
        return Err(ApiError::bad_request(
            "worker must report at least one capability",
        ));
    }
    let max_concurrent_jobs =
        validate_max_concurrent_jobs(request.max_concurrent_jobs.unwrap_or(1))?;

    let now = Utc::now();
    let worker = Worker {
        id: WorkerId::new(),
        tenant_id: ctx.tenant_id,
        name: request.name,
        status: WorkerStatus::Registered,
        provider: request.provider,
        capabilities: request.capabilities,
        max_concurrent_jobs,
        labels: request.labels,
        registered_at: now,
        last_heartbeat_at: None,
    };
    insert_worker(&state.db, &worker).await?;

    Ok(Json(WorkerResponse { ok: true, worker }))
}

async fn heartbeat_worker(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Json(request): Json<WorkerHeartbeatRequest>,
) -> Result<Json<WorkerResponse>, ApiError> {
    let worker_id = WorkerId(worker_id);
    ensure_worker_tenant(&state.db, worker_id, &ctx).await?;
    let now = Utc::now();
    let labels = serde_json::to_string(&request.labels)?;
    let result = if let Some(max_concurrent_jobs) = request.max_concurrent_jobs {
        let max_concurrent_jobs = validate_max_concurrent_jobs(max_concurrent_jobs)?;
        let sql = format!(
            "update workers
             set status = {}, last_heartbeat_at = {}, labels = {}, max_concurrent_jobs = {}
             where id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2),
            state.db.placeholder(3),
            state.db.placeholder(4),
            state.db.placeholder(5)
        );
        sqlx::query(&sql)
            .bind(worker_status_to_str(&WorkerStatus::Online))
            .bind(now.to_rfc3339())
            .bind(labels.clone())
            .bind(i64::from(max_concurrent_jobs))
            .bind(worker_id.to_string())
            .execute(&state.db.pool)
            .await?
    } else {
        let sql = format!(
            "update workers
             set status = {}, last_heartbeat_at = {}, labels = {}
             where id = {}",
            state.db.placeholder(1),
            state.db.placeholder(2),
            state.db.placeholder(3),
            state.db.placeholder(4)
        );
        sqlx::query(&sql)
            .bind(worker_status_to_str(&WorkerStatus::Online))
            .bind(now.to_rfc3339())
            .bind(labels.clone())
            .bind(worker_id.to_string())
            .execute(&state.db.pool)
            .await?
    };

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("worker not found"));
    }

    insert_worker_heartbeat(&state.db, worker_id, &labels, now).await?;
    let worker = fetch_worker(&state.db, worker_id).await?;

    Ok(Json(WorkerResponse { ok: true, worker }))
}

async fn reconcile_runtime_resources(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Json(request): Json<ReconcileRuntimeResourcesRequest>,
) -> Result<Json<ReconcileRuntimeResourcesResponse>, ApiError> {
    let worker = ensure_worker_tenant(&state.db, WorkerId(worker_id), &ctx).await?;
    if worker.provider != request.provider {
        return Err(ApiError::bad_request(
            "runtime resource provider must match worker provider",
        ));
    }
    validate_reconcile_runtime_resources_request(&request)?;

    let observed_at = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let reconciled =
        reconcile_runtime_resources_on_connection(&state.db, &mut *tx, &request, observed_at).await;

    match reconciled {
        Ok((upserted, deleted)) => {
            tx.commit().await?;
            Ok(Json(ReconcileRuntimeResourcesResponse {
                ok: true,
                observed_at,
                upserted,
                deleted,
            }))
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back runtime resource reconcile");
            }
            Err(error)
        }
    }
}

async fn list_workers(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<WorkerListResponse>, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at
         from workers
         where tenant_id = {}
         order by registered_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&state.db.pool)
        .await?;

    let workers = rows
        .into_iter()
        .map(row_to_worker)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(WorkerListResponse { ok: true, workers }))
}

async fn get_capacity(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<CapacityResponse>, ApiError> {
    expire_due_leases(&state.db).await?;
    let workers = list_worker_capacities(&state.db, &ctx.tenant_id).await?;
    let total_max_concurrent_jobs = workers
        .iter()
        .map(|worker| worker.max_concurrent_jobs)
        .sum();
    let total_active_leases = workers.iter().map(|worker| worker.active_leases).sum();
    let total_available_slots = workers.iter().map(|worker| worker.available_slots).sum();

    Ok(Json(CapacityResponse {
        ok: true,
        workers,
        total_max_concurrent_jobs,
        total_active_leases,
        total_available_slots,
    }))
}

async fn create_job(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateJobRequest>,
) -> Result<Json<JobResponse>, ApiError> {
    let now = Utc::now();
    let job = Job {
        id: JobId::new(),
        tenant_id: ctx.tenant_id,
        kind: request.kind,
        status: JobStatus::Queued,
        payload: request.payload,
        required_capability: request.required_capability,
        priority: request.priority.unwrap_or(0),
        attempts: 0,
        max_attempts: request.max_attempts.unwrap_or(3).max(1),
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job(&state.db, &job).await?;
    Ok(Json(JobResponse { ok: true, job }))
}

async fn list_jobs(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
) -> Result<Json<JobListResponse>, ApiError> {
    expire_due_leases(&state.db).await?;
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where tenant_id = {}
         order by created_at asc, id asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&state.db.pool)
        .await?;
    let jobs = rows
        .into_iter()
        .map(row_to_job)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(JobListResponse { ok: true, jobs }))
}

async fn get_guest_health(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<GuestHealthResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let guest_health = fetch_guest_health(&state.db, sandbox_id)
        .await?
        .unwrap_or_else(|| GuestHealth {
            sandbox_id,
            status: GuestStatus::Pending,
            last_probe_at: Utc::now(),
            agent_version: None,
            checks: json!({}),
            message: Some("guest has not reported health yet".to_string()),
        });

    Ok(Json(GuestHealthResponse {
        ok: true,
        guest_health,
    }))
}

async fn update_guest_health(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<UpdateGuestHealthRequest>,
) -> Result<Json<GuestHealthResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let now = Utc::now();
    let guest_health = GuestHealth {
        sandbox_id,
        status: request.status,
        last_probe_at: now,
        agent_version: request.agent_version,
        checks: request.checks.unwrap_or_else(|| json!({})),
        message: request.message,
    };
    upsert_guest_health(&state.db, &guest_health).await?;

    Ok(Json(GuestHealthResponse {
        ok: true,
        guest_health,
    }))
}

async fn request_ssh_key(
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

async fn list_ssh_keys(
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

async fn create_ssh_access(
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

async fn update_ssh_key_status(
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

async fn claim_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Json(request): Json<ClaimLeaseRequest>,
) -> Result<Json<ClaimLeaseResponse>, ApiError> {
    expire_due_leases(&state.db).await?;
    let worker = ensure_worker_tenant(&state.db, WorkerId(worker_id), &ctx).await?;
    if !worker_has_capacity(&state.db, &worker).await? {
        return Ok(Json(ClaimLeaseResponse {
            ok: true,
            lease: None,
        }));
    }

    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where tenant_id = {} and status = 'queued'
         order by priority desc, scheduled_at asc, created_at asc, id asc
         limit 25",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&worker.tenant_id)
        .fetch_all(&state.db.pool)
        .await?;

    for row in rows {
        let job = row_to_job(row)?;
        if !worker.capabilities.contains(&job.required_capability) {
            continue;
        }
        if let Some(lease) =
            try_claim_job(&state.db, worker.id, &job, request.lease_seconds).await?
        {
            return Ok(Json(ClaimLeaseResponse {
                ok: true,
                lease: Some(lease),
            }));
        }
    }

    Ok(Json(ClaimLeaseResponse {
        ok: true,
        lease: None,
    }))
}

async fn renew_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<RenewLeaseRequest>,
) -> Result<Json<LeaseResponse>, ApiError> {
    let lease_id = LeaseId(lease_id);
    ensure_lease_tenant(&state.db, lease_id, &ctx).await?;
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(request.lease_seconds.unwrap_or(60) as i64);
    let sql = format!(
        "update job_leases
         set expires_at = {}
         where id = {} and status = 'active'",
        state.db.placeholder(1),
        state.db.placeholder(2)
    );
    let result = sqlx::query(&sql)
        .bind(expires_at.to_rfc3339())
        .bind(lease_id.to_string())
        .execute(&state.db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("active lease not found"));
    }

    let lease = fetch_lease(&state.db, lease_id).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

async fn append_lease_output(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<AppendCommandOutputRequest>,
) -> Result<Json<CommandOutputChunkResponse>, ApiError> {
    if request.chunk.is_empty() {
        return Err(ApiError::bad_request(
            "command output chunk cannot be empty",
        ));
    }
    let lease = ensure_lease_tenant(&state.db, LeaseId(lease_id), &ctx).await?;
    if lease.status != LeaseStatus::Active {
        return Err(ApiError::bad_request("lease is not active"));
    }
    if lease.job.kind != JobKind::RunCommand {
        return Err(ApiError::bad_request(
            "lease does not belong to a run command job",
        ));
    }
    let command_id = command_id_from_job(&lease.job)?;
    let sandbox_id = sandbox_id_from_job(&lease.job)?;
    let chunk = append_command_output_chunk(
        &state.db,
        command_id,
        sandbox_id,
        request.stream,
        request.chunk,
    )
    .await?;
    Ok(Json(CommandOutputChunkResponse { ok: true, chunk }))
}

async fn complete_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<CompleteLeaseRequest>,
) -> Result<Json<LeaseResponse>, ApiError> {
    let lease_id = LeaseId(lease_id);
    ensure_lease_tenant(&state.db, lease_id, &ctx).await?;
    let result = request
        .result
        .ok_or_else(|| ApiError::bad_request("completion result is required"))?;
    let lease = complete_lease_in_transaction(&state.db, lease_id, result).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

async fn complete_lease_in_transaction(
    db: &Database,
    lease_id: LeaseId,
    result: WorkerJobResult,
) -> Result<JobLease, ApiError> {
    let mut tx = db.pool.begin().await?;

    let completed = async {
        let lease = fetch_lease_on_connection(db, &mut *tx, lease_id).await?;
        if lease.status != LeaseStatus::Active {
            return Err(ApiError::bad_request("lease is not active"));
        }

        let now = Utc::now();
        complete_active_lease_on_connection(db, &mut *tx, lease_id, now).await?;
        apply_completed_job_on_connection(db, &mut *tx, &lease.job, result).await?;
        update_job_status_on_connection(
            db,
            &mut *tx,
            lease.job_id,
            JobStatus::Succeeded,
            None,
            now,
        )
        .await?;

        fetch_lease_on_connection(db, &mut *tx, lease_id).await
    }
    .await;

    match completed {
        Ok(lease) => {
            tx.commit().await?;
            Ok(lease)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::error!(%rollback_error, "failed to roll back lease completion");
            }
            Err(error)
        }
    }
}

async fn fail_lease(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(lease_id): Path<Uuid>,
    Json(request): Json<FailLeaseRequest>,
) -> Result<Json<LeaseResponse>, ApiError> {
    if request.error.trim().is_empty() {
        return Err(ApiError::bad_request("error is required"));
    }
    let lease_id = LeaseId(lease_id);
    let lease = ensure_lease_tenant(&state.db, lease_id, &ctx).await?;
    if lease.status != LeaseStatus::Active {
        return Err(ApiError::bad_request("lease is not active"));
    }

    let now = Utc::now();
    update_lease_status(
        &state.db,
        lease_id,
        LeaseStatus::Failed,
        Some(now),
        Some(&request.error),
    )
    .await?;
    let retry = request.retry && lease.job.attempts < lease.job.max_attempts;
    if retry {
        update_job_status(
            &state.db,
            lease.job_id,
            JobStatus::Queued,
            Some(&request.error),
            now,
        )
        .await?;
        apply_retryable_job(&state.db, &lease.job, &request.error).await?;
    } else {
        update_job_status(
            &state.db,
            lease.job_id,
            JobStatus::Failed,
            Some(&request.error),
            now,
        )
        .await?;
        apply_failed_job(&state.db, &lease.job, &request.error).await?;
    }

    let lease = fetch_lease(&state.db, lease_id).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

async fn transition_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
    next_state: SandboxState,
    reason: &'static str,
) -> Result<Json<SandboxResponse>, ApiError> {
    fetch_sandbox(db, sandbox_id).await?;
    let event_state = next_state.clone();
    set_sandbox_state(
        db,
        sandbox_id,
        next_state,
        json!({
            "state": event_state,
            "reason": reason
        }),
    )
    .await?;

    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    Ok(Json(SandboxResponse { ok: true, sandbox }))
}

async fn set_sandbox_state(
    db: &Database,
    sandbox_id: SandboxId,
    next_state: SandboxState,
    event_data: serde_json::Value,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let sql = format!(
        "update sandboxes set state = {}, updated_at = {} where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    let result = sqlx::query(&sql)
        .bind(state)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&db.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("sandbox not found"));
    }

    insert_event(
        db,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        event_data,
    )
    .await?;
    Ok(())
}

async fn set_sandbox_state_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    next_state: SandboxState,
    event_data: serde_json::Value,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let sql = format!(
        "update sandboxes set state = {}, updated_at = {} where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    let result = sqlx::query(&sql)
        .bind(state)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("sandbox not found"));
    }

    insert_event_on_connection(
        db,
        connection,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        event_data,
    )
    .await?;
    Ok(())
}

async fn fetch_sandbox(db: &Database, sandbox_id: SandboxId) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    row_to_sandbox(row)
}

async fn list_runtime_resources_for_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where sandbox_id = {}
         order by provider asc, namespace asc, resource_kind asc, purpose asc, resource_name asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;

    rows.into_iter().map(row_to_runtime_resource).collect()
}

async fn upsert_provider_runtime_resources_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resources: &[ProviderRuntimeResource],
) -> Result<(), ApiError> {
    let observed_at = Utc::now();
    for resource in resources {
        upsert_provider_runtime_resource_on_connection(
            db,
            connection,
            resource,
            Some(observed_at),
            None,
        )
        .await?;
    }

    Ok(())
}

async fn reconcile_runtime_resources_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    request: &ReconcileRuntimeResourcesRequest,
    observed_at: DateTime<Utc>,
) -> Result<(Vec<RuntimeResource>, Vec<RuntimeResource>), ApiError> {
    let mut upserted = Vec::new();
    let mut observed = Vec::new();

    for resource in &request.resources {
        let resource = upsert_provider_runtime_resource_on_connection(
            db,
            connection,
            resource,
            Some(observed_at),
            Some(observed_at),
        )
        .await?;
        observed.push(ObservedRuntimeResourceIdentity {
            resource_kind: resource.resource_kind.clone(),
            resource_name: resource.resource_name.clone(),
        });
        upserted.push(resource);
    }

    let deleted = if request.mark_missing_deleted {
        mark_missing_runtime_resources_deleted_on_connection(
            db,
            connection,
            request,
            &observed,
            observed_at,
        )
        .await?
    } else {
        Vec::new()
    };

    Ok((upserted, deleted))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedRuntimeResourceIdentity {
    resource_kind: RuntimeResourceKind,
    resource_name: String,
}

fn validate_reconcile_runtime_resources_request(
    request: &ReconcileRuntimeResourcesRequest,
) -> Result<(), ApiError> {
    if request.provider.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource provider is required",
        ));
    }
    if request.namespace.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource namespace is required",
        ));
    }
    if request
        .cluster
        .as_ref()
        .is_some_and(|cluster| cluster.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "runtime resource cluster cannot be empty",
        ));
    }

    for resource in &request.resources {
        validate_provider_runtime_resource(resource)?;
        if resource.provider != request.provider {
            return Err(ApiError::bad_request(
                "observed runtime resource provider must match reconcile provider",
            ));
        }
        if resource.namespace != request.namespace {
            return Err(ApiError::bad_request(
                "observed runtime resource namespace must match reconcile namespace",
            ));
        }
        if resource.cluster != request.cluster {
            return Err(ApiError::bad_request(
                "observed runtime resource cluster must match reconcile cluster",
            ));
        }
    }

    Ok(())
}

fn validate_provider_runtime_resource(resource: &ProviderRuntimeResource) -> Result<(), ApiError> {
    if resource.provider.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource provider is required",
        ));
    }
    if resource.namespace.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource namespace is required",
        ));
    }
    if resource
        .cluster
        .as_ref()
        .is_some_and(|cluster| cluster.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "runtime resource cluster cannot be empty",
        ));
    }
    if resource.resource_name.trim().is_empty() {
        return Err(ApiError::bad_request("runtime resource name is required"));
    }
    if resource.service_port == Some(0) {
        return Err(ApiError::bad_request(
            "runtime resource service_port must be greater than 0",
        ));
    }
    Ok(())
}

async fn fetch_runtime_resource_id_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    provider: &str,
    resource_kind: &RuntimeResourceKind,
    namespace: &str,
    cluster: &Option<String>,
    resource_name: &str,
) -> Result<Option<RuntimeResourceId>, ApiError> {
    let (sql, bind_cluster) = if cluster.is_some() {
        (
            format!(
                "select id
                 from runtime_resources
                 where provider = {} and resource_kind = {} and namespace = {} and cluster = {}
                   and resource_name = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4),
                db.placeholder(5)
            ),
            true,
        )
    } else {
        (
            format!(
                "select id
                 from runtime_resources
                 where provider = {} and resource_kind = {} and namespace = {} and cluster is null
                   and resource_name = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4)
            ),
            false,
        )
    };
    let mut query = sqlx::query(&sql)
        .bind(provider)
        .bind(runtime_resource_kind_to_str(resource_kind))
        .bind(namespace);
    if bind_cluster {
        query = query.bind(cluster);
    }
    let row = query
        .bind(resource_name)
        .fetch_optional(&mut *connection)
        .await?;
    row.map(|row| {
        let id: String = row.try_get("id")?;
        Ok(RuntimeResourceId(parse_uuid(&id)?))
    })
    .transpose()
}

async fn fetch_runtime_resource_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource_id: RuntimeResourceId,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(resource_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("runtime resource not found"))?;

    row_to_runtime_resource(row)
}

async fn upsert_provider_runtime_resource_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource: &ProviderRuntimeResource,
    observed_at: Option<DateTime<Utc>>,
    last_reconciled_at: Option<DateTime<Utc>>,
) -> Result<RuntimeResource, ApiError> {
    validate_provider_runtime_resource(resource)?;
    let existing_id = fetch_runtime_resource_id_on_connection(
        db,
        connection,
        &resource.provider,
        &resource.resource_kind,
        &resource.namespace,
        &resource.cluster,
        &resource.resource_name,
    )
    .await?;
    if let Some(resource_id) = existing_id {
        update_runtime_resource_from_provider_on_connection(
            db,
            connection,
            resource_id,
            resource,
            observed_at,
            last_reconciled_at,
        )
        .await
    } else {
        insert_runtime_resource_from_provider_on_connection(
            db,
            connection,
            resource,
            observed_at,
            last_reconciled_at,
        )
        .await
    }
}

async fn insert_runtime_resource_from_provider_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource: &ProviderRuntimeResource,
    observed_at: Option<DateTime<Utc>>,
    last_reconciled_at: Option<DateTime<Utc>>,
) -> Result<RuntimeResource, ApiError> {
    let now = Utc::now();
    let resource_id = RuntimeResourceId::new();
    let deleted_at = deleted_at_for_runtime_resource(&resource.status, now);
    let sql = format!(
        "insert into runtime_resources
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, observed_at, last_reconciled_at,
          ready_at, deleted_at, error)
         values ({})",
        db.placeholders(24)
    );
    sqlx::query(&sql)
        .bind(resource_id.to_string())
        .bind(resource.sandbox_id.to_string())
        .bind(
            resource
                .snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(&resource.provider)
        .bind(runtime_resource_kind_to_str(&resource.resource_kind))
        .bind(runtime_resource_purpose_to_str(&resource.purpose))
        .bind(&resource.resource_name)
        .bind(&resource.namespace)
        .bind(runtime_resource_status_to_str(&resource.status))
        .bind(&resource.cluster)
        .bind(&resource.storage_class)
        .bind(&resource.snapshot_class)
        .bind(&resource.storage_size)
        .bind(&resource.runtime_image)
        .bind(resource.service_port.map(i64::from))
        .bind(&resource.target_port)
        .bind(
            resource
                .source_snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(observed_at.map(|time| time.to_rfc3339()))
        .bind(last_reconciled_at.map(|time| time.to_rfc3339()))
        .bind(resource.ready_at.map(|time| time.to_rfc3339()))
        .bind(deleted_at.map(|time| time.to_rfc3339()))
        .bind(&resource.error)
        .execute(&mut *connection)
        .await?;
    fetch_runtime_resource_on_connection(db, connection, resource_id).await
}

async fn update_runtime_resource_from_provider_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource_id: RuntimeResourceId,
    resource: &ProviderRuntimeResource,
    observed_at: Option<DateTime<Utc>>,
    last_reconciled_at: Option<DateTime<Utc>>,
) -> Result<RuntimeResource, ApiError> {
    let now = Utc::now();
    let deleted_at = deleted_at_for_runtime_resource(&resource.status, now);
    let sql = format!(
        "update runtime_resources
         set sandbox_id = {}, snapshot_id = {}, provider = {}, resource_kind = {}, purpose = {},
             resource_name = {}, namespace = {}, status = {}, cluster = {}, storage_class = {},
             snapshot_class = {}, storage_size = {}, runtime_image = {}, service_port = {},
             target_port = {}, source_snapshot_id = {}, updated_at = {}, ready_at = {},
             deleted_at = {}, error = {}, observed_at = {}, last_reconciled_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9),
        db.placeholder(10),
        db.placeholder(11),
        db.placeholder(12),
        db.placeholder(13),
        db.placeholder(14),
        db.placeholder(15),
        db.placeholder(16),
        db.placeholder(17),
        db.placeholder(18),
        db.placeholder(19),
        db.placeholder(20),
        db.placeholder(21),
        db.placeholder(22),
        db.placeholder(23)
    );
    let result = sqlx::query(&sql)
        .bind(resource.sandbox_id.to_string())
        .bind(
            resource
                .snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(&resource.provider)
        .bind(runtime_resource_kind_to_str(&resource.resource_kind))
        .bind(runtime_resource_purpose_to_str(&resource.purpose))
        .bind(&resource.resource_name)
        .bind(&resource.namespace)
        .bind(runtime_resource_status_to_str(&resource.status))
        .bind(&resource.cluster)
        .bind(&resource.storage_class)
        .bind(&resource.snapshot_class)
        .bind(&resource.storage_size)
        .bind(&resource.runtime_image)
        .bind(resource.service_port.map(i64::from))
        .bind(&resource.target_port)
        .bind(
            resource
                .source_snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(now.to_rfc3339())
        .bind(resource.ready_at.map(|time| time.to_rfc3339()))
        .bind(deleted_at.map(|time| time.to_rfc3339()))
        .bind(&resource.error)
        .bind(observed_at.map(|time| time.to_rfc3339()))
        .bind(last_reconciled_at.map(|time| time.to_rfc3339()))
        .bind(resource_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("runtime resource not found"));
    }
    fetch_runtime_resource_on_connection(db, connection, resource_id).await
}

async fn mark_missing_runtime_resources_deleted_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    request: &ReconcileRuntimeResourcesRequest,
    observed: &[ObservedRuntimeResourceIdentity],
    reconciled_at: DateTime<Utc>,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let (sql, cluster_bind) = if request.cluster.is_some() {
        (
            format!(
                "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                        namespace, status, cluster, storage_class, snapshot_class, storage_size,
                        runtime_image, service_port, target_port, source_snapshot_id, created_at,
                        updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
                 from runtime_resources
                 where provider = {} and namespace = {} and cluster = {} and status != 'deleted'
                 order by resource_kind asc, resource_name asc, id asc",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            ),
            true,
        )
    } else {
        (
            format!(
                "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                        namespace, status, cluster, storage_class, snapshot_class, storage_size,
                        runtime_image, service_port, target_port, source_snapshot_id, created_at,
                        updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
                 from runtime_resources
                 where provider = {} and namespace = {} and cluster is null and status != 'deleted'
                 order by resource_kind asc, resource_name asc, id asc",
                db.placeholder(1),
                db.placeholder(2)
            ),
            false,
        )
    };
    let mut query = sqlx::query(&sql)
        .bind(&request.provider)
        .bind(&request.namespace);
    if cluster_bind {
        query = query.bind(&request.cluster);
    }
    let candidates = query.fetch_all(&mut *connection).await?;

    let mut deleted = Vec::new();
    for row in candidates {
        let resource = row_to_runtime_resource(row)?;
        if observed.iter().any(|identity| {
            identity.resource_kind == resource.resource_kind
                && identity.resource_name == resource.resource_name
        }) {
            continue;
        }
        deleted.push(
            mark_runtime_resource_deleted_on_connection(
                db,
                connection,
                resource.id,
                reconciled_at,
                "missing from runtime resource reconcile observation",
            )
            .await?,
        );
    }

    Ok(deleted)
}

async fn mark_runtime_resource_deleted_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource_id: RuntimeResourceId,
    deleted_at: DateTime<Utc>,
    error: &str,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "update runtime_resources
         set status = {}, updated_at = {}, last_reconciled_at = {}, deleted_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let result = sqlx::query(&sql)
        .bind(runtime_resource_status_to_str(
            &RuntimeResourceStatus::Deleted,
        ))
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(error)
        .bind(resource_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("runtime resource not found"));
    }

    fetch_runtime_resource_on_connection(db, connection, resource_id).await
}

async fn mark_runtime_resource_deleted(
    db: &Database,
    resource_id: RuntimeResourceId,
    deleted_at: DateTime<Utc>,
    error: &str,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "update runtime_resources
         set status = {}, updated_at = {}, last_reconciled_at = {}, deleted_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let result = sqlx::query(&sql)
        .bind(runtime_resource_status_to_str(
            &RuntimeResourceStatus::Deleted,
        ))
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(error)
        .bind(resource_id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("runtime resource not found"));
    }

    fetch_runtime_resource(db, resource_id).await
}

async fn mark_runtime_resources_deleted_for_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
    deleted_at: DateTime<Utc>,
    error: &str,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where sandbox_id = {} and status != 'deleted'
         order by updated_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;

    let mut deleted = Vec::new();
    for row in rows {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(mark_runtime_resource_deleted(db, resource.id, deleted_at, error).await?);
    }

    Ok(deleted)
}

fn deleted_at_for_runtime_resource(
    status: &RuntimeResourceStatus,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if *status == RuntimeResourceStatus::Deleted {
        Some(now)
    } else {
        None
    }
}

async fn fetch_runtime_resource(
    db: &Database,
    resource_id: RuntimeResourceId,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(resource_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("runtime resource not found"))?;

    row_to_runtime_resource(row)
}

async fn fetch_command(db: &Database, command_id: CommandId) -> Result<CommandRun, ApiError> {
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

    row_to_command(row)
}

async fn list_command_output_chunks(
    db: &Database,
    command_id: CommandId,
) -> Result<Vec<CommandOutputChunk>, ApiError> {
    let sql = format!(
        "select id, command_id, stream, sequence, chunk, created_at
         from command_output_chunks
         where command_id = {}
         order by sequence asc, created_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(command_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    rows.into_iter().map(row_to_command_output_chunk).collect()
}

async fn append_command_output_chunk(
    db: &Database,
    command_id: CommandId,
    sandbox_id: SandboxId,
    stream: CommandOutputStream,
    chunk: String,
) -> Result<CommandOutputChunk, ApiError> {
    let mut tx = db.pool.begin().await?;
    let appended = append_command_output_chunk_on_connection(
        db, &mut *tx, command_id, sandbox_id, stream, chunk,
    )
    .await;
    match appended {
        Ok(chunk) => {
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

async fn append_command_output_chunk_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    sandbox_id: SandboxId,
    stream: CommandOutputStream,
    chunk: String,
) -> Result<CommandOutputChunk, ApiError> {
    let sequence =
        next_command_output_sequence_on_connection(db, connection, command_id, &stream).await?;
    let now = Utc::now();
    let output_chunk = CommandOutputChunk {
        id: CommandOutputChunkId::new(),
        command_id,
        stream,
        sequence,
        chunk,
        created_at: now,
    };
    let sql = format!(
        "insert into command_output_chunks (id, command_id, stream, sequence, chunk, created_at)
         values ({})",
        db.placeholders(6)
    );
    sqlx::query(&sql)
        .bind(output_chunk.id.to_string())
        .bind(output_chunk.command_id.to_string())
        .bind(command_output_stream_to_str(&output_chunk.stream))
        .bind(count_to_i64(output_chunk.sequence)?)
        .bind(&output_chunk.chunk)
        .bind(output_chunk.created_at.to_rfc3339())
        .execute(&mut *connection)
        .await?;

    append_command_output_to_command_on_connection(
        db,
        connection,
        command_id,
        &output_chunk.stream,
        &output_chunk.chunk,
    )
    .await?;
    insert_event_on_connection(
        db,
        connection,
        sandbox_id,
        SandboxEventKind::CommandOutput,
        json!({
            "commandId": command_id,
            "stream": output_chunk.stream,
            "sequence": output_chunk.sequence,
            "chunk": output_chunk.chunk
        }),
    )
    .await?;

    Ok(output_chunk)
}

async fn next_command_output_sequence_on_connection(
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

async fn append_command_output_to_command_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
    chunk: &str,
) -> Result<(), ApiError> {
    let column = match stream {
        CommandOutputStream::Stdout => "stdout",
        CommandOutputStream::Stderr => "stderr",
    };
    let sql = format!(
        "update commands
         set {column} = {column} || {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let result = sqlx::query(&sql)
        .bind(chunk)
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("command not found"));
    }
    Ok(())
}

async fn command_has_output_chunks_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select id
         from command_output_chunks
         where command_id = {} and stream = {}
         limit 1",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(command_id.to_string())
        .bind(command_output_stream_to_str(stream))
        .fetch_optional(&mut *connection)
        .await?;
    Ok(row.is_some())
}

async fn fetch_worker(db: &Database, worker_id: WorkerId) -> Result<Worker, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at
         from workers
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("worker not found"))?;

    row_to_worker(row)
}

async fn active_lease_count_for_worker(
    db: &Database,
    worker_id: WorkerId,
) -> Result<u32, ApiError> {
    let sql = format!(
        "select count(*) as active_leases
         from job_leases
         where worker_id = {} and status = 'active'",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .fetch_one(&db.pool)
        .await?;
    let active_leases: i64 = row.try_get("active_leases")?;
    u32::try_from(active_leases)
        .map_err(|_| ApiError::internal("database contains invalid active lease count"))
}

async fn worker_has_capacity(db: &Database, worker: &Worker) -> Result<bool, ApiError> {
    let active_leases = active_lease_count_for_worker(db, worker.id).await?;
    Ok(active_leases < worker.max_concurrent_jobs)
}

async fn list_worker_capacities(
    db: &Database,
    tenant_id: &str,
) -> Result<Vec<WorkerCapacity>, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at
         from workers
         where tenant_id = {}
         order by registered_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(&db.pool)
        .await?;

    let mut capacities = Vec::new();
    for row in rows {
        let worker = row_to_worker(row)?;
        let active_leases = active_lease_count_for_worker(db, worker.id).await?;
        capacities.push(WorkerCapacity {
            worker_id: worker.id,
            worker_name: worker.name,
            provider: worker.provider,
            status: worker.status,
            max_concurrent_jobs: worker.max_concurrent_jobs,
            active_leases,
            available_slots: worker.max_concurrent_jobs.saturating_sub(active_leases),
        });
    }

    Ok(capacities)
}

async fn fetch_guest_health(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Option<GuestHealth>, ApiError> {
    let sql = format!(
        "select sandbox_id, status, last_probe_at, agent_version, checks, message
         from guest_health
         where sandbox_id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    row.map(row_to_guest_health).transpose()
}

async fn fetch_ssh_key(db: &Database, ssh_key_id: SshKeyId) -> Result<SshKey, ApiError> {
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

fn pending_snapshot_from_request(
    sandbox_id: SandboxId,
    request: CreateSnapshotRequest,
) -> Result<Snapshot, ApiError> {
    let now = Utc::now();
    let label = match request.label {
        Some(label) if label.trim().is_empty() => {
            return Err(ApiError::bad_request("snapshot label cannot be empty"));
        }
        Some(label) => label,
        None => "manual-snapshot".to_string(),
    };

    Ok(Snapshot {
        id: SnapshotId::new(),
        sandbox_id,
        status: SnapshotStatus::Pending,
        label,
        inventory: request.inventory.unwrap_or_else(|| json!({})),
        provider_metadata: request.provider_metadata.unwrap_or_else(|| json!({})),
        created_at: now,
        ready_at: None,
        expires_at: expires_at_from_ttl(now, request.ttl_seconds)?,
        error: None,
    })
}

fn desktop_session_from_request(
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

fn updated_desktop_session(
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

fn validate_broker(broker: String) -> Result<String, ApiError> {
    let broker = broker.trim();
    if broker.is_empty() {
        return Err(ApiError::bad_request("desktop broker is required"));
    }
    Ok(broker.to_string())
}

fn sanitize_broker_url(value: Option<String>) -> Result<Option<String>, ApiError> {
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

fn expires_at_from_ttl(
    now: DateTime<Utc>,
    ttl_seconds: Option<u64>,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    let Some(ttl_seconds) = ttl_seconds else {
        return Ok(None);
    };
    let ttl_seconds = i64::try_from(ttl_seconds)
        .map_err(|_| ApiError::bad_request("ttl_seconds is too large"))?;
    Ok(Some(now + chrono::Duration::seconds(ttl_seconds)))
}

async fn insert_sandbox(db: &Database, sandbox: &Sandbox) -> Result<(), ApiError> {
    let sql = format!(
        "insert into sandboxes
         (id, tenant_id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        db.placeholders(9)
    );
    sqlx::query(&sql)
        .bind(sandbox.id.to_string())
        .bind(&sandbox.tenant_id)
        .bind(&sandbox.name)
        .bind(state_to_str(&sandbox.state))
        .bind(&sandbox.template)
        .bind(sandbox.created_at.to_rfc3339())
        .bind(sandbox.updated_at.to_rfc3339())
        .bind(sandbox.ttl_seconds.map(|ttl| ttl as i64))
        .bind(
            sandbox
                .parent_snapshot_id
                .map(|snapshot| snapshot.0.to_string()),
        )
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn insert_snapshot(db: &Database, snapshot: &Snapshot) -> Result<(), ApiError> {
    let sql = format!(
        "insert into snapshots
         (id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error)
         values ({})",
        db.placeholders(10)
    );
    sqlx::query(&sql)
        .bind(snapshot.id.to_string())
        .bind(snapshot.sandbox_id.to_string())
        .bind(snapshot_status_to_str(&snapshot.status))
        .bind(&snapshot.label)
        .bind(serde_json::to_string(&snapshot.inventory)?)
        .bind(serde_json::to_string(&snapshot.provider_metadata)?)
        .bind(snapshot.created_at.to_rfc3339())
        .bind(snapshot.ready_at.map(|time| time.to_rfc3339()))
        .bind(snapshot.expires_at.map(|time| time.to_rfc3339()))
        .bind(&snapshot.error)
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn insert_cleanup_run(db: &Database, cleanup_run: &CleanupRun) -> Result<(), ApiError> {
    let sql = format!(
        "insert into cleanup_runs
         (id, status, started_at, finished_at, expired_snapshots, archived_sandboxes_deleted,
          archived_sandboxes_skipped, runtime_resources_deleted, error)
         values ({})",
        db.placeholders(9)
    );
    sqlx::query(&sql)
        .bind(cleanup_run.id.to_string())
        .bind(cleanup_run_status_to_str(&cleanup_run.status))
        .bind(cleanup_run.started_at.to_rfc3339())
        .bind(cleanup_run.finished_at.map(|time| time.to_rfc3339()))
        .bind(count_to_i64(cleanup_run.expired_snapshots)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_deleted)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_skipped)?)
        .bind(count_to_i64(cleanup_run.runtime_resources_deleted)?)
        .bind(&cleanup_run.error)
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn update_cleanup_run(db: &Database, cleanup_run: &CleanupRun) -> Result<(), ApiError> {
    let sql = format!(
        "update cleanup_runs
         set status = {}, finished_at = {}, expired_snapshots = {},
             archived_sandboxes_deleted = {}, archived_sandboxes_skipped = {},
             runtime_resources_deleted = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8)
    );
    let result = sqlx::query(&sql)
        .bind(cleanup_run_status_to_str(&cleanup_run.status))
        .bind(cleanup_run.finished_at.map(|time| time.to_rfc3339()))
        .bind(count_to_i64(cleanup_run.expired_snapshots)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_deleted)?)
        .bind(count_to_i64(cleanup_run.archived_sandboxes_skipped)?)
        .bind(count_to_i64(cleanup_run.runtime_resources_deleted)?)
        .bind(&cleanup_run.error)
        .bind(cleanup_run.id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("cleanup run not found"));
    }
    Ok(())
}

fn count_to_i64(count: u64) -> Result<i64, ApiError> {
    i64::try_from(count).map_err(|_| ApiError::internal("cleanup count is too large"))
}

async fn fetch_snapshot(db: &Database, snapshot_id: SnapshotId) -> Result<Snapshot, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("snapshot not found"))?;

    row_to_snapshot(row)
}

async fn fetch_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
) -> Result<Snapshot, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("snapshot not found"))?;

    row_to_snapshot(row)
}

async fn list_snapshots_for_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<Snapshot>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where sandbox_id = {}
         order by created_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;

    rows.into_iter().map(row_to_snapshot).collect()
}

struct CleanupControllerReport {
    cleanup_run: CleanupRun,
    expired: Vec<Snapshot>,
    archived_sandboxes_deleted: u64,
    archived_sandboxes: Vec<Sandbox>,
    archived_sandboxes_skipped: Vec<ArchivedSandboxCleanupSkip>,
    runtime_resources_deleted: Vec<RuntimeResource>,
}

struct ArchivedSandboxCleanupResult {
    deleted: Vec<Sandbox>,
    skipped: Vec<ArchivedSandboxCleanupSkip>,
    runtime_resources_deleted: Vec<RuntimeResource>,
}

async fn run_cleanup_controller(db: &Database) -> Result<CleanupControllerReport, ApiError> {
    let started_at = Utc::now();
    let cleanup_run = CleanupRun {
        id: CleanupRunId::new(),
        status: CleanupRunStatus::Running,
        started_at,
        finished_at: None,
        expired_snapshots: 0,
        archived_sandboxes_deleted: 0,
        archived_sandboxes_skipped: 0,
        runtime_resources_deleted: 0,
        error: None,
    };
    insert_cleanup_run(db, &cleanup_run).await?;

    let started_run = cleanup_run.clone();
    let result: Result<CleanupControllerReport, ApiError> = async {
        let expired = expire_due_snapshots(db).await?;
        let mut runtime_resources_deleted =
            cleanup_runtime_resources_for_expired_snapshots(db).await?;
        let archived = cleanup_archived_sandboxes(db).await?;
        runtime_resources_deleted.extend(archived.runtime_resources_deleted);

        let archived_sandboxes_deleted = archived.deleted.len() as u64;
        let cleanup_run = CleanupRun {
            status: CleanupRunStatus::Succeeded,
            finished_at: Some(Utc::now()),
            expired_snapshots: expired.len() as u64,
            archived_sandboxes_deleted,
            archived_sandboxes_skipped: archived.skipped.len() as u64,
            runtime_resources_deleted: runtime_resources_deleted.len() as u64,
            ..started_run.clone()
        };
        update_cleanup_run(db, &cleanup_run).await?;

        Ok(CleanupControllerReport {
            cleanup_run,
            expired,
            archived_sandboxes_deleted,
            archived_sandboxes: archived.deleted,
            archived_sandboxes_skipped: archived.skipped,
            runtime_resources_deleted,
        })
    }
    .await;

    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            let failed = CleanupRun {
                status: CleanupRunStatus::Failed,
                finished_at: Some(Utc::now()),
                error: Some(format!("{error:?}")),
                ..cleanup_run
            };
            if let Err(update_error) = update_cleanup_run(db, &failed).await {
                tracing::warn!(?update_error, "failed to mark cleanup run failed");
            }
            Err(error)
        }
    }
}

async fn expire_due_snapshots(db: &Database) -> Result<Vec<Snapshot>, ApiError> {
    let now = Utc::now();
    let rows = sqlx::query(
        "select id, sandbox_id, status, label, inventory, provider_metadata, created_at, ready_at, expires_at, error
         from snapshots
         where status in ('pending', 'ready') and expires_at is not null
         order by expires_at asc, id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let mut expired = Vec::new();
    for row in rows {
        let snapshot = row_to_snapshot(row)?;
        let Some(expires_at) = snapshot.expires_at else {
            continue;
        };
        if expires_at > now {
            continue;
        }
        update_snapshot_status(db, snapshot.id, SnapshotStatus::Expired, None).await?;
        dead_queued_snapshot_jobs(db, snapshot.id, "snapshot expired").await?;
        let expired_snapshot = fetch_snapshot(db, snapshot.id).await?;
        insert_event(
            db,
            expired_snapshot.sandbox_id,
            SandboxEventKind::LifecycleChanged,
            json!({
                "reason": "snapshot_expired",
                "snapshotId": expired_snapshot.id,
                "snapshotStatus": expired_snapshot.status
            }),
        )
        .await?;
        expired.push(expired_snapshot);
    }

    Ok(expired)
}

async fn update_snapshot_status(
    db: &Database,
    snapshot_id: SnapshotId,
    status: SnapshotStatus,
    error: Option<&str>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update snapshots
         set status = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    let result = sqlx::query(&sql)
        .bind(snapshot_status_to_str(&status))
        .bind(error)
        .bind(snapshot_id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("snapshot not found"));
    }
    Ok(())
}

async fn dead_queued_snapshot_jobs(
    db: &Database,
    snapshot_id: SnapshotId,
    error: &str,
) -> Result<(), ApiError> {
    let rows = sqlx::query(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where kind = 'create_snapshot' and status = 'queued'
         order by scheduled_at asc, created_at asc, id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let now = Utc::now();
    for row in rows {
        let job = row_to_job(row)?;
        if snapshot_id_from_job(&job)? == snapshot_id {
            update_job_status(db, job.id, JobStatus::Dead, Some(error), now).await?;
        }
    }

    Ok(())
}

async fn cleanup_runtime_resources_for_expired_snapshots(
    db: &Database,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let rows = sqlx::query(
        "select runtime_resources.id, runtime_resources.sandbox_id, runtime_resources.snapshot_id,
                runtime_resources.provider, runtime_resources.resource_kind, runtime_resources.purpose,
                runtime_resources.resource_name, runtime_resources.namespace, runtime_resources.status,
                runtime_resources.cluster, runtime_resources.storage_class, runtime_resources.snapshot_class,
                runtime_resources.storage_size, runtime_resources.runtime_image, runtime_resources.service_port,
                runtime_resources.target_port, runtime_resources.source_snapshot_id, runtime_resources.created_at,
                runtime_resources.updated_at, runtime_resources.observed_at, runtime_resources.last_reconciled_at,
                runtime_resources.ready_at, runtime_resources.deleted_at, runtime_resources.error
         from runtime_resources
         join snapshots on snapshots.id = runtime_resources.snapshot_id
         where snapshots.status = 'expired' and runtime_resources.status != 'deleted'
         order by runtime_resources.updated_at asc, runtime_resources.id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let mut deleted = Vec::new();
    for row in rows {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(
            mark_runtime_resource_deleted(
                db,
                resource.id,
                Utc::now(),
                "snapshot expired during cleanup",
            )
            .await?,
        );
    }

    Ok(deleted)
}

async fn cleanup_archived_sandboxes(
    db: &Database,
) -> Result<ArchivedSandboxCleanupResult, ApiError> {
    let rows = sqlx::query(
        "select id, tenant_id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where state = 'archived' and ttl_seconds is not null
         order by updated_at asc, id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let now = Utc::now();
    let mut deleted = Vec::new();
    let mut skipped = Vec::new();
    let mut runtime_resources_deleted = Vec::new();
    for row in rows {
        let sandbox = row_to_sandbox(row)?;
        let Some(ttl_seconds) = sandbox.ttl_seconds else {
            continue;
        };
        let expires_at = expires_at_from_ttl(sandbox.updated_at, Some(ttl_seconds))?;
        if expires_at.is_some_and(|expires_at| expires_at > now) {
            continue;
        }
        if sandbox_snapshot_is_referenced(db, sandbox.id).await? {
            skipped.push(ArchivedSandboxCleanupSkip {
                sandbox,
                reason: "sandbox has snapshots referenced by child sandboxes".to_string(),
            });
            continue;
        }
        runtime_resources_deleted.extend(
            mark_runtime_resources_deleted_for_sandbox(
                db,
                sandbox.id,
                now,
                "archived sandbox deleted during cleanup",
            )
            .await?,
        );
        let sql = format!(
            "delete from sandboxes where id = {} and state = 'archived'",
            db.placeholder(1)
        );
        let result = sqlx::query(&sql)
            .bind(sandbox.id.to_string())
            .execute(&db.pool)
            .await?;
        if result.rows_affected() > 0 {
            deleted.push(sandbox);
        }
    }

    Ok(ArchivedSandboxCleanupResult {
        deleted,
        skipped,
        runtime_resources_deleted,
    })
}

async fn sandbox_snapshot_is_referenced(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select snapshots.id
         from snapshots
         join sandboxes on sandboxes.parent_snapshot_id = snapshots.id
         where snapshots.sandbox_id = {}
         limit 1",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?;
    Ok(row.is_some())
}

async fn insert_desktop_session(
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

async fn fetch_desktop_session(
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

async fn list_desktop_sessions_for_sandbox(
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

async fn update_desktop_session(
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

async fn expire_due_desktop_sessions(db: &Database) -> Result<Vec<DesktopSession>, ApiError> {
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
        let mut desktop_session = row_to_desktop_session(row)?;
        let Some(expires_at) = desktop_session.expires_at else {
            continue;
        };
        if expires_at > now {
            continue;
        }
        desktop_session.status = DesktopSessionStatus::Expired;
        desktop_session.updated_at = now;
        desktop_session.error = Some("desktop session expired".to_string());
        update_desktop_session(db, &desktop_session).await?;
        insert_desktop_event(db, &desktop_session, SandboxEventKind::DesktopExpired).await?;
        expired.push(fetch_desktop_session(db, desktop_session.id).await?);
    }

    Ok(expired)
}

async fn insert_desktop_event(
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

fn desktop_event_kind_for_status(status: &DesktopSessionStatus) -> SandboxEventKind {
    match status {
        DesktopSessionStatus::Pending => SandboxEventKind::DesktopRequested,
        DesktopSessionStatus::Ready => SandboxEventKind::DesktopReady,
        DesktopSessionStatus::Failed => SandboxEventKind::DesktopFailed,
        DesktopSessionStatus::Closed => SandboxEventKind::DesktopClosed,
        DesktopSessionStatus::Expired => SandboxEventKind::DesktopExpired,
    }
}

fn mint_desktop_access(
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

fn desktop_access_url(desktop_session: &DesktopSession) -> String {
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

fn mint_ssh_access(
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

async fn upsert_guest_health(db: &Database, guest_health: &GuestHealth) -> Result<(), ApiError> {
    if fetch_guest_health(db, guest_health.sandbox_id)
        .await?
        .is_some()
    {
        let sql = format!(
            "update guest_health
             set status = {}, last_probe_at = {}, agent_version = {}, checks = {}, message = {}
             where sandbox_id = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4),
            db.placeholder(5),
            db.placeholder(6)
        );
        sqlx::query(&sql)
            .bind(guest_status_to_str(&guest_health.status))
            .bind(guest_health.last_probe_at.to_rfc3339())
            .bind(&guest_health.agent_version)
            .bind(serde_json::to_string(&guest_health.checks)?)
            .bind(&guest_health.message)
            .bind(guest_health.sandbox_id.to_string())
            .execute(&db.pool)
            .await?;
    } else {
        let sql = format!(
            "insert into guest_health
             (sandbox_id, status, last_probe_at, agent_version, checks, message)
             values ({})",
            db.placeholders(6)
        );
        sqlx::query(&sql)
            .bind(guest_health.sandbox_id.to_string())
            .bind(guest_status_to_str(&guest_health.status))
            .bind(guest_health.last_probe_at.to_rfc3339())
            .bind(&guest_health.agent_version)
            .bind(serde_json::to_string(&guest_health.checks)?)
            .bind(&guest_health.message)
            .execute(&db.pool)
            .await?;
    }

    Ok(())
}

async fn insert_ssh_key(db: &Database, ssh_key: &SshKey) -> Result<(), ApiError> {
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

async fn insert_command(db: &Database, command: &CommandRun) -> Result<(), ApiError> {
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

async fn insert_job(db: &Database, job: &Job) -> Result<(), ApiError> {
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error)
         values ({})",
        db.placeholders(13)
    );
    sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.priority)
        .bind(job.attempts)
        .bind(job.max_attempts)
        .bind(job.scheduled_at.to_rfc3339())
        .bind(job.created_at.to_rfc3339())
        .bind(job.updated_at.to_rfc3339())
        .bind(&job.last_error)
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn insert_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error)
         values ({})",
        db.placeholders(13)
    );
    sqlx::query(&sql)
        .bind(job.id.to_string())
        .bind(&job.tenant_id)
        .bind(job_kind_to_str(&job.kind))
        .bind(job_status_to_str(&job.status))
        .bind(serde_json::to_string(&job.payload)?)
        .bind(worker_capability_to_str(&job.required_capability))
        .bind(job.priority)
        .bind(job.attempts)
        .bind(job.max_attempts)
        .bind(job.scheduled_at.to_rfc3339())
        .bind(job.created_at.to_rfc3339())
        .bind(job.updated_at.to_rfc3339())
        .bind(&job.last_error)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn try_claim_job(
    db: &Database,
    worker_id: WorkerId,
    job: &Job,
    lease_seconds: Option<u64>,
) -> Result<Option<JobLease>, ApiError> {
    let now = Utc::now();
    let attempt = job.attempts + 1;
    let expires_at = now + chrono::Duration::seconds(lease_seconds.unwrap_or(60) as i64);
    let sql = format!(
        "update jobs
         set status = {}, attempts = {}, updated_at = {}
         where id = {} and status = 'queued'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let result = sqlx::query(&sql)
        .bind(job_status_to_str(&JobStatus::Leased))
        .bind(attempt)
        .bind(now.to_rfc3339())
        .bind(job.id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    let lease = JobLease {
        id: LeaseId::new(),
        job_id: job.id,
        worker_id,
        status: LeaseStatus::Active,
        attempt,
        leased_at: now,
        expires_at,
        completed_at: None,
        error: None,
        job: fetch_job(db, job.id).await?,
    };
    insert_lease(db, &lease).await?;
    let lease = fetch_lease(db, lease.id).await?;
    apply_claimed_job(db, &lease.job).await?;
    Ok(Some(lease))
}

async fn insert_lease(db: &Database, lease: &JobLease) -> Result<(), ApiError> {
    let sql = format!(
        "insert into job_leases
         (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
         values ({})",
        db.placeholders(9)
    );
    sqlx::query(&sql)
        .bind(lease.id.to_string())
        .bind(lease.job_id.to_string())
        .bind(lease.worker_id.to_string())
        .bind(lease_status_to_str(&lease.status))
        .bind(lease.attempt)
        .bind(lease.leased_at.to_rfc3339())
        .bind(lease.expires_at.to_rfc3339())
        .bind(lease.completed_at.map(|time| time.to_rfc3339()))
        .bind(&lease.error)
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn expire_due_leases(db: &Database) -> Result<(), ApiError> {
    let now = Utc::now();
    let rows = sqlx::query(
        "select id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error
         from job_leases
         where status = 'active'
         order by expires_at asc, id asc",
    )
    .fetch_all(&db.pool)
    .await?;

    for row in rows {
        let lease = row_to_lease_without_job(row)?;
        if lease.expires_at > now {
            continue;
        }
        let job = fetch_job(db, lease.job_id).await?;
        let next_status = if job.attempts >= job.max_attempts {
            JobStatus::Dead
        } else {
            JobStatus::Queued
        };
        update_lease_status(
            db,
            lease.id,
            LeaseStatus::Expired,
            Some(now),
            Some("lease expired"),
        )
        .await?;
        update_job_status(db, job.id, next_status, Some("lease expired"), now).await?;
        if job.attempts >= job.max_attempts {
            apply_failed_job(db, &job, "lease expired").await?;
        } else {
            apply_retryable_job(db, &job, "lease expired").await?;
        }
    }

    Ok(())
}

async fn fetch_job(db: &Database, job_id: JobId) -> Result<Job, ApiError> {
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(job_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    row_to_job(row)
}

async fn fetch_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job_id: JobId,
) -> Result<Job, ApiError> {
    let sql = format!(
        "select id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
                scheduled_at, created_at, updated_at, last_error
         from jobs
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(job_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("job not found"))?;
    row_to_job(row)
}

async fn fetch_lease(db: &Database, lease_id: LeaseId) -> Result<JobLease, ApiError> {
    let sql = format!(
        "select id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error
         from job_leases
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("lease not found"))?;
    let lease = row_to_lease_without_job(row)?;
    let job = fetch_job(db, lease.job_id).await?;
    Ok(JobLease { job, ..lease })
}

async fn fetch_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
) -> Result<JobLease, ApiError> {
    let sql = format!(
        "select id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error
         from job_leases
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("lease not found"))?;
    let lease = row_to_lease_without_job(row)?;
    let job = fetch_job_on_connection(db, connection, lease.job_id).await?;
    Ok(JobLease { job, ..lease })
}

async fn update_lease_status(
    db: &Database,
    lease_id: LeaseId,
    status: LeaseStatus,
    completed_at: Option<DateTime<Utc>>,
    error: Option<&str>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update job_leases
         set status = {}, completed_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(lease_status_to_str(&status))
        .bind(completed_at.map(|time| time.to_rfc3339()))
        .bind(error)
        .bind(lease_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn complete_active_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
    completed_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update job_leases
         set status = {}, completed_at = {}, error = {}
         where id = {} and status = 'active'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let result = sqlx::query(&sql)
        .bind(lease_status_to_str(&LeaseStatus::Completed))
        .bind(completed_at.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(lease_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::bad_request("lease is not active"));
    }
    Ok(())
}

async fn update_job_status(
    db: &Database,
    job_id: JobId,
    status: JobStatus,
    error: Option<&str>,
    updated_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update jobs
         set status = {}, last_error = {}, updated_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(job_status_to_str(&status))
        .bind(error)
        .bind(updated_at.to_rfc3339())
        .bind(job_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn update_job_status_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job_id: JobId,
    status: JobStatus,
    error: Option<&str>,
    updated_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "update jobs
         set status = {}, last_error = {}, updated_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(job_status_to_str(&status))
        .bind(error)
        .bind(updated_at.to_rfc3339())
        .bind(job_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn update_command_from_lease_result(
    db: &Database,
    command_id: CommandId,
    status: CommandStatus,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let sql = format!(
        "update commands
         set status = {}, stdout = {}, stderr = {}, exit_code = {}, finished_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    sqlx::query(&sql)
        .bind(command_status_to_str(&status))
        .bind(stdout)
        .bind(stderr)
        .bind(exit_code)
        .bind(now.to_rfc3339())
        .bind(command_id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn finish_command_from_lease_result_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    status: CommandStatus,
    exit_code: Option<i32>,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let sql = format!(
        "update commands
         set status = {}, exit_code = {}, finished_at = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    sqlx::query(&sql)
        .bind(command_status_to_str(&status))
        .bind(exit_code)
        .bind(now.to_rfc3339())
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn append_completion_output_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    sandbox_id: SandboxId,
    stream: CommandOutputStream,
    chunk: &str,
) -> Result<(), ApiError> {
    if chunk.is_empty()
        || command_has_output_chunks_on_connection(db, connection, command_id, &stream).await?
    {
        return Ok(());
    }
    append_command_output_chunk_on_connection(
        db,
        connection,
        command_id,
        sandbox_id,
        stream,
        chunk.to_string(),
    )
    .await?;
    Ok(())
}

async fn apply_completed_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    result: WorkerJobResult,
) -> Result<(), ApiError> {
    match (&job.kind, result) {
        (JobKind::RunCommand, WorkerJobResult::RunCommand { result }) => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            let stdout = result.stdout.as_str();
            let stderr = result.stderr.as_str();
            let exit_code = result.exit_code.or(Some(0));
            append_completion_output_on_connection(
                db,
                connection,
                command_id,
                sandbox_id,
                CommandOutputStream::Stdout,
                stdout,
            )
            .await?;
            append_completion_output_on_connection(
                db,
                connection,
                command_id,
                sandbox_id,
                CommandOutputStream::Stderr,
                stderr,
            )
            .await?;
            finish_command_from_lease_result_on_connection(
                db,
                connection,
                command_id,
                CommandStatus::Finished,
                exit_code,
            )
            .await?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::CommandFinished,
                json!({
                    "commandId": command_id,
                    "exitCode": exit_code,
                    "stdout": stdout,
                    "stderr": stderr
                }),
            )
            .await?;
        }
        (JobKind::CreateSnapshot, WorkerJobResult::CreateSnapshot { handle }) => {
            let snapshot_id = snapshot_id_from_job(job)?;
            if handle.snapshot_id != snapshot_id {
                return Err(ApiError::bad_request(
                    "snapshot completion result does not match job snapshot",
                ));
            }
            mark_snapshot_ready_from_provider_handle_on_connection(
                db,
                connection,
                sandbox_id_from_job(job)?,
                handle,
            )
            .await?;
        }
        (JobKind::RunPrompt, WorkerJobResult::RunPrompt { output }) => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::PromptFinished,
                json!({
                    "promptEventId": prompt_event_id,
                    "output": output
                }),
            )
            .await?;
        }
        (JobKind::ForkSandbox, WorkerJobResult::ForkSandbox { handle }) => {
            let parent_id = parent_sandbox_id_from_job(job)?;
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            if handle.parent_sandbox_id != parent_id
                || handle.child_sandbox_id != child_id
                || handle.snapshot_id != snapshot_id
            {
                return Err(ApiError::bad_request(
                    "fork completion result does not match job payload",
                ));
            }
            upsert_provider_runtime_resources_on_connection(db, connection, &handle.resources)
                .await?;
            let next_state = SandboxState::Ready;
            set_sandbox_state_on_connection(
                db,
                connection,
                child_id,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_ready",
                    "parentSnapshotId": snapshot_id
                }),
            )
            .await?;
        }
        (JobKind::ProvisionSandbox, WorkerJobResult::ProvisionSandbox { handle }) => {
            let sandbox_id = sandbox_id_from_job(job)?;
            if handle.sandbox_id != sandbox_id {
                return Err(ApiError::bad_request(
                    "provision completion result does not match job sandbox",
                ));
            }
            upsert_provider_runtime_resources_on_connection(db, connection, &handle.resources)
                .await?;
            let next_state = SandboxState::Ready;
            set_sandbox_state_on_connection(
                db,
                connection,
                sandbox_id,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "provision_ready",
                    "provider": handle.provider
                }),
            )
            .await?;
        }
        (JobKind::StopSandbox, WorkerJobResult::StopSandbox { sandbox_id, .. }) => {
            if sandbox_id != sandbox_id_from_job(job)? {
                return Err(ApiError::bad_request(
                    "stop completion result does not match job sandbox",
                ));
            }
        }
        (JobKind::ResumeSandbox, WorkerJobResult::ResumeSandbox { sandbox_id, .. }) => {
            if sandbox_id != sandbox_id_from_job(job)? {
                return Err(ApiError::bad_request(
                    "resume completion result does not match job sandbox",
                ));
            }
        }
        _ => {
            return Err(ApiError::bad_request(
                "completion result kind does not match job kind",
            ));
        }
    }
    Ok(())
}

async fn apply_claimed_job(db: &Database, job: &Job) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            let sql = format!(
                "update commands
                 set status = {}
                 where id = {}",
                db.placeholder(1),
                db.placeholder(2)
            );
            sqlx::query(&sql)
                .bind(command_status_to_str(&CommandStatus::Running))
                .bind(command_id.to_string())
                .execute(&db.pool)
                .await?;
            insert_event(
                db,
                sandbox_id,
                SandboxEventKind::CommandStarted,
                json!({
                    "commandId": command_id
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            update_snapshot_status(
                db,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Pending,
                None,
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event(
                db,
                sandbox_id,
                SandboxEventKind::PromptStarted,
                json!({
                    "promptEventId": prompt_event_id
                }),
            )
            .await?;
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            let next_state = SandboxState::Provisioning;
            set_sandbox_state(
                db,
                child_id,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_provisioning",
                    "parentSnapshotId": snapshot_id
                }),
            )
            .await?;
        }
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

async fn apply_retryable_job(db: &Database, job: &Job, error: &str) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            let sql = format!(
                "update commands
                 set status = {}, stderr = {}
                 where id = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            );
            sqlx::query(&sql)
                .bind(command_status_to_str(&CommandStatus::Queued))
                .bind(error)
                .bind(command_id.to_string())
                .execute(&db.pool)
                .await?;
            insert_event(
                db,
                sandbox_id,
                SandboxEventKind::CommandQueued,
                json!({
                    "commandId": command_id,
                    "reason": "retry",
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            update_snapshot_status(
                db,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Pending,
                Some(error),
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event(
                db,
                sandbox_id,
                SandboxEventKind::PromptQueued,
                json!({
                    "promptEventId": prompt_event_id,
                    "reason": "retry",
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            let next_state = SandboxState::Planning;
            set_sandbox_state(
                db,
                child_id,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_retry",
                    "parentSnapshotId": snapshot_id,
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

async fn apply_failed_job(db: &Database, job: &Job, error: &str) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            update_command_from_lease_result(
                db,
                command_id,
                CommandStatus::Failed,
                "",
                error,
                None,
            )
            .await?;
            insert_event(
                db,
                sandbox_id,
                SandboxEventKind::CommandFinished,
                json!({
                    "commandId": command_id,
                    "exitCode": null,
                    "stderr": error
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            update_snapshot_status(
                db,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Failed,
                Some(error),
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event(
                db,
                sandbox_id,
                SandboxEventKind::PromptFinished,
                json!({
                    "promptEventId": prompt_event_id,
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ForkSandbox => {
            let child_id = child_sandbox_id_from_job(job)?;
            let snapshot_id = snapshot_id_from_job(job)?;
            let next_state = SandboxState::Error;
            set_sandbox_state(
                db,
                child_id,
                next_state.clone(),
                json!({
                    "state": next_state,
                    "reason": "fork_failed",
                    "parentSnapshotId": snapshot_id,
                    "error": error
                }),
            )
            .await?;
        }
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

async fn mark_snapshot_ready_from_provider_handle_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    handle: sandboxwich_core::ProviderSnapshotHandle,
) -> Result<(), ApiError> {
    let snapshot_id = handle.snapshot_id;
    upsert_provider_runtime_resources_on_connection(db, connection, &handle.resources).await?;
    let snapshot = fetch_snapshot_on_connection(db, connection, snapshot_id).await?;
    let provider = handle.provider.clone();
    let inventory = if snapshot.inventory == json!({}) {
        json!({
            "sandboxId": sandbox_id,
            "snapshotId": snapshot_id,
            "provider": provider
        })
    } else {
        snapshot.inventory
    };
    let provider_metadata = handle.metadata;
    let now = Utc::now();
    let sql = format!(
        "update snapshots
         set status = {}, inventory = {}, provider_metadata = {}, ready_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let result = sqlx::query(&sql)
        .bind(snapshot_status_to_str(&SnapshotStatus::Ready))
        .bind(serde_json::to_string(&inventory)?)
        .bind(serde_json::to_string(&provider_metadata)?)
        .bind(now.to_rfc3339())
        .bind(Option::<String>::None)
        .bind(snapshot_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("snapshot not found"));
    }
    queue_forks_waiting_on_snapshot_on_connection(db, connection, snapshot_id, sandbox_id).await?;
    Ok(())
}

async fn queue_forks_waiting_on_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    parent_sandbox_id: SandboxId,
) -> Result<(), ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where parent_snapshot_id = {} and state = 'planning'
         order by created_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    for row in rows {
        let child = row_to_sandbox(row)?;
        let now = Utc::now();
        insert_job_on_connection(
            db,
            connection,
            &Job {
                id: JobId::new(),
                tenant_id: child.tenant_id.clone(),
                kind: JobKind::ForkSandbox,
                status: JobStatus::Queued,
                payload: json!({
                    "parentSandboxId": parent_sandbox_id,
                    "childSandboxId": child.id,
                    "snapshotId": snapshot_id
                }),
                required_capability: WorkerCapability::Snapshot,
                priority: 0,
                attempts: 0,
                max_attempts: 3,
                scheduled_at: now,
                created_at: now,
                updated_at: now,
                last_error: None,
            },
        )
        .await?;
        insert_event_on_connection(
            db,
            connection,
            child.id,
            SandboxEventKind::LifecycleChanged,
            json!({
                "state": child.state,
                "reason": "fork_snapshot_ready",
                "parentSandboxId": parent_sandbox_id,
                "parentSnapshotId": snapshot_id
            }),
        )
        .await?;
    }

    Ok(())
}

fn command_id_from_job(job: &Job) -> Result<CommandId, ApiError> {
    uuid_from_job_payload(job, "commandId", "run command job is missing command id").map(CommandId)
}

fn prompt_event_id_from_job(job: &Job) -> Result<EventId, ApiError> {
    uuid_from_job_payload(
        job,
        "promptEventId",
        "prompt job is missing prompt event id",
    )
    .map(EventId)
}

fn sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(job, "sandboxId", "run command job is missing sandbox id").map(SandboxId)
}

fn parent_sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(
        job,
        "parentSandboxId",
        "fork job is missing parent sandbox id",
    )
    .map(SandboxId)
}

fn child_sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(
        job,
        "childSandboxId",
        "fork job is missing child sandbox id",
    )
    .map(SandboxId)
}

fn snapshot_id_from_job(job: &Job) -> Result<SnapshotId, ApiError> {
    uuid_from_job_payload(job, "snapshotId", "snapshot job is missing snapshot id").map(SnapshotId)
}

fn uuid_from_job_payload(
    job: &Job,
    key: &'static str,
    missing: &'static str,
) -> Result<Uuid, ApiError> {
    let value = job
        .payload
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::internal(missing))?;
    parse_uuid(value)
}

async fn insert_event(
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

async fn insert_event_on_connection(
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

impl SqlDialect {
    fn from_url(database_url: &str) -> anyhow::Result<Self> {
        if database_url.starts_with("sqlite:") {
            return Ok(Self::Sqlite);
        }
        if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
            return Ok(Self::Postgres);
        }
        anyhow::bail!("unsupported database URL scheme");
    }
}

impl Database {
    fn placeholder(&self, index: usize) -> String {
        match self.dialect {
            SqlDialect::Postgres => format!("${index}"),
            SqlDialect::Sqlite => "?".to_string(),
        }
    }

    fn placeholders(&self, count: usize) -> String {
        (1..=count)
            .map(|index| self.placeholder(index))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

async fn insert_worker(db: &Database, worker: &Worker) -> Result<(), ApiError> {
    let sql = format!(
        "insert into workers
         (id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at)
         values ({})",
        db.placeholders(10)
    );
    sqlx::query(&sql)
        .bind(worker.id.to_string())
        .bind(&worker.tenant_id)
        .bind(&worker.name)
        .bind(worker_status_to_str(&worker.status))
        .bind(&worker.provider)
        .bind(serde_json::to_string(&worker.capabilities)?)
        .bind(i64::from(worker.max_concurrent_jobs))
        .bind(serde_json::to_string(&worker.labels)?)
        .bind(worker.registered_at.to_rfc3339())
        .bind(worker.last_heartbeat_at.map(|time| time.to_rfc3339()))
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn insert_worker_heartbeat(
    db: &Database,
    worker_id: WorkerId,
    labels: &str,
    created_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into worker_heartbeats (id, worker_id, labels, created_at)
         values ({})",
        db.placeholders(4)
    );
    sqlx::query(&sql)
        .bind(EventId::new().to_string())
        .bind(worker_id.to_string())
        .bind(labels)
        .bind(created_at.to_rfc3339())
        .execute(&db.pool)
        .await?;
    Ok(())
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
        tenant_id: row.try_get("tenant_id")?,
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

fn row_to_runtime_resource(row: AnyRow) -> Result<RuntimeResource, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let snapshot_id: Option<String> = row.try_get("snapshot_id")?;
    let resource_kind: String = row.try_get("resource_kind")?;
    let purpose: String = row.try_get("purpose")?;
    let status: String = row.try_get("status")?;
    let service_port: Option<i64> = row.try_get("service_port")?;
    let source_snapshot_id: Option<String> = row.try_get("source_snapshot_id")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let observed_at: Option<String> = row.try_get("observed_at")?;
    let last_reconciled_at: Option<String> = row.try_get("last_reconciled_at")?;
    let ready_at: Option<String> = row.try_get("ready_at")?;
    let deleted_at: Option<String> = row.try_get("deleted_at")?;

    Ok(RuntimeResource {
        id: RuntimeResourceId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        snapshot_id: snapshot_id
            .map(|snapshot_id| parse_uuid(&snapshot_id).map(SnapshotId))
            .transpose()?,
        provider: row.try_get("provider")?,
        resource_kind: parse_runtime_resource_kind(&resource_kind)?,
        purpose: parse_runtime_resource_purpose(&purpose)?,
        resource_name: row.try_get("resource_name")?,
        namespace: row.try_get("namespace")?,
        status: parse_runtime_resource_status(&status)?,
        cluster: row.try_get("cluster")?,
        storage_class: row.try_get("storage_class")?,
        snapshot_class: row.try_get("snapshot_class")?,
        storage_size: row.try_get("storage_size")?,
        runtime_image: row.try_get("runtime_image")?,
        service_port: service_port
            .map(u16::try_from)
            .transpose()
            .map_err(|_| ApiError::internal("database contains invalid service port"))?,
        target_port: row.try_get("target_port")?,
        source_snapshot_id: source_snapshot_id
            .map(|snapshot_id| parse_uuid(&snapshot_id).map(SnapshotId))
            .transpose()?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        observed_at: observed_at.map(|time| parse_timestamp(&time)).transpose()?,
        last_reconciled_at: last_reconciled_at
            .map(|time| parse_timestamp(&time))
            .transpose()?,
        ready_at: ready_at.map(|time| parse_timestamp(&time)).transpose()?,
        deleted_at: deleted_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

fn row_to_snapshot(row: AnyRow) -> Result<Snapshot, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let inventory: String = row.try_get("inventory")?;
    let provider_metadata: String = row.try_get("provider_metadata")?;
    let created_at: String = row.try_get("created_at")?;
    let ready_at: Option<String> = row.try_get("ready_at")?;
    let expires_at: Option<String> = row.try_get("expires_at")?;

    Ok(Snapshot {
        id: SnapshotId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_snapshot_status(&status)?,
        label: row.try_get("label")?,
        inventory: serde_json::from_str(&inventory)?,
        provider_metadata: serde_json::from_str(&provider_metadata)?,
        created_at: parse_timestamp(&created_at)?,
        ready_at: ready_at.map(|time| parse_timestamp(&time)).transpose()?,
        expires_at: expires_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

fn row_to_desktop_session(row: AnyRow) -> Result<DesktopSession, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let access_mode: String = row.try_get("access_mode")?;
    let connection_metadata: String = row.try_get("connection_metadata")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let expires_at: Option<String> = row.try_get("expires_at")?;

    Ok(DesktopSession {
        id: DesktopSessionId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_desktop_session_status(&status)?,
        broker: row.try_get("broker")?,
        broker_url: row.try_get("broker_url")?,
        access_mode: parse_desktop_access_mode(&access_mode)?,
        connection_metadata: serde_json::from_str(&connection_metadata)?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        expires_at: expires_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

fn row_to_worker(row: AnyRow) -> Result<Worker, ApiError> {
    let id: String = row.try_get("id")?;
    let status: String = row.try_get("status")?;
    let capabilities: String = row.try_get("capabilities")?;
    let max_concurrent_jobs: i64 = row.try_get("max_concurrent_jobs")?;
    let labels: String = row.try_get("labels")?;
    let registered_at: String = row.try_get("registered_at")?;
    let last_heartbeat_at: Option<String> = row.try_get("last_heartbeat_at")?;

    Ok(Worker {
        id: WorkerId(parse_uuid(&id)?),
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        status: parse_worker_status(&status)?,
        provider: row.try_get("provider")?,
        capabilities: serde_json::from_str::<Vec<WorkerCapability>>(&capabilities)?,
        max_concurrent_jobs: u32::try_from(max_concurrent_jobs)
            .map_err(|_| ApiError::internal("database contains invalid worker capacity"))?,
        labels: serde_json::from_str(&labels)?,
        registered_at: parse_timestamp(&registered_at)?,
        last_heartbeat_at: last_heartbeat_at
            .map(|time| parse_timestamp(&time))
            .transpose()?,
    })
}

fn row_to_guest_health(row: AnyRow) -> Result<GuestHealth, ApiError> {
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let last_probe_at: String = row.try_get("last_probe_at")?;
    let checks: String = row.try_get("checks")?;

    Ok(GuestHealth {
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_guest_status(&status)?,
        last_probe_at: parse_timestamp(&last_probe_at)?,
        agent_version: row.try_get("agent_version")?,
        checks: serde_json::from_str(&checks)?,
        message: row.try_get("message")?,
    })
}

fn row_to_ssh_key(row: AnyRow) -> Result<SshKey, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let requested_at: String = row.try_get("requested_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let applied_at: Option<String> = row.try_get("applied_at")?;

    Ok(SshKey {
        id: SshKeyId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        public_key: row.try_get("public_key")?,
        principal: row.try_get("principal")?,
        status: parse_ssh_key_status(&status)?,
        requested_at: parse_timestamp(&requested_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        applied_at: applied_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
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

fn row_to_job(row: AnyRow) -> Result<Job, ApiError> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let status: String = row.try_get("status")?;
    let payload: String = row.try_get("payload")?;
    let required_capability: String = row.try_get("required_capability")?;
    let scheduled_at: String = row.try_get("scheduled_at")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;

    Ok(Job {
        id: JobId(parse_uuid(&id)?),
        tenant_id: row.try_get("tenant_id")?,
        kind: parse_job_kind(&kind)?,
        status: parse_job_status(&status)?,
        payload: serde_json::from_str(&payload)?,
        required_capability: parse_worker_capability(&required_capability)?,
        priority: row.try_get("priority")?,
        attempts: row.try_get("attempts")?,
        max_attempts: row.try_get("max_attempts")?,
        scheduled_at: parse_timestamp(&scheduled_at)?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        last_error: row.try_get("last_error")?,
    })
}

fn row_to_command_output_chunk(row: AnyRow) -> Result<CommandOutputChunk, ApiError> {
    let id: String = row.try_get("id")?;
    let command_id: String = row.try_get("command_id")?;
    let stream: String = row.try_get("stream")?;
    let sequence: i64 = row.try_get("sequence")?;
    let created_at: String = row.try_get("created_at")?;

    Ok(CommandOutputChunk {
        id: CommandOutputChunkId(parse_uuid(&id)?),
        command_id: CommandId(parse_uuid(&command_id)?),
        stream: parse_command_output_stream(&stream)?,
        sequence: u64::try_from(sequence)
            .map_err(|_| ApiError::internal("database contains invalid output sequence"))?,
        chunk: row.try_get("chunk")?,
        created_at: parse_timestamp(&created_at)?,
    })
}

fn row_to_lease_without_job(row: AnyRow) -> Result<JobLease, ApiError> {
    let id: String = row.try_get("id")?;
    let job_id: String = row.try_get("job_id")?;
    let worker_id: String = row.try_get("worker_id")?;
    let status: String = row.try_get("status")?;
    let leased_at: String = row.try_get("leased_at")?;
    let expires_at: String = row.try_get("expires_at")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;

    Ok(JobLease {
        id: LeaseId(parse_uuid(&id)?),
        job_id: JobId(parse_uuid(&job_id)?),
        worker_id: WorkerId(parse_uuid(&worker_id)?),
        status: parse_lease_status(&status)?,
        attempt: row.try_get("attempt")?,
        leased_at: parse_timestamp(&leased_at)?,
        expires_at: parse_timestamp(&expires_at)?,
        completed_at: completed_at
            .map(|time| parse_timestamp(&time))
            .transpose()?,
        error: row.try_get("error")?,
        job: Job {
            id: JobId::new(),
            tenant_id: "default".to_string(),
            kind: JobKind::RunCommand,
            status: JobStatus::Queued,
            payload: json!({}),
            required_capability: WorkerCapability::RunCommand,
            priority: 0,
            attempts: 0,
            max_attempts: 1,
            scheduled_at: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_error: None,
        },
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
        SandboxState::Planning => "planning",
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
        "planning" => Ok(SandboxState::Planning),
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

fn snapshot_status_to_str(status: &SnapshotStatus) -> &'static str {
    match status {
        SnapshotStatus::Pending => "pending",
        SnapshotStatus::Ready => "ready",
        SnapshotStatus::Failed => "failed",
        SnapshotStatus::Expired => "expired",
    }
}

fn desktop_session_status_to_str(status: &DesktopSessionStatus) -> &'static str {
    match status {
        DesktopSessionStatus::Pending => "pending",
        DesktopSessionStatus::Ready => "ready",
        DesktopSessionStatus::Failed => "failed",
        DesktopSessionStatus::Closed => "closed",
        DesktopSessionStatus::Expired => "expired",
    }
}

fn desktop_access_mode_to_str(access_mode: &DesktopAccessMode) -> &'static str {
    match access_mode {
        DesktopAccessMode::Browser => "browser",
        DesktopAccessMode::Vnc => "vnc",
        DesktopAccessMode::Rdp => "rdp",
    }
}

fn runtime_resource_kind_to_str(kind: &RuntimeResourceKind) -> &'static str {
    match kind {
        RuntimeResourceKind::Pod => "pod",
        RuntimeResourceKind::PersistentVolumeClaim => "persistent_volume_claim",
        RuntimeResourceKind::Service => "service",
        RuntimeResourceKind::VolumeSnapshot => "volume_snapshot",
    }
}

fn runtime_resource_purpose_to_str(purpose: &RuntimeResourcePurpose) -> &'static str {
    match purpose {
        RuntimeResourcePurpose::Runtime => "runtime",
        RuntimeResourcePurpose::Workspace => "workspace",
        RuntimeResourcePurpose::Ssh => "ssh",
        RuntimeResourcePurpose::Desktop => "desktop",
        RuntimeResourcePurpose::Snapshot => "snapshot",
    }
}

fn runtime_resource_status_to_str(status: &RuntimeResourceStatus) -> &'static str {
    match status {
        RuntimeResourceStatus::Planned => "planned",
        RuntimeResourceStatus::Applied => "applied",
        RuntimeResourceStatus::Ready => "ready",
        RuntimeResourceStatus::Failed => "failed",
        RuntimeResourceStatus::Deleted => "deleted",
    }
}

fn cleanup_run_status_to_str(status: &CleanupRunStatus) -> &'static str {
    match status {
        CleanupRunStatus::Running => "running",
        CleanupRunStatus::Succeeded => "succeeded",
        CleanupRunStatus::Failed => "failed",
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

fn command_output_stream_to_str(stream: &CommandOutputStream) -> &'static str {
    match stream {
        CommandOutputStream::Stdout => "stdout",
        CommandOutputStream::Stderr => "stderr",
    }
}

fn worker_status_to_str(status: &WorkerStatus) -> &'static str {
    match status {
        WorkerStatus::Registered => "registered",
        WorkerStatus::Online => "online",
        WorkerStatus::Draining => "draining",
        WorkerStatus::Offline => "offline",
    }
}

fn worker_capability_to_str(capability: &WorkerCapability) -> &'static str {
    match capability {
        WorkerCapability::ProvisionSandbox => "provision_sandbox",
        WorkerCapability::RunCommand => "run_command",
        WorkerCapability::AgentPrompt => "agent_prompt",
        WorkerCapability::Snapshot => "snapshot",
        WorkerCapability::DesktopStream => "desktop_stream",
        WorkerCapability::K8sPod => "k8s_pod",
    }
}

fn job_kind_to_str(kind: &JobKind) -> &'static str {
    match kind {
        JobKind::ProvisionSandbox => "provision_sandbox",
        JobKind::StopSandbox => "stop_sandbox",
        JobKind::ResumeSandbox => "resume_sandbox",
        JobKind::RunCommand => "run_command",
        JobKind::RunPrompt => "run_prompt",
        JobKind::CreateSnapshot => "create_snapshot",
        JobKind::ForkSandbox => "fork_sandbox",
    }
}

fn job_status_to_str(status: &JobStatus) -> &'static str {
    match status {
        JobStatus::Queued => "queued",
        JobStatus::Leased => "leased",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
        JobStatus::Dead => "dead",
    }
}

fn lease_status_to_str(status: &LeaseStatus) -> &'static str {
    match status {
        LeaseStatus::Active => "active",
        LeaseStatus::Completed => "completed",
        LeaseStatus::Failed => "failed",
        LeaseStatus::Expired => "expired",
    }
}

fn guest_status_to_str(status: &GuestStatus) -> &'static str {
    match status {
        GuestStatus::Pending => "pending",
        GuestStatus::Ready => "ready",
        GuestStatus::Unreachable => "unreachable",
        GuestStatus::Unhealthy => "unhealthy",
        GuestStatus::Terminated => "terminated",
    }
}

fn ssh_key_status_to_str(status: &SshKeyStatus) -> &'static str {
    match status {
        SshKeyStatus::Requested => "requested",
        SshKeyStatus::Applied => "applied",
        SshKeyStatus::Failed => "failed",
        SshKeyStatus::Revoked => "revoked",
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

fn parse_command_output_stream(value: &str) -> Result<CommandOutputStream, ApiError> {
    match value {
        "stdout" => Ok(CommandOutputStream::Stdout),
        "stderr" => Ok(CommandOutputStream::Stderr),
        _ => Err(ApiError::internal(
            "database contains invalid command output stream",
        )),
    }
}

fn parse_snapshot_status(value: &str) -> Result<SnapshotStatus, ApiError> {
    match value {
        "pending" => Ok(SnapshotStatus::Pending),
        "ready" => Ok(SnapshotStatus::Ready),
        "failed" => Ok(SnapshotStatus::Failed),
        "expired" => Ok(SnapshotStatus::Expired),
        _ => Err(ApiError::internal(
            "database contains invalid snapshot status",
        )),
    }
}

fn parse_desktop_session_status(value: &str) -> Result<DesktopSessionStatus, ApiError> {
    match value {
        "pending" => Ok(DesktopSessionStatus::Pending),
        "ready" => Ok(DesktopSessionStatus::Ready),
        "failed" => Ok(DesktopSessionStatus::Failed),
        "closed" => Ok(DesktopSessionStatus::Closed),
        "expired" => Ok(DesktopSessionStatus::Expired),
        _ => Err(ApiError::internal(
            "database contains invalid desktop session status",
        )),
    }
}

fn parse_desktop_access_mode(value: &str) -> Result<DesktopAccessMode, ApiError> {
    match value {
        "browser" => Ok(DesktopAccessMode::Browser),
        "vnc" => Ok(DesktopAccessMode::Vnc),
        "rdp" => Ok(DesktopAccessMode::Rdp),
        _ => Err(ApiError::internal(
            "database contains invalid desktop access mode",
        )),
    }
}

fn parse_runtime_resource_kind(value: &str) -> Result<RuntimeResourceKind, ApiError> {
    match value {
        "pod" => Ok(RuntimeResourceKind::Pod),
        "persistent_volume_claim" => Ok(RuntimeResourceKind::PersistentVolumeClaim),
        "service" => Ok(RuntimeResourceKind::Service),
        "volume_snapshot" => Ok(RuntimeResourceKind::VolumeSnapshot),
        _ => Err(ApiError::internal(
            "database contains invalid runtime resource kind",
        )),
    }
}

fn parse_runtime_resource_purpose(value: &str) -> Result<RuntimeResourcePurpose, ApiError> {
    match value {
        "runtime" => Ok(RuntimeResourcePurpose::Runtime),
        "workspace" => Ok(RuntimeResourcePurpose::Workspace),
        "ssh" => Ok(RuntimeResourcePurpose::Ssh),
        "desktop" => Ok(RuntimeResourcePurpose::Desktop),
        "snapshot" => Ok(RuntimeResourcePurpose::Snapshot),
        _ => Err(ApiError::internal(
            "database contains invalid runtime resource purpose",
        )),
    }
}

fn parse_runtime_resource_status(value: &str) -> Result<RuntimeResourceStatus, ApiError> {
    match value {
        "planned" => Ok(RuntimeResourceStatus::Planned),
        "applied" => Ok(RuntimeResourceStatus::Applied),
        "ready" => Ok(RuntimeResourceStatus::Ready),
        "failed" => Ok(RuntimeResourceStatus::Failed),
        "deleted" => Ok(RuntimeResourceStatus::Deleted),
        _ => Err(ApiError::internal(
            "database contains invalid runtime resource status",
        )),
    }
}

fn parse_worker_capability(value: &str) -> Result<WorkerCapability, ApiError> {
    match value {
        "provision_sandbox" => Ok(WorkerCapability::ProvisionSandbox),
        "run_command" => Ok(WorkerCapability::RunCommand),
        "agent_prompt" => Ok(WorkerCapability::AgentPrompt),
        "snapshot" => Ok(WorkerCapability::Snapshot),
        "desktop_stream" => Ok(WorkerCapability::DesktopStream),
        "k8s_pod" => Ok(WorkerCapability::K8sPod),
        _ => Err(ApiError::internal(
            "database contains invalid worker capability",
        )),
    }
}

fn parse_job_kind(value: &str) -> Result<JobKind, ApiError> {
    match value {
        "provision_sandbox" => Ok(JobKind::ProvisionSandbox),
        "stop_sandbox" => Ok(JobKind::StopSandbox),
        "resume_sandbox" => Ok(JobKind::ResumeSandbox),
        "run_command" => Ok(JobKind::RunCommand),
        "run_prompt" => Ok(JobKind::RunPrompt),
        "create_snapshot" => Ok(JobKind::CreateSnapshot),
        "fork_sandbox" => Ok(JobKind::ForkSandbox),
        _ => Err(ApiError::internal("database contains invalid job kind")),
    }
}

fn parse_job_status(value: &str) -> Result<JobStatus, ApiError> {
    match value {
        "queued" => Ok(JobStatus::Queued),
        "leased" => Ok(JobStatus::Leased),
        "succeeded" => Ok(JobStatus::Succeeded),
        "failed" => Ok(JobStatus::Failed),
        "dead" => Ok(JobStatus::Dead),
        _ => Err(ApiError::internal("database contains invalid job status")),
    }
}

fn parse_lease_status(value: &str) -> Result<LeaseStatus, ApiError> {
    match value {
        "active" => Ok(LeaseStatus::Active),
        "completed" => Ok(LeaseStatus::Completed),
        "failed" => Ok(LeaseStatus::Failed),
        "expired" => Ok(LeaseStatus::Expired),
        _ => Err(ApiError::internal("database contains invalid lease status")),
    }
}

fn parse_guest_status(value: &str) -> Result<GuestStatus, ApiError> {
    match value {
        "pending" => Ok(GuestStatus::Pending),
        "ready" => Ok(GuestStatus::Ready),
        "unreachable" => Ok(GuestStatus::Unreachable),
        "unhealthy" => Ok(GuestStatus::Unhealthy),
        "terminated" => Ok(GuestStatus::Terminated),
        _ => Err(ApiError::internal("database contains invalid guest status")),
    }
}

fn parse_ssh_key_status(value: &str) -> Result<SshKeyStatus, ApiError> {
    match value {
        "requested" => Ok(SshKeyStatus::Requested),
        "applied" => Ok(SshKeyStatus::Applied),
        "failed" => Ok(SshKeyStatus::Failed),
        "revoked" => Ok(SshKeyStatus::Revoked),
        _ => Err(ApiError::internal(
            "database contains invalid ssh key status",
        )),
    }
}

fn parse_worker_status(value: &str) -> Result<WorkerStatus, ApiError> {
    match value {
        "registered" => Ok(WorkerStatus::Registered),
        "online" => Ok(WorkerStatus::Online),
        "draining" => Ok(WorkerStatus::Draining),
        "offline" => Ok(WorkerStatus::Offline),
        _ => Err(ApiError::internal(
            "database contains invalid worker status",
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
        SandboxEventKind::PromptStarted => "prompt_started",
        SandboxEventKind::PromptFinished => "prompt_finished",
        SandboxEventKind::DesktopRequested => "desktop_requested",
        SandboxEventKind::DesktopReady => "desktop_ready",
        SandboxEventKind::DesktopFailed => "desktop_failed",
        SandboxEventKind::DesktopClosed => "desktop_closed",
        SandboxEventKind::DesktopExpired => "desktop_expired",
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
        "prompt_started" => Ok(SandboxEventKind::PromptStarted),
        "prompt_finished" => Ok(SandboxEventKind::PromptFinished),
        "desktop_requested" => Ok(SandboxEventKind::DesktopRequested),
        "desktop_ready" => Ok(SandboxEventKind::DesktopReady),
        "desktop_failed" => Ok(SandboxEventKind::DesktopFailed),
        "desktop_closed" => Ok(SandboxEventKind::DesktopClosed),
        "desktop_expired" => Ok(SandboxEventKind::DesktopExpired),
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

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
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
