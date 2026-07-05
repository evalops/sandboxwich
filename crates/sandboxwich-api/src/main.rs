use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Multipart, Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use sandboxwich_core::{
    AppendCommandOutputRequest, ArchivedSandboxCleanupSkip, CapacityResponse, ClaimLeaseRequest,
    ClaimLeaseResponse, CleanupRun, CleanupRunId, CleanupRunStatus, CommandId, CommandListResponse,
    CommandOutputAnnotation, CommandOutputChunk, CommandOutputChunkId, CommandOutputChunkResponse,
    CommandOutputListResponse, CommandOutputStream, CommandRequest, CommandResponse, CommandRun,
    CommandStatus, CompleteLeaseRequest, CreateDesktopSessionRequest, CreateJobRequest,
    CreateSandboxRequest, CreateSnapshotRequest, DbVariant, DesktopAccess, DesktopAccessMode,
    DesktopAccessRequest, DesktopAccessResponse, DesktopSession, DesktopSessionId,
    DesktopSessionListResponse, DesktopSessionResponse, DesktopSessionStatus, ErrorEnvelope,
    EventId, EventListResponse, FailLeaseRequest, FileId, FileResponse, GuestHealth,
    GuestHealthResponse, GuestStatus, HealthComponent, HealthResponse, Job, JobId, JobKind,
    JobLease, JobListResponse, JobResponse, JobStatus, LeaseId, LeaseResponse, LeaseStatus,
    ListFilesResponse, MAX_SANDBOX_FILE_BYTES, MemoryLimit, NetworkAllowRule, NetworkAllowRuleKind,
    NetworkEgress, NetworkEgressMode, PromptQueuedResponse, PromptRequest, ProviderRuntimeResource,
    ReconcileRuntimeResourcesRequest, ReconcileRuntimeResourcesResponse, RegisterWorkerRequest,
    RenewLeaseRequest, RequestSshKeyRequest, RuntimeResource, RuntimeResourceId,
    RuntimeResourceKind, RuntimeResourceListResponse, RuntimeResourcePurpose,
    RuntimeResourceStatus, Sandbox, SandboxEvent, SandboxEventKind, SandboxFile, SandboxId,
    SandboxListResponse, SandboxProvisionSpec, SandboxResponse, SandboxState, Snapshot,
    SnapshotCleanupResponse, SnapshotId, SnapshotListResponse, SnapshotResponse, SnapshotStatus,
    SshAccess, SshAccessRequest, SshAccessResponse, SshKey, SshKeyId, SshKeyListResponse,
    SshKeyResponse, SshKeyStatus, UpdateDesktopSessionRequest, UpdateGuestHealthRequest,
    UpdateSshKeyStatusRequest, Worker, WorkerCapability, WorkerCapacity, WorkerHeartbeatRequest,
    WorkerId, WorkerJobResult, WorkerListResponse, WorkerResponse, WorkerStatus,
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
    auth: AuthConfig,
    default_tenant_id: String,
}

#[derive(Clone, Debug)]
struct TenantContext {
    tenant_id: String,
}

#[derive(Clone)]
struct AuthConfig {
    shared_token: Option<String>,
    tenant_tokens: Vec<TenantToken>,
}

#[derive(Clone)]
struct TenantToken {
    tenant_id: String,
    token: String,
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

enum ApiCommand {
    Serve,
    Migrate,
    CheckSchema,
}

struct ApiConfig {
    command: ApiCommand,
    database_url: String,
    bind: SocketAddr,
    database_max_connections: u32,
    auto_migrate: bool,
    shared_token: Option<String>,
    tenant_tokens: Vec<TenantToken>,
    default_tenant_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = load_api_config()?;
    let db = connect_database(&config.database_url, config.database_max_connections).await?;

    match config.command {
        ApiCommand::Migrate => {
            migrate_database(&db).await?;
            tracing::info!(database_url = %config.database_url, "database migrations complete");
            return Ok(());
        }
        ApiCommand::CheckSchema => {
            verify_database_schema(&db).await?;
            tracing::info!(database_url = %config.database_url, "database schema ready");
            return Ok(());
        }
        ApiCommand::Serve => {
            if config.auto_migrate {
                migrate_database(&db).await?;
            } else {
                verify_database_schema(&db).await?;
            }
        }
    }

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(addr = %config.bind, database_url = %config.database_url, "sandboxwich-api listening");
    axum::serve(
        listener,
        app(AppState {
            db,
            auth: AuthConfig {
                shared_token: config.shared_token,
                tenant_tokens: config.tenant_tokens,
            },
            default_tenant_id: config.default_tenant_id,
        }),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

fn load_api_config() -> anyhow::Result<ApiConfig> {
    let command = parse_api_command(std::env::args().skip(1))?;
    let bind = std::env::var("SANDBOXWICH_BIND").unwrap_or_else(|_| "127.0.0.1:3217".to_string());
    let bind: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid SANDBOXWICH_BIND value: {bind}"))?;

    let database_url = std::env::var("SANDBOXWICH_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://sandboxwich.db".to_string());
    let database_max_connections = parse_env_u32("SANDBOXWICH_DATABASE_MAX_CONNECTIONS", 5)?.max(1);
    let auto_migrate = parse_env_bool("SANDBOXWICH_AUTO_MIGRATE", true)?;
    let shared_token = std::env::var("SANDBOXWICH_API_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let tenant_tokens =
        parse_tenant_tokens(std::env::var("SANDBOXWICH_TENANT_TOKENS").ok().as_deref())?;
    let default_tenant_id = std::env::var("SANDBOXWICH_DEFAULT_TENANT")
        .ok()
        .filter(|tenant| !tenant.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());

    Ok(ApiConfig {
        command,
        database_url,
        bind,
        database_max_connections,
        auto_migrate,
        shared_token,
        tenant_tokens,
        default_tenant_id,
    })
}

fn parse_api_command(args: impl IntoIterator<Item = String>) -> anyhow::Result<ApiCommand> {
    let mut args = args.into_iter();
    let command = match args.next().as_deref() {
        None | Some("serve") => ApiCommand::Serve,
        Some("migrate") => ApiCommand::Migrate,
        Some("check-schema") => ApiCommand::CheckSchema,
        Some("--help") | Some("-h") => {
            println!("usage: sandboxwich-api [serve|migrate|check-schema]");
            std::process::exit(0);
        }
        Some(command) => anyhow::bail!(
            "unknown sandboxwich-api command {command:?}; expected serve, migrate, or check-schema"
        ),
    };
    if let Some(extra) = args.next() {
        anyhow::bail!("unexpected extra sandboxwich-api argument {extra:?}");
    }
    Ok(command)
}

fn parse_env_u32(name: &'static str, default: u32) -> anyhow::Result<u32> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse()
        .with_context(|| format!("invalid {name} value: {value}"))
}

fn parse_env_bool(name: &'static str, default: bool) -> anyhow::Result<bool> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        value => anyhow::bail!("invalid {name} value: {value}"),
    }
}

async fn migrate_database(db: &Database) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(&db.pool).await?;
    ensure_database_constraints(&db).await?;
    Ok(())
}

async fn verify_database_schema(db: &Database) -> anyhow::Result<()> {
    let migration = sqlx::query(
        "select version from _sqlx_migrations where success = true order by version desc limit 1",
    )
    .fetch_optional(&db.pool)
    .await
    .context("database migrations have not been applied; run `sandboxwich-api migrate`")?;
    if migration.is_none() {
        anyhow::bail!("database migrations have not been applied; run `sandboxwich-api migrate`");
    }
    let Some(value) = fetch_schema_metadata(db, DB_ENUM_SCHEMA_METADATA_KEY).await? else {
        anyhow::bail!(
            "database enum constraints have not been reconciled; run `sandboxwich-api migrate`"
        );
    };
    let expected = db_enum_schema_fingerprint();
    if value != expected {
        anyhow::bail!(
            "database enum constraints are out of date; expected fingerprint {expected}, found {value}; run `sandboxwich-api migrate`"
        );
    }
    Ok(())
}

async fn connect_database(database_url: &str, max_connections: u32) -> anyhow::Result<Database> {
    sqlx::any::install_default_drivers();
    let dialect = SqlDialect::from_url(database_url)?;
    if matches!(dialect, SqlDialect::Sqlite)
        && !Sqlite::database_exists(database_url).await.unwrap_or(false)
    {
        Sqlite::create_database(database_url).await?;
    }

    let pool = AnyPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await?;
    Ok(Database { pool, dialect })
}

fn parse_tenant_tokens(value: Option<&str>) -> anyhow::Result<Vec<TenantToken>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (tenant_id, token) = entry
                .split_once('=')
                .with_context(|| format!("invalid SANDBOXWICH_TENANT_TOKENS entry: {entry}"))?;
            let tenant_id = tenant_id.trim();
            let token = token.trim();
            if tenant_id.is_empty() || token.is_empty() {
                anyhow::bail!("invalid SANDBOXWICH_TENANT_TOKENS entry: {entry}");
            }
            Ok(TenantToken {
                tenant_id: tenant_id.to_string(),
                token: token.to_string(),
            })
        })
        .collect()
}

async fn ensure_database_constraints(db: &Database) -> anyhow::Result<()> {
    let fingerprint = db_enum_schema_fingerprint();
    if fetch_schema_metadata(db, DB_ENUM_SCHEMA_METADATA_KEY)
        .await?
        .as_deref()
        == Some(fingerprint.as_str())
    {
        return Ok(());
    }

    match db.dialect {
        SqlDialect::Postgres => ensure_postgres_constraints(db).await?,
        SqlDialect::Sqlite => ensure_sqlite_constraints(db).await?,
    };
    write_schema_metadata(db, DB_ENUM_SCHEMA_METADATA_KEY, &fingerprint).await?;
    Ok(())
}

const DB_ENUM_SCHEMA_METADATA_KEY: &str = "db_enum_constraints_fingerprint";
const DB_ENUM_SCHEMA_FINGERPRINT_VERSION: &str = "db-enum-v1";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

fn db_enum_schema_fingerprint() -> String {
    let mut hash = FNV_OFFSET_BASIS;
    feed_hash(&mut hash, DB_ENUM_SCHEMA_FINGERPRINT_VERSION);
    for column in db_enum_columns() {
        feed_hash(&mut hash, column.table);
        feed_hash(&mut hash, column.column);
        feed_hash(&mut hash, column.constraint_name);
        feed_hash(&mut hash, column.error_message);
        for value in column.values {
            feed_hash(&mut hash, value);
        }
    }
    feed_hash(&mut hash, "runtime_resources.cluster:not_empty");
    format!("{DB_ENUM_SCHEMA_FINGERPRINT_VERSION}:{hash:016x}")
}

fn feed_hash(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
    *hash ^= 0xff;
    *hash = hash.wrapping_mul(FNV_PRIME);
}

async fn fetch_schema_metadata(db: &Database, key: &str) -> anyhow::Result<Option<String>> {
    let sql = format!(
        "select value from schema_metadata where key = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql).bind(key).fetch_optional(&db.pool).await?;
    row.map(|row| row.try_get("value"))
        .transpose()
        .map_err(Into::into)
}

async fn write_schema_metadata(db: &Database, key: &str, value: &str) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    let sql = match db.dialect {
        SqlDialect::Postgres => format!(
            "insert into schema_metadata (key, value, updated_at)
             values ({}, {}, {})
             on conflict (key) do update set
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3)
        ),
        SqlDialect::Sqlite => format!(
            "insert into schema_metadata (key, value, updated_at)
             values ({}, {}, {})
             on conflict (key) do update set
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3)
        ),
    };
    sqlx::query(&sql)
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&db.pool)
        .await?;
    Ok(())
}

#[derive(Clone, Copy)]
struct DbEnumColumn {
    table: &'static str,
    column: &'static str,
    constraint_name: &'static str,
    values: &'static [&'static str],
    error_message: &'static str,
}

const DB_ENUM_COLUMNS: &[DbEnumColumn] = &[
    DbEnumColumn::new(
        "sandboxes",
        "state",
        "sandboxes_state_check",
        <SandboxState as DbVariant>::VALUES,
        "invalid sandbox state",
    ),
    DbEnumColumn::new(
        "sandboxes",
        "memory_limit",
        "sandboxes_memory_limit_check",
        <MemoryLimit as DbVariant>::VALUES,
        "invalid sandbox memory limit",
    ),
    DbEnumColumn::new(
        "sandboxes",
        "network_egress_mode",
        "sandboxes_network_egress_mode_check",
        <NetworkEgressMode as DbVariant>::VALUES,
        "invalid sandbox network egress mode",
    ),
    DbEnumColumn::new(
        "sandbox_network_egress_rules",
        "kind",
        "sandbox_network_egress_rules_kind_check",
        <NetworkAllowRuleKind as DbVariant>::VALUES,
        "invalid network allow rule kind",
    ),
    DbEnumColumn::new(
        "commands",
        "status",
        "commands_status_check",
        <CommandStatus as DbVariant>::VALUES,
        "invalid command status",
    ),
    DbEnumColumn::new(
        "command_output_chunks",
        "stream",
        "command_output_chunks_stream_check",
        <CommandOutputStream as DbVariant>::VALUES,
        "invalid command output stream",
    ),
    DbEnumColumn::new(
        "sandbox_events",
        "kind",
        "sandbox_events_kind_check",
        <SandboxEventKind as DbVariant>::VALUES,
        "invalid event kind",
    ),
    DbEnumColumn::new(
        "workers",
        "status",
        "workers_status_check",
        <WorkerStatus as DbVariant>::VALUES,
        "invalid worker status",
    ),
    DbEnumColumn::new(
        "jobs",
        "kind",
        "jobs_kind_check",
        <JobKind as DbVariant>::VALUES,
        "invalid job kind",
    ),
    DbEnumColumn::new(
        "jobs",
        "status",
        "jobs_status_check",
        <JobStatus as DbVariant>::VALUES,
        "invalid job status",
    ),
    DbEnumColumn::new(
        "jobs",
        "required_capability",
        "jobs_required_capability_check",
        <WorkerCapability as DbVariant>::VALUES,
        "invalid job required capability",
    ),
    DbEnumColumn::new(
        "job_leases",
        "status",
        "job_leases_status_check",
        <LeaseStatus as DbVariant>::VALUES,
        "invalid lease status",
    ),
    DbEnumColumn::new(
        "guest_health",
        "status",
        "guest_health_status_check",
        <GuestStatus as DbVariant>::VALUES,
        "invalid guest status",
    ),
    DbEnumColumn::new(
        "snapshots",
        "status",
        "snapshots_status_check",
        <SnapshotStatus as DbVariant>::VALUES,
        "invalid snapshot status",
    ),
    DbEnumColumn::new(
        "desktop_sessions",
        "status",
        "desktop_sessions_status_check",
        <DesktopSessionStatus as DbVariant>::VALUES,
        "invalid desktop session status",
    ),
    DbEnumColumn::new(
        "desktop_sessions",
        "access_mode",
        "desktop_sessions_access_mode_check",
        <DesktopAccessMode as DbVariant>::VALUES,
        "invalid desktop access mode",
    ),
    DbEnumColumn::new(
        "ssh_keys",
        "status",
        "ssh_keys_status_check",
        <SshKeyStatus as DbVariant>::VALUES,
        "invalid ssh key status",
    ),
    DbEnumColumn::new(
        "runtime_resources",
        "resource_kind",
        "runtime_resources_kind_check",
        <RuntimeResourceKind as DbVariant>::VALUES,
        "invalid runtime resource kind",
    ),
    DbEnumColumn::new(
        "runtime_resources",
        "purpose",
        "runtime_resources_purpose_check",
        <RuntimeResourcePurpose as DbVariant>::VALUES,
        "invalid runtime resource purpose",
    ),
    DbEnumColumn::new(
        "runtime_resources",
        "status",
        "runtime_resources_status_check",
        <RuntimeResourceStatus as DbVariant>::VALUES,
        "invalid runtime resource status",
    ),
    DbEnumColumn::new(
        "runtime_resource_tombstones",
        "resource_kind",
        "runtime_resource_tombstones_kind_check",
        <RuntimeResourceKind as DbVariant>::VALUES,
        "invalid runtime resource tombstone kind",
    ),
    DbEnumColumn::new(
        "runtime_resource_tombstones",
        "purpose",
        "runtime_resource_tombstones_purpose_check",
        <RuntimeResourcePurpose as DbVariant>::VALUES,
        "invalid runtime resource tombstone purpose",
    ),
    DbEnumColumn::new(
        "runtime_resource_tombstones",
        "status",
        "runtime_resource_tombstones_status_check",
        <RuntimeResourceStatus as DbVariant>::VALUES,
        "invalid runtime resource tombstone status",
    ),
    DbEnumColumn::new(
        "cleanup_runs",
        "status",
        "cleanup_runs_status_check",
        <CleanupRunStatus as DbVariant>::VALUES,
        "invalid cleanup run status",
    ),
];

fn db_enum_columns() -> &'static [DbEnumColumn] {
    DB_ENUM_COLUMNS
}

impl DbEnumColumn {
    const fn new(
        table: &'static str,
        column: &'static str,
        constraint_name: &'static str,
        values: &'static [&'static str],
        error_message: &'static str,
    ) -> Self {
        Self {
            table,
            column,
            constraint_name,
            values,
            error_message,
        }
    }
}

async fn ensure_postgres_constraints(db: &Database) -> anyhow::Result<()> {
    for &column in db_enum_columns() {
        for statement in postgres_enum_constraint_statements(column) {
            sqlx::query(&statement).execute(&db.pool).await?;
        }
    }

    for statement in [
        "alter table runtime_resources drop constraint if exists runtime_resources_cluster_not_empty_check",
        "alter table runtime_resources add constraint runtime_resources_cluster_not_empty_check check (cluster is null or cluster <> '')",
    ] {
        sqlx::query(statement).execute(&db.pool).await?;
    }

    Ok(())
}

fn postgres_enum_constraint_statements(column: DbEnumColumn) -> [String; 2] {
    [
        format!(
            "alter table {table} drop constraint if exists {constraint_name}",
            table = column.table,
            constraint_name = column.constraint_name
        ),
        format!(
            "alter table {table} add constraint {constraint_name} check ({column_name} in ({values}))",
            table = column.table,
            constraint_name = column.constraint_name,
            column_name = column.column,
            values = sql_literal_list(column.values)
        ),
    ]
}

async fn ensure_sqlite_constraints(db: &Database) -> anyhow::Result<()> {
    for &column in db_enum_columns() {
        for statement in sqlite_enum_trigger_statements(column) {
            sqlx::query(&statement).execute(&db.pool).await?;
        }
    }

    for statement in [
        "drop trigger if exists validate_runtime_resources_cluster_insert",
        "drop trigger if exists validate_runtime_resources_cluster_update",
        r#"
        create trigger validate_runtime_resources_cluster_insert
        before insert on runtime_resources
        for each row
        when new.cluster = ''
        begin
            select raise(abort, 'invalid runtime resource cluster');
        end;
        "#,
        r#"
        create trigger validate_runtime_resources_cluster_update
        before update of cluster on runtime_resources
        for each row
        when new.cluster = ''
        begin
            select raise(abort, 'invalid runtime resource cluster');
        end;
        "#,
    ] {
        sqlx::query(statement).execute(&db.pool).await?;
    }

    Ok(())
}

fn sqlite_enum_trigger_statements(column: DbEnumColumn) -> Vec<String> {
    let insert_trigger = format!("validate_{}_{}_insert", column.table, column.column);
    let update_trigger = format!("validate_{}_{}_update", column.table, column.column);
    let values = sql_literal_list(column.values);
    let error = sql_literal(column.error_message);
    vec![
        format!("drop trigger if exists {insert_trigger}"),
        format!("drop trigger if exists {update_trigger}"),
        format!(
            "create trigger {insert_trigger}
             before insert on {table}
             for each row
             when new.{column_name} not in ({values})
             begin
                 select raise(abort, {error});
             end;",
            table = column.table,
            column_name = column.column
        ),
        format!(
            "create trigger {update_trigger}
             before update of {column_name} on {table}
             for each row
             when new.{column_name} not in ({values})
             begin
                 select raise(abort, {error});
             end;",
            table = column.table,
            column_name = column.column
        ),
    ]
}

fn sql_literal_list(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| sql_literal(value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn db_enum_registry_covers_persisted_variant_columns() {
        let mut seen = BTreeSet::new();
        for column in db_enum_columns() {
            assert!(
                seen.insert((column.table, column.column)),
                "duplicate db enum registry entry for {}.{}",
                column.table,
                column.column
            );
            assert!(
                !column.values.is_empty(),
                "empty db enum values for {}.{}",
                column.table,
                column.column
            );
        }

        for expected in [
            ("sandboxes", "state"),
            ("sandboxes", "memory_limit"),
            ("sandboxes", "network_egress_mode"),
            ("sandbox_network_egress_rules", "kind"),
            ("commands", "status"),
            ("command_output_chunks", "stream"),
            ("sandbox_events", "kind"),
            ("workers", "status"),
            ("jobs", "kind"),
            ("jobs", "status"),
            ("jobs", "required_capability"),
            ("job_leases", "status"),
            ("guest_health", "status"),
            ("snapshots", "status"),
            ("desktop_sessions", "status"),
            ("desktop_sessions", "access_mode"),
            ("ssh_keys", "status"),
            ("runtime_resources", "resource_kind"),
            ("runtime_resources", "purpose"),
            ("runtime_resources", "status"),
            ("runtime_resource_tombstones", "resource_kind"),
            ("runtime_resource_tombstones", "purpose"),
            ("runtime_resource_tombstones", "status"),
            ("cleanup_runs", "status"),
        ] {
            assert!(
                seen.contains(&expected),
                "missing db enum registry entry for {}.{}",
                expected.0,
                expected.1
            );
        }
    }

    #[test]
    fn generated_sql_quotes_enum_values_and_errors() {
        let column = DbEnumColumn::new(
            "widgets",
            "state",
            "widgets_state_check",
            &["ready", "it''s-weird"],
            "invalid widget's state",
        );

        let postgres = postgres_enum_constraint_statements(column).join("\n");
        assert!(postgres.contains("'ready', 'it''''s-weird'"));

        let sqlite = sqlite_enum_trigger_statements(column).join("\n");
        assert!(sqlite.contains("'ready', 'it''''s-weird'"));
        assert!(sqlite.contains("'invalid widget''s state'"));
    }

    #[test]
    fn api_command_parser_accepts_operational_modes() {
        assert!(matches!(
            parse_api_command(Vec::<String>::new()).unwrap(),
            ApiCommand::Serve
        ));
        assert!(matches!(
            parse_api_command(["serve".to_string()]).unwrap(),
            ApiCommand::Serve
        ));
        assert!(matches!(
            parse_api_command(["migrate".to_string()]).unwrap(),
            ApiCommand::Migrate
        ));
        assert!(matches!(
            parse_api_command(["check-schema".to_string()]).unwrap(),
            ApiCommand::CheckSchema
        ));
        assert!(parse_api_command(["migrate".to_string(), "extra".to_string()]).is_err());
        assert!(parse_api_command(["wat".to_string()]).is_err());
    }

    #[test]
    fn db_enum_fingerprint_is_versioned_and_stable_for_current_registry() {
        let fingerprint = db_enum_schema_fingerprint();
        assert!(fingerprint.starts_with("db-enum-v1:"));
        assert_eq!(fingerprint, db_enum_schema_fingerprint());
    }
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/sandboxes", get(list_sandboxes).post(create_sandbox))
        .route("/sandboxes/{sandbox_id}", get(get_sandbox))
        .route(
            "/sandboxes/{sandbox_id}/files",
            get(list_files).post(upload_file),
        )
        .route(
            "/sandboxes/{sandbox_id}/files/{file_id}",
            get(download_file),
        )
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
        .layer(DefaultBodyLimit::max(
            usize::try_from(MAX_SANDBOX_FILE_BYTES + 1024 * 1024)
                .expect("file upload limit should fit usize"),
        ))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_and_tenant))
}

const PROBE_PATHS: &[&str] = &["/healthz", "/readyz"];

async fn auth_and_tenant(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let tenant_id = if PROBE_PATHS.contains(&path) {
        state.default_tenant_id.clone()
    } else if !state.auth.tenant_tokens.is_empty() {
        let Some(token) = bearer_token(&request) else {
            return ApiError::unauthorized("valid bearer token is required").into_response();
        };
        let Some(tenant) = state
            .auth
            .tenant_tokens
            .iter()
            .find(|candidate| constant_time_eq(token.as_bytes(), candidate.token.as_bytes()))
        else {
            return ApiError::unauthorized("valid tenant bearer token is required").into_response();
        };
        tenant.tenant_id.clone()
    } else if let Some(expected_token) = &state.auth.shared_token {
        let authorized = bearer_token(&request)
            .is_some_and(|token| constant_time_eq(token.as_bytes(), expected_token.as_bytes()));
        if !authorized {
            return ApiError::unauthorized("valid bearer token is required").into_response();
        }
        state.default_tenant_id.clone()
    } else {
        request
            .headers()
            .get("x-sandboxwich-tenant")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty())
            .unwrap_or(&state.default_tenant_id)
            .to_string()
    };
    request.extensions_mut().insert(TenantContext { tenant_id });

    next.run(request).await
}

fn bearer_token(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
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
        checked_at: Utc::now(),
        database: None,
    })
}

async fn readyz(State(state): State<AppState>) -> Response {
    match check_database_health(&state.db).await {
        Ok(database) => (
            StatusCode::OK,
            Json(HealthResponse {
                ok: true,
                service: "sandboxwich-api".to_string(),
                checked_at: Utc::now(),
                database: Some(database),
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                ok: false,
                service: "sandboxwich-api".to_string(),
                checked_at: Utc::now(),
                database: Some(HealthComponent {
                    ok: false,
                    message: Some("database unavailable".to_string()),
                }),
            }),
        )
            .into_response(),
    }
}

async fn metrics(State(state): State<AppState>) -> Result<Response, ApiError> {
    let body = collect_prometheus_metrics(&state.db).await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

async fn check_database_health(db: &Database) -> Result<HealthComponent, ApiError> {
    sqlx::query("select 1").execute(&db.pool).await?;
    Ok(HealthComponent {
        ok: true,
        message: None,
    })
}

async fn collect_prometheus_metrics(db: &Database) -> Result<String, ApiError> {
    let metrics = fetch_prometheus_metrics(db).await?;
    let mut body = String::new();
    append_count_family(
        &mut body,
        "sandboxwich_sandbox_count",
        "Sandboxes by lifecycle state.",
        "state",
        metrics.counts("sandbox"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_worker_count",
        "Workers by registration status.",
        "status",
        metrics.counts("worker"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_job_count",
        "Jobs by scheduler status.",
        "status",
        metrics.counts("job"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_runtime_resource_count",
        "Runtime resources by provider status.",
        "status",
        metrics.counts("runtime_resource"),
    );
    append_gauge(
        &mut body,
        "sandboxwich_job_leases_active",
        "Active job leases.",
        metrics.scalar("job_leases_active"),
    );
    append_gauge(
        &mut body,
        "sandboxwich_worker_capacity_slots",
        "Total configured online worker concurrency slots.",
        metrics.scalar("worker_capacity_slots"),
    );
    Ok(body)
}

struct PrometheusMetrics {
    values: BTreeMap<String, Vec<(String, i64)>>,
}

impl PrometheusMetrics {
    fn counts(&self, family: &'static str) -> Vec<(String, i64)> {
        self.values.get(family).cloned().unwrap_or_default()
    }

    fn scalar(&self, family: &'static str) -> i64 {
        self.values
            .get(family)
            .and_then(|values| values.first())
            .map(|(_, value)| *value)
            .unwrap_or_default()
    }
}

async fn fetch_prometheus_metrics(db: &Database) -> Result<PrometheusMetrics, ApiError> {
    let rows = sqlx::query(
        "select 'sandbox' as family, state as label, count(*) as value
         from sandboxes
         group by state
         union all
         select 'worker' as family, status as label, count(*) as value
         from workers
         group by status
         union all
         select 'job' as family, status as label, count(*) as value
         from jobs
         group by status
         union all
         select 'runtime_resource' as family, status as label, count(*) as value
         from runtime_resources
         group by status
         union all
         select 'job_leases_active' as family, '' as label, count(*) as value
         from job_leases
         where status = 'active'
         union all
         select 'worker_capacity_slots' as family, '' as label, coalesce(sum(max_concurrent_jobs), 0) as value
         from workers
         where status = 'online'
         order by family asc, label asc",
    )
    .fetch_all(&db.pool)
    .await?;

    let mut values = BTreeMap::new();
    for row in rows {
        let family: String = row.try_get("family")?;
        let label: String = row.try_get("label")?;
        let value: i64 = row.try_get("value")?;
        values
            .entry(family)
            .or_insert_with(Vec::new)
            .push((label, value));
    }
    Ok(PrometheusMetrics { values })
}

fn append_count_family(
    body: &mut String,
    name: &'static str,
    help: &'static str,
    label_name: &'static str,
    values: Vec<(String, i64)>,
) {
    body.push_str("# HELP ");
    body.push_str(name);
    body.push(' ');
    body.push_str(help);
    body.push('\n');
    body.push_str("# TYPE ");
    body.push_str(name);
    body.push_str(" gauge\n");
    for (label, value) in values {
        body.push_str(name);
        body.push('{');
        body.push_str(label_name);
        body.push_str("=\"");
        body.push_str(&escape_prometheus_label(&label));
        body.push_str("\"} ");
        body.push_str(&value.to_string());
        body.push('\n');
    }
}

fn append_gauge(body: &mut String, name: &'static str, help: &'static str, value: i64) {
    body.push_str("# HELP ");
    body.push_str(name);
    body.push(' ');
    body.push_str(help);
    body.push('\n');
    body.push_str("# TYPE ");
    body.push_str(name);
    body.push_str(" gauge\n");
    body.push_str(name);
    body.push(' ');
    body.push_str(&value.to_string());
    body.push('\n');
}

fn escape_prometheus_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
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

fn provision_spec_from_request(
    request: &CreateSandboxRequest,
    parent: Option<&Sandbox>,
) -> Result<SandboxProvisionSpec, ApiError> {
    let memory_limit = request
        .memory_limit
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.memory_limit.clone()))
        .unwrap_or_default();
    let network_egress = request
        .network_egress
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.network_egress.clone()))
        .unwrap_or_default();
    validate_network_egress(&network_egress)?;
    Ok(SandboxProvisionSpec {
        memory_limit,
        network_egress,
    })
}

fn validate_network_egress(network_egress: &NetworkEgress) -> Result<(), ApiError> {
    match network_egress {
        NetworkEgress::DenyAll | NetworkEgress::AllowAll => Ok(()),
        NetworkEgress::Allowlist { rules } => {
            for rule in rules {
                let value = rule.value.trim();
                if value.is_empty() {
                    return Err(ApiError::bad_request(
                        "network allow rule value cannot be empty",
                    ));
                }
                if value.len() > 253 {
                    return Err(ApiError::bad_request(
                        "network allow rule value is too long",
                    ));
                }
                if rule.kind == NetworkAllowRuleKind::Cidr && !looks_like_cidr(value) {
                    return Err(ApiError::bad_request(
                        "cidr network allow rule must use CIDR notation",
                    ));
                }
                if rule.kind == NetworkAllowRuleKind::Host {
                    return Err(ApiError::bad_request(
                        "host network allow rules require a provider with FQDN egress support; use cidr rules for Kubernetes NetworkPolicy",
                    ));
                }
            }
            Ok(())
        }
    }
}

fn looks_like_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    !address.trim().is_empty()
        && prefix
            .parse::<u8>()
            .is_ok_and(|prefix| matches!(prefix, 0..=128))
}

const ALLOWED_FILE_MIME_TYPES: &[&str] = &[
    "application/json",
    "application/octet-stream",
    "application/pdf",
    "image/jpeg",
    "image/png",
    "text/csv",
    "text/markdown",
    "text/plain",
    "text/x-python",
    "text/x-rust",
    "text/x-shellscript",
];

fn normalize_file_path(path: Option<String>) -> Result<String, ApiError> {
    let path = path
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .ok_or_else(|| ApiError::bad_request("file path is required"))?;
    if path.contains('\0') {
        return Err(ApiError::bad_request("file path cannot contain NUL"));
    }
    if path.len() > 1024 {
        return Err(ApiError::bad_request("file path is too long"));
    }
    Ok(path)
}

fn normalize_mime_type(mime_type: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(mime_type) = mime_type else {
        return Ok(Some("application/octet-stream".to_string()));
    };
    let mime_type = mime_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if mime_type.is_empty() {
        return Ok(Some("application/octet-stream".to_string()));
    }
    if mime_type.len() > 128 {
        return Err(ApiError::bad_request("mime_type is too long"));
    }
    Ok(Some(mime_type))
}

fn validate_file_mime_type(mime_type: Option<&str>) -> Result<(), ApiError> {
    let Some(mime_type) = mime_type else {
        return Ok(());
    };
    if ALLOWED_FILE_MIME_TYPES.contains(&mime_type) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "unsupported mime_type {mime_type:?}"
        )))
    }
}

fn validate_file_size(size_bytes: u64) -> Result<(), ApiError> {
    if size_bytes > MAX_SANDBOX_FILE_BYTES {
        return Err(ApiError::bad_request(format!(
            "file exceeds maximum size of {MAX_SANDBOX_FILE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn download_name(path: &str) -> String {
    path.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("sandbox-file")
        .replace(['"', '\\'], "_")
}

async fn create_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let now = Utc::now();
    let provision_spec = provision_spec_from_request(&request, None)?;
    let sandbox = Sandbox {
        id: SandboxId::new(),
        tenant_id: ctx.tenant_id.clone(),
        name: request.name.unwrap_or_else(|| "fresh-sandwich".to_string()),
        state: SandboxState::Ready,
        template: request.template.unwrap_or_else(|| "ubuntu-dev".to_string()),
        memory_limit: provision_spec.memory_limit,
        network_egress: provision_spec.network_egress,
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
            "reason": "created",
            "memoryLimit": sandbox.memory_limit,
            "networkEgress": sandbox.network_egress
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
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where tenant_id = {}
         order by created_at asc",
        state.db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(&ctx.tenant_id)
        .fetch_all(&state.db.pool)
        .await?;

    let mut sandboxes = rows
        .into_iter()
        .map(row_to_sandbox)
        .collect::<Result<Vec<_>, _>>()?;
    hydrate_sandboxes_network_egress(&state.db, &mut sandboxes).await?;

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

async fn upload_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<FileResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;

    let mut path = None;
    let mut mime_type = None;
    let mut content = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request(format!("invalid multipart upload: {error}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "path" => {
                path = Some(field.text().await.map_err(|error| {
                    ApiError::bad_request(format!("invalid multipart path field: {error}"))
                })?);
            }
            "mime_type" => {
                mime_type = Some(field.text().await.map_err(|error| {
                    ApiError::bad_request(format!("invalid multipart mime_type field: {error}"))
                })?);
            }
            "file" | "content" => {
                if mime_type.is_none() {
                    mime_type = field.content_type().map(ToOwned::to_owned);
                }
                if path.is_none() {
                    path = field.file_name().map(ToOwned::to_owned);
                }
                content = Some(field.bytes().await.map_err(|error| {
                    ApiError::bad_request(format!("invalid multipart file field: {error}"))
                })?);
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let path = normalize_file_path(path)?;
    let content = content.ok_or_else(|| ApiError::bad_request("file part is required"))?;
    validate_file_size(content.len() as u64)?;
    let mime_type = normalize_mime_type(mime_type)?;
    validate_file_mime_type(mime_type.as_deref())?;
    let file =
        upsert_sandbox_file(&state.db, sandbox_id, &path, mime_type.as_deref(), &content).await?;
    insert_event(
        &state.db,
        sandbox_id,
        SandboxEventKind::FileUploaded,
        json!({
            "fileId": file.id,
            "path": file.path,
            "sizeBytes": file.size_bytes,
            "mimeType": file.mime_type
        }),
    )
    .await?;

    Ok(Json(FileResponse { ok: true, file }))
}

async fn list_files(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<ListFilesResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let files = list_sandbox_files(&state.db, sandbox_id).await?;
    Ok(Json(ListFilesResponse { ok: true, files }))
}

async fn download_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path((sandbox_id, file_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let stored = fetch_sandbox_file(&state.db, sandbox_id, FileId(file_id)).await?;
    let content_type = stored
        .file
        .mime_type
        .as_deref()
        .unwrap_or("application/octet-stream")
        .to_string();
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}\"",
                    download_name(&stored.file.path)
                ),
            ),
        ],
        Bytes::from(stored.content),
    )
        .into_response())
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
    let provision_spec = provision_spec_from_request(&request, Some(&parent))?;
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
        expires_at: None,
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
        template: request.template.unwrap_or_else(|| parent.template.clone()),
        memory_limit: provision_spec.memory_limit,
        network_egress: provision_spec.network_egress,
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
            "parentSnapshotId": snapshot.id,
            "memoryLimit": child.memory_limit,
            "networkEgress": child.network_egress
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
                "snapshotId": snapshot.id,
                "provisionSpec": SandboxProvisionSpec {
                    memory_limit: parent.memory_limit.clone(),
                    network_egress: parent.network_egress.clone(),
                }
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
    let reconciled = reconcile_runtime_resources_on_connection(
        &state.db,
        &mut *tx,
        &request,
        &ctx.tenant_id,
        observed_at,
    )
    .await;

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
        .filter(|worker| worker.status == WorkerStatus::Online)
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
    let mut job = Job {
        id: JobId::new(),
        tenant_id: ctx.tenant_id.clone(),
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
    validate_job_payload_tenant(&state.db, &job, &ctx).await?;
    enrich_job_payload_with_provision_spec(&state.db, &mut job).await?;
    insert_job(&state.db, &job).await?;
    Ok(Json(JobResponse { ok: true, job }))
}

async fn enrich_job_payload_with_provision_spec(
    db: &Database,
    job: &mut Job,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::RunCommand => {
            let sandbox = fetch_sandbox(db, sandbox_id_from_job(job)?).await?;
            add_provision_spec_to_payload(job, &sandbox)?;
        }
        JobKind::ForkSandbox => {
            let child = fetch_sandbox(db, child_sandbox_id_from_job(job)?).await?;
            add_provision_spec_to_payload(job, &child)?;
        }
        JobKind::RunPrompt
        | JobKind::CreateSnapshot
        | JobKind::StopSandbox
        | JobKind::ResumeSandbox => {}
    }
    Ok(())
}

fn add_provision_spec_to_payload(job: &mut Job, sandbox: &Sandbox) -> Result<(), ApiError> {
    if job.payload.get("provisionSpec").is_some() {
        return Ok(());
    }
    let Some(payload) = job.payload.as_object_mut() else {
        return Err(ApiError::bad_request("job payload must be an object"));
    };
    payload.insert(
        "provisionSpec".to_string(),
        serde_json::to_value(SandboxProvisionSpec {
            memory_limit: sandbox.memory_limit.clone(),
            network_egress: sandbox.network_egress.clone(),
        })?,
    );
    Ok(())
}

async fn validate_job_payload_tenant(
    db: &Database,
    job: &Job,
    ctx: &TenantContext,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
        }
        JobKind::RunCommand => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            let command = fetch_command(db, command_id_from_job(job)?).await?;
            ensure_sandbox_tenant(db, command.sandbox_id, ctx).await?;
        }
        JobKind::RunPrompt => {
            ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
        }
        JobKind::CreateSnapshot => {
            let snapshot = fetch_snapshot(db, snapshot_id_from_job(job)?).await?;
            let sandbox = ensure_sandbox_tenant(db, sandbox_id_from_job(job)?, ctx).await?;
            if snapshot.sandbox_id != sandbox.id {
                return Err(ApiError::bad_request(
                    "snapshot must belong to the referenced sandbox",
                ));
            }
        }
        JobKind::ForkSandbox => {
            ensure_sandbox_tenant(db, parent_sandbox_id_from_job(job)?, ctx).await?;
            ensure_sandbox_tenant(db, child_sandbox_id_from_job(job)?, ctx).await?;
            let snapshot = fetch_snapshot(db, snapshot_id_from_job(job)?).await?;
            ensure_sandbox_tenant(db, snapshot.sandbox_id, ctx).await?;
        }
    }
    Ok(())
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
    maybe_insert_guest_failure_event(&state.db, &guest_health).await?;

    Ok(Json(GuestHealthResponse {
        ok: true,
        guest_health,
    }))
}

async fn maybe_insert_guest_failure_event(
    db: &Database,
    guest_health: &GuestHealth,
) -> Result<(), ApiError> {
    let reason = match &guest_health.status {
        GuestStatus::Unhealthy => "guest_unhealthy",
        GuestStatus::Unreachable => "guest_unreachable",
        GuestStatus::Pending | GuestStatus::Ready | GuestStatus::Terminated => return Ok(()),
    };

    insert_event(
        db,
        guest_health.sandbox_id,
        SandboxEventKind::DesktopExpired,
        json!({
            "reason": reason,
            "guestStatus": &guest_health.status,
            "agentVersion": &guest_health.agent_version,
            "checks": &guest_health.checks,
            "message": &guest_health.message,
            "lastProbeAt": &guest_health.last_probe_at
        }),
    )
    .await?;
    Ok(())
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
        if let Some(lease) = try_claim_job(&state.db, &worker, &job, request.lease_seconds).await? {
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
        request.annotations,
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
    ensure_lease_tenant(&state.db, lease_id, &ctx).await?;
    let lease =
        fail_lease_in_transaction(&state.db, lease_id, request.retry, &request.error).await?;
    Ok(Json(LeaseResponse { ok: true, lease }))
}

async fn fail_lease_in_transaction(
    db: &Database,
    lease_id: LeaseId,
    retry_requested: bool,
    error: &str,
) -> Result<JobLease, ApiError> {
    let mut tx = db.pool.begin().await?;

    let failed = async {
        let lease = fetch_lease_on_connection(db, &mut *tx, lease_id).await?;
        if lease.status != LeaseStatus::Active {
            return Err(ApiError::bad_request("lease is not active"));
        }

        let now = Utc::now();
        fail_active_lease_on_connection(db, &mut *tx, lease_id, now, error).await?;
        let retry = retry_requested && lease.job.attempts < lease.job.max_attempts;
        if retry {
            update_job_status_on_connection(
                db,
                &mut *tx,
                lease.job_id,
                JobStatus::Queued,
                Some(error),
                now,
            )
            .await?;
            apply_retryable_job_on_connection(db, &mut *tx, &lease.job, error).await?;
        } else {
            update_job_status_on_connection(
                db,
                &mut *tx,
                lease.job_id,
                JobStatus::Failed,
                Some(error),
                now,
            )
            .await?;
            apply_failed_job_on_connection(db, &mut *tx, &lease.job, error).await?;
        }

        fetch_lease_on_connection(db, &mut *tx, lease_id).await
    }
    .await;

    match failed {
        Ok(lease) => {
            tx.commit().await?;
            Ok(lease)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back lease failure");
            }
            Err(error)
        }
    }
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
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress(db, &mut sandbox).await?;
    Ok(sandbox)
}

async fn fetch_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress_on_connection(db, connection, &mut sandbox).await?;
    Ok(sandbox)
}

async fn ensure_sandbox_tenant_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    tenant_id: &str,
) -> Result<Sandbox, ApiError> {
    let sandbox = fetch_sandbox_on_connection(db, connection, sandbox_id).await?;
    if sandbox.tenant_id != tenant_id {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(sandbox)
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
    tenant_id: &str,
    observed_at: DateTime<Utc>,
) -> Result<(Vec<RuntimeResource>, Vec<RuntimeResource>), ApiError> {
    let mut upserted = Vec::new();
    let mut observed = Vec::new();

    for resource in &request.resources {
        ensure_sandbox_tenant_on_connection(db, connection, resource.sandbox_id, tenant_id).await?;
        if let Some(snapshot_id) = resource.snapshot_id {
            let snapshot = fetch_snapshot_on_connection(db, connection, snapshot_id).await?;
            if snapshot.sandbox_id != resource.sandbox_id {
                return Err(ApiError::bad_request(
                    "runtime resource snapshot must belong to the resource sandbox",
                ));
            }
        }
        let resource = upsert_provider_runtime_resource_on_connection(
            db,
            connection,
            resource,
            Some(observed_at),
            Some(observed_at),
            Some(tenant_id),
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
            tenant_id,
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
    tenant_id: Option<&str>,
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
        if let Some(tenant_id) = tenant_id {
            let existing =
                fetch_runtime_resource_on_connection(db, connection, resource_id).await?;
            ensure_sandbox_tenant_on_connection(db, connection, existing.sandbox_id, tenant_id)
                .await?;
        }
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
             deleted_at = {}, error = {}, observed_at = {}, last_reconciled_at = coalesce({}, last_reconciled_at)
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
    tenant_id: &str,
    observed: &[ObservedRuntimeResourceIdentity],
    reconciled_at: DateTime<Utc>,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let mut placeholder_index = 1;
    let provider_placeholder = db.placeholder(placeholder_index);
    placeholder_index += 1;
    let namespace_placeholder = db.placeholder(placeholder_index);
    placeholder_index += 1;
    let cluster_filter = if request.cluster.is_some() {
        let cluster_placeholder = db.placeholder(placeholder_index);
        placeholder_index += 1;
        format!("runtime_resources.cluster = {cluster_placeholder}")
    } else {
        "runtime_resources.cluster is null".to_string()
    };
    let tenant_placeholder = db.placeholder(placeholder_index);
    placeholder_index += 1;

    let mut observed_filters = Vec::new();
    for _ in observed {
        let kind_placeholder = db.placeholder(placeholder_index);
        placeholder_index += 1;
        let name_placeholder = db.placeholder(placeholder_index);
        placeholder_index += 1;
        observed_filters.push(format!(
            "(runtime_resources.resource_kind = {kind_placeholder} and runtime_resources.resource_name = {name_placeholder})"
        ));
    }
    let missing_filter = if observed_filters.is_empty() {
        String::new()
    } else {
        format!(" and not ({})", observed_filters.join(" or "))
    };

    let sql = format!(
        "select runtime_resources.id, runtime_resources.sandbox_id, runtime_resources.snapshot_id,
                runtime_resources.provider, runtime_resources.resource_kind, runtime_resources.purpose,
                runtime_resources.resource_name, runtime_resources.namespace, runtime_resources.status,
                runtime_resources.cluster, runtime_resources.storage_class, runtime_resources.snapshot_class,
                runtime_resources.storage_size, runtime_resources.runtime_image, runtime_resources.service_port,
                runtime_resources.target_port, runtime_resources.source_snapshot_id, runtime_resources.created_at,
                runtime_resources.updated_at, runtime_resources.observed_at, runtime_resources.last_reconciled_at,
                runtime_resources.ready_at, runtime_resources.deleted_at, runtime_resources.error
         from runtime_resources
         join sandboxes on sandboxes.id = runtime_resources.sandbox_id
         where runtime_resources.provider = {provider_placeholder}
           and runtime_resources.namespace = {namespace_placeholder}
           and {cluster_filter}
           and sandboxes.tenant_id = {tenant_placeholder}
           and runtime_resources.status not in ('deleted', 'destroyed')
           {missing_filter}
         order by runtime_resources.resource_kind asc, runtime_resources.resource_name asc, runtime_resources.id asc"
    );
    let mut query = sqlx::query(&sql)
        .bind(&request.provider)
        .bind(&request.namespace);
    if request.cluster.is_some() {
        query = query.bind(&request.cluster);
    }
    query = query.bind(tenant_id);
    for identity in observed {
        query = query
            .bind(runtime_resource_kind_to_str(&identity.resource_kind))
            .bind(&identity.resource_name);
    }
    let candidates = query.fetch_all(&mut *connection).await?;

    let mut deleted = Vec::new();
    for row in candidates {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(
            mark_runtime_resource_deleted_on_connection(
                db,
                connection,
                resource.id,
                reconciled_at,
                RuntimeResourceStatus::Deleted,
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
    status: RuntimeResourceStatus,
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
        .bind(runtime_resource_status_to_str(&status))
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

async fn mark_runtime_resources_deleted_for_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
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
         where sandbox_id = {} and status not in ('deleted', 'destroyed')
         order by updated_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    let mut deleted = Vec::new();
    for row in rows {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(
            mark_runtime_resource_deleted_on_connection(
                db,
                connection,
                resource.id,
                deleted_at,
                RuntimeResourceStatus::Destroyed,
                error,
            )
            .await?,
        );
    }

    Ok(deleted)
}

async fn insert_runtime_resource_tombstone_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource: &RuntimeResource,
    tombstoned_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into runtime_resource_tombstones
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, observed_at, last_reconciled_at,
          ready_at, deleted_at, error, tombstoned_at)
         values ({})
         on conflict (id) do update set
             status = excluded.status,
             updated_at = excluded.updated_at,
             last_reconciled_at = excluded.last_reconciled_at,
             deleted_at = excluded.deleted_at,
             error = excluded.error,
             tombstoned_at = excluded.tombstoned_at",
        db.placeholders(25)
    );
    sqlx::query(&sql)
        .bind(resource.id.to_string())
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
        .bind(resource.created_at.to_rfc3339())
        .bind(resource.updated_at.to_rfc3339())
        .bind(resource.observed_at.map(|time| time.to_rfc3339()))
        .bind(resource.last_reconciled_at.map(|time| time.to_rfc3339()))
        .bind(resource.ready_at.map(|time| time.to_rfc3339()))
        .bind(resource.deleted_at.map(|time| time.to_rfc3339()))
        .bind(&resource.error)
        .bind(tombstoned_at.to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

fn deleted_at_for_runtime_resource(
    status: &RuntimeResourceStatus,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if matches!(
        status,
        RuntimeResourceStatus::Deleted | RuntimeResourceStatus::Destroyed
    ) {
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

struct StoredSandboxFile {
    file: SandboxFile,
    content: Vec<u8>,
}

async fn upsert_sandbox_file(
    db: &Database,
    sandbox_id: SandboxId,
    path: &str,
    mime_type: Option<&str>,
    content: &[u8],
) -> Result<SandboxFile, ApiError> {
    let mut tx = db.pool.begin().await?;
    let upserted = async {
        let now = Utc::now();
        let existing_id = fetch_sandbox_file_id_by_path_on_connection(
            db,
            &mut *tx,
            sandbox_id,
            path,
        )
        .await?;
        let file_id = existing_id.unwrap_or_else(FileId::new);
        let content_base64 = general_purpose::STANDARD.encode(content);
        let size_bytes = i64::try_from(content.len())
            .map_err(|_| ApiError::bad_request("file is too large"))?;
        if existing_id.is_some() {
            let sql = format!(
                "update sandbox_files
                 set size_bytes = {}, mime_type = {}, content_base64 = {}, updated_at = {}
                 where id = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4),
                db.placeholder(5)
            );
            sqlx::query(&sql)
                .bind(size_bytes)
                .bind(mime_type)
                .bind(content_base64)
                .bind(now.to_rfc3339())
                .bind(file_id.to_string())
                .execute(&mut *tx)
                .await?;
        } else {
            let sql = format!(
                "insert into sandbox_files
                 (id, sandbox_id, path, size_bytes, mime_type, content_base64, created_at, updated_at)
                 values ({})",
                db.placeholders(8)
            );
            sqlx::query(&sql)
                .bind(file_id.to_string())
                .bind(sandbox_id.to_string())
                .bind(path)
                .bind(size_bytes)
                .bind(mime_type)
                .bind(content_base64)
                .bind(now.to_rfc3339())
                .bind(now.to_rfc3339())
                .execute(&mut *tx)
                .await?;
        }
        fetch_sandbox_file_metadata_on_connection(db, &mut *tx, sandbox_id, file_id).await
    }
    .await;
    match upserted {
        Ok(file) => {
            tx.commit().await?;
            Ok(file)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back sandbox file upsert");
            }
            Err(error)
        }
    }
}

async fn fetch_sandbox_file_id_by_path_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    path: &str,
) -> Result<Option<FileId>, ApiError> {
    let sql = format!(
        "select id from sandbox_files where sandbox_id = {} and path = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(path)
        .fetch_optional(&mut *connection)
        .await?;
    row.map(|row| {
        let id: String = row.try_get("id")?;
        Ok(FileId(parse_uuid(&id)?))
    })
    .transpose()
}

async fn list_sandbox_files(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<SandboxFile>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, path, size_bytes, mime_type, created_at, updated_at
         from sandbox_files
         where sandbox_id = {}
         order by path asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    rows.into_iter().map(row_to_sandbox_file).collect()
}

async fn fetch_sandbox_file(
    db: &Database,
    sandbox_id: SandboxId,
    file_id: FileId,
) -> Result<StoredSandboxFile, ApiError> {
    let sql = format!(
        "select id, sandbox_id, path, size_bytes, mime_type, content_base64, created_at, updated_at
         from sandbox_files
         where sandbox_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(file_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("file not found"))?;
    row_to_stored_sandbox_file(row)
}

async fn fetch_sandbox_file_metadata_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    file_id: FileId,
) -> Result<SandboxFile, ApiError> {
    let sql = format!(
        "select id, sandbox_id, path, size_bytes, mime_type, created_at, updated_at
         from sandbox_files
         where sandbox_id = {} and id = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(file_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("file not found"))?;
    row_to_sandbox_file(row)
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
        "select id, command_id, stream, sequence, chunk, annotations, created_at
         from command_output_chunks
         where command_id = {}
         order by created_at asc, id asc",
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
    annotations: Vec<CommandOutputAnnotation>,
) -> Result<CommandOutputChunk, ApiError> {
    let mut tx = db.pool.begin().await?;
    let appended = append_command_output_chunk_on_connection(
        db,
        &mut *tx,
        command_id,
        sandbox_id,
        stream,
        chunk,
        annotations,
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
    annotations: Vec<CommandOutputAnnotation>,
) -> Result<CommandOutputChunk, ApiError> {
    lock_command_output_for_append_on_connection(db, connection, command_id).await?;
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

async fn lock_command_output_for_append_on_connection(
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
    let column = stream.as_db_str();
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

async fn reset_command_for_retry_on_connection(
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

async fn active_lease_count_for_worker_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
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
        .fetch_one(&mut *connection)
        .await?;
    let active_leases: i64 = row.try_get("active_leases")?;
    u32::try_from(active_leases)
        .map_err(|_| ApiError::internal("database contains invalid active lease count"))
}

async fn list_worker_capacities(
    db: &Database,
    tenant_id: &str,
) -> Result<Vec<WorkerCapacity>, ApiError> {
    let sql = format!(
        "select workers.id, workers.tenant_id, workers.name, workers.status, workers.provider,
                workers.capabilities, workers.max_concurrent_jobs, workers.labels,
                workers.registered_at, workers.last_heartbeat_at,
                coalesce(count(job_leases.id), 0) as active_leases
         from workers
         left join job_leases on job_leases.worker_id = workers.id and job_leases.status = 'active'
         where workers.tenant_id = {}
         group by workers.id, workers.tenant_id, workers.name, workers.status, workers.provider,
                  workers.capabilities, workers.max_concurrent_jobs, workers.labels,
                  workers.registered_at, workers.last_heartbeat_at
         order by workers.registered_at asc, workers.id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(tenant_id)
        .fetch_all(&db.pool)
        .await?;

    let mut capacities = Vec::new();
    for row in rows {
        let active_leases = count_to_u32(row.try_get("active_leases")?)?;
        let worker = row_to_worker(row)?;
        let available_slots = if worker.status == WorkerStatus::Online {
            worker.max_concurrent_jobs.saturating_sub(active_leases)
        } else {
            0
        };
        capacities.push(WorkerCapacity {
            worker_id: worker.id,
            worker_name: worker.name,
            provider: worker.provider,
            status: worker.status,
            max_concurrent_jobs: worker.max_concurrent_jobs,
            active_leases,
            available_slots,
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
    validate_network_egress(&sandbox.network_egress)?;
    let mut tx = db.pool.begin().await?;
    let inserted = async {
        insert_sandbox_on_connection(db, &mut *tx, sandbox).await?;
        replace_sandbox_network_rules_on_connection(
            db,
            &mut *tx,
            sandbox.id,
            sandbox.network_egress.rules(),
        )
        .await
    }
    .await;
    match inserted {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back sandbox insert");
            }
            Err(error)
        }
    }
}

async fn insert_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &Sandbox,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into sandboxes
         (id, tenant_id, name, state, template, memory_limit, network_egress_mode,
          created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        db.placeholders(11)
    );
    sqlx::query(&sql)
        .bind(sandbox.id.to_string())
        .bind(&sandbox.tenant_id)
        .bind(&sandbox.name)
        .bind(state_to_str(&sandbox.state))
        .bind(&sandbox.template)
        .bind(memory_limit_to_str(&sandbox.memory_limit))
        .bind(network_egress_mode_to_str(&sandbox.network_egress.mode()))
        .bind(sandbox.created_at.to_rfc3339())
        .bind(sandbox.updated_at.to_rfc3339())
        .bind(sandbox.ttl_seconds.map(|ttl| ttl as i64))
        .bind(
            sandbox
                .parent_snapshot_id
                .map(|snapshot| snapshot.0.to_string()),
        )
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn replace_sandbox_network_rules_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    rules: &[NetworkAllowRule],
) -> Result<(), ApiError> {
    let delete_sql = format!(
        "delete from sandbox_network_egress_rules where sandbox_id = {}",
        db.placeholder(1)
    );
    sqlx::query(&delete_sql)
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    for rule in rules {
        let sql = format!(
            "insert into sandbox_network_egress_rules (id, sandbox_id, kind, value, created_at)
             values ({})",
            db.placeholders(5)
        );
        sqlx::query(&sql)
            .bind(EventId::new().to_string())
            .bind(sandbox_id.to_string())
            .bind(network_allow_rule_kind_to_str(&rule.kind))
            .bind(&rule.value)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *connection)
            .await?;
    }

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

fn count_to_u32(count: i64) -> Result<u32, ApiError> {
    u32::try_from(count).map_err(|_| ApiError::internal("database count is out of range"))
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

    let mut expired_count = 0;
    let mut archived_deleted_count = 0;
    let mut archived_skipped_count = 0;
    let mut runtime_deleted_count = 0;

    let expired = match expire_due_snapshots(db).await {
        Ok(expired) => {
            expired_count = expired.len() as u64;
            expired
        }
        Err(error) => {
            mark_cleanup_run_failed(
                db,
                &cleanup_run,
                expired_count,
                archived_deleted_count,
                archived_skipped_count,
                runtime_deleted_count,
                &error,
            )
            .await;
            return Err(error);
        }
    };
    let mut runtime_resources_deleted =
        match cleanup_runtime_resources_for_expired_snapshots(db).await {
            Ok(deleted) => {
                runtime_deleted_count = deleted.len() as u64;
                deleted
            }
            Err(error) => {
                mark_cleanup_run_failed(
                    db,
                    &cleanup_run,
                    expired_count,
                    archived_deleted_count,
                    archived_skipped_count,
                    runtime_deleted_count,
                    &error,
                )
                .await;
                return Err(error);
            }
        };
    let archived = match cleanup_archived_sandboxes(db).await {
        Ok(archived) => archived,
        Err(error) => {
            mark_cleanup_run_failed(
                db,
                &cleanup_run,
                expired_count,
                archived_deleted_count,
                archived_skipped_count,
                runtime_deleted_count,
                &error,
            )
            .await;
            return Err(error);
        }
    };
    runtime_resources_deleted.extend(archived.runtime_resources_deleted);
    archived_deleted_count = archived.deleted.len() as u64;
    archived_skipped_count = archived.skipped.len() as u64;
    runtime_deleted_count = runtime_resources_deleted.len() as u64;

    let cleanup_run = CleanupRun {
        status: CleanupRunStatus::Succeeded,
        finished_at: Some(Utc::now()),
        expired_snapshots: expired_count,
        archived_sandboxes_deleted: archived_deleted_count,
        archived_sandboxes_skipped: archived_skipped_count,
        runtime_resources_deleted: runtime_deleted_count,
        ..cleanup_run
    };
    update_cleanup_run(db, &cleanup_run).await?;

    Ok(CleanupControllerReport {
        cleanup_run,
        expired,
        archived_sandboxes_deleted: archived_deleted_count,
        archived_sandboxes: archived.deleted,
        archived_sandboxes_skipped: archived.skipped,
        runtime_resources_deleted,
    })
}

async fn mark_cleanup_run_failed(
    db: &Database,
    cleanup_run: &CleanupRun,
    expired_snapshots: u64,
    archived_sandboxes_deleted: u64,
    archived_sandboxes_skipped: u64,
    runtime_resources_deleted: u64,
    error: &ApiError,
) {
    let failed = CleanupRun {
        status: CleanupRunStatus::Failed,
        finished_at: Some(Utc::now()),
        expired_snapshots,
        archived_sandboxes_deleted,
        archived_sandboxes_skipped,
        runtime_resources_deleted,
        error: Some(format!("{error:?}")),
        ..cleanup_run.clone()
    };
    if let Err(update_error) = update_cleanup_run(db, &failed).await {
        tracing::warn!(?update_error, "failed to mark cleanup run failed");
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
        let mut tx = db.pool.begin().await?;
        let expired_snapshot = async {
            update_snapshot_status_on_connection(
                db,
                &mut *tx,
                snapshot.id,
                SnapshotStatus::Expired,
                None,
            )
            .await?;
            dead_queued_snapshot_jobs_on_connection(db, &mut *tx, snapshot.id, "snapshot expired")
                .await?;
            fail_sandboxes_waiting_on_snapshot_on_connection(
                db,
                &mut *tx,
                snapshot.id,
                "snapshot_expired",
                "snapshot expired",
            )
            .await?;
            let expired_snapshot = fetch_snapshot_on_connection(db, &mut *tx, snapshot.id).await?;
            insert_event_on_connection(
                db,
                &mut *tx,
                expired_snapshot.sandbox_id,
                SandboxEventKind::LifecycleChanged,
                json!({
                    "reason": "snapshot_expired",
                    "snapshotId": expired_snapshot.id,
                    "snapshotStatus": expired_snapshot.status
                }),
            )
            .await?;
            Ok(expired_snapshot)
        }
        .await;
        match expired_snapshot {
            Ok(expired_snapshot) => {
                tx.commit().await?;
                expired.push(expired_snapshot);
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back snapshot expiration");
                }
                return Err(error);
            }
        }
    }

    Ok(expired)
}

async fn update_snapshot_status_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
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
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("snapshot not found"));
    }
    Ok(())
}

async fn dead_queued_snapshot_jobs_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    error: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "select id
         from jobs
         where kind = 'create_snapshot' and status = 'queued' and snapshot_id = {}",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(snapshot_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    let now = Utc::now();
    for row in rows {
        let job_id: String = row.try_get("id")?;
        update_job_status_on_connection(
            db,
            connection,
            JobId(parse_uuid(&job_id)?),
            JobStatus::Dead,
            Some(error),
            now,
        )
        .await?;
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
         where snapshots.status = 'expired' and runtime_resources.status not in ('deleted', 'destroyed')
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
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
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
        let mut sandbox = row_to_sandbox(row)?;
        hydrate_sandbox_network_egress(db, &mut sandbox).await?;
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
        let mut tx = db.pool.begin().await?;
        let cleaned = async {
            let deleted_resources = mark_runtime_resources_deleted_for_sandbox_on_connection(
                db,
                &mut *tx,
                sandbox.id,
                now,
                "archived sandbox deleted during cleanup",
            )
            .await?;
            for resource in &deleted_resources {
                insert_runtime_resource_tombstone_on_connection(db, &mut *tx, resource, now)
                    .await?;
            }
            let sql = format!(
                "delete from sandboxes where id = {} and state = 'archived'",
                db.placeholder(1)
            );
            let result = sqlx::query(&sql)
                .bind(sandbox.id.to_string())
                .execute(&mut *tx)
                .await?;
            Ok((result.rows_affected() > 0, deleted_resources))
        }
        .await;
        match cleaned {
            Ok((true, deleted_resources)) => {
                tx.commit().await?;
                runtime_resources_deleted.extend(deleted_resources);
                deleted.push(sandbox);
            }
            Ok((false, _)) => {
                tx.rollback().await?;
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back archived sandbox cleanup");
                }
                return Err(error);
            }
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
    let references = job_references(job)?;
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id)
         values ({})",
        db.placeholders(19)
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
        .bind(references.sandbox_id.map(|id| id.to_string()))
        .bind(references.command_id.map(|id| id.to_string()))
        .bind(references.snapshot_id.map(|id| id.to_string()))
        .bind(references.parent_sandbox_id.map(|id| id.to_string()))
        .bind(references.child_sandbox_id.map(|id| id.to_string()))
        .bind(references.prompt_event_id.map(|id| id.to_string()))
        .execute(&db.pool)
        .await?;
    Ok(())
}

async fn insert_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    let references = job_references(job)?;
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error, sandbox_id, command_id, snapshot_id,
          parent_sandbox_id, child_sandbox_id, prompt_event_id)
         values ({})",
        db.placeholders(19)
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
        .bind(references.sandbox_id.map(|id| id.to_string()))
        .bind(references.command_id.map(|id| id.to_string()))
        .bind(references.snapshot_id.map(|id| id.to_string()))
        .bind(references.parent_sandbox_id.map(|id| id.to_string()))
        .bind(references.child_sandbox_id.map(|id| id.to_string()))
        .bind(references.prompt_event_id.map(|id| id.to_string()))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

#[derive(Default)]
struct JobReferences {
    sandbox_id: Option<SandboxId>,
    command_id: Option<CommandId>,
    snapshot_id: Option<SnapshotId>,
    parent_sandbox_id: Option<SandboxId>,
    child_sandbox_id: Option<SandboxId>,
    prompt_event_id: Option<EventId>,
}

fn job_references(job: &Job) -> Result<JobReferences, ApiError> {
    let mut references = JobReferences::default();
    match job.kind {
        JobKind::ProvisionSandbox | JobKind::StopSandbox | JobKind::ResumeSandbox => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
        }
        JobKind::RunCommand => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.command_id = Some(command_id_from_job(job)?);
        }
        JobKind::RunPrompt => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.prompt_event_id = Some(prompt_event_id_from_job(job)?);
        }
        JobKind::CreateSnapshot => {
            references.sandbox_id = Some(sandbox_id_from_job(job)?);
            references.snapshot_id = Some(snapshot_id_from_job(job)?);
        }
        JobKind::ForkSandbox => {
            references.parent_sandbox_id = Some(parent_sandbox_id_from_job(job)?);
            references.child_sandbox_id = Some(child_sandbox_id_from_job(job)?);
            references.snapshot_id = Some(snapshot_id_from_job(job)?);
        }
    }
    Ok(references)
}

async fn try_claim_job(
    db: &Database,
    worker: &Worker,
    job: &Job,
    lease_seconds: Option<u64>,
) -> Result<Option<JobLease>, ApiError> {
    let mut tx = db.pool.begin().await?;
    let claimed = async {
        lock_worker_for_claim_on_connection(db, &mut *tx, worker.id).await?;
        let active_leases =
            active_lease_count_for_worker_on_connection(db, &mut *tx, worker.id).await?;
        if active_leases >= worker.max_concurrent_jobs {
            return Ok(None);
        }

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
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }

        let lease = JobLease {
            id: LeaseId::new(),
            job_id: job.id,
            worker_id: worker.id,
            status: LeaseStatus::Active,
            attempt,
            leased_at: now,
            expires_at,
            completed_at: None,
            error: None,
            job: fetch_job_on_connection(db, &mut *tx, job.id).await?,
        };
        insert_lease_on_connection(db, &mut *tx, &lease).await?;
        apply_claimed_job_on_connection(db, &mut *tx, &lease.job).await?;
        let lease = fetch_lease_on_connection(db, &mut *tx, lease.id).await?;
        Ok(Some(lease))
    };
    match claimed.await {
        Ok(Some(lease)) => {
            tx.commit().await?;
            Ok(Some(lease))
        }
        Ok(None) => {
            tx.rollback().await?;
            Ok(None)
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back lease claim");
            }
            Err(error)
        }
    }
}

async fn lock_worker_for_claim_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    worker_id: WorkerId,
) -> Result<(), ApiError> {
    let sql = format!(
        "update workers
         set last_heartbeat_at = last_heartbeat_at
         where id = {}",
        db.placeholder(1)
    );
    let result = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("worker not found"));
    }
    Ok(())
}

async fn insert_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease: &JobLease,
) -> Result<(), ApiError> {
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
        .execute(&mut *connection)
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

async fn fail_active_lease_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    lease_id: LeaseId,
    completed_at: DateTime<Utc>,
    error: &str,
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
        .bind(lease_status_to_str(&LeaseStatus::Failed))
        .bind(completed_at.to_rfc3339())
        .bind(error)
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
    if chunk.is_empty() {
        return Ok(());
    }
    let current =
        command_output_for_stream_on_connection(db, connection, command_id, &stream).await?;
    if current == chunk {
        return Ok(());
    }
    if let Some(suffix) = chunk.strip_prefix(&current) {
        if suffix.is_empty() {
            return Ok(());
        }
        append_command_output_chunk_on_connection(
            db,
            connection,
            command_id,
            sandbox_id,
            stream,
            suffix.to_string(),
            Vec::new(),
        )
        .await?;
        return Ok(());
    }
    replace_command_output_stream_on_connection(db, connection, command_id, &stream).await?;
    append_command_output_chunk_on_connection(
        db,
        connection,
        command_id,
        sandbox_id,
        stream,
        chunk.to_string(),
        Vec::new(),
    )
    .await?;
    Ok(())
}

async fn command_output_for_stream_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
) -> Result<String, ApiError> {
    let column = stream.as_db_str();
    let sql = format!(
        "select {column} as output
         from commands
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(command_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("command not found"))?;
    Ok(row.try_get("output")?)
}

async fn replace_command_output_stream_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    command_id: CommandId,
    stream: &CommandOutputStream,
) -> Result<(), ApiError> {
    let column = stream.as_db_str();
    let delete_sql = format!(
        "delete from command_output_chunks
         where command_id = {} and stream = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&delete_sql)
        .bind(command_id.to_string())
        .bind(command_output_stream_to_str(stream))
        .execute(&mut *connection)
        .await?;

    let update_sql = format!(
        "update commands
         set {column} = ''
         where id = {}",
        db.placeholder(1)
    );
    let result = sqlx::query(&update_sql)
        .bind(command_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("command not found"));
    }
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

async fn apply_claimed_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
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
                .execute(&mut *connection)
                .await?;
            insert_event_on_connection(
                db,
                connection,
                sandbox_id,
                SandboxEventKind::CommandStarted,
                json!({
                    "commandId": command_id
                }),
            )
            .await?;
        }
        JobKind::CreateSnapshot => {
            update_snapshot_status_on_connection(
                db,
                connection,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Pending,
                None,
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
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
            set_sandbox_state_on_connection(
                db,
                connection,
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
    let mut tx = db.pool.begin().await?;
    let applied = apply_retryable_job_on_connection(db, &mut *tx, job, error).await;
    match applied {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back retryable job side effects");
            }
            Err(error)
        }
    }
}

async fn apply_failed_job(db: &Database, job: &Job, error: &str) -> Result<(), ApiError> {
    let mut tx = db.pool.begin().await?;
    let applied = apply_failed_job_on_connection(db, &mut *tx, job, error).await;
    match applied {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back failed job side effects");
            }
            Err(error)
        }
    }
}

async fn apply_retryable_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    error: &str,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            reset_command_for_retry_on_connection(db, connection, command_id).await?;
            insert_event_on_connection(
                db,
                connection,
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
            update_snapshot_status_on_connection(
                db,
                connection,
                snapshot_id_from_job(job)?,
                SnapshotStatus::Pending,
                Some(error),
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
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
            set_sandbox_state_on_connection(
                db,
                connection,
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

async fn apply_failed_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    error: &str,
) -> Result<(), ApiError> {
    match job.kind {
        JobKind::RunCommand => {
            let command_id = command_id_from_job(job)?;
            let sandbox_id = sandbox_id_from_job(job)?;
            append_command_output_chunk_on_connection(
                db,
                connection,
                command_id,
                sandbox_id,
                CommandOutputStream::Stderr,
                error.to_string(),
                Vec::new(),
            )
            .await?;
            finish_command_from_lease_result_on_connection(
                db,
                connection,
                command_id,
                CommandStatus::Failed,
                None,
            )
            .await?;
            insert_event_on_connection(
                db,
                connection,
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
            let snapshot_id = snapshot_id_from_job(job)?;
            update_snapshot_status_on_connection(
                db,
                connection,
                snapshot_id,
                SnapshotStatus::Failed,
                Some(error),
            )
            .await?;
            fail_sandboxes_waiting_on_snapshot_on_connection(
                db,
                connection,
                snapshot_id,
                "snapshot_failed",
                error,
            )
            .await?;
        }
        JobKind::RunPrompt => {
            let sandbox_id = sandbox_id_from_job(job)?;
            let prompt_event_id = prompt_event_id_from_job(job)?;
            insert_event_on_connection(
                db,
                connection,
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
            set_sandbox_state_on_connection(
                db,
                connection,
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
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
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
        let mut child = row_to_sandbox(row)?;
        hydrate_sandbox_network_egress_on_connection(db, connection, &mut child).await?;
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
                    "snapshotId": snapshot_id,
                    "provisionSpec": SandboxProvisionSpec {
                        memory_limit: child.memory_limit.clone(),
                        network_egress: child.network_egress.clone(),
                    }
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

async fn fail_sandboxes_waiting_on_snapshot_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    snapshot_id: SnapshotId,
    reason: &'static str,
    error: &str,
) -> Result<(), ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
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
        let mut child = row_to_sandbox(row)?;
        hydrate_sandbox_network_egress_on_connection(db, connection, &mut child).await?;
        let next_state = SandboxState::Error;
        set_sandbox_state_on_connection(
            db,
            connection,
            child.id,
            next_state.clone(),
            json!({
                "state": next_state,
                "reason": reason,
                "parentSnapshotId": snapshot_id,
                "error": error
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
    let memory_limit: String = row.try_get("memory_limit")?;
    let network_egress_mode: String = row.try_get("network_egress_mode")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let ttl_seconds: Option<i64> = row.try_get("ttl_seconds")?;
    let parent_snapshot_id: Option<String> = row.try_get("parent_snapshot_id")?;
    let network_egress = match parse_network_egress_mode(&network_egress_mode)? {
        NetworkEgressMode::DenyAll => NetworkEgress::DenyAll,
        NetworkEgressMode::Allowlist => NetworkEgress::Allowlist { rules: Vec::new() },
        NetworkEgressMode::AllowAll => NetworkEgress::AllowAll,
    };

    Ok(Sandbox {
        id: SandboxId(parse_uuid(&id)?),
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        state: parse_state(&state)?,
        template: row.try_get("template")?,
        memory_limit: parse_memory_limit(&memory_limit)?,
        network_egress,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        ttl_seconds: ttl_seconds.map(|ttl| ttl as u64),
        parent_snapshot_id: parent_snapshot_id
            .map(|snapshot| parse_uuid(&snapshot).map(SnapshotId))
            .transpose()?,
    })
}

async fn hydrate_sandboxes_network_egress(
    db: &Database,
    sandboxes: &mut [Sandbox],
) -> Result<(), ApiError> {
    for sandbox in sandboxes {
        hydrate_sandbox_network_egress(db, sandbox).await?;
    }
    Ok(())
}

async fn hydrate_sandbox_network_egress(
    db: &Database,
    sandbox: &mut Sandbox,
) -> Result<(), ApiError> {
    if !matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
        return Ok(());
    }
    let rules = list_network_allow_rules(db, sandbox.id).await?;
    sandbox.network_egress = NetworkEgress::Allowlist { rules };
    Ok(())
}

async fn hydrate_sandbox_network_egress_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &mut Sandbox,
) -> Result<(), ApiError> {
    if !matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
        return Ok(());
    }
    let rules = list_network_allow_rules_on_connection(db, connection, sandbox.id).await?;
    sandbox.network_egress = NetworkEgress::Allowlist { rules };
    Ok(())
}

async fn list_network_allow_rules(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<NetworkAllowRule>, ApiError> {
    let sql = format!(
        "select kind, value
         from sandbox_network_egress_rules
         where sandbox_id = {}
         order by kind asc, value asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    rows.into_iter().map(row_to_network_allow_rule).collect()
}

async fn list_network_allow_rules_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Vec<NetworkAllowRule>, ApiError> {
    let sql = format!(
        "select kind, value
         from sandbox_network_egress_rules
         where sandbox_id = {}
         order by kind asc, value asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&mut *connection)
        .await?;
    rows.into_iter().map(row_to_network_allow_rule).collect()
}

fn row_to_network_allow_rule(row: AnyRow) -> Result<NetworkAllowRule, ApiError> {
    let kind: String = row.try_get("kind")?;
    Ok(NetworkAllowRule {
        kind: parse_network_allow_rule_kind(&kind)?,
        value: row.try_get("value")?,
    })
}

fn row_to_sandbox_file(row: AnyRow) -> Result<SandboxFile, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    Ok(SandboxFile {
        id: FileId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        path: row.try_get("path")?,
        size_bytes: u64::try_from(size_bytes)
            .map_err(|_| ApiError::internal("database contains invalid file size"))?,
        mime_type: row.try_get("mime_type")?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
    })
}

fn row_to_stored_sandbox_file(row: AnyRow) -> Result<StoredSandboxFile, ApiError> {
    let content_base64: String = row.try_get("content_base64")?;
    let content = general_purpose::STANDARD
        .decode(content_base64)
        .map_err(|_| ApiError::internal("database contains invalid file content"))?;
    Ok(StoredSandboxFile {
        file: row_to_sandbox_file(row)?,
        content,
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
    let annotations: String = row.try_get("annotations")?;
    let created_at: String = row.try_get("created_at")?;

    Ok(CommandOutputChunk {
        id: CommandOutputChunkId(parse_uuid(&id)?),
        command_id: CommandId(parse_uuid(&command_id)?),
        stream: parse_command_output_stream(&stream)?,
        sequence: u64::try_from(sequence)
            .map_err(|_| ApiError::internal("database contains invalid output sequence"))?,
        chunk: row.try_get("chunk")?,
        annotations: serde_json::from_str(&annotations)
            .map_err(|_| ApiError::internal("database contains invalid output annotations"))?,
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
    state.as_db_str()
}

fn parse_state(value: &str) -> Result<SandboxState, ApiError> {
    parse_db_variant(value, "database contains invalid sandbox state")
}

fn memory_limit_to_str(memory_limit: &MemoryLimit) -> &'static str {
    memory_limit.as_db_str()
}

fn parse_memory_limit(value: &str) -> Result<MemoryLimit, ApiError> {
    parse_db_variant(value, "database contains invalid sandbox memory limit")
}

fn network_egress_mode_to_str(mode: &NetworkEgressMode) -> &'static str {
    mode.as_db_str()
}

fn parse_network_egress_mode(value: &str) -> Result<NetworkEgressMode, ApiError> {
    parse_db_variant(
        value,
        "database contains invalid sandbox network egress mode",
    )
}

fn network_allow_rule_kind_to_str(kind: &NetworkAllowRuleKind) -> &'static str {
    kind.as_db_str()
}

fn parse_network_allow_rule_kind(value: &str) -> Result<NetworkAllowRuleKind, ApiError> {
    parse_db_variant(value, "database contains invalid network allow rule kind")
}

fn snapshot_status_to_str(status: &SnapshotStatus) -> &'static str {
    status.as_db_str()
}

fn desktop_session_status_to_str(status: &DesktopSessionStatus) -> &'static str {
    status.as_db_str()
}

fn desktop_access_mode_to_str(access_mode: &DesktopAccessMode) -> &'static str {
    access_mode.as_db_str()
}

fn runtime_resource_kind_to_str(kind: &RuntimeResourceKind) -> &'static str {
    kind.as_db_str()
}

fn runtime_resource_purpose_to_str(purpose: &RuntimeResourcePurpose) -> &'static str {
    purpose.as_db_str()
}

fn runtime_resource_status_to_str(status: &RuntimeResourceStatus) -> &'static str {
    status.as_db_str()
}

fn cleanup_run_status_to_str(status: &CleanupRunStatus) -> &'static str {
    status.as_db_str()
}

fn command_status_to_str(status: &CommandStatus) -> &'static str {
    status.as_db_str()
}

fn command_output_stream_to_str(stream: &CommandOutputStream) -> &'static str {
    stream.as_db_str()
}

fn worker_status_to_str(status: &WorkerStatus) -> &'static str {
    status.as_db_str()
}

fn worker_capability_to_str(capability: &WorkerCapability) -> &'static str {
    capability.as_db_str()
}

fn job_kind_to_str(kind: &JobKind) -> &'static str {
    kind.as_db_str()
}

fn job_status_to_str(status: &JobStatus) -> &'static str {
    status.as_db_str()
}

fn lease_status_to_str(status: &LeaseStatus) -> &'static str {
    status.as_db_str()
}

fn guest_status_to_str(status: &GuestStatus) -> &'static str {
    status.as_db_str()
}

fn ssh_key_status_to_str(status: &SshKeyStatus) -> &'static str {
    status.as_db_str()
}

fn event_kind_to_str(kind: &SandboxEventKind) -> &'static str {
    kind.as_db_str()
}

fn parse_db_variant<T: DbVariant>(value: &str, message: &'static str) -> Result<T, ApiError> {
    T::parse_db_str(value).map_err(|_| ApiError::internal(message))
}

fn parse_command_status(value: &str) -> Result<CommandStatus, ApiError> {
    parse_db_variant(value, "database contains invalid command status")
}

fn parse_command_output_stream(value: &str) -> Result<CommandOutputStream, ApiError> {
    parse_db_variant(value, "database contains invalid command output stream")
}

fn parse_snapshot_status(value: &str) -> Result<SnapshotStatus, ApiError> {
    parse_db_variant(value, "database contains invalid snapshot status")
}

fn parse_desktop_session_status(value: &str) -> Result<DesktopSessionStatus, ApiError> {
    parse_db_variant(value, "database contains invalid desktop session status")
}

fn parse_desktop_access_mode(value: &str) -> Result<DesktopAccessMode, ApiError> {
    parse_db_variant(value, "database contains invalid desktop access mode")
}

fn parse_runtime_resource_kind(value: &str) -> Result<RuntimeResourceKind, ApiError> {
    parse_db_variant(value, "database contains invalid runtime resource kind")
}

fn parse_runtime_resource_purpose(value: &str) -> Result<RuntimeResourcePurpose, ApiError> {
    parse_db_variant(value, "database contains invalid runtime resource purpose")
}

fn parse_runtime_resource_status(value: &str) -> Result<RuntimeResourceStatus, ApiError> {
    parse_db_variant(value, "database contains invalid runtime resource status")
}

fn parse_worker_capability(value: &str) -> Result<WorkerCapability, ApiError> {
    parse_db_variant(value, "database contains invalid worker capability")
}

fn parse_job_kind(value: &str) -> Result<JobKind, ApiError> {
    parse_db_variant(value, "database contains invalid job kind")
}

fn parse_job_status(value: &str) -> Result<JobStatus, ApiError> {
    parse_db_variant(value, "database contains invalid job status")
}

fn parse_lease_status(value: &str) -> Result<LeaseStatus, ApiError> {
    parse_db_variant(value, "database contains invalid lease status")
}

fn parse_guest_status(value: &str) -> Result<GuestStatus, ApiError> {
    parse_db_variant(value, "database contains invalid guest status")
}

fn parse_ssh_key_status(value: &str) -> Result<SshKeyStatus, ApiError> {
    parse_db_variant(value, "database contains invalid ssh key status")
}

fn parse_worker_status(value: &str) -> Result<WorkerStatus, ApiError> {
    parse_db_variant(value, "database contains invalid worker status")
}

fn parse_event_kind(value: &str) -> Result<SandboxEventKind, ApiError> {
    parse_db_variant(value, "database contains invalid event kind")
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
