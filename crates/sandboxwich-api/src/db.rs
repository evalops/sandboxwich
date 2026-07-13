use crate::rows::*;
use anyhow::Context;
use chrono::Utc;
use sandboxwich_core::*;
use sqlx::Row;
use sqlx::any::{AnyArguments, AnyPoolOptions, AnyRow};
use sqlx::encode::Encode;
use sqlx::migrate::MigrateDatabase;
use sqlx::types::Type;
use sqlx::{Any, AnyPool, Arguments, Sqlite};
use std::fmt::{Display, Write as _};
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct Database {
    pub(crate) pool: AnyPool,
    pub(crate) dialect: SqlDialect,
}

#[derive(Clone, Copy)]
pub(crate) enum SqlDialect {
    Postgres,
    Sqlite,
}

pub(crate) async fn migrate_database(db: &Database) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(&db.pool).await?;
    ensure_database_constraints(db).await?;
    Ok(())
}

pub(crate) async fn verify_database_schema(db: &Database) -> anyhow::Result<()> {
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

pub(crate) async fn connect_database(
    database_url: &str,
    max_connections: u32,
) -> anyhow::Result<Database> {
    sqlx::any::install_default_drivers();
    let dialect = SqlDialect::from_url(database_url)?;
    if matches!(dialect, SqlDialect::Sqlite)
        && !Sqlite::database_exists(database_url).await.unwrap_or(false)
    {
        Sqlite::create_database(database_url).await?;
    }

    let pool_max_connections = match dialect {
        SqlDialect::Sqlite => 1,
        SqlDialect::Postgres => max_connections,
    };
    let mut pool_options = AnyPoolOptions::new()
        .max_connections(pool_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Some(Duration::from_secs(5 * 60)));

    if matches!(dialect, SqlDialect::Sqlite) {
        // SQLite allows exactly one writer at a time. The API's request handlers
        // and expiry sweeps issue frequent short write transactions, so without a
        // busy timeout and WAL mode, concurrent writers surface as SQLITE_BUSY
        // errors instead of waiting briefly for the writer ahead of them.
        pool_options = pool_options.after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("PRAGMA busy_timeout = 5000;")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("PRAGMA journal_mode = WAL;")
                    .execute(&mut *conn)
                    .await?;
                // SQLite itself defaults `foreign_keys` to OFF for backward
                // compatibility, and `sqlx`'s `SqliteConnectOptions` default
                // (which the `Any` driver used here goes through) currently
                // overrides that back to ON per connection -- so every
                // `ON DELETE CASCADE` in the migrations already works on
                // SQLite as of this sqlx version, verified by
                // `cleanup::archived_sandbox_cleanup_cascades_dependent_rows_on_sqlite`.
                // Set it explicitly anyway: relying on an upstream default we
                // don't control for a correctness property this load-bearing
                // (archived-sandbox cleanup silently orphaning
                // commands/events/snapshots/sandbox_files rows if it were
                // ever OFF) is fragile, and this pragma is idempotent and
                // free if the default ever changes out from under us.
                sqlx::query("PRAGMA foreign_keys = ON;")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        });
    }

    let pool = pool_options.connect(database_url).await?;
    Ok(Database { pool, dialect })
}

pub(crate) async fn ensure_database_constraints(db: &Database) -> anyhow::Result<()> {
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

pub(crate) const DB_ENUM_SCHEMA_METADATA_KEY: &str = "db_enum_constraints_fingerprint";
// v5 adds the sandboxes.parent_snapshot_id -> snapshot_restore_sources(snapshot_id)
// foreign key. Bumping the version forces existing installations to install
// the new guards on upgrade.
pub(crate) const DB_ENUM_SCHEMA_FINGERPRINT_VERSION: &str = "db-enum-v5";
pub(crate) const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
pub(crate) const FNV_PRIME: u64 = 0x00000100000001b3;

pub(crate) fn db_enum_schema_fingerprint() -> String {
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
    feed_hash(
        &mut hash,
        "sandboxes.parent_snapshot_id:fk_snapshot_restore_sources_restrict",
    );
    for (from, to) in sandbox_legal_transition_pairs() {
        feed_hash(&mut hash, "sandboxes.state:transition");
        feed_hash(&mut hash, from);
        feed_hash(&mut hash, to);
    }
    format!("{DB_ENUM_SCHEMA_FINGERPRINT_VERSION}:{hash:016x}")
}

pub(crate) fn feed_hash(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
    *hash ^= 0xff;
    *hash = hash.wrapping_mul(FNV_PRIME);
}

pub(crate) async fn fetch_schema_metadata(
    db: &Database,
    key: &str,
) -> anyhow::Result<Option<String>> {
    let sql = format!(
        "select value from schema_metadata where key = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql).bind(key).fetch_optional(&db.pool).await?;
    row.map(|row| row.try_get("value"))
        .transpose()
        .map_err(Into::into)
}

pub(crate) async fn write_schema_metadata(
    db: &Database,
    key: &str,
    value: &str,
) -> anyhow::Result<()> {
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
pub(crate) struct DbEnumColumn {
    pub(crate) table: &'static str,
    pub(crate) column: &'static str,
    pub(crate) constraint_name: &'static str,
    pub(crate) values: &'static [&'static str],
    pub(crate) error_message: &'static str,
}

pub(crate) const DB_ENUM_COLUMNS: &[DbEnumColumn] = &[
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
        "sandboxes",
        "workspace_mode",
        "sandboxes_workspace_mode_check",
        <WorkspaceMode as DbVariant>::VALUES,
        "invalid sandbox workspace mode",
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
    DbEnumColumn::new(
        "provisioning_operations",
        "stage",
        "provisioning_operations_stage_check",
        <ProvisioningStage as DbVariant>::VALUES,
        "invalid provisioning stage",
    ),
    DbEnumColumn::new(
        "provisioning_operations",
        "resource_kind",
        "provisioning_operations_resource_kind_check",
        <RuntimeResourceKind as DbVariant>::VALUES,
        "invalid provisioning resource kind",
    ),
    DbEnumColumn::new(
        "provisioning_operations",
        "last_error_class",
        "provisioning_operations_error_class_check",
        <ProvisioningErrorClass as DbVariant>::VALUES,
        "invalid provisioning error class",
    ),
    DbEnumColumn::new(
        "provisioning_operation_resources",
        "stage",
        "provisioning_operation_resources_stage_check",
        <ProvisioningStage as DbVariant>::VALUES,
        "invalid provisioning resource stage",
    ),
    DbEnumColumn::new(
        "provisioning_operation_resources",
        "resource_kind",
        "provisioning_operation_resources_kind_check",
        <RuntimeResourceKind as DbVariant>::VALUES,
        "invalid provisioning resource kind",
    ),
    DbEnumColumn::new(
        "provisioning_stage_observations",
        "stage",
        "provisioning_stage_observations_stage_check",
        <ProvisioningStage as DbVariant>::VALUES,
        "invalid provisioning observation stage",
    ),
    DbEnumColumn::new(
        "provisioning_stage_observations",
        "error_class",
        "provisioning_stage_observations_error_class_check",
        <ProvisioningErrorClass as DbVariant>::VALUES,
        "invalid provisioning observation error class",
    ),
];

pub(crate) fn db_enum_columns() -> &'static [DbEnumColumn] {
    DB_ENUM_COLUMNS
}

impl DbEnumColumn {
    pub(crate) const fn new(
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

pub(crate) async fn ensure_postgres_constraints(db: &Database) -> anyhow::Result<()> {
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

    for statement in postgres_sandbox_transition_guard_statements() {
        sqlx::query(&statement).execute(&db.pool).await?;
    }

    for statement in postgres_sandbox_parent_snapshot_fk_statements() {
        sqlx::query(statement).execute(&db.pool).await?;
    }

    Ok(())
}

/// Foreign key enforcing that `sandboxes.parent_snapshot_id` (set when a
/// sandbox is forked from a snapshot; see `fork_sandbox` / `fork_snapshot`)
/// always points at a snapshot id that genuinely existed.
///
/// Targets `snapshot_restore_sources(snapshot_id)`, **not** `snapshots(id)`.
/// That looks backwards at first -- `parent_snapshot_id` conceptually points
/// at a `snapshots` row -- but `snapshots` rows are not durable: they
/// cascade-delete along with their owning sandbox
/// (`snapshots.sandbox_id references sandboxes(id) on delete cascade`), and
/// this codebase deliberately allows that even while some *other* sandbox's
/// `parent_snapshot_id` still names that snapshot id. That's the entire
/// point of `snapshot_restore_sources` (see
/// `20260710000200_snapshot_tenant_ownership.sql`'s doc comment): every
/// snapshot insert writes a matching, permanent
/// `snapshot_restore_sources(snapshot_id)` row in the same transaction
/// (`insert_snapshot_on_connection`), and nothing in this codebase ever
/// deletes one -- so `POST /v1/snapshots/{id}/fork`
/// (`claim_snapshot_restore_source_on_connection`) can still restore from a
/// snapshot id whose source sandbox, and therefore whose `snapshots` row,
/// has already been cleaned up. A hard FK to `snapshots(id)` would reject
/// exactly that insert (proven by
/// `platform_provider_lifecycle_contract_is_tenant_bound_idempotent_and_correlated`,
/// which forks from a snapshot after deleting its source sandbox and
/// expects `202 Accepted`, not a constraint violation).
/// `snapshot_restore_sources(snapshot_id)` is the row that's actually
/// guaranteed to still be there.
///
/// `ON DELETE RESTRICT`: nothing in this codebase ever deletes a
/// `snapshot_restore_sources` row, so this is a pure backstop -- if some
/// future code path ever tried to, while a sandbox's `parent_snapshot_id`
/// still named it, this turns that into a loud constraint violation instead
/// of a silently accepted `NULL`, matching how the enum/transition
/// constraints above are backstops for invariants the application is
/// already supposed to enforce, not a replacement for them.
///
/// `NOT VALID` + a separate `VALIDATE CONSTRAINT` rather than a plain `ADD
/// CONSTRAINT`: the preceding migration
/// (`20260713000400_sandbox_parent_snapshot_fk.sql`) already nulls out any
/// pre-existing orphaned values, so validation here is expected to be a
/// formality, but `NOT VALID` still avoids holding the constraint's
/// `ACCESS EXCLUSIVE` lock for the length of a full-table scan on Postgres.
pub(crate) fn postgres_sandbox_parent_snapshot_fk_statements() -> [&'static str; 3] {
    [
        "alter table sandboxes drop constraint if exists sandboxes_parent_snapshot_id_fkey",
        "alter table sandboxes add constraint sandboxes_parent_snapshot_id_fkey \
         foreign key (parent_snapshot_id) references snapshot_restore_sources(snapshot_id) \
         on delete restrict not valid",
        "alter table sandboxes validate constraint sandboxes_parent_snapshot_id_fkey",
    ]
}

pub(crate) fn postgres_enum_constraint_statements(column: DbEnumColumn) -> [String; 2] {
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

pub(crate) async fn ensure_sqlite_constraints(db: &Database) -> anyhow::Result<()> {
    sqlite_rebuild_sandboxes_with_parent_snapshot_fk(db).await?;

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

    for statement in sqlite_sandbox_transition_guard_statements() {
        sqlx::query(&statement).execute(&db.pool).await?;
    }

    Ok(())
}

/// SQLite equivalent of [`postgres_sandbox_parent_snapshot_fk_statements`]
/// (see its doc comment for why the FK target is
/// `snapshot_restore_sources(snapshot_id)`, not `snapshots(id)`).
/// SQLite's `ALTER TABLE` cannot add a foreign key to an existing column, so
/// this performs the table-rebuild procedure the SQLite docs recommend for
/// exactly this case (<https://www.sqlite.org/lang_altertable.html#otheralter>):
/// disable foreign key enforcement, create a replacement table with the
/// constraint baked in, copy every row across, drop the original, rename the
/// replacement back to `sandboxes`, and recreate its indexes. Every other
/// table's `references sandboxes(id)` clause is untouched and keeps
/// resolving correctly after the rename, because SQLite looks up foreign key
/// parents by table *name* at enforcement time rather than binding to some
/// internal table identity created with the original `CREATE TABLE`.
///
/// Checks for the constraint first and returns early if it is already
/// present, so this is safe to call more than once even though
/// `ensure_sqlite_constraints` (the only real caller) is already gated by the
/// enum-schema fingerprint and normally only runs this once per upgrade.
pub(crate) async fn sqlite_rebuild_sandboxes_with_parent_snapshot_fk(
    db: &Database,
) -> anyhow::Result<()> {
    let existing_fks = sqlx::query("pragma foreign_key_list(sandboxes)")
        .fetch_all(&db.pool)
        .await?;
    let already_has_fk = existing_fks.iter().any(|row| {
        row.try_get::<String, _>("table").ok().as_deref() == Some("snapshot_restore_sources")
            && row.try_get::<String, _>("from").ok().as_deref() == Some("parent_snapshot_id")
    });
    if already_has_fk {
        return Ok(());
    }

    for statement in [
        "PRAGMA foreign_keys = OFF",
        "drop table if exists sandboxes_new",
        "create table sandboxes_new (
            id text primary key not null,
            name text not null,
            state text not null,
            template text not null,
            created_at text not null,
            updated_at text not null,
            ttl_seconds integer,
            parent_snapshot_id text references snapshot_restore_sources(snapshot_id) on delete restrict,
            tenant_id text not null default 'default',
            memory_limit text not null default '1g',
            network_egress_mode text not null default 'deny_all',
            workspace_mode text not null default 'persistent'
                check (workspace_mode in ('ephemeral', 'generic_ephemeral', 'persistent'))
        )",
        "insert into sandboxes_new
            (id, name, state, template, created_at, updated_at, ttl_seconds,
             parent_snapshot_id, tenant_id, memory_limit, network_egress_mode, workspace_mode)
         select id, name, state, template, created_at, updated_at, ttl_seconds,
                parent_snapshot_id, tenant_id, memory_limit, network_egress_mode, workspace_mode
         from sandboxes",
        "drop table sandboxes",
        "alter table sandboxes_new rename to sandboxes",
        "create index if not exists idx_sandboxes_state on sandboxes(state)",
        "create index if not exists idx_sandboxes_created_at on sandboxes(created_at)",
        "create index if not exists idx_sandboxes_tenant_state on sandboxes(tenant_id, state)",
        "create index if not exists idx_sandboxes_workspace_mode on sandboxes(workspace_mode)",
        "create index if not exists idx_sandboxes_parent_snapshot_id on sandboxes(parent_snapshot_id)",
        "PRAGMA foreign_keys = ON",
    ] {
        sqlx::query(statement).execute(&db.pool).await?;
    }

    let violations = sqlx::query("pragma foreign_key_check(sandboxes)")
        .fetch_all(&db.pool)
        .await?;
    if !violations.is_empty() {
        anyhow::bail!(
            "sandboxes table rebuild left {} foreign key violation(s) on parent_snapshot_id; \
             the preceding orphan-cleanup migration should have prevented this",
            violations.len()
        );
    }

    Ok(())
}

pub(crate) fn sqlite_enum_trigger_statements(column: DbEnumColumn) -> Vec<String> {
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

pub(crate) fn sql_literal_list(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| sql_literal(value))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Every legal `(from, to)` sandbox state transition per
/// [`SandboxState::can_transition_to`], as raw DB string pairs. This is the
/// database-level backstop for the sandbox lifecycle state machine: even if
/// application code somehow bypasses the compare-and-swap helpers in
/// `set_sandbox_state`/`set_sandbox_state_on_connection` (a bug, a manual
/// SQL statement, a future code path), this coarse union of every action's
/// legal edges still rejects nonsensical writes (e.g. `archived -> planning`)
/// at the database itself. It is coarser than the application-level checks
/// -- e.g. it allows `planning -> ready` (legal for `ProvisionSandbox`
/// completion) even though a `resume` call is additionally restricted to
/// `archived -> ready` only in Rust -- so it is a backstop, not a substitute,
/// for the CAS-based enforcement.
pub(crate) fn sandbox_legal_transition_pairs() -> Vec<(&'static str, &'static str)> {
    let mut pairs = Vec::new();
    for from in SandboxState::ALL {
        for to in SandboxState::ALL {
            if from.can_transition_to(&to) {
                pairs.push((state_to_str(&from), state_to_str(&to)));
            }
        }
    }
    pairs
}

pub(crate) fn sql_tuple_list(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(a, b)| format!("({}, {})", sql_literal(a), sql_literal(b)))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn sqlite_sandbox_transition_guard_statements() -> Vec<String> {
    let tuple_list = sql_tuple_list(&sandbox_legal_transition_pairs());
    vec![
        "drop trigger if exists validate_sandboxes_state_transition_update".to_string(),
        format!(
            "create trigger validate_sandboxes_state_transition_update
             before update of state on sandboxes
             for each row
             when (old.state, new.state) not in ({tuple_list})
             begin
                 select raise(abort, 'illegal sandbox state transition');
             end;"
        ),
    ]
}

/// Postgres equivalent of [`sqlite_sandbox_transition_guard_statements`].
/// Postgres `check` constraints cannot reference the pre-update row, so this
/// uses a `plpgsql` trigger function instead of a `check` constraint (unlike
/// the plain enum-value guards in [`postgres_enum_constraint_statements`]).
pub(crate) fn postgres_sandbox_transition_guard_statements() -> Vec<String> {
    let tuple_list = sql_tuple_list(&sandbox_legal_transition_pairs());
    vec![
        format!(
            "create or replace function sandboxwich_validate_sandbox_state_transition()
             returns trigger as $$
             begin
                 if (old.state, new.state) not in ({tuple_list}) then
                     raise exception 'illegal sandbox state transition from % to %', old.state, new.state;
                 end if;
                 return new;
             end;
             $$ language plpgsql"
        ),
        "drop trigger if exists validate_sandboxes_state_transition on sandboxes".to_string(),
        "create trigger validate_sandboxes_state_transition
         before update of state on sandboxes
         for each row
         execute function sandboxwich_validate_sandbox_state_transition()"
            .to_string(),
    ]
}

impl SqlDialect {
    pub(crate) fn from_url(database_url: &str) -> anyhow::Result<Self> {
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
    /// Starts a database-portable query whose values are bound as SQL is assembled.
    ///
    /// Unlike `sqlx::QueryBuilder<Any>`, this formats dialect-correct placeholders
    /// (`$n` for Postgres, `?` for SQLite). `QueryBuilder<Any>` always emits `?`,
    /// which Postgres rejects at execution time.
    pub(crate) fn query_builder<'args>(
        &self,
        sql: impl Into<String>,
    ) -> PortableQueryBuilder<'args> {
        PortableQueryBuilder {
            sql: sql.into(),
            arguments: AnyArguments::default(),
            dialect: self.dialect,
            next_placeholder: 1,
        }
    }

    pub(crate) fn placeholder(&self, index: usize) -> String {
        match self.dialect {
            SqlDialect::Postgres => format!("${index}"),
            SqlDialect::Sqlite => "?".to_string(),
        }
    }

    pub(crate) fn placeholders(&self, count: usize) -> String {
        (1..=count)
            .map(|index| self.placeholder(index))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Runtime query builder that keeps dynamic bind lists aligned with dialect
/// placeholder numbering for both Postgres and SQLite via `sqlx::Any`.
pub(crate) struct PortableQueryBuilder<'args> {
    sql: String,
    arguments: AnyArguments<'args>,
    dialect: SqlDialect,
    next_placeholder: usize,
}

impl<'args> PortableQueryBuilder<'args> {
    pub(crate) fn push(&mut self, sql: impl Display) -> &mut Self {
        write!(self.sql, "{sql}").expect("query SQL write");
        self
    }

    pub(crate) fn push_bind<T>(&mut self, value: T) -> &mut Self
    where
        T: 'args + Encode<'args, Any> + Type<Any>,
    {
        match self.dialect {
            SqlDialect::Postgres => {
                write!(self.sql, "${}", self.next_placeholder).expect("placeholder write");
            }
            SqlDialect::Sqlite => {
                self.sql.push('?');
            }
        }
        self.next_placeholder += 1;
        self.arguments
            .add(value)
            .expect("portable query bind encode");
        self
    }

    pub(crate) fn separated(&mut self, separator: &'static str) -> PortableSeparated<'_, 'args> {
        PortableSeparated {
            builder: self,
            separator,
            push_separator: false,
        }
    }

    pub(crate) fn build(self) -> PortableQuery<'args> {
        PortableQuery {
            sql: self.sql,
            arguments: self.arguments,
        }
    }

    #[cfg(test)]
    pub(crate) fn sql(&self) -> &str {
        &self.sql
    }
}

pub(crate) struct PortableSeparated<'qb, 'args> {
    builder: &'qb mut PortableQueryBuilder<'args>,
    separator: &'static str,
    push_separator: bool,
}

impl<'qb, 'args> PortableSeparated<'qb, 'args> {
    pub(crate) fn push_bind<T>(&mut self, value: T) -> &mut Self
    where
        T: 'args + Encode<'args, Any> + Type<Any>,
    {
        if self.push_separator {
            self.builder.push(self.separator);
        } else {
            self.push_separator = true;
        }
        self.builder.push_bind(value);
        self
    }
}

pub(crate) struct PortableQuery<'args> {
    sql: String,
    arguments: AnyArguments<'args>,
}

impl<'args> PortableQuery<'args> {
    pub(crate) async fn fetch_all<'c, E>(self, executor: E) -> Result<Vec<AnyRow>, sqlx::Error>
    where
        E: sqlx::Executor<'c, Database = Any>,
    {
        let PortableQuery { sql, arguments } = self;
        sqlx::query_with(&sql, arguments).fetch_all(executor).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    fn builder(dialect: SqlDialect, sql: &str) -> PortableQueryBuilder<'static> {
        PortableQueryBuilder {
            sql: sql.to_string(),
            arguments: AnyArguments::default(),
            dialect,
            next_placeholder: 1,
        }
    }

    #[tokio::test]
    async fn sqlite_pool_serializes_connections() {
        let data_dir = tempfile::tempdir().unwrap();
        let database_url = format!(
            "sqlite://{}",
            data_dir.path().join("serialized-pool.db").display()
        );
        let db = connect_database(&database_url, 5).await.unwrap();
        let _connection = db.pool.acquire().await.unwrap();

        assert!(
            timeout(Duration::from_millis(50), db.pool.acquire())
                .await
                .is_err(),
            "SQLite must expose only one pooled connection so deferred read transactions cannot race writer transactions"
        );
    }

    #[test]
    fn portable_query_builder_uses_postgres_placeholders() {
        let mut query = builder(SqlDialect::Postgres, "select 1 where a = ");
        query.push_bind("one").push(" and b in (");
        {
            let mut values = query.separated(", ");
            values.push_bind("two").push_bind("three");
        }
        query.push(")");
        assert_eq!(query.sql(), "select 1 where a = $1 and b in ($2, $3)");
    }

    #[test]
    fn portable_query_builder_uses_sqlite_placeholders() {
        let mut query = builder(SqlDialect::Sqlite, "select 1 where a = ");
        query.push_bind("one").push(" and b = ").push_bind("two");
        assert_eq!(query.sql(), "select 1 where a = ? and b = ?");
    }
}
