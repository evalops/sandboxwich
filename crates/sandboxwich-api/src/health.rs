use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::rows::parse_timestamp;
use crate::slo_metrics::append_slo_metrics;
use crate::state::*;
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use sandboxwich_core::*;
use sqlx::Row;
use std::collections::BTreeMap;

pub(crate) async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "sandboxwich-api".to_string(),
        checked_at: Utc::now(),
        database: None,
    })
}

pub(crate) async fn readyz(State(state): State<AppState>) -> Response {
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

pub(crate) async fn metrics(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Ordinary tenant credentials only ever see their own tenant's counts: an
    // authenticated tenant token must never be able to read another tenant's
    // sandbox/worker/job/lease volumes. The dedicated operator credential
    // (already used to gate `/snapshots/cleanup`) additionally unlocks the
    // unscoped, cross-tenant view that operator tooling (e.g. a Prometheus
    // scraper) legitimately needs.
    let tenant_scope = if is_operator_request(&state, &headers) {
        None
    } else {
        Some(ctx.tenant_id.as_str())
    };
    let body = collect_prometheus_metrics(&state.db, tenant_scope).await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

pub(crate) async fn check_database_health(db: &Database) -> Result<HealthComponent, ApiError> {
    sqlx::query("select 1").execute(&db.pool).await?;
    Ok(HealthComponent {
        ok: true,
        message: None,
    })
}

pub(crate) async fn collect_prometheus_metrics(
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<String, ApiError> {
    let metrics = fetch_prometheus_metrics(db, tenant_id).await?;
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
    append_gauge(
        &mut body,
        "sandboxwich_worker_available_slots",
        "Online worker concurrency slots not currently leased.",
        metrics.scalar("worker_available_slots").max(0),
    );
    append_count_family(
        &mut body,
        "sandboxwich_job_lease_count",
        "Job leases by lifecycle status.",
        "status",
        metrics.counts("job_lease"),
    );
    append_gauge(
        &mut body,
        "sandboxwich_job_attempts",
        "Total scheduler attempts retained for jobs.",
        metrics.scalar("job_attempts"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_idempotency_record_count",
        "Idempotency records by state.",
        "state",
        metrics.counts("idempotency_record"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_guest_token_count",
        "Sandbox-bound guest credentials by revocation state.",
        "state",
        metrics.counts("guest_token"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_cleanup_run_count",
        "Operator cleanup runs by status.",
        "status",
        metrics.counts("cleanup_run"),
    );
    append_count_family(
        &mut body,
        "sandboxwich_resident_process_count",
        "Resident processes by observed state.",
        "state",
        metrics.counts("resident_process"),
    );
    append_counter_family(
        &mut body,
        "sandboxwich_sidecar_bootstrap_block_total",
        "Fail-closed orb-executor bootstrap denials by bounded sidecar readiness reason.",
        "reason",
        metrics.counts("sidecar_bootstrap_block"),
    );
    append_gauge(
        &mut body,
        "sandboxwich_job_queue_oldest_seconds",
        "Age in seconds of the oldest queued job.",
        metrics.scalar("job_queue_oldest_seconds"),
    );
    append_gauge(
        &mut body,
        "sandboxwich_worker_heartbeat_oldest_seconds",
        "Age in seconds of the stalest online worker heartbeat.",
        metrics.scalar("worker_heartbeat_oldest_seconds"),
    );
    append_slo_metrics(&mut body, db, tenant_id).await?;
    Ok(body)
}

pub(crate) struct PrometheusMetrics {
    pub(crate) values: BTreeMap<String, Vec<(String, i64)>>,
}

impl PrometheusMetrics {
    pub(crate) fn counts(&self, family: &'static str) -> Vec<(String, i64)> {
        self.values.get(family).cloned().unwrap_or_default()
    }

    pub(crate) fn scalar(&self, family: &'static str) -> i64 {
        self.values
            .get(family)
            .and_then(|values| values.first())
            .map(|(_, value)| *value)
            .unwrap_or_default()
    }
}

/// Fetch aggregate counts for the Prometheus exposition.
///
/// `tenant_id: None` returns global, cross-tenant totals and must only ever be reached via the
/// operator credential (see [`metrics`]); `Some(tenant_id)` scopes every aggregate to that
/// tenant's own resources so an ordinary tenant bearer token can never observe another tenant's
/// sandbox/worker/job/lease volumes.
pub(crate) async fn fetch_prometheus_metrics(
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<PrometheusMetrics, ApiError> {
    let sql = match tenant_id {
        None => "select 'sandbox' as family, state as label, count(*) as value
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
             union all
             select 'worker_available_slots' as family, '' as label,
                    coalesce((select sum(max_concurrent_jobs) from workers where status = 'online'), 0)
                      - (select count(*) from job_leases where status = 'active') as value
             union all
             select 'job_lease' as family, status as label, count(*) as value
             from job_leases group by status
             union all
             select 'job_attempts' as family, '' as label, coalesce(sum(attempts), 0) as value
             from jobs
             union all
             select 'idempotency_record' as family, state as label, count(*) as value
             from idempotency_records group by state
             union all
             select 'guest_token' as family,
                    case when revoked_at is null then 'issued' else 'revoked' end as label,
                    count(*) as value
             from guest_tokens group by case when revoked_at is null then 'issued' else 'revoked' end
             union all
             select 'cleanup_run' as family, status as label, count(*) as value
             from cleanup_runs group by status
             order by family asc, label asc"
            .to_string(),
        Some(_) => format!(
            "select 'sandbox' as family, state as label, count(*) as value
             from sandboxes
             where tenant_id = {p1}
             group by state
             union all
             select 'worker' as family, status as label, count(*) as value
             from workers
             where tenant_id = {p2}
             group by status
             union all
             select 'job' as family, status as label, count(*) as value
             from jobs
             where tenant_id = {p3}
             group by status
             union all
             select 'runtime_resource' as family, runtime_resources.status as label, count(*) as value
             from runtime_resources
             join sandboxes on sandboxes.id = runtime_resources.sandbox_id
             where sandboxes.tenant_id = {p4}
             group by runtime_resources.status
             union all
             select 'job_leases_active' as family, '' as label, count(*) as value
             from job_leases
             join jobs on jobs.id = job_leases.job_id
             where job_leases.status = 'active' and jobs.tenant_id = {p5}
             union all
             select 'worker_capacity_slots' as family, '' as label, coalesce(sum(max_concurrent_jobs), 0) as value
             from workers
             where status = 'online' and tenant_id = {p6}
             union all
             select 'worker_available_slots' as family, '' as label,
                    coalesce((select sum(max_concurrent_jobs) from workers where status = 'online' and tenant_id = {p11}), 0)
                      - (select count(*) from job_leases join jobs on jobs.id = job_leases.job_id
                         where job_leases.status = 'active' and jobs.tenant_id = {p12}) as value
             union all
             select 'job_lease' as family, job_leases.status as label, count(*) as value
             from job_leases join jobs on jobs.id = job_leases.job_id
             where jobs.tenant_id = {p7} group by job_leases.status
             union all
             select 'job_attempts' as family, '' as label, coalesce(sum(attempts), 0) as value
             from jobs where tenant_id = {p8}
             union all
             select 'idempotency_record' as family, state as label, count(*) as value
             from idempotency_records where tenant_id = {p9} group by state
             union all
             select 'guest_token' as family,
                    case when revoked_at is null then 'issued' else 'revoked' end as label,
                    count(*) as value
             from guest_tokens where tenant_id = {p10}
             group by case when revoked_at is null then 'issued' else 'revoked' end
             order by family asc, label asc",
            p1 = db.placeholder(1),
            p2 = db.placeholder(2),
            p3 = db.placeholder(3),
            p4 = db.placeholder(4),
            p5 = db.placeholder(5),
            p6 = db.placeholder(6),
            p7 = db.placeholder(7),
            p8 = db.placeholder(8),
            p9 = db.placeholder(9),
            p10 = db.placeholder(10),
            p11 = db.placeholder(11),
            p12 = db.placeholder(12),
        ),
    };

    let mut query = sqlx::query(&sql);
    if let Some(tenant_id) = tenant_id {
        for _ in 0..12 {
            query = query.bind(tenant_id.to_string());
        }
    }
    let rows = query.fetch_all(&db.pool).await?;

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
    fetch_resident_observability_metrics(db, tenant_id, &mut values).await?;
    let queued_sql = match tenant_id {
        None => {
            "select min(scheduled_at) as observed_at from jobs where status = 'queued'".to_string()
        }
        Some(_) => format!(
            "select min(scheduled_at) as observed_at from jobs where status = 'queued' and tenant_id = {}",
            db.placeholder(1)
        ),
    };
    let heartbeat_sql = match tenant_id {
        None => "select min(last_heartbeat_at) as observed_at from workers where status = 'online'"
            .to_string(),
        Some(_) => format!(
            "select min(last_heartbeat_at) as observed_at from workers where status = 'online' and tenant_id = {}",
            db.placeholder(1)
        ),
    };
    for (family, sql) in [
        ("job_queue_oldest_seconds", queued_sql),
        ("worker_heartbeat_oldest_seconds", heartbeat_sql),
    ] {
        let mut query = sqlx::query(&sql);
        if let Some(tenant_id) = tenant_id {
            query = query.bind(tenant_id);
        }
        let row = query.fetch_one(&db.pool).await?;
        let observed_at: Option<String> = row.try_get("observed_at")?;
        let age = observed_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?
            .map(|observed_at| (Utc::now() - observed_at).num_seconds().max(0))
            .unwrap_or_default();
        values.insert(family.to_string(), vec![(String::new(), age)]);
    }
    Ok(PrometheusMetrics { values })
}

async fn fetch_resident_observability_metrics(
    db: &Database,
    tenant_id: Option<&str>,
    values: &mut BTreeMap<String, Vec<(String, i64)>>,
) -> Result<(), ApiError> {
    let resident_sql = match tenant_id {
        None => "select observed_state as label, count(*) as value
                 from resident_processes group by observed_state"
            .to_string(),
        Some(_) => format!(
            "select observed_state as label, count(*) as value
             from resident_processes where tenant_id = {} group by observed_state",
            db.placeholder(1)
        ),
    };
    let mut resident_query = sqlx::query(&resident_sql);
    if let Some(tenant_id) = tenant_id {
        resident_query = resident_query.bind(tenant_id);
    }
    let mut resident_counts = Vec::new();
    for row in resident_query.fetch_all(&db.pool).await? {
        let state: String = row.try_get("label")?;
        // Keep the label domain bounded even if a database constraint is
        // bypassed during an operator repair.
        if ResidentProcessObservedState::parse_db_str(&state).is_ok() {
            resident_counts.push((state, row.try_get("value")?));
        }
    }
    values.insert("resident_process".into(), resident_counts);

    let event_sql = match tenant_id {
        None => "select sandbox_events.data from sandbox_events
                 where sandbox_events.kind = 'sidecar_bootstrap_blocked'"
            .to_string(),
        Some(_) => format!(
            "select sandbox_events.data from sandbox_events
             join sandboxes on sandboxes.id = sandbox_events.sandbox_id
             where sandbox_events.kind = 'sidecar_bootstrap_blocked'
               and sandboxes.tenant_id = {}",
            db.placeholder(1)
        ),
    };
    let mut event_query = sqlx::query(&event_sql);
    if let Some(tenant_id) = tenant_id {
        event_query = event_query.bind(tenant_id);
    }
    let mut block_counts = BTreeMap::<String, i64>::new();
    for row in event_query.fetch_all(&db.pool).await? {
        let data: String = row.try_get("data")?;
        let reason = serde_json::from_str::<serde_json::Value>(&data)
            .ok()
            .and_then(|data| data.get("reason")?.as_str().map(str::to_owned));
        if let Some(
            reason @ ("not_running" | "no_active_lease" | "inactive_lease" | "expired_lease"),
        ) = reason.as_deref()
        {
            *block_counts.entry(reason.to_string()).or_default() += 1;
        }
    }
    values.insert(
        "sidecar_bootstrap_block".into(),
        block_counts.into_iter().collect(),
    );
    Ok(())
}

pub(crate) fn append_count_family(
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

pub(crate) fn append_counter_family(
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
    body.push_str(" counter\n");
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

pub(crate) fn append_gauge(body: &mut String, name: &'static str, help: &'static str, value: i64) {
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

pub(crate) fn escape_prometheus_label(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}
