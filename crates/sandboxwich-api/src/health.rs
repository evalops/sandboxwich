use crate::auth::*;
use crate::db::*;
use crate::error::*;
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
             order by family asc, label asc",
            p1 = db.placeholder(1),
            p2 = db.placeholder(2),
            p3 = db.placeholder(3),
            p4 = db.placeholder(4),
            p5 = db.placeholder(5),
            p6 = db.placeholder(6),
        ),
    };

    let mut query = sqlx::query(&sql);
    if let Some(tenant_id) = tenant_id {
        for _ in 0..6 {
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
    Ok(PrometheusMetrics { values })
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
