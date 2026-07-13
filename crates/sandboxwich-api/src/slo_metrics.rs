use crate::db::Database;
use crate::error::ApiError;
use crate::health::escape_prometheus_label;
use crate::rows::parse_timestamp;
use chrono::{DateTime, Utc};
use sqlx::Row;
use std::collections::BTreeMap;

const LATENCY_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 900.0];
#[derive(Clone)]
struct Observation {
    labels: Vec<String>,
    seconds: f64,
}

pub(crate) async fn append_slo_metrics(
    body: &mut String,
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<(), ApiError> {
    let creation = fetch_creation_observations(db, tenant_id).await?;
    append_histogram(
        body,
        "sandboxwich_sandbox_creation_seconds",
        "Sandbox creation latency from scheduling to terminal provisioning outcome.",
        &["workspace_mode", "start_type", "outcome"],
        &creation,
    );
    append_counter_from_observations(
        body,
        "sandboxwich_sandbox_creation_total",
        "Terminal sandbox creation outcomes.",
        &["workspace_mode", "start_type", "outcome"],
        &creation,
    );
    append_histogram(
        body,
        "sandboxwich_command_duration_seconds",
        "Terminal command latency.",
        &["outcome"],
        &fetch_simple_terminal_observations(db, tenant_id, "command").await?,
    );
    append_histogram(
        body,
        "sandboxwich_cleanup_duration_seconds",
        "Sandbox cleanup job latency.",
        &["outcome"],
        &fetch_simple_terminal_observations(db, tenant_id, "cleanup").await?,
    );
    append_histogram(
        body,
        "sandboxwich_worker_claim_seconds",
        "Delay from job scheduling to the first worker lease.",
        &["job_kind"],
        &fetch_claim_observations(db, tenant_id).await?,
    );
    append_histogram(
        body,
        "sandboxwich_provisioning_stage_seconds",
        "Elapsed time between durable provisioning stages.",
        &["stage", "workspace_mode", "error_class"],
        &fetch_stage_observations(db, tenant_id).await?,
    );
    Ok(())
}

async fn fetch_creation_observations(
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<Vec<Observation>, ApiError> {
    let tenant_filter = tenant_id
        .map(|_| format!(" and tenant_id = {}", db.placeholder(1)))
        .unwrap_or_default();
    let sql = format!(
        "select outcome, workspace_mode, start_type, duration_ms
         from terminal_slo_observations
         where metric_kind = 'sandbox_creation'{tenant_filter}"
    );
    let rows = fetch_rows(db, &sql, tenant_id).await?;
    rows.into_iter()
        .map(|row| {
            let duration_ms: i64 = row.try_get("duration_ms")?;
            Ok(Observation {
                labels: vec![
                    row.try_get("workspace_mode")?,
                    row.try_get("start_type")?,
                    row.try_get("outcome")?,
                ],
                seconds: duration_ms.max(0) as f64 / 1000.0,
            })
        })
        .collect()
}

async fn fetch_simple_terminal_observations(
    db: &Database,
    tenant_id: Option<&str>,
    family: &str,
) -> Result<Vec<Observation>, ApiError> {
    let metric_kind = match family {
        "command" => "command",
        "cleanup" => "cleanup",
        _ => unreachable!("bounded metric family"),
    };
    let base = format!(
        "select outcome, duration_ms from terminal_slo_observations where metric_kind = '{metric_kind}'"
    );
    let sql = if tenant_id.is_some() {
        format!("{base} and tenant_id = {}", db.placeholder(1))
    } else {
        base.to_string()
    };
    fetch_rows(db, &sql, tenant_id)
        .await?
        .into_iter()
        .map(|row| {
            let duration_ms: i64 = row.try_get("duration_ms")?;
            Ok(Observation {
                labels: vec![row.try_get("outcome")?],
                seconds: duration_ms.max(0) as f64 / 1000.0,
            })
        })
        .collect()
}

async fn fetch_claim_observations(
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<Vec<Observation>, ApiError> {
    let filter = tenant_id
        .map(|_| format!(" where j.tenant_id = {}", db.placeholder(1)))
        .unwrap_or_default();
    let sql = format!(
        "select j.kind, j.scheduled_at, min(l.leased_at) as leased_at
         from jobs j join job_leases l on l.job_id = j.id{filter}
         group by j.id, j.kind, j.scheduled_at"
    );
    fetch_rows(db, &sql, tenant_id)
        .await?
        .into_iter()
        .map(|row| {
            Ok(Observation {
                labels: vec![row.try_get("kind")?],
                seconds: elapsed_seconds(
                    timestamp(&row, "scheduled_at")?,
                    timestamp(&row, "leased_at")?,
                ),
            })
        })
        .collect()
}

async fn fetch_stage_observations(
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<Vec<Observation>, ApiError> {
    let filter = tenant_id
        .map(|_| format!(" and o.tenant_id = {}", db.placeholder(1)))
        .unwrap_or_default();
    let sql = format!(
        "select o.lease_id, o.stage, o.error_class, o.started_at, o.observed_at,
                o.workspace_mode
         from provisioning_stage_observations o
         where 1 = 1{filter}
         order by o.lease_id, o.observed_at, o.stage_index"
    );
    let rows = fetch_rows(db, &sql, tenant_id).await?;
    let mut previous = BTreeMap::<String, DateTime<Utc>>::new();
    let mut observations = Vec::with_capacity(rows.len());
    for row in rows {
        let lease_id: String = row.try_get("lease_id")?;
        let observed = timestamp(&row, "observed_at")?;
        let started = timestamp(&row, "started_at")?;
        let prior = previous.insert(lease_id, observed).unwrap_or(started);
        let error_class: Option<String> = row.try_get("error_class")?;
        observations.push(Observation {
            labels: vec![
                row.try_get("stage")?,
                row.try_get("workspace_mode")?,
                error_class.unwrap_or_else(|| "none".to_string()),
            ],
            seconds: elapsed_seconds(prior, observed),
        });
    }
    Ok(observations)
}

async fn fetch_rows(
    db: &Database,
    sql: &str,
    tenant_id: Option<&str>,
) -> Result<Vec<sqlx::any::AnyRow>, ApiError> {
    let mut query = sqlx::query(sql);
    if let Some(tenant_id) = tenant_id {
        query = query.bind(tenant_id);
    }
    Ok(query.fetch_all(&db.pool).await?)
}

fn timestamp(row: &sqlx::any::AnyRow, column: &str) -> Result<DateTime<Utc>, ApiError> {
    let value: String = row.try_get(column)?;
    parse_timestamp(&value)
}

fn elapsed_seconds(start: DateTime<Utc>, end: DateTime<Utc>) -> f64 {
    (end - start).num_milliseconds().max(0) as f64 / 1000.0
}

fn append_counter_from_observations(
    body: &mut String,
    name: &str,
    help: &str,
    label_names: &[&str],
    observations: &[Observation],
) {
    let mut counts = BTreeMap::<Vec<String>, u64>::new();
    for observation in observations {
        *counts.entry(observation.labels.clone()).or_default() += 1;
    }
    body.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
    for (labels, count) in counts {
        append_sample(body, name, label_names, &labels, None, count as f64);
    }
}

fn append_histogram(
    body: &mut String,
    name: &str,
    help: &str,
    label_names: &[&str],
    observations: &[Observation],
) {
    let mut groups = BTreeMap::<Vec<String>, Vec<f64>>::new();
    for observation in observations {
        groups
            .entry(observation.labels.clone())
            .or_default()
            .push(observation.seconds);
    }
    body.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
    for (labels, values) in groups {
        for bucket in LATENCY_BUCKETS {
            let count = values.iter().filter(|value| **value <= *bucket).count();
            append_sample(
                body,
                &format!("{name}_bucket"),
                label_names,
                &labels,
                Some(&bucket.to_string()),
                count as f64,
            );
        }
        append_sample(
            body,
            &format!("{name}_bucket"),
            label_names,
            &labels,
            Some("+Inf"),
            values.len() as f64,
        );
        append_sample(
            body,
            &format!("{name}_sum"),
            label_names,
            &labels,
            None,
            values.iter().sum(),
        );
        append_sample(
            body,
            &format!("{name}_count"),
            label_names,
            &labels,
            None,
            values.len() as f64,
        );
    }
}

fn append_sample(
    body: &mut String,
    name: &str,
    label_names: &[&str],
    label_values: &[String],
    le: Option<&str>,
    value: f64,
) {
    body.push_str(name);
    body.push('{');
    let mut first = true;
    for (label_name, label_value) in label_names.iter().zip(label_values) {
        if !first {
            body.push(',');
        }
        first = false;
        body.push_str(label_name);
        body.push_str("=\"");
        body.push_str(&escape_prometheus_label(label_value));
        body.push('"');
    }
    if let Some(le) = le {
        if !first {
            body.push(',');
        }
        body.push_str("le=\"");
        body.push_str(le);
        body.push('"');
    }
    body.push_str("} ");
    body.push_str(&value.to_string());
    body.push('\n');
}
