use crate::db::Database;
use crate::error::ApiError;
use crate::health::escape_prometheus_label;
use crate::rows::parse_timestamp;
use chrono::{DateTime, Utc};
use sqlx::Row;
use std::collections::BTreeMap;

const LATENCY_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 900.0];
const WARM_CLAIM_THRESHOLD_SECONDS: f64 = 30.0;

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
        .map(|_| format!(" and j.tenant_id = {}", db.placeholder(1)))
        .unwrap_or_default();
    let sql = format!(
        "select j.status, s.workspace_mode, j.scheduled_at, j.updated_at,
                min(l.leased_at) as leased_at
         from jobs j
         join sandboxes s on s.id = j.sandbox_id
         left join job_leases l on l.job_id = j.id
         where j.kind = 'provision_sandbox'
           and j.status in ('succeeded', 'failed', 'dead', 'cancelled'){tenant_filter}
         group by j.id, j.status, s.workspace_mode, j.scheduled_at, j.updated_at"
    );
    let rows = fetch_rows(db, &sql, tenant_id).await?;
    rows.into_iter()
        .map(|row| {
            let scheduled = timestamp(&row, "scheduled_at")?;
            let updated = timestamp(&row, "updated_at")?;
            let leased: Option<String> = row.try_get("leased_at")?;
            let claim_seconds = leased
                .as_deref()
                .map(parse_timestamp)
                .transpose()?
                .map(|value| elapsed_seconds(scheduled, value))
                .unwrap_or(f64::INFINITY);
            let status: String = row.try_get("status")?;
            Ok(Observation {
                labels: vec![
                    row.try_get("workspace_mode")?,
                    if claim_seconds <= WARM_CLAIM_THRESHOLD_SECONDS {
                        "warm".to_string()
                    } else {
                        "cold".to_string()
                    },
                    terminal_outcome(&status).to_string(),
                ],
                seconds: elapsed_seconds(scheduled, updated),
            })
        })
        .collect()
}

async fn fetch_simple_terminal_observations(
    db: &Database,
    tenant_id: Option<&str>,
    family: &str,
) -> Result<Vec<Observation>, ApiError> {
    let (base, tenant_column) = match family {
        "command" => (
            "select c.status, c.created_at, c.finished_at
             from commands c join sandboxes s on s.id = c.sandbox_id
             where c.status in ('finished', 'failed') and c.finished_at is not null",
            "s.tenant_id",
        ),
        "cleanup" => (
            "select j.status, j.created_at, j.updated_at as finished_at
             from jobs j where j.kind = 'stop_sandbox'
             and j.status in ('succeeded', 'failed', 'dead', 'cancelled')",
            "j.tenant_id",
        ),
        _ => unreachable!("bounded metric family"),
    };
    let sql = if tenant_id.is_some() {
        format!("{base} and {tenant_column} = {}", db.placeholder(1))
    } else {
        base.to_string()
    };
    fetch_rows(db, &sql, tenant_id)
        .await?
        .into_iter()
        .map(|row| {
            let status: String = row.try_get("status")?;
            Ok(Observation {
                labels: vec![terminal_outcome(&status).to_string()],
                seconds: elapsed_seconds(
                    timestamp(&row, "created_at")?,
                    timestamp(&row, "finished_at")?,
                ),
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
        .map(|_| format!(" and s.tenant_id = {}", db.placeholder(1)))
        .unwrap_or_default();
    let sql = format!(
        "select o.lease_id, o.stage, o.error_class, o.observed_at,
                j.scheduled_at as created_at, s.workspace_mode
         from provisioning_stage_observations o
         join sandboxes s on s.id = o.sandbox_id
         join job_leases l on l.id = o.lease_id
         join jobs j on j.id = l.job_id
         where 1 = 1{filter}
         order by o.lease_id, o.observed_at, o.stage_index"
    );
    let rows = fetch_rows(db, &sql, tenant_id).await?;
    let mut previous = BTreeMap::<String, DateTime<Utc>>::new();
    let mut observations = Vec::with_capacity(rows.len());
    for row in rows {
        let lease_id: String = row.try_get("lease_id")?;
        let observed = timestamp(&row, "observed_at")?;
        let created = timestamp(&row, "created_at")?;
        let prior = previous.insert(lease_id, observed).unwrap_or(created);
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

fn terminal_outcome(status: &str) -> &'static str {
    match status {
        "succeeded" | "finished" => "success",
        _ => "failure",
    }
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
