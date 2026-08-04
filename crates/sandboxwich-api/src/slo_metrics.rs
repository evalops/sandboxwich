use crate::db::Database;
use crate::error::ApiError;
use crate::health::escape_prometheus_label;
use crate::rows::parse_timestamp;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::Row;
use std::collections::BTreeMap;
use std::time::Instant;

const LATENCY_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 900.0];
/// `/metrics` only materializes raw observations from this recent window.
/// Older rows remain durable for later rollup work (#262); scrapes must stay
/// O(recent) rather than O(lifetime history).
const METRICS_RAW_RETENTION: ChronoDuration = ChronoDuration::days(14);
/// Hard safety cap on rows examined per observation family. When exceeded the
/// scrape still succeeds but reports truncation so operators can see budget
/// pressure before latency collapses.
const METRICS_MAX_ROWS_PER_FAMILY: i64 = 50_000;

#[derive(Clone)]
struct Observation {
    labels: Vec<String>,
    seconds: f64,
}

struct ObservationBatch {
    observations: Vec<Observation>,
    rows_examined: u64,
    truncated: bool,
}

pub(crate) async fn append_slo_metrics(
    body: &mut String,
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<(), ApiError> {
    let scrape_started = Instant::now();
    let since = Utc::now() - METRICS_RAW_RETENTION;
    let since = since.to_rfc3339();

    let creation = fetch_creation_observations(db, tenant_id, &since).await?;
    append_histogram(
        body,
        "sandboxwich_sandbox_creation_seconds",
        "Sandbox creation latency from scheduling to terminal provisioning outcome.",
        &["workspace_mode", "start_type", "outcome"],
        &creation.observations,
    );
    append_counter_from_observations(
        body,
        "sandboxwich_sandbox_creation_total",
        "Terminal sandbox creation outcomes.",
        &["workspace_mode", "start_type", "outcome"],
        &creation.observations,
    );
    let command = fetch_simple_terminal_observations(db, tenant_id, "command", &since).await?;
    append_histogram(
        body,
        "sandboxwich_command_duration_seconds",
        "Terminal command latency.",
        &["outcome"],
        &command.observations,
    );
    let cleanup = fetch_simple_terminal_observations(db, tenant_id, "cleanup", &since).await?;
    append_histogram(
        body,
        "sandboxwich_cleanup_duration_seconds",
        "Sandbox cleanup job latency.",
        &["outcome"],
        &cleanup.observations,
    );
    let claim = fetch_claim_observations(db, tenant_id, &since).await?;
    append_histogram(
        body,
        "sandboxwich_worker_claim_seconds",
        "Delay from job scheduling to the first worker lease.",
        &["job_kind"],
        &claim.observations,
    );
    let stage = fetch_stage_observations(db, tenant_id, &since).await?;
    append_histogram(
        body,
        "sandboxwich_provisioning_stage_seconds",
        "Elapsed time between durable provisioning stages.",
        &["stage", "workspace_mode", "error_class"],
        &stage.observations,
    );

    let rows_examined = creation.rows_examined
        + command.rows_examined
        + cleanup.rows_examined
        + claim.rows_examined
        + stage.rows_examined;
    let truncated = creation.truncated
        || command.truncated
        || cleanup.truncated
        || claim.truncated
        || stage.truncated;
    let scrape_seconds = scrape_started.elapsed().as_secs_f64();
    // Result bytes are measured by the caller after the body is fully built;
    // here we only emit scrape-side cost that this module controls.
    body.push_str(
        "# HELP sandboxwich_metrics_scrape_duration_seconds Wall time to build SLO histograms from recent observations.\n",
    );
    body.push_str("# TYPE sandboxwich_metrics_scrape_duration_seconds gauge\n");
    body.push_str(&format!(
        "sandboxwich_metrics_scrape_duration_seconds {scrape_seconds:.6}\n"
    ));
    body.push_str(
        "# HELP sandboxwich_metrics_rows_examined Observation rows loaded while building the last /metrics scrape.\n",
    );
    body.push_str("# TYPE sandboxwich_metrics_rows_examined gauge\n");
    body.push_str(&format!(
        "sandboxwich_metrics_rows_examined {rows_examined}\n"
    ));
    body.push_str(
        "# HELP sandboxwich_metrics_scrape_truncated 1 when a family hit METRICS_MAX_ROWS_PER_FAMILY during the last scrape.\n",
    );
    body.push_str("# TYPE sandboxwich_metrics_scrape_truncated gauge\n");
    body.push_str(&format!(
        "sandboxwich_metrics_scrape_truncated {}\n",
        if truncated { 1 } else { 0 }
    ));
    if scrape_seconds >= 0.5 || truncated {
        tracing::warn!(
            tenant_id = tenant_id.unwrap_or("operator"),
            rows_examined,
            truncated,
            scrape_seconds,
            "sandboxwich_metrics_scrape_slow"
        );
    }
    Ok(())
}

async fn fetch_creation_observations(
    db: &Database,
    tenant_id: Option<&str>,
    since: &str,
) -> Result<ObservationBatch, ApiError> {
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select outcome, workspace_mode, start_type, duration_ms
                 from terminal_slo_observations
                 where metric_kind = 'sandbox_creation'
                   and observed_at >= {}
                   and tenant_id = {}
                 order by observed_at desc
                 limit {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            ),
            vec![since, tenant_id],
        )
    } else {
        (
            format!(
                "select outcome, workspace_mode, start_type, duration_ms
                 from terminal_slo_observations
                 where metric_kind = 'sandbox_creation'
                   and observed_at >= {}
                 order by observed_at desc
                 limit {}",
                db.placeholder(1),
                db.placeholder(2)
            ),
            vec![since],
        )
    };
    let rows = fetch_rows_with_limit(db, &sql, &binds).await?;
    let truncated = rows.len() as i64 >= METRICS_MAX_ROWS_PER_FAMILY;
    let rows_examined = rows.len() as u64;
    let observations = rows
        .into_iter()
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
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(ObservationBatch {
        observations,
        rows_examined,
        truncated,
    })
}

async fn fetch_simple_terminal_observations(
    db: &Database,
    tenant_id: Option<&str>,
    family: &str,
    since: &str,
) -> Result<ObservationBatch, ApiError> {
    let metric_kind = match family {
        "command" => "command",
        "cleanup" => "cleanup",
        _ => unreachable!("bounded metric family"),
    };
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select outcome, duration_ms from terminal_slo_observations
                 where metric_kind = '{metric_kind}'
                   and observed_at >= {}
                   and tenant_id = {}
                 order by observed_at desc
                 limit {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            ),
            vec![since, tenant_id],
        )
    } else {
        (
            format!(
                "select outcome, duration_ms from terminal_slo_observations
                 where metric_kind = '{metric_kind}'
                   and observed_at >= {}
                 order by observed_at desc
                 limit {}",
                db.placeholder(1),
                db.placeholder(2)
            ),
            vec![since],
        )
    };
    let rows = fetch_rows_with_limit(db, &sql, &binds).await?;
    let truncated = rows.len() as i64 >= METRICS_MAX_ROWS_PER_FAMILY;
    let rows_examined = rows.len() as u64;
    let observations = rows
        .into_iter()
        .map(|row| {
            let duration_ms: i64 = row.try_get("duration_ms")?;
            Ok(Observation {
                labels: vec![row.try_get("outcome")?],
                seconds: duration_ms.max(0) as f64 / 1000.0,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(ObservationBatch {
        observations,
        rows_examined,
        truncated,
    })
}

async fn fetch_claim_observations(
    db: &Database,
    tenant_id: Option<&str>,
    since: &str,
) -> Result<ObservationBatch, ApiError> {
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select j.kind, j.scheduled_at, min(l.leased_at) as leased_at
                 from jobs j join job_leases l on l.job_id = j.id
                 where j.tenant_id = {}
                   and l.leased_at >= {}
                 group by j.id, j.kind, j.scheduled_at
                 order by min(l.leased_at) desc
                 limit {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            ),
            vec![tenant_id, since],
        )
    } else {
        (
            format!(
                "select j.kind, j.scheduled_at, min(l.leased_at) as leased_at
                 from jobs j join job_leases l on l.job_id = j.id
                 where l.leased_at >= {}
                 group by j.id, j.kind, j.scheduled_at
                 order by min(l.leased_at) desc
                 limit {}",
                db.placeholder(1),
                db.placeholder(2)
            ),
            vec![since],
        )
    };
    let rows = fetch_rows_with_limit(db, &sql, &binds).await?;
    let truncated = rows.len() as i64 >= METRICS_MAX_ROWS_PER_FAMILY;
    let rows_examined = rows.len() as u64;
    let observations = rows
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
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(ObservationBatch {
        observations,
        rows_examined,
        truncated,
    })
}

async fn fetch_stage_observations(
    db: &Database,
    tenant_id: Option<&str>,
    since: &str,
) -> Result<ObservationBatch, ApiError> {
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select o.lease_id, o.stage, o.error_class, o.started_at, o.observed_at,
                        o.workspace_mode
                 from provisioning_stage_observations o
                 where o.observed_at >= {}
                   and o.tenant_id = {}
                 order by o.lease_id, o.observed_at, o.stage_index
                 limit {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3)
            ),
            vec![since, tenant_id],
        )
    } else {
        (
            format!(
                "select o.lease_id, o.stage, o.error_class, o.started_at, o.observed_at,
                        o.workspace_mode
                 from provisioning_stage_observations o
                 where o.observed_at >= {}
                 order by o.lease_id, o.observed_at, o.stage_index
                 limit {}",
                db.placeholder(1),
                db.placeholder(2)
            ),
            vec![since],
        )
    };
    let started = Instant::now();
    let rows = fetch_rows_with_limit(db, &sql, &binds).await?;
    let duration_ms = started.elapsed().as_millis() as u64;
    if duration_ms >= 500 {
        tracing::warn!(
            tenant_id = tenant_id.unwrap_or("operator"),
            rows_returned = rows.len(),
            duration_ms,
            "sandboxwich_provisioning_stage_metrics_slow"
        );
    } else {
        tracing::debug!(
            tenant_id = tenant_id.unwrap_or("operator"),
            rows_returned = rows.len(),
            duration_ms,
            "sandboxwich_provisioning_stage_metrics_completed"
        );
    }
    let truncated = rows.len() as i64 >= METRICS_MAX_ROWS_PER_FAMILY;
    let rows_examined = rows.len() as u64;
    let mut previous = BTreeMap::<String, DateTime<Utc>>::new();
    let mut observations = Vec::with_capacity(rows.len());
    for row in rows {
        let lease_id: String = row.try_get("lease_id")?;
        let observed = timestamp(&row, "observed_at")?;
        let started_at = timestamp(&row, "started_at")?;
        let prior = previous.insert(lease_id, observed).unwrap_or(started_at);
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
    Ok(ObservationBatch {
        observations,
        rows_examined,
        truncated,
    })
}

async fn fetch_rows_with_limit(
    db: &Database,
    sql: &str,
    string_binds: &[&str],
) -> Result<Vec<sqlx::any::AnyRow>, ApiError> {
    let mut query = sqlx::query(sql);
    for value in string_binds {
        query = query.bind(*value);
    }
    // Limit is always the last bind when present in the SQL.
    if sql.contains("limit ") {
        query = query.bind(METRICS_MAX_ROWS_PER_FAMILY);
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
    // One pass: count per (labels, first bucket index that contains the sample).
    // Cumulative le= buckets and +Inf are derived from those per-bucket counts.
    let mut bucket_counts = BTreeMap::<(Vec<String>, usize), u64>::new();
    let mut sums = BTreeMap::<Vec<String>, f64>::new();
    let mut counts = BTreeMap::<Vec<String>, u64>::new();
    for observation in observations {
        let index = LATENCY_BUCKETS
            .partition_point(|limit| *limit < observation.seconds)
            .min(LATENCY_BUCKETS.len());
        *bucket_counts
            .entry((observation.labels.clone(), index))
            .or_default() += 1;
        *sums.entry(observation.labels.clone()).or_default() += observation.seconds;
        *counts.entry(observation.labels.clone()).or_default() += 1;
    }

    body.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
    let label_sets: Vec<Vec<String>> = counts.keys().cloned().collect();
    for labels in label_sets {
        let mut cumulative = 0_u64;
        for (bucket_index, le) in LATENCY_BUCKETS.iter().enumerate() {
            cumulative += bucket_counts
                .get(&(labels.clone(), bucket_index))
                .copied()
                .unwrap_or(0);
            append_sample(
                body,
                &format!("{name}_bucket"),
                label_names,
                &labels,
                Some(*le),
                cumulative as f64,
            );
        }
        cumulative += bucket_counts
            .get(&(labels.clone(), LATENCY_BUCKETS.len()))
            .copied()
            .unwrap_or(0);
        append_sample(
            body,
            &format!("{name}_bucket"),
            label_names,
            &labels,
            Some(f64::INFINITY),
            cumulative as f64,
        );
        append_sample(
            body,
            &format!("{name}_sum"),
            label_names,
            &labels,
            None,
            sums.get(&labels).copied().unwrap_or(0.0),
        );
        append_sample(
            body,
            &format!("{name}_count"),
            label_names,
            &labels,
            None,
            counts.get(&labels).copied().unwrap_or(0) as f64,
        );
    }
}

fn append_sample(
    body: &mut String,
    name: &str,
    label_names: &[&str],
    label_values: &[String],
    le: Option<f64>,
    value: f64,
) {
    body.push_str(name);
    body.push('{');
    let mut first = true;
    for (name, value) in label_names.iter().zip(label_values.iter()) {
        if !first {
            body.push(',');
        }
        first = false;
        body.push_str(name);
        body.push_str("=\"");
        body.push_str(&escape_prometheus_label(value));
        body.push('"');
    }
    if let Some(le) = le {
        if !first {
            body.push(',');
        }
        body.push_str("le=\"");
        if le.is_infinite() {
            body.push_str("+Inf");
        } else {
            body.push_str(&format!("{le}"));
        }
        body.push('"');
    }
    body.push_str(&format!("}} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_classifies_each_observation_once_and_keeps_cumulative_buckets() {
        let observations = vec![
            Observation {
                labels: vec!["ok".into()],
                seconds: 0.5,
            },
            Observation {
                labels: vec!["ok".into()],
                seconds: 20.0,
            },
            Observation {
                labels: vec!["ok".into()],
                seconds: 1_000.0,
            },
        ];
        let mut body = String::new();
        append_histogram(
            &mut body,
            "sandboxwich_test_seconds",
            "test",
            &["outcome"],
            &observations,
        );
        assert!(body.contains("le=\"1\"} 1\n"));
        assert!(body.contains("le=\"30\"} 2\n"));
        assert!(body.contains("le=\"+Inf\"} 3\n"));
        assert!(body.contains("sandboxwich_test_seconds_count{outcome=\"ok\"} 3\n"));
        assert!(body.contains("sandboxwich_test_seconds_sum{outcome=\"ok\"} 1020.5\n"));
    }
}
