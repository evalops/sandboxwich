use crate::db::Database;
use crate::error::ApiError;
use crate::health::escape_prometheus_label;
use crate::rows::parse_timestamp;
use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use sqlx::Row;
use std::collections::BTreeMap;
use std::time::Instant;

const LATENCY_BUCKETS: &[f64] = &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 900.0];
/// Millisecond ceilings matching [`LATENCY_BUCKETS`] for SQL-side histogram
/// aggregation of `duration_ms` observation columns.
const LATENCY_BUCKETS_MS: &[i64] = &[
    1_000, 5_000, 15_000, 30_000, 60_000, 120_000, 300_000, 900_000,
];
/// Raw terminal observations kept for scrape + late rollup. Older raw rows are
/// folded into [`slo_histogram_rollups`] by the expiry sweeper (#262).
const METRICS_RAW_RETENTION: ChronoDuration = ChronoDuration::hours(2);
/// Rollup + raw history retained for scrape windows (rollups cover the bulk).
const METRICS_HISTORY_RETENTION: ChronoDuration = ChronoDuration::days(14);
/// Observations older than this are eligible to fold into hourly rollups.
const METRICS_ROLLUP_AGE: ChronoDuration = ChronoDuration::hours(1);
/// Max raw terminal rows processed per rollup sweep tick.
const METRICS_ROLLUP_BATCH: i64 = 5_000;
/// Hard safety cap on rows examined per observation family for families that
/// still load individual samples (claim join, provisioning stages). Terminal
/// families aggregate in SQL and never pull one row per event. 50k/family
/// examined ~250k rows per scrape in prod (0.6–1.4s) without flipping
/// `truncated`; 5k keeps the scrape under the SLO warn.
const METRICS_MAX_ROWS_PER_FAMILY: i64 = 5_000;

/// PostgreSQL promotes `sum(bigint)` to `numeric`, which `sqlx::Any` cannot
/// decode. Keep every Prometheus aggregate on the i64 boundary explicitly;
/// SQLite accepts the same expression without a cast.
fn coalesced_sum_i64(db: &Database, expression: &str) -> String {
    let aggregate = format!("coalesce(sum({expression}), 0)");
    match db.dialect {
        crate::db::SqlDialect::Postgres => format!("{aggregate}::bigint"),
        crate::db::SqlDialect::Sqlite => aggregate,
    }
}

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

/// Pre-aggregated histogram series (one row per label set). Terminal SLO
/// families are reduced in SQL so scrapes stay O(cardinality) not O(events).
struct HistogramSeries {
    labels: Vec<String>,
    count: u64,
    sum_seconds: f64,
    /// Cumulative counts for each [`LATENCY_BUCKETS`] entry, then +Inf is count.
    cumulative_buckets: Vec<u64>,
}

struct HistogramBatch {
    series: Vec<HistogramSeries>,
    rows_examined: u64,
    truncated: bool,
}

pub(crate) async fn append_slo_metrics(
    body: &mut String,
    db: &Database,
    tenant_id: Option<&str>,
) -> Result<(), ApiError> {
    let scrape_started = Instant::now();
    let now = Utc::now();
    let raw_since = (now - METRICS_RAW_RETENTION).to_rfc3339();
    let history_since = (now - METRICS_HISTORY_RETENTION).to_rfc3339();
    // Claim/stage families still load samples; keep them on the short raw window.
    let sample_since = raw_since.clone();

    // Terminal families: recent raw aggregates + hourly rollups for history.
    // Independent family scrapes: run concurrently so /metrics latency is
    // dominated by the slowest query, not the sum of five sequential ones.
    let (
        creation_raw,
        command_raw,
        cleanup_raw,
        creation_roll,
        command_roll,
        cleanup_roll,
        claim,
        stage,
        activation_duration,
        activation_total,
    ) = tokio::try_join!(
        fetch_creation_histogram(db, tenant_id, &raw_since),
        fetch_simple_terminal_histogram(db, tenant_id, "command", &raw_since),
        fetch_simple_terminal_histogram(db, tenant_id, "cleanup", &raw_since),
        fetch_creation_rollups(db, tenant_id, &history_since, &raw_since),
        fetch_simple_terminal_rollups(db, tenant_id, "command", &history_since, &raw_since),
        fetch_simple_terminal_rollups(db, tenant_id, "cleanup", &history_since, &raw_since),
        fetch_claim_observations(db, tenant_id, &sample_since),
        fetch_stage_observations(db, tenant_id, &sample_since),
        fetch_activation_histogram(db, tenant_id, false),
        fetch_activation_histogram(db, tenant_id, true),
    )?;
    let creation = merge_histogram_batches(creation_raw, creation_roll);
    let command = merge_histogram_batches(command_raw, command_roll);
    let cleanup = merge_histogram_batches(cleanup_raw, cleanup_roll);

    append_histogram_series(
        body,
        "sandboxwich_sandbox_creation_seconds",
        "Sandbox creation latency from scheduling to terminal provisioning outcome.",
        &["workspace_mode", "start_type", "outcome"],
        &creation.series,
    );
    append_counter_from_series(
        body,
        "sandboxwich_sandbox_creation_total",
        "Terminal sandbox creation outcomes.",
        &["workspace_mode", "start_type", "outcome"],
        &creation.series,
    );
    append_histogram_series(
        body,
        "sandboxwich_command_duration_seconds",
        "Terminal command latency.",
        &["outcome"],
        &command.series,
    );
    append_histogram_series(
        body,
        "sandboxwich_cleanup_duration_seconds",
        "Sandbox cleanup job latency.",
        &["outcome"],
        &cleanup.series,
    );
    append_histogram(
        body,
        "sandboxwich_worker_claim_seconds",
        "Delay from job scheduling to the first worker lease.",
        &["job_kind"],
        &claim.observations,
    );
    append_histogram(
        body,
        "sandboxwich_provisioning_stage_seconds",
        "Elapsed time between durable provisioning stages.",
        &["stage", "workspace_mode", "error_class"],
        &stage.observations,
    );
    append_histogram_series(
        body,
        "sandboxwich_maestro_activation_validation_duration_seconds",
        "Sandboxwich validation latency for authenticated Maestro activation tuples.",
        &["outcome"],
        &activation_duration.series,
    );
    append_counter_from_series(
        body,
        "sandboxwich_maestro_activation_total",
        "Authenticated Maestro activation validation outcomes in the retained observation window.",
        &["outcome", "reason"],
        &activation_total.series,
    );

    let rows_examined = creation.rows_examined
        + command.rows_examined
        + cleanup.rows_examined
        + claim.rows_examined
        + stage.rows_examined
        + activation_duration.rows_examined
        + activation_total.rows_examined;
    let truncated = creation.truncated
        || command.truncated
        || cleanup.truncated
        || claim.truncated
        || stage.truncated
        || activation_duration.truncated
        || activation_total.truncated;
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

fn duration_bucket_selects(db: &Database) -> String {
    // Placeholder indices are unused; these are bare expressions over duration_ms.
    LATENCY_BUCKETS_MS
        .iter()
        .enumerate()
        .map(|(index, ms)| {
            let expression = format!("case when duration_ms <= {ms} then 1 else 0 end");
            format!("{} as b{index}", coalesced_sum_i64(db, &expression))
        })
        .collect::<Vec<_>>()
        .join(",\n                        ")
}

async fn fetch_creation_histogram(
    db: &Database,
    tenant_id: Option<&str>,
    since: &str,
) -> Result<HistogramBatch, ApiError> {
    let buckets = duration_bucket_selects(db);
    let sum_ms = coalesced_sum_i64(db, "duration_ms");
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select outcome, workspace_mode, start_type,
                        count(*) as n,
                        {sum_ms} as sum_ms,
                        {buckets}
                 from terminal_slo_observations
                 where metric_kind = 'sandbox_creation'
                   and observed_at >= {}
                   and tenant_id = {}
                 group by outcome, workspace_mode, start_type",
                db.placeholder(1),
                db.placeholder(2)
            ),
            vec![since, tenant_id],
        )
    } else {
        (
            format!(
                "select outcome, workspace_mode, start_type,
                        count(*) as n,
                        {sum_ms} as sum_ms,
                        {buckets}
                 from terminal_slo_observations
                 where metric_kind = 'sandbox_creation'
                   and observed_at >= {}
                 group by outcome, workspace_mode, start_type",
                db.placeholder(1)
            ),
            vec![since],
        )
    };
    let rows = fetch_rows(db, &sql, &binds).await?;
    map_histogram_rows(
        rows,
        &["workspace_mode", "start_type", "outcome"],
        &["workspace_mode", "start_type", "outcome"],
    )
}

async fn fetch_simple_terminal_histogram(
    db: &Database,
    tenant_id: Option<&str>,
    family: &str,
    since: &str,
) -> Result<HistogramBatch, ApiError> {
    let metric_kind = match family {
        "command" => "command",
        "cleanup" => "cleanup",
        _ => unreachable!("bounded metric family"),
    };
    let buckets = duration_bucket_selects(db);
    let sum_ms = coalesced_sum_i64(db, "duration_ms");
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select outcome,
                        count(*) as n,
                        {sum_ms} as sum_ms,
                        {buckets}
                 from terminal_slo_observations
                 where metric_kind = '{metric_kind}'
                   and observed_at >= {}
                   and tenant_id = {}
                 group by outcome",
                db.placeholder(1),
                db.placeholder(2)
            ),
            vec![since, tenant_id],
        )
    } else {
        (
            format!(
                "select outcome,
                        count(*) as n,
                        {sum_ms} as sum_ms,
                        {buckets}
                 from terminal_slo_observations
                 where metric_kind = '{metric_kind}'
                   and observed_at >= {}
                 group by outcome",
                db.placeholder(1)
            ),
            vec![since],
        )
    };
    let rows = fetch_rows(db, &sql, &binds).await?;
    map_histogram_rows(rows, &["outcome"], &["outcome"])
}

async fn fetch_activation_histogram(
    db: &Database,
    tenant_id: Option<&str>,
    include_reason: bool,
) -> Result<HistogramBatch, ApiError> {
    let count = coalesced_sum_i64(db, "sample_count");
    let sum_ms = coalesced_sum_i64(db, "sum_ms");
    let buckets = (0..LATENCY_BUCKETS_MS.len())
        .map(|index| {
            format!(
                "{} as b{index}",
                coalesced_sum_i64(db, &format!("b{index}"))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let reason_select = if include_reason { ", reason" } else { "" };
    let reason_group = if include_reason { ", reason" } else { "" };
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select outcome{reason_select}, {count} as n, {sum_ms} as sum_ms, {buckets}
                 from maestro_activation_validation_metrics
                 where tenant_id = {}
                 group by outcome{reason_group}",
                db.placeholder(1),
            ),
            vec![tenant_id],
        )
    } else {
        (
            format!(
                "select outcome{reason_select}, {count} as n, {sum_ms} as sum_ms, {buckets}
                 from maestro_activation_validation_metrics
                 group by outcome{reason_group}",
            ),
            vec![],
        )
    };
    let rows = fetch_rows(db, &sql, &binds).await?;
    if include_reason {
        map_histogram_rows(rows, &["outcome", "reason"], &["outcome", "reason"])
    } else {
        map_histogram_rows(rows, &["outcome"], &["outcome"])
    }
}

fn map_histogram_rows(
    rows: Vec<sqlx::any::AnyRow>,
    _label_names: &[&str],
    label_columns: &[&str],
) -> Result<HistogramBatch, ApiError> {
    let mut series = Vec::with_capacity(rows.len());
    let mut rows_examined = 0_u64;
    for row in rows {
        let n: i64 = row.try_get("n")?;
        let count = u64::try_from(n.max(0)).unwrap_or(0);
        rows_examined = rows_examined.saturating_add(count);
        let sum_ms: i64 = row.try_get("sum_ms")?;
        let mut labels = Vec::with_capacity(label_columns.len());
        for column in label_columns {
            labels.push(row.try_get(*column)?);
        }
        let mut cumulative_buckets = Vec::with_capacity(LATENCY_BUCKETS_MS.len());
        for index in 0..LATENCY_BUCKETS_MS.len() {
            let bucket: i64 = row.try_get(format!("b{index}").as_str())?;
            cumulative_buckets.push(u64::try_from(bucket.max(0)).unwrap_or(0));
        }
        series.push(HistogramSeries {
            labels,
            count,
            sum_seconds: sum_ms.max(0) as f64 / 1000.0,
            cumulative_buckets,
        });
    }
    Ok(HistogramBatch {
        series,
        rows_examined,
        // SQL aggregation never loads one row per event; group cardinality is
        // the bound. Truncation is reserved for sample-loading families.
        truncated: false,
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

fn merge_histogram_batches(mut left: HistogramBatch, right: HistogramBatch) -> HistogramBatch {
    let mut by_labels: BTreeMap<Vec<String>, HistogramSeries> = BTreeMap::new();
    for series in left.series.drain(..).chain(right.series) {
        by_labels
            .entry(series.labels.clone())
            .and_modify(|existing| {
                existing.count = existing.count.saturating_add(series.count);
                existing.sum_seconds += series.sum_seconds;
                for (index, value) in series.cumulative_buckets.iter().enumerate() {
                    if let Some(slot) = existing.cumulative_buckets.get_mut(index) {
                        *slot = slot.saturating_add(*value);
                    }
                }
            })
            .or_insert(series);
    }
    HistogramBatch {
        series: by_labels.into_values().collect(),
        rows_examined: left.rows_examined.saturating_add(right.rows_examined),
        truncated: left.truncated || right.truncated,
    }
}

async fn fetch_creation_rollups(
    db: &Database,
    tenant_id: Option<&str>,
    history_since: &str,
    raw_since: &str,
) -> Result<HistogramBatch, ApiError> {
    fetch_rollup_histogram(
        db,
        tenant_id,
        "sandbox_creation",
        history_since,
        raw_since,
        &["label_a", "label_b", "label_c"],
    )
    .await
}

async fn fetch_simple_terminal_rollups(
    db: &Database,
    tenant_id: Option<&str>,
    family: &str,
    history_since: &str,
    raw_since: &str,
) -> Result<HistogramBatch, ApiError> {
    let metric_kind = match family {
        "command" => "command",
        "cleanup" => "cleanup",
        _ => unreachable!("bounded metric family"),
    };
    fetch_rollup_histogram(
        db,
        tenant_id,
        metric_kind,
        history_since,
        raw_since,
        &["label_a"],
    )
    .await
}

async fn fetch_rollup_histogram(
    db: &Database,
    tenant_id: Option<&str>,
    metric_kind: &str,
    history_since: &str,
    raw_since: &str,
    label_columns: &[&str],
) -> Result<HistogramBatch, ApiError> {
    let p1 = db.placeholder(1);
    let p2 = db.placeholder(2);
    let p3 = db.placeholder(3);
    let p4 = db.placeholder(4);
    let sample_count = coalesced_sum_i64(db, "sample_count");
    let sum_ms = coalesced_sum_i64(db, "sum_ms");
    let buckets = LATENCY_BUCKETS_MS
        .iter()
        .enumerate()
        .map(|(index, _)| {
            format!(
                "{} as b{index}",
                coalesced_sum_i64(db, &format!("b{index}"))
            )
        })
        .collect::<Vec<_>>()
        .join(",\n                        ");
    let (sql, binds) = if let Some(tenant_id) = tenant_id {
        (
            format!(
                "select label_a, label_b, label_c,
                        {sample_count} as n,
                        {sum_ms} as sum_ms,
                        {buckets}
                 from slo_histogram_rollups
                 where metric_kind = {p1}
                   and bucket_start >= {p2}
                   and bucket_start < {p3}
                   and tenant_id = {p4}
                 group by label_a, label_b, label_c"
            ),
            vec![metric_kind, history_since, raw_since, tenant_id],
        )
    } else {
        (
            format!(
                "select label_a, label_b, label_c,
                        {sample_count} as n,
                        {sum_ms} as sum_ms,
                        {buckets}
                 from slo_histogram_rollups
                 where metric_kind = {p1}
                   and bucket_start >= {p2}
                   and bucket_start < {p3}
                 group by label_a, label_b, label_c"
            ),
            vec![metric_kind, history_since, raw_since],
        )
    };
    let rows = fetch_rows(db, &sql, &binds).await?;
    map_histogram_rows(rows, label_columns, label_columns)
}

/// Fold aged raw terminal observations into hourly histogram rollups and drop
/// the raw rows. Called from the expiry sweeper so scrapes stay O(recent+rollups).
pub(crate) async fn rollup_terminal_slo_observations(db: &Database) -> Result<u64, ApiError> {
    let cutoff = (Utc::now() - METRICS_ROLLUP_AGE).to_rfc3339();
    let sql = format!(
        "select source_id, tenant_id, metric_kind, outcome, workspace_mode, start_type,
                duration_ms, observed_at
         from terminal_slo_observations
         where observed_at < {}
         order by observed_at asc
         limit {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let rows = sqlx::query(&sql)
        .bind(&cutoff)
        .bind(METRICS_ROLLUP_BATCH)
        .fetch_all(&db.pool)
        .await?;
    if rows.is_empty() {
        return Ok(0);
    }

    #[derive(Default)]
    struct Agg {
        count: i64,
        sum_ms: i64,
        buckets: [i64; 8],
    }
    let mut groups: BTreeMap<(String, String, String, String, String, String), Agg> =
        BTreeMap::new();
    let mut delete_keys: Vec<(String, String)> = Vec::with_capacity(rows.len());

    for row in rows {
        let source_id: String = row.try_get("source_id")?;
        let tenant_id: String = row.try_get("tenant_id")?;
        let metric_kind: String = row.try_get("metric_kind")?;
        let outcome: String = row.try_get("outcome")?;
        let workspace_mode: Option<String> = row.try_get("workspace_mode")?;
        let start_type: Option<String> = row.try_get("start_type")?;
        let duration_ms: i64 = row.try_get("duration_ms")?;
        let observed_at: String = row.try_get("observed_at")?;
        let observed = parse_timestamp(&observed_at)?;
        let bucket_start = hour_floor(observed).to_rfc3339();
        let (label_a, label_b, label_c) = match metric_kind.as_str() {
            "sandbox_creation" => (
                workspace_mode.unwrap_or_default(),
                start_type.unwrap_or_default(),
                outcome,
            ),
            "command" | "cleanup" => (outcome, String::new(), String::new()),
            _ => continue,
        };
        let key = (
            bucket_start,
            tenant_id,
            metric_kind.clone(),
            label_a,
            label_b,
            label_c,
        );
        let entry = groups.entry(key).or_default();
        entry.count += 1;
        entry.sum_ms += duration_ms.max(0);
        let seconds = duration_ms.max(0) as f64 / 1000.0;
        for (index, le) in LATENCY_BUCKETS.iter().enumerate() {
            if seconds <= *le {
                entry.buckets[index] += 1;
            }
        }
        // Cumulative: b_i = count of samples with seconds <= LATENCY_BUCKETS[i]
        // Above loop already counts per-bucket non-cumulative - need cumulative
        // for storage. Fix: store non-cumulative then convert, or accumulate.
        delete_keys.push((source_id, metric_kind));
    }

    // Convert non-cumulative per-le counts: we counted "<= le" already so buckets
    // are already cumulative. Good.

    let mut rolled = 0_u64;
    for ((bucket_start, tenant_id, metric_kind, label_a, label_b, label_c), agg) in groups {
        let upsert = format!(
            "insert into slo_histogram_rollups
             (bucket_start, tenant_id, metric_kind, label_a, label_b, label_c,
              sample_count, sum_ms, b0, b1, b2, b3, b4, b5, b6, b7)
             values ({})
             on conflict (bucket_start, tenant_id, metric_kind, label_a, label_b, label_c)
             do update set
               sample_count = slo_histogram_rollups.sample_count + excluded.sample_count,
               sum_ms = slo_histogram_rollups.sum_ms + excluded.sum_ms,
               b0 = slo_histogram_rollups.b0 + excluded.b0,
               b1 = slo_histogram_rollups.b1 + excluded.b1,
               b2 = slo_histogram_rollups.b2 + excluded.b2,
               b3 = slo_histogram_rollups.b3 + excluded.b3,
               b4 = slo_histogram_rollups.b4 + excluded.b4,
               b5 = slo_histogram_rollups.b5 + excluded.b5,
               b6 = slo_histogram_rollups.b6 + excluded.b6,
               b7 = slo_histogram_rollups.b7 + excluded.b7",
            db.placeholders(16)
        );
        sqlx::query(&upsert)
            .bind(&bucket_start)
            .bind(&tenant_id)
            .bind(&metric_kind)
            .bind(&label_a)
            .bind(&label_b)
            .bind(&label_c)
            .bind(agg.count)
            .bind(agg.sum_ms)
            .bind(agg.buckets[0])
            .bind(agg.buckets[1])
            .bind(agg.buckets[2])
            .bind(agg.buckets[3])
            .bind(agg.buckets[4])
            .bind(agg.buckets[5])
            .bind(agg.buckets[6])
            .bind(agg.buckets[7])
            .execute(&db.pool)
            .await?;
        rolled = rolled.saturating_add(u64::try_from(agg.count.max(0)).unwrap_or(0));
    }

    for (source_id, metric_kind) in delete_keys {
        let delete = format!(
            "delete from terminal_slo_observations
             where source_id = {} and metric_kind = {}",
            db.placeholder(1),
            db.placeholder(2)
        );
        sqlx::query(&delete)
            .bind(source_id)
            .bind(metric_kind)
            .execute(&db.pool)
            .await?;
    }

    // Drop rollups past the history window so the table stays bounded.
    let history_cutoff = (Utc::now() - METRICS_HISTORY_RETENTION).to_rfc3339();
    let purge = format!(
        "delete from slo_histogram_rollups where bucket_start < {}",
        db.placeholder(1)
    );
    sqlx::query(&purge)
        .bind(history_cutoff)
        .execute(&db.pool)
        .await?;

    Ok(rolled)
}

fn hour_floor(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(ts)
}

async fn fetch_rows(
    db: &Database,
    sql: &str,
    string_binds: &[&str],
) -> Result<Vec<sqlx::any::AnyRow>, ApiError> {
    let mut query = sqlx::query(sql);
    for value in string_binds {
        query = query.bind(*value);
    }
    Ok(query.fetch_all(db.read_pool()).await?)
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
    Ok(query.fetch_all(db.read_pool()).await?)
}

fn timestamp(row: &sqlx::any::AnyRow, column: &str) -> Result<DateTime<Utc>, ApiError> {
    let value: String = row.try_get(column)?;
    parse_timestamp(&value)
}

fn elapsed_seconds(start: DateTime<Utc>, end: DateTime<Utc>) -> f64 {
    (end - start).num_milliseconds().max(0) as f64 / 1000.0
}

fn append_counter_from_series(
    body: &mut String,
    name: &str,
    help: &str,
    label_names: &[&str],
    series: &[HistogramSeries],
) {
    body.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
    for entry in series {
        append_sample(
            body,
            name,
            label_names,
            &entry.labels,
            None,
            entry.count as f64,
        );
    }
}

fn append_histogram_series(
    body: &mut String,
    name: &str,
    help: &str,
    label_names: &[&str],
    series: &[HistogramSeries],
) {
    body.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
    for entry in series {
        for (bucket_index, le) in LATENCY_BUCKETS.iter().enumerate() {
            let cumulative = entry
                .cumulative_buckets
                .get(bucket_index)
                .copied()
                .unwrap_or(0);
            append_sample(
                body,
                &format!("{name}_bucket"),
                label_names,
                &entry.labels,
                Some(*le),
                cumulative as f64,
            );
        }
        append_sample(
            body,
            &format!("{name}_bucket"),
            label_names,
            &entry.labels,
            Some(f64::INFINITY),
            entry.count as f64,
        );
        append_sample(
            body,
            &format!("{name}_sum"),
            label_names,
            &entry.labels,
            None,
            entry.sum_seconds,
        );
        append_sample(
            body,
            &format!("{name}_count"),
            label_names,
            &entry.labels,
            None,
            entry.count as f64,
        );
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

    #[test]
    fn histogram_series_emits_cumulative_sql_buckets() {
        let series = vec![HistogramSeries {
            labels: vec!["ok".into()],
            count: 3,
            sum_seconds: 1020.5,
            // SQL returns cumulative le= counts already.
            cumulative_buckets: vec![1, 1, 1, 2, 2, 2, 2, 2],
        }];
        let mut body = String::new();
        append_histogram_series(
            &mut body,
            "sandboxwich_test_seconds",
            "test",
            &["outcome"],
            &series,
        );
        assert!(body.contains("le=\"1\"} 1\n"));
        assert!(body.contains("le=\"30\"} 2\n"));
        assert!(body.contains("le=\"+Inf\"} 3\n"));
        assert!(body.contains("sandboxwich_test_seconds_count{outcome=\"ok\"} 3\n"));
        assert!(body.contains("sandboxwich_test_seconds_sum{outcome=\"ok\"} 1020.5\n"));
    }

    #[test]
    fn placement_match_bucket_ms_aligns_with_second_buckets() {
        assert_eq!(LATENCY_BUCKETS.len(), LATENCY_BUCKETS_MS.len());
        for (seconds, ms) in LATENCY_BUCKETS.iter().zip(LATENCY_BUCKETS_MS.iter()) {
            assert_eq!((*seconds * 1000.0) as i64, *ms);
        }
    }

    #[test]
    fn hour_floor_zeros_minute_second() {
        let ts = DateTime::parse_from_rfc3339("2026-08-04T15:37:42.123Z")
            .unwrap()
            .with_timezone(&Utc);
        let floor = hour_floor(ts);
        assert_eq!(floor.to_rfc3339(), "2026-08-04T15:00:00+00:00");
    }

    #[test]
    fn merge_histogram_batches_adds_matching_labels() {
        let left = HistogramBatch {
            series: vec![HistogramSeries {
                labels: vec!["ok".into()],
                count: 2,
                sum_seconds: 3.0,
                cumulative_buckets: vec![1, 2, 2, 2, 2, 2, 2, 2],
            }],
            rows_examined: 2,
            truncated: false,
        };
        let right = HistogramBatch {
            series: vec![HistogramSeries {
                labels: vec!["ok".into()],
                count: 3,
                sum_seconds: 4.0,
                cumulative_buckets: vec![0, 1, 3, 3, 3, 3, 3, 3],
            }],
            rows_examined: 3,
            truncated: false,
        };
        let merged = merge_histogram_batches(left, right);
        assert_eq!(merged.rows_examined, 5);
        assert_eq!(merged.series.len(), 1);
        assert_eq!(merged.series[0].count, 5);
        assert!((merged.series[0].sum_seconds - 7.0).abs() < f64::EPSILON);
        assert_eq!(merged.series[0].cumulative_buckets[1], 3);
    }
}
