use crate::common::*;
use crate::types::{insert_job_lease_sql, insert_job_sql, insert_worker_sql};
use chrono::{Duration, Utc};
use sandboxwich_core::*;
use sqlx::AnyPool;
use uuid::Uuid;

/// Regression test: `/metrics` aggregated sandbox/worker/job/lease counts across every tenant and
/// served them to any authenticated tenant token, an information leak across the tenant boundary.
/// Each tenant's own bearer token must now only ever see its own tenant's counts; only the
/// dedicated operator credential unlocks the cross-tenant, unscoped view.
#[tokio::test]
pub(crate) async fn metrics_are_scoped_to_the_authenticated_tenant() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-metrics-tenant-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let default_client = server.client();
    let tenant_b_client = reqwest::Client::new();

    const DEFAULT_TENANT_SANDBOXES: usize = 2;
    const TENANT_B_SANDBOXES: usize = 3;

    let mut default_sandbox_ids = Vec::new();
    for index in 0..DEFAULT_TENANT_SANDBOXES {
        let created: SandboxResponse = default_client
            .post(format!("{}/sandboxes", server.base_url))
            .json(&CreateSandboxRequest {
                secret_ref_ids: Vec::new(),
                execution_class: None,
                workspace_mode: None,
                runtime_profile: None,
                name: Some(format!("metrics-default-{index}")),
                template: None,
                memory_limit: None,
                network_egress: None,
                ttl_seconds: Some(120),
                max_lifetime_seconds: None,
                idle_ttl_seconds: None,
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        default_sandbox_ids.push(created.sandbox.id);
    }
    let mut tenant_b_sandbox_ids = Vec::new();
    for index in 0..TENANT_B_SANDBOXES {
        let created: SandboxResponse = tenant_b_client
            .post(format!("{}/sandboxes", server.base_url))
            .bearer_auth(TEST_TENANT_B_TOKEN)
            .json(&CreateSandboxRequest {
                secret_ref_ids: Vec::new(),
                execution_class: None,
                workspace_mode: None,
                runtime_profile: None,
                name: Some(format!("metrics-tenant-b-{index}")),
                template: None,
                memory_limit: None,
                network_egress: None,
                ttl_seconds: Some(120),
                max_lifetime_seconds: None,
                idle_ttl_seconds: None,
            })
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        tenant_b_sandbox_ids.push(created.sandbox.id);
    }

    // Seed only bounded resident state/rollup dimensions. The metrics query
    // must scope both families through their owning sandbox tenant.
    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&server.database_url).await.unwrap();
    for (index, (sandbox_id, tenant_id, state)) in [
        (default_sandbox_ids[0], "default", "running"),
        (tenant_b_sandbox_ids[0], "tenant-b", "failed"),
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query(
            "insert into resident_processes
             (id, sandbox_id, tenant_id, name, argv, env, restart_policy,
              desired_state, observed_state, generation, created_at, updated_at)
             values (?, ?, ?, 'orb-sidecar', '[]', '{}', 'always', 'running', ?, 1,
                     '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z')",
        )
        .bind(format!("00000000-0000-0000-0000-00000000001{index}"))
        .bind(sandbox_id.to_string())
        .bind(tenant_id)
        .bind(state)
        .execute(&pool)
        .await
        .unwrap();
    }
    for (tenant_id, reason) in [
        ("default", "not_running"),
        ("tenant-b", "inactive_lease"),
        ("tenant-b", "expired_lease"),
    ] {
        sqlx::query(
            "insert into sidecar_bootstrap_block_rollups (tenant_id, reason, total)
             values (?, ?, 1)",
        )
        .bind(tenant_id)
        .bind(reason)
        .execute(&pool)
        .await
        .unwrap();
    }

    let default_metrics = default_client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        planning_sandbox_gauge(&default_metrics),
        DEFAULT_TENANT_SANDBOXES as i64,
        "default tenant's /metrics must count only its own sandboxes, not tenant-b's:\n{default_metrics}"
    );
    assert_eq!(
        labeled_metric_value(
            &default_metrics,
            "sandboxwich_resident_process_count{state=\"running\"}",
        ),
        1
    );
    assert_eq!(
        labeled_metric_value(
            &default_metrics,
            "sandboxwich_sidecar_bootstrap_block_total{reason=\"not_running\"}",
        ),
        1
    );
    assert!(!default_metrics.contains("inactive_lease"));
    assert!(!default_metrics.contains("expired_lease"));

    let tenant_b_metrics = tenant_b_client
        .get(format!("{}/metrics", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        planning_sandbox_gauge(&tenant_b_metrics),
        TENANT_B_SANDBOXES as i64,
        "tenant-b's /metrics must count only its own sandboxes, not the default tenant's:\n{tenant_b_metrics}"
    );
    assert_eq!(
        labeled_metric_value(
            &tenant_b_metrics,
            "sandboxwich_resident_process_count{state=\"failed\"}",
        ),
        1
    );
    assert_eq!(
        labeled_metric_value(
            &tenant_b_metrics,
            "sandboxwich_sidecar_bootstrap_block_total{reason=\"inactive_lease\"}",
        ),
        1
    );
    assert_eq!(
        labeled_metric_value(
            &tenant_b_metrics,
            "sandboxwich_sidecar_bootstrap_block_total{reason=\"expired_lease\"}",
        ),
        1
    );
    assert!(!tenant_b_metrics.contains("not_running"));

    // The dedicated operator credential additionally unlocks the unscoped, cross-tenant view.
    let operator_metrics = default_client
        .get(format!("{}/metrics", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        planning_sandbox_gauge(&operator_metrics),
        (DEFAULT_TENANT_SANDBOXES + TENANT_B_SANDBOXES) as i64,
        "the operator credential must see totals across every tenant:\n{operator_metrics}"
    );
    assert!(operator_metrics.contains("state=\"running\""));
    assert!(operator_metrics.contains("state=\"failed\""));
    assert!(operator_metrics.contains("reason=\"not_running\""));
    assert!(operator_metrics.contains("reason=\"inactive_lease\""));
    assert!(operator_metrics.contains("reason=\"expired_lease\""));
    for forbidden in [
        "tenant_id=",
        "sandbox_id=",
        "resident_process_id=",
        "lease_id=",
        "generation=",
        "sha256=",
    ] {
        assert!(
            !operator_metrics.contains(forbidden),
            "resident metrics must not expose high-cardinality label {forbidden}:\n{operator_metrics}"
        );
    }

    // A wrong operator token header must not grant the global view -- it falls back to
    // tenant-scoped output exactly as if no operator header had been sent at all.
    let wrong_operator_metrics = default_client
        .get(format!("{}/metrics", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, "not-the-operator-token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        planning_sandbox_gauge(&wrong_operator_metrics),
        DEFAULT_TENANT_SANDBOXES as i64,
        "a wrong operator token must not unlock the cross-tenant view:\n{wrong_operator_metrics}"
    );
}

/// Resident-process leases are long-lived control-plane state and do not consume
/// the ordinary scheduler slots. Keep the aggregate metric aligned with the
/// worker claim and capacity endpoints so an operator does not diagnose a false
/// capacity exhaustion from `/metrics`.
#[tokio::test]
async fn metrics_available_capacity_excludes_resident_process_leases() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir
            .path()
            .join("sandboxwich-metrics-capacity-test.db")
            .display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&server.database_url).await.unwrap();
    let timestamp = "2026-08-04T00:00:00Z";
    let worker_id = Uuid::now_v7().to_string();
    sqlx::query(&insert_worker_sql(&server.database_url))
        .bind(&worker_id)
        .bind("metrics-capacity-worker")
        .bind("online")
        .bind("kubernetes")
        .bind("[\"provision_sandbox\"]")
        .bind("{}")
        .bind(timestamp)
        .bind(timestamp)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("update workers set max_concurrent_jobs = ? where id = ?")
        .bind(2_i64)
        .bind(&worker_id)
        .execute(&pool)
        .await
        .unwrap();

    for (job_id, kind, capability) in [
        (
            "00000000-0000-0000-0000-000000000801",
            "run_command",
            "run_command",
        ),
        (
            "00000000-0000-0000-0000-000000000802",
            "run_resident_process",
            "uid_isolated_resident_process",
        ),
    ] {
        sqlx::query(&insert_job_sql(&server.database_url))
            .bind(job_id)
            .bind(kind)
            .bind("leased")
            .bind("{}")
            .bind(capability)
            .bind("development_container")
            .bind(0_i64)
            .bind(1_i64)
            .bind(3_i64)
            .bind(timestamp)
            .bind(timestamp)
            .bind(timestamp)
            .bind(Option::<String>::None)
            .execute(&pool)
            .await
            .unwrap();
    }
    for (lease_id, job_id) in [
        (
            "00000000-0000-0000-0000-000000000811",
            "00000000-0000-0000-0000-000000000801",
        ),
        (
            "00000000-0000-0000-0000-000000000812",
            "00000000-0000-0000-0000-000000000802",
        ),
    ] {
        sqlx::query(&insert_job_lease_sql(&server.database_url))
            .bind(lease_id)
            .bind(job_id)
            .bind(&worker_id)
            .bind("active")
            .bind(1_i64)
            .bind(timestamp)
            .bind("2026-08-04T01:00:00Z")
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .execute(&pool)
            .await
            .unwrap();
    }

    let metrics = server
        .client()
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        labeled_metric_value(&metrics, "sandboxwich_worker_available_slots "),
        1,
        "resident-process leases must not consume ordinary worker capacity:\n{metrics}"
    );
}

#[tokio::test]
async fn bootstrap_block_rollup_is_bounded_and_monotonic_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("bootstrap-block-rollup.db").display()
    );
    assert_bootstrap_block_rollup_is_bounded_and_monotonic(
        TestServer::start(database_url, Some(data_dir)).await,
    )
    .await;
}

#[tokio::test]
async fn bootstrap_block_rollup_is_bounded_and_monotonic_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    assert_bootstrap_block_rollup_is_bounded_and_monotonic(
        TestServer::start(database_url, None).await,
    )
    .await;
}

#[tokio::test]
async fn operator_global_rollup_decodes_postgres_bigint_sum_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start(database_url, None).await;
    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&server.database_url).await.unwrap();
    for (tenant_id, total) in [("default", 40_i64), ("tenant-b", 2_i64)] {
        sqlx::query(
            "insert into sidecar_bootstrap_block_rollups (tenant_id, reason, total)
             values ($1, $2, $3)",
        )
        .bind(tenant_id)
        .bind("not_running")
        .bind(total)
        .execute(&pool)
        .await
        .unwrap();
    }

    let metrics = server
        .client()
        .get(format!("{}/metrics", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        labeled_metric_value(
            &metrics,
            "sandboxwich_sidecar_bootstrap_block_total{reason=\"not_running\"}",
        ),
        42,
        "operator/global metrics must decode PostgreSQL sum(bigint) as an i64 gauge"
    );
}

#[tokio::test]
async fn metrics_decode_postgres_slo_rollup_bigint_sums_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start(database_url, None).await;
    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&server.database_url).await.unwrap();
    let bucket_start = (Utc::now() - Duration::hours(3)).to_rfc3339();
    sqlx::query(
        "insert into slo_histogram_rollups
         (bucket_start, tenant_id, metric_kind, label_a, label_b, label_c,
          sample_count, sum_ms, b0, b1, b2, b3, b4, b5, b6, b7)
         values ($1, $2, 'command', 'success', '', '', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(bucket_start)
    .bind("default")
    .bind(2_i64)
    .bind(300_i64)
    .bind(1_i64)
    .bind(1_i64)
    .bind(2_i64)
    .bind(2_i64)
    .bind(2_i64)
    .bind(2_i64)
    .bind(2_i64)
    .bind(2_i64)
    .execute(&pool)
    .await
    .unwrap();

    let tenant_metrics = server
        .client()
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        tenant_metrics
            .contains("sandboxwich_command_duration_seconds_count{outcome=\"success\"} 2\n")
    );
    assert!(
        tenant_metrics
            .contains("sandboxwich_command_duration_seconds_sum{outcome=\"success\"} 0.3\n")
    );

    let operator_metrics = server
        .client()
        .get(format!("{}/metrics", server.base_url))
        .header(OPERATOR_TOKEN_HEADER, TEST_OPERATOR_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        operator_metrics
            .contains("sandboxwich_command_duration_seconds_count{outcome=\"success\"} 2\n")
    );
}

async fn assert_bootstrap_block_rollup_is_bounded_and_monotonic(server: TestServer) {
    const RETAINED_EVENT_ROWS: usize = 2_048;
    const DURABLE_TOTAL: i64 = 7;

    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            secret_ref_ids: Vec::new(),
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("bootstrap-block-rollup".into()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    sqlx::any::install_default_drivers();
    let pool = AnyPool::connect(&server.database_url).await.unwrap();
    let postgres = server.database_url.starts_with("postgres:")
        || server.database_url.starts_with("postgresql:");
    let placeholders = |count: usize| {
        (1..=count)
            .map(|index| {
                if postgres {
                    format!("${index}")
                } else {
                    "?".to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    sqlx::query(&format!(
        "insert into sidecar_bootstrap_block_rollups (tenant_id, reason, total) values ({})",
        placeholders(3)
    ))
    .bind("default")
    .bind("not_running")
    .bind(DURABLE_TOTAL)
    .execute(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let event_sql = format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at) values ({})",
        placeholders(5)
    );
    for index in 0..RETAINED_EVENT_ROWS {
        sqlx::query(&event_sql)
            .bind(format!("large-history-{index}"))
            .bind(created.sandbox.id.to_string())
            .bind("lifecycle_changed")
            .bind(r#"{"eventType":"sidecar_bootstrap_blocked","reason":"not_running"}"#)
            .bind("2026-07-18T00:00:00Z")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();

    let metrics = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        labeled_metric_value(
            &metrics,
            "sandboxwich_sidecar_bootstrap_block_total{reason=\"not_running\"}",
        ),
        DURABLE_TOTAL,
        "metric must read the bounded rollup, not scan retained event history"
    );

    sqlx::query(&format!(
        "delete from sandbox_events where sandbox_id = {}",
        placeholders(1)
    ))
    .bind(created.sandbox.id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "delete from sandboxes where id = {}",
        placeholders(1)
    ))
    .bind(created.sandbox.id.to_string())
    .execute(&pool)
    .await
    .unwrap();

    let metrics_after_deletion = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        labeled_metric_value(
            &metrics_after_deletion,
            "sandboxwich_sidecar_bootstrap_block_total{reason=\"not_running\"}",
        ),
        DURABLE_TOTAL,
        "event and sandbox deletion must not decrease the durable counter"
    );
}

fn labeled_metric_value(metrics_text: &str, prefix: &str) -> i64 {
    metrics_text
        .lines()
        .find(|line| line.starts_with(prefix))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_else(|| panic!("{prefix} not found in:\n{metrics_text}"))
}

/// Extracts the value of `sandboxwich_sandbox_count{state="ready"}` from a Prometheus text
/// exposition body produced by `/metrics`.
pub(crate) fn planning_sandbox_gauge(metrics_text: &str) -> i64 {
    metrics_text
        .lines()
        .find(|line| line.starts_with("sandboxwich_sandbox_count{state=\"planning\"}"))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_else(|| {
            panic!("sandboxwich_sandbox_count{{state=\"planning\"}} not found in:\n{metrics_text}")
        })
}

pub(crate) async fn assert_metrics_are_exposed(client: &reqwest::Client, server: &TestServer) {
    let metrics = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("# TYPE sandboxwich_sandbox_count gauge"));
    assert!(metrics.contains("sandboxwich_sandbox_count{state=\"planning\"}"));
    assert!(metrics.contains("# TYPE sandboxwich_archived_runtime_resource_count gauge"));
    assert!(metrics.contains("sandboxwich_worker_capacity_slots"));
    assert!(metrics.contains("sandboxwich_worker_available_slots"));
    assert!(metrics.contains("# TYPE sandboxwich_job_lease_count gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_job_attempts gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_idempotency_record_count gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_guest_token_count gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_cleanup_run_count gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_resident_process_count gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_sidecar_bootstrap_block_total counter"));
    assert!(metrics.contains("# TYPE sandboxwich_job_queue_oldest_seconds gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_worker_heartbeat_oldest_seconds gauge"));
    assert!(metrics.contains("# TYPE sandboxwich_sandbox_creation_seconds histogram"));
    assert!(metrics.contains("# TYPE sandboxwich_sandbox_creation_total counter"));
    assert!(metrics.contains("# TYPE sandboxwich_command_duration_seconds histogram"));
    assert!(metrics.contains("# TYPE sandboxwich_cleanup_duration_seconds histogram"));
    assert!(metrics.contains("# TYPE sandboxwich_worker_claim_seconds histogram"));
    assert!(metrics.contains("# TYPE sandboxwich_provisioning_stage_seconds histogram"));
}

pub(crate) async fn assert_slo_metrics_have_bounded_observations(
    client: &reqwest::Client,
    server: &TestServer,
) {
    let metrics = client
        .get(format!("{}/metrics", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("sandboxwich_sandbox_creation_seconds_bucket{"));
    assert!(metrics.contains("workspace_mode=\"persistent\""));
    assert!(metrics.contains("start_type=\"warm\"") || metrics.contains("start_type=\"cold\""));
    assert!(metrics.contains("sandboxwich_command_duration_seconds_bucket{"));
    assert!(metrics.contains("sandboxwich_cleanup_duration_seconds_bucket{"));
    assert!(metrics.contains("sandboxwich_worker_claim_seconds_bucket{"));
    for forbidden in ["tenant_id=", "sandbox_id=", "command_id=", "hostname="] {
        assert!(!metrics.contains(forbidden), "forbidden label {forbidden}");
    }
}
