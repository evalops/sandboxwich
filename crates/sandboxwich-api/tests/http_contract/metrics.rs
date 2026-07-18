use crate::common::*;
use sandboxwich_core::*;
use sqlx::AnyPool;

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

    // Seed only bounded resident state/event dimensions. The metrics query
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
    for (index, (sandbox_id, reason)) in [
        (default_sandbox_ids[0], "not_running"),
        (tenant_b_sandbox_ids[0], "inactive_lease"),
        (tenant_b_sandbox_ids[0], "expired_lease"),
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query(
            "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
             values (?, ?, 'sidecar_bootstrap_blocked', ?, '2026-07-18T00:00:00Z')",
        )
        .bind(format!("00000000-0000-0000-0000-00000000002{index}"))
        .bind(sandbox_id.to_string())
        .bind(format!(
            r#"{{"reason":"{reason}","processName":"orb-sidecar","generation":1}}"#
        ))
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
