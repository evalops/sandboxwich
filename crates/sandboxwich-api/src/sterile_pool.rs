use crate::config::SterilePoolConfig;
use crate::db::Database;
use crate::error::ApiError;
use crate::handlers::jobs::insert_job_on_connection;
use crate::handlers::sandboxes::{
    fetch_sandbox, fetch_sandbox_on_connection, insert_sandbox_on_connection, sandbox_id_from_job,
    set_sandbox_state_on_connection,
};
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sqlx::{AnyConnection, Row};
use std::time::Duration;
use uuid::Uuid;

pub(crate) const POOL_JOB_MARKER: &str = "sterilePool";
/// Ready admission happens at provision completion, before the supervisor
/// posts guest-health. Keep a short grace so a healthy first probe is not
/// treated as a dead cell.
const GUEST_HEALTH_READY_GRACE: Duration = Duration::from_secs(30);
/// Supervisor heartbeat is 5s. Twelve missed probes matches the agent
/// heartbeat failure threshold and means the supervisor is gone.
const GUEST_HEALTH_PROBE_STALE: Duration = Duration::from_secs(60);

pub(crate) async fn lock_controller_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
) -> Result<(), ApiError> {
    let lock_sql = format!(
        "update sterile_pool_controller_lock set updated_at = {} where singleton = 1",
        db.placeholder(1)
    );
    sqlx::query(&lock_sql)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) fn spawn_sterile_pool_reconciler(
    db: Database,
    config: Option<SterilePoolConfig>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let result = match config.as_ref() {
                Some(config) => reconcile_sterile_pool(&db, config).await.map(|_| ()),
                None => reconcile_sterile_pool_cleanup(&db).await,
            };
            if let Err(error) = result {
                tracing::warn!(?error, "sterile pool reconciliation failed");
            }
        }
    })
}

pub(crate) async fn reconcile_sterile_pool(
    db: &Database,
    config: &SterilePoolConfig,
) -> Result<u32, ApiError> {
    let mut tx = db.pool.begin().await?;
    let now = Utc::now();
    lock_controller_on_connection(db, &mut tx).await?;

    reconcile_sterile_pool_cleanup_on_connection(db, &mut tx, now).await?;

    // Claims are committed by a different request path. Fold them into pool
    // membership under this same replenishment lock before counting reserve.
    let lease_sync = format!(
        "update sterile_pool_memberships
         set state = 'leased', lease_id = (select lease_id from sterile_cells where id = sandbox_id),
             generation = (select generation from sterile_cells where id = sandbox_id), updated_at = {}
         where state = 'ready' and exists (
           select 1 from sterile_cells where sterile_cells.id = sandbox_id and sterile_cells.state = 'leased'
         )",
        db.placeholder(1)
    );
    sqlx::query(&lease_sync)
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    let quarantine_sync = format!(
        "update sterile_pool_memberships set state = 'quarantined', quarantine_reason = 'cell_terminalized_outside_pool', updated_at = {}
         where state = 'provisioning' and exists (
           select 1 from sterile_cells where sterile_cells.id = sandbox_id and sterile_cells.state = 'quarantined'
         )",
        db.placeholder(1)
    );
    sqlx::query(&quarantine_sync)
        .bind(now.to_rfc3339())
        .execute(&mut *tx)
        .await?;
    enqueue_expired_ready_stops_on_connection(db, &mut tx, now).await?;
    enqueue_expired_leased_stops_on_connection(db, &mut tx, now).await?;

    let count_sql = format!(
        "select
             sum(case when state in ('provisioning', 'ready', 'leased', 'stopping', 'cleanup_pending') then 1 else 0 end) as live_count,
             sum(case when state = 'provisioning' then 1 else 0 end) as provisioning_count
         from sterile_pool_memberships
         where tenant_id = {} and release_set_id = {} and runtime_class = {}
           and policy_digest = {} and release_signature = {}
           and candidate_agent_image = {} and candidate_maestro_image = {}
           ",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7)
    );
    let counts = sqlx::query(&count_sql)
        .bind(&config.tenant_id)
        .bind(&config.release.release_set_id)
        .bind(config.release.runtime_class.as_db_str())
        .bind(&config.release.policy_digest)
        .bind(&config.release.signature)
        .bind(&config.agent_image)
        .bind(&config.maestro_image)
        .fetch_one(&mut *tx)
        .await?;
    let live_count = counts
        .try_get::<Option<i64>, _>("live_count")?
        .unwrap_or_default();
    let provisioning_count = counts
        .try_get::<Option<i64>, _>("provisioning_count")?
        .unwrap_or_default();
    let to_create = i64::from(config.target)
        .saturating_sub(live_count)
        .max(0)
        .min(
            i64::from(config.max_provisioning)
                .saturating_sub(provisioning_count)
                .max(0),
        );
    for _ in 0..to_create {
        insert_pool_member_on_connection(db, &mut tx, config, now).await?;
    }
    tx.commit().await?;
    u32::try_from(to_create).map_err(|_| ApiError::internal("sterile pool target exceeds range"))
}

pub(crate) async fn reconcile_sterile_pool_cleanup(db: &Database) -> Result<(), ApiError> {
    let mut tx = db.pool.begin().await?;
    let now = Utc::now();
    lock_controller_on_connection(db, &mut tx).await?;
    reconcile_sterile_pool_cleanup_on_connection(db, &mut tx, now).await?;
    enqueue_expired_ready_stops_on_connection(db, &mut tx, now).await?;
    enqueue_expired_leased_stops_on_connection(db, &mut tx, now).await?;
    tx.commit().await?;
    Ok(())
}

async fn reconcile_sterile_pool_cleanup_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    enqueue_cleanup_pending_stops_on_connection(db, connection, now).await
}

async fn insert_pool_member_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    config: &SterilePoolConfig,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    let sandbox_id = SandboxId::new();
    let job_id = JobId::new();
    let execution_class = match config.release.runtime_class {
        SterileCellRuntimeClass::KataMicrovm => ExecutionClass::VirtualMachine,
        SterileCellRuntimeClass::GvisorLowerRisk => ExecutionClass::SandboxedContainer,
    };
    let sandbox = Sandbox {
        id: sandbox_id,
        tenant_id: config.tenant_id.clone(),
        name: format!("sterile-pool-{}", &sandbox_id.to_string()[..12]),
        state: SandboxState::Planning,
        template: config.template.clone(),
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::DenyAll,
        workspace_mode: WorkspaceMode::Persistent,
        runtime_profile: config.sandbox_profile.clone(),
        execution_class: execution_class.clone(),
        created_at: now,
        updated_at: now,
        ttl_seconds: None,
        max_lifetime_seconds: None,
        idle_ttl_seconds: None,
        parent_snapshot_id: None,
        last_activity_at: None,
    };
    let provision_spec = SandboxProvisionSpec {
        memory_limit: sandbox.memory_limit.clone(),
        network_egress: sandbox.network_egress.clone(),
        workspace_mode: sandbox.workspace_mode.clone(),
        runtime_profile: sandbox.runtime_profile.clone(),
        execution_class: execution_class.clone(),
        provider_preference: ProviderPreference::Kubernetes,
        tenant_id: Some(config.tenant_id.clone()),
        provider_external_id: None,
        provider_routing_scope: None,
        secret_mounts: Vec::new(),
        sterile_pool_candidate: Some(SterilePoolCandidateV1 {
            cell_id: SterileCellId(sandbox_id.0),
            release: config.release.clone(),
            agent_image: config.agent_image.clone(),
            maestro_image: config.maestro_image.clone(),
            service_name: sandboxwich_core::sterile_maestro_candidate_service_name(SterileCellId(
                sandbox_id.0,
            )),
            pod_name: None,
            pod_uid: None,
        }),
    };
    let job = Job {
        id: job_id,
        tenant_id: config.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "runtimeImage": sandbox.template,
            "provisionSpec": provision_spec,
            POOL_JOB_MARKER: {
                "cellId": sandbox_id,
                "providerCellId": sandbox_id,
                "release": config.release,
                "readyTtlSeconds": config.ready_ttl.as_secs(),
            }
        }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: execution_class,
        priority: 50,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_sandbox_on_connection(db, connection, &sandbox).await?;
    insert_job_on_connection(db, connection, &job).await?;
    let sql = format!(
        "insert into sterile_pool_memberships
         (sandbox_id, tenant_id, state, provision_job_id, release_set_id, runtime_class,
          policy_digest, release_signature, candidate_agent_image, candidate_maestro_image,
          candidate_service_name, ready_ttl_seconds, created_at, updated_at)
         values ({})",
        db.placeholders(14)
    );
    sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(&config.tenant_id)
        .bind("provisioning")
        .bind(job_id.to_string())
        .bind(&config.release.release_set_id)
        .bind(config.release.runtime_class.as_db_str())
        .bind(&config.release.policy_digest)
        .bind(&config.release.signature)
        .bind(&config.agent_image)
        .bind(&config.maestro_image)
        .bind(sandboxwich_core::sterile_maestro_candidate_service_name(
            SterileCellId(sandbox_id.0),
        ))
        .bind(
            i64::try_from(config.ready_ttl.as_secs())
                .map_err(|_| ApiError::internal("sterile pool ready TTL exceeds range"))?,
        )
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn enqueue_cleanup_pending_stops_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = "select sandbox_id, lease_id, generation, provision_job_id,
                      requested_disposition
               from sterile_pool_memberships p
               where state = 'cleanup_pending'
                 and (stop_job_id is null or exists (
                   select 1 from jobs j where j.id = p.stop_job_id and j.status in ('failed', 'dead')
                 ))
               order by updated_at asc, sandbox_id asc limit 100";
    let rows = sqlx::query(sql).fetch_all(&mut *connection).await?;
    for row in rows {
        let sandbox_id = SandboxId(
            Uuid::parse_str(row.try_get("sandbox_id")?)
                .map_err(|error| ApiError::internal(error.to_string()))?,
        );
        let lease_id: Option<String> = row.try_get("lease_id")?;
        let generation: i64 = row.try_get("generation")?;
        let disposition: String = row.try_get("requested_disposition")?;
        let provision_job_id: String = row.try_get("provision_job_id")?;
        let provision_payload_sql =
            format!("select payload from jobs where id = {}", db.placeholder(1));
        let provision_payload: String = sqlx::query_scalar(&provision_payload_sql)
            .bind(provision_job_id)
            .fetch_one(&mut *connection)
            .await?;
        let provision_payload: serde_json::Value = serde_json::from_str(&provision_payload)?;
        let provision_spec = provision_payload
            .get("provisionSpec")
            .cloned()
            .ok_or_else(|| {
                ApiError::internal("sterile pool provision job lost its provider specification")
            })?;
        let sandbox = fetch_sandbox_on_connection(db, connection, sandbox_id).await?;
        let _ = set_sandbox_state_on_connection(
            db,
            connection,
            sandbox_id,
            SandboxState::STOP_LEGAL_FROM,
            SandboxState::Archiving,
            json!({"state": SandboxState::Archiving, "reason": "sterile_pool_cleanup_retry"}),
        )
        .await?;
        let stop_job = Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id.clone(),
            kind: JobKind::StopSandbox,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": sandbox_id,
                "deleteGkeFqdnPolicy": true,
                "provisionSpec": provision_spec,
                POOL_JOB_MARKER: {
                    "cellId": SterileCellId(sandbox_id.0),
                    "providerCellId": sandbox_id,
                    "leaseId": lease_id,
                    "generation": u64::try_from(generation).map_err(|_| ApiError::internal("generation is outside the valid range"))?,
                    "disposition": SterileCellDisposition::parse_db_str(&disposition)
                        .map_err(|error| ApiError::internal(error.to_string()))?,
                    "reason": "cleanup_retry",
                }
            }),
            required_capability: WorkerCapability::ProvisionSandbox,
            required_execution_class: sandbox.execution_class,
            priority: 1000,
            attempts: 0,
            max_attempts: 1,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        };
        insert_job_on_connection(db, connection, &stop_job).await?;
        let update = format!(
            "update sterile_pool_memberships set state = 'stopping', stop_job_id = {}, updated_at = {}
             where sandbox_id = {} and state = 'cleanup_pending'",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3)
        );
        let updated = sqlx::query(&update)
            .bind(stop_job.id.to_string())
            .bind(now.to_rfc3339())
            .bind(sandbox_id.to_string())
            .execute(&mut *connection)
            .await?;
        if updated.rows_affected() != 1 {
            let delete = format!("delete from jobs where id = {}", db.placeholder(1));
            sqlx::query(&delete)
                .bind(stop_job.id.to_string())
                .execute(&mut *connection)
                .await?;
        }
    }
    Ok(())
}

async fn enqueue_expired_ready_stops_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    let grace_cutoff = now
        - chrono::Duration::from_std(GUEST_HEALTH_READY_GRACE)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let stale_cutoff = now
        - chrono::Duration::from_std(GUEST_HEALTH_PROBE_STALE)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let sql = format!(
        "select p.sandbox_id, p.worker_id, j.payload,
                case
                  when p.cell_expires_at <= {now_ttl} or c.state = 'quarantined' then 'ready_ttl_expired'
                  else 'guest_health_unready'
                end as stop_reason
         from sterile_pool_memberships p
         join jobs j on j.id = p.provision_job_id
         join sterile_cells c on c.id = p.sandbox_id
         where p.state = 'ready' and (
           p.cell_expires_at <= {now_ready}
           or c.state = 'quarantined'
           or (
             p.updated_at <= {grace}
             and not exists (
               select 1 from guest_health g
               where g.sandbox_id = p.sandbox_id
                 and g.status = 'ready'
                 and g.last_probe_at > {stale}
             )
           )
         )
         order by p.cell_expires_at asc, p.sandbox_id asc limit 100",
        now_ttl = db.placeholder(1),
        now_ready = db.placeholder(2),
        grace = db.placeholder(3),
        stale = db.placeholder(4),
    );
    let rows = sqlx::query(&sql)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(grace_cutoff.to_rfc3339())
        .bind(stale_cutoff.to_rfc3339())
        .fetch_all(&mut *connection)
        .await?;
    for row in rows {
        let sandbox_id = SandboxId(
            Uuid::parse_str(row.try_get("sandbox_id")?)
                .map_err(|error| ApiError::internal(error.to_string()))?,
        );
        let worker_id: String = row.try_get("worker_id")?;
        let stop_reason: String = row.try_get("stop_reason")?;
        let archive_reason = match stop_reason.as_str() {
            "guest_health_unready" => "sterile_pool_guest_health_unready",
            _ => "sterile_pool_ready_expired",
        };
        let provision_payload: String = row.try_get("payload")?;
        let provision_payload: serde_json::Value = serde_json::from_str(&provision_payload)?;
        let provision_spec = provision_payload
            .get("provisionSpec")
            .cloned()
            .ok_or_else(|| ApiError::internal("pool provision job lost provider specification"))?;
        let sandbox = fetch_sandbox_on_connection(db, connection, sandbox_id).await?;
        if !set_sandbox_state_on_connection(
            db,
            connection,
            sandbox_id,
            SandboxState::STOP_LEGAL_FROM,
            SandboxState::Archiving,
            json!({"state": SandboxState::Archiving, "reason": archive_reason}),
        )
        .await?
        {
            return Err(ApiError::conflict(
                "expired sterile pool sandbox changed before teardown",
            ));
        }
        let stop_job = Job {
            id: JobId::new(),
            tenant_id: sandbox.tenant_id.clone(),
            kind: JobKind::StopSandbox,
            status: JobStatus::Queued,
            payload: json!({
                "sandboxId": sandbox_id,
                "deleteGkeFqdnPolicy": true,
                "provisionSpec": provision_spec,
                POOL_JOB_MARKER: {
                    "cellId": SterileCellId(sandbox_id.0),
                    "providerCellId": sandbox_id,
                    "leaseId": null,
                    "generation": 1,
                    "disposition": SterileCellDisposition::Quarantined,
                    "reason": stop_reason,
                }
            }),
            required_capability: WorkerCapability::ProvisionSandbox,
            required_execution_class: sandbox.execution_class,
            priority: 1000,
            attempts: 0,
            max_attempts: 1,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        };
        insert_job_on_connection(db, connection, &stop_job).await?;
        let update = format!(
            "update sterile_pool_memberships set state = 'stopping', stop_job_id = {}, generation = 1,
             requested_disposition = 'quarantined', quarantine_reason = {}, updated_at = {}
             where sandbox_id = {} and worker_id = {} and state = 'ready' and generation = 1",
            db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4), db.placeholder(5)
        );
        let updated = sqlx::query(&update)
            .bind(stop_job.id.to_string())
            .bind(&stop_reason)
            .bind(now.to_rfc3339())
            .bind(sandbox_id.to_string())
            .bind(worker_id)
            .execute(&mut *connection)
            .await?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::conflict(
                "expired sterile pool cell changed during teardown",
            ));
        }
    }
    Ok(())
}

async fn enqueue_expired_leased_stops_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    now: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "select p.sandbox_id, p.worker_id, p.lease_id, p.generation
         from sterile_pool_memberships p
         join sterile_cells c on c.id = p.sandbox_id
         where p.state = 'leased' and (
           c.state = 'quarantined'
           or c.cell_expires_at <= {}
           or (c.lease_expires_at is not null and c.lease_expires_at <= {})
         )
         order by p.updated_at asc, p.sandbox_id asc limit 100",
        db.placeholder(1),
        db.placeholder(2)
    );
    let rows = sqlx::query(&sql)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .fetch_all(&mut *connection)
        .await?;
    for row in rows {
        let cell_id = SterileCellId(
            Uuid::parse_str(row.try_get("sandbox_id")?)
                .map_err(|error| ApiError::internal(error.to_string()))?,
        );
        let worker_id = WorkerId(
            Uuid::parse_str(row.try_get("worker_id")?)
                .map_err(|error| ApiError::internal(error.to_string()))?,
        );
        let lease_id = Uuid::parse_str(row.try_get("lease_id")?)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let generation: i64 = row.try_get("generation")?;
        let generation = u64::try_from(generation)
            .map_err(|_| ApiError::internal("pool generation is outside the valid range"))?;
        enqueue_pool_stop_with_policy_on_connection(
            db,
            connection,
            worker_id,
            cell_id,
            lease_id,
            generation,
            SterileCellDisposition::Quarantined,
            false,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn admit_provisioned_cell_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    if job.payload.get(POOL_JOB_MARKER).is_none() {
        return Ok(());
    }
    let sandbox_id = sandbox_id_from_job(job)?;
    let placement_sql = format!(
        "select worker_id from sandbox_placements where sandbox_id = {}",
        db.placeholder(1)
    );
    let worker_id: String = sqlx::query_scalar(&placement_sql)
        .bind(sandbox_id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    let membership_sql = format!(
        "select ready_ttl_seconds from sterile_pool_memberships
         where sandbox_id = {} and provision_job_id = {} and state = 'provisioning'",
        db.placeholder(1),
        db.placeholder(2)
    );
    let ready_ttl_seconds: i64 = sqlx::query_scalar(&membership_sql)
        .bind(sandbox_id.to_string())
        .bind(job.id.to_string())
        .fetch_one(&mut *connection)
        .await?;
    let pod_identity_sql = format!(
        "select resource_name, resource_uid
         from provisioning_operation_resources
         where sandbox_id = {} and stage = 'pod_ready' and resource_kind = 'pod'
           and resource_name = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let expected_pod_name = format!("sandboxwich-{sandbox_id}");
    let pod_identity = sqlx::query(&pod_identity_sql)
        .bind(sandbox_id.to_string())
        .bind(&expected_pod_name)
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| {
            ApiError::conflict(
                "sterile pool candidate completion is missing its exact Pod identity",
            )
        })?;
    let candidate_pod_name: String = pod_identity.try_get("resource_name")?;
    let candidate_pod_uid: String = pod_identity.try_get("resource_uid")?;
    if candidate_pod_uid.trim().is_empty() {
        return Err(ApiError::conflict(
            "sterile pool candidate completion reported an empty Pod UID",
        ));
    }
    let expires_at = Utc::now() + chrono::Duration::seconds(ready_ttl_seconds);
    let sql = format!(
        "insert into sterile_cells
         (id, worker_id, provider_cell_id, state, generation, release_set_id, runtime_class,
          policy_digest, release_signature, tenant_id, cell_expires_at, created_at, updated_at)
         select sandbox_id, {}, sandbox_id, 'ready', 1, release_set_id, runtime_class,
                policy_digest, release_signature, tenant_id, {}, {}, {}
         from sterile_pool_memberships
         where sandbox_id = {} and provision_job_id = {} and state = 'provisioning'
         on conflict (id) do nothing",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let now = Utc::now().to_rfc3339();
    let inserted = sqlx::query(&sql)
        .bind(&worker_id)
        .bind(expires_at.to_rfc3339())
        .bind(&now)
        .bind(&now)
        .bind(sandbox_id.to_string())
        .bind(job.id.to_string())
        .execute(&mut *connection)
        .await?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "sterile pool provision completion is stale or ambiguous",
        ));
    }
    let update = format!(
        "update sterile_pool_memberships set state = 'ready', worker_id = {}, generation = 1,
         candidate_pod_name = {}, candidate_pod_uid = {}, cell_expires_at = {}, updated_at = {}
         where sandbox_id = {} and provision_job_id = {} and state = 'provisioning'",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7)
    );
    let updated = sqlx::query(&update)
        .bind(worker_id)
        .bind(candidate_pod_name)
        .bind(candidate_pod_uid)
        .bind(expires_at.to_rfc3339())
        .bind(&now)
        .bind(sandbox_id.to_string())
        .bind(job.id.to_string())
        .execute(&mut *connection)
        .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("sterile pool admission fence changed"));
    }
    Ok(())
}

pub(crate) async fn record_pool_claim_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    cell_id: SterileCellId,
    lease_id: Uuid,
    generation: u64,
) -> Result<(), ApiError> {
    let sql = format!(
        "update sterile_pool_memberships set state = 'leased', lease_id = {}, generation = {}, updated_at = {}
         where sandbox_id = {} and state = 'ready' and generation = 1",
        db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4)
    );
    let updated = sqlx::query(&sql)
        .bind(lease_id.to_string())
        .bind(i64::try_from(generation).map_err(|_| ApiError::bad_request("generation too large"))?)
        .bind(Utc::now().to_rfc3339())
        .bind(cell_id.to_string())
        .execute(&mut *connection)
        .await?;
    if updated.rows_affected() != 1 {
        let membership = format!(
            "select 1 from sterile_pool_memberships where sandbox_id = {}",
            db.placeholder(1)
        );
        if sqlx::query(&membership)
            .bind(cell_id.to_string())
            .fetch_optional(&mut *connection)
            .await?
            .is_some()
        {
            return Err(ApiError::conflict(
                "sterile pool claim membership fence changed",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn enqueue_pool_stop_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    worker_id: WorkerId,
    cell_id: SterileCellId,
    lease_id: Uuid,
    generation: u64,
    disposition: SterileCellDisposition,
) -> Result<bool, ApiError> {
    enqueue_pool_stop_with_policy_on_connection(
        db,
        connection,
        worker_id,
        cell_id,
        lease_id,
        generation,
        disposition,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_pool_stop_with_policy_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    worker_id: WorkerId,
    cell_id: SterileCellId,
    lease_id: Uuid,
    generation: u64,
    disposition: SterileCellDisposition,
    require_live_lease: bool,
) -> Result<bool, ApiError> {
    // A release changes a live membership into another live state. Serialize
    // that transition with reconciliation so a concurrent count cannot create
    // a replacement before the stopping/cleanup_pending row is visible.
    lock_controller_on_connection(db, connection).await?;
    let membership_sql = format!(
        "select provision_job_id, state, worker_id, lease_id, generation, requested_disposition
         from sterile_pool_memberships where sandbox_id = {}",
        db.placeholder(1)
    );
    let Some(row) = sqlx::query(&membership_sql)
        .bind(cell_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(false);
    };
    let state: String = row.try_get("state")?;
    if state == "stopping"
        && row.try_get::<Option<String>, _>("lease_id")?.as_deref()
            == Some(lease_id.to_string().as_str())
        && row.try_get::<Option<i64>, _>("generation")? == i64::try_from(generation).ok()
        && row
            .try_get::<Option<String>, _>("requested_disposition")?
            .as_deref()
            == Some(disposition.as_db_str())
    {
        return Ok(true);
    }
    if state != "leased"
        || row.try_get::<Option<String>, _>("worker_id")?.as_deref()
            != Some(worker_id.to_string().as_str())
        || row.try_get::<Option<String>, _>("lease_id")?.as_deref()
            != Some(lease_id.to_string().as_str())
        || row.try_get::<Option<i64>, _>("generation")? != i64::try_from(generation).ok()
    {
        mark_pool_cleanup_pending_on_connection(
            db,
            connection,
            cell_id,
            "cleanup_fence_mismatch",
            true,
        )
        .await?;
        return Err(ApiError::conflict(
            "sterile-cell cleanup fence is ambiguous; cell was quarantined",
        ));
    }
    let provision_job_id: String = row.try_get("provision_job_id")?;
    let provision_payload_sql =
        format!("select payload from jobs where id = {}", db.placeholder(1));
    let provision_payload: String = sqlx::query_scalar(&provision_payload_sql)
        .bind(provision_job_id)
        .fetch_one(&mut *connection)
        .await?;
    let provision_payload: serde_json::Value = serde_json::from_str(&provision_payload)?;
    let provision_spec = provision_payload
        .get("provisionSpec")
        .cloned()
        .ok_or_else(|| {
            ApiError::internal("sterile pool provision job lost its provider specification")
        })?;
    let sandbox = fetch_sandbox_on_connection(db, connection, SandboxId(cell_id.0)).await?;
    let now = Utc::now();
    let stop_job_id = JobId::new();
    let generation =
        i64::try_from(generation).map_err(|_| ApiError::bad_request("generation too large"))?;
    let stop_job = Job {
        id: stop_job_id,
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::StopSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox.id,
            "deleteGkeFqdnPolicy": true,
            "provisionSpec": provision_spec,
            POOL_JOB_MARKER: {
                "cellId": cell_id,
                "providerCellId": cell_id,
                "leaseId": lease_id,
                "generation": u64::try_from(generation).map_err(|_| ApiError::internal("generation is outside the valid range"))?,
                "disposition": disposition,
            }
        }),
        required_capability: WorkerCapability::ProvisionSandbox,
        required_execution_class: sandbox.execution_class.clone(),
        priority: 1000,
        attempts: 0,
        max_attempts: 1,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    insert_job_on_connection(db, connection, &stop_job).await?;
    let update = if require_live_lease {
        format!(
            "update sterile_pool_memberships set state = 'stopping', stop_job_id = {}, requested_disposition = {}, updated_at = {}
             where sandbox_id = {} and state = 'leased' and worker_id = {} and lease_id = {} and generation = {}
               and exists (select 1 from sterile_cells c where c.id = {} and c.state = 'leased'
                 and c.lease_id = {} and c.generation = {} and c.lease_expires_at > {})",
            db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4),
            db.placeholder(5), db.placeholder(6), db.placeholder(7), db.placeholder(8),
            db.placeholder(9), db.placeholder(10), db.placeholder(11)
        )
    } else {
        format!(
            "update sterile_pool_memberships set state = 'stopping', stop_job_id = {}, requested_disposition = {}, updated_at = {}
             where sandbox_id = {} and state = 'leased' and worker_id = {} and lease_id = {} and generation = {}",
            db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4),
            db.placeholder(5), db.placeholder(6), db.placeholder(7)
        )
    };
    let mut update_query = sqlx::query(&update)
        .bind(stop_job_id.to_string())
        .bind(disposition.as_db_str())
        .bind(now.to_rfc3339())
        .bind(cell_id.to_string())
        .bind(worker_id.to_string())
        .bind(lease_id.to_string())
        .bind(generation);
    if require_live_lease {
        update_query = update_query
            .bind(cell_id.to_string())
            .bind(lease_id.to_string())
            .bind(generation)
            .bind(now.to_rfc3339());
    }
    let updated = update_query.execute(&mut *connection).await?;
    if updated.rows_affected() != 1 {
        let delete_job = format!("delete from jobs where id = {}", db.placeholder(1));
        sqlx::query(&delete_job)
            .bind(stop_job.id.to_string())
            .execute(&mut *connection)
            .await?;
        let retry = sqlx::query(&membership_sql)
            .bind(cell_id.to_string())
            .fetch_optional(&mut *connection)
            .await?;
        if let Some(retry) = retry
            && retry.try_get::<String, _>("state")? == "stopping"
            && retry.try_get::<Option<String>, _>("lease_id")?.as_deref()
                == Some(lease_id.to_string().as_str())
            && retry.try_get::<Option<i64>, _>("generation")? == Some(generation)
            && retry
                .try_get::<Option<String>, _>("requested_disposition")?
                .as_deref()
                == Some(disposition.as_db_str())
        {
            return Ok(true);
        }
        quarantine_pool_cell_record_on_connection(db, connection, cell_id).await?;
        return Err(ApiError::conflict(
            "sterile pool cleanup fence changed; cell was quarantined",
        ));
    }
    if !set_sandbox_state_on_connection(
        db,
        connection,
        sandbox.id,
        SandboxState::STOP_LEGAL_FROM,
        SandboxState::Archiving,
        json!({"state": SandboxState::Archiving, "reason": "sterile_pool_released"}),
    )
    .await?
    {
        quarantine_pool_cell_record_on_connection(db, connection, cell_id).await?;
        let reason = format!(
            "update sterile_pool_memberships set quarantine_reason = {}, updated_at = {}
             where sandbox_id = {} and state = 'stopping' and stop_job_id = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4)
        );
        sqlx::query(&reason)
            .bind("sandbox_stop_state_ambiguous")
            .bind(Utc::now().to_rfc3339())
            .bind(cell_id.to_string())
            .bind(stop_job.id.to_string())
            .execute(&mut *connection)
            .await?;
    }
    Ok(true)
}

pub(crate) async fn complete_pool_stop_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
) -> Result<(), ApiError> {
    let Some(fence) = job.payload.get(POOL_JOB_MARKER) else {
        return Ok(());
    };
    if job.kind != JobKind::StopSandbox {
        return Ok(());
    }
    let cell_id: SterileCellId = serde_json::from_value(
        fence
            .get("cellId")
            .cloned()
            .ok_or_else(|| ApiError::internal("pool stop is missing cellId"))?,
    )?;
    let lease_id: Option<Uuid> = fence
        .get("leaseId")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let generation = fence
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ApiError::internal("pool stop is missing generation"))?;
    let disposition: SterileCellDisposition = serde_json::from_value(
        fence
            .get("disposition")
            .cloned()
            .ok_or_else(|| ApiError::internal("pool stop is missing disposition"))?,
    )?;
    let generation_i64 = i64::try_from(generation)
        .map_err(|_| ApiError::internal("generation exceeds database range"))?;
    let membership_fence = if lease_id.is_some() {
        format!(
            "select 1 from sterile_pool_memberships where sandbox_id = {}
             and state in ('stopping', 'cleanup_pending') and lease_id = {} and generation = {}
             and requested_disposition = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4)
        )
    } else {
        format!(
            "select 1 from sterile_pool_memberships where sandbox_id = {}
             and state in ('stopping', 'cleanup_pending') and lease_id is null and generation = {}
             and requested_disposition = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3)
        )
    };
    let mut fence_query = sqlx::query(&membership_fence).bind(cell_id.to_string());
    if let Some(lease_id) = lease_id {
        fence_query = fence_query.bind(lease_id.to_string());
    }
    if fence_query
        .bind(generation_i64)
        .bind(disposition.as_db_str())
        .fetch_optional(&mut *connection)
        .await?
        .is_none()
    {
        mark_pool_cleanup_pending_on_connection(
            db,
            connection,
            cell_id,
            "provider_stop_completion_fence_mismatch",
            true,
        )
        .await?;
        return Ok(());
    }
    let cell_fence = if lease_id.is_some() {
        format!(
            "select state, disposition from sterile_cells where id = {} and lease_id = {} and generation = {}
             and state in ('leased', 'destroyed', 'quarantined')",
            db.placeholder(1), db.placeholder(2), db.placeholder(3)
        )
    } else {
        format!(
            "select state, disposition from sterile_cells where id = {} and lease_id is null and generation = {}
             and state in ('ready', 'destroyed', 'quarantined')",
            db.placeholder(1), db.placeholder(2)
        )
    };
    let mut cell_fence_query = sqlx::query(&cell_fence).bind(cell_id.to_string());
    if let Some(lease_id) = lease_id {
        cell_fence_query = cell_fence_query.bind(lease_id.to_string());
    }
    let Some(cell_row) = cell_fence_query
        .bind(generation_i64)
        .fetch_optional(&mut *connection)
        .await?
    else {
        mark_pool_cleanup_pending_on_connection(
            db,
            connection,
            cell_id,
            "provider_stop_cell_fence_mismatch",
            true,
        )
        .await?;
        return Ok(());
    };
    let prior_cell_state: String = cell_row.try_get("state")?;
    let prior_disposition: Option<String> = cell_row.try_get("disposition")?;
    if prior_cell_state == SterileCellState::Destroyed.as_db_str()
        && prior_disposition.as_deref() != Some(disposition.as_db_str())
    {
        mark_pool_cleanup_pending_on_connection(
            db,
            connection,
            cell_id,
            "provider_stop_terminal_disposition_mismatch",
            true,
        )
        .await?;
        return Ok(());
    }
    let now = Utc::now().to_rfc3339();
    let cell_update = if lease_id.is_some() {
        format!(
            "update sterile_cells set state = {}, disposition = {}, destroyed_at = {}, updated_at = {}
             where id = {} and state in ('leased', 'destroyed', 'quarantined') and lease_id = {} and generation = {}",
            db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4),
            db.placeholder(5), db.placeholder(6), db.placeholder(7)
        )
    } else {
        format!(
            "update sterile_cells set state = {}, disposition = {}, destroyed_at = {}, updated_at = {}
             where id = {} and state in ('ready', 'destroyed', 'quarantined') and lease_id is null and generation = {}",
            db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4),
            db.placeholder(5), db.placeholder(6)
        )
    };
    let terminal_disposition = if prior_cell_state == SterileCellState::Quarantined.as_db_str() {
        SterileCellDisposition::Quarantined
    } else {
        disposition.clone()
    };
    let cell_state = match terminal_disposition {
        SterileCellDisposition::Destroyed => SterileCellState::Destroyed,
        SterileCellDisposition::Quarantined => SterileCellState::Quarantined,
    };
    let mut cell_query = sqlx::query(&cell_update)
        .bind(cell_state.as_db_str())
        .bind(terminal_disposition.as_db_str())
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string());
    if let Some(lease_id) = lease_id {
        cell_query = cell_query.bind(lease_id.to_string());
    }
    let updated = cell_query
        .bind(generation_i64)
        .execute(&mut *connection)
        .await?;
    if updated.rows_affected() != 1 {
        mark_pool_cleanup_pending_on_connection(
            db,
            connection,
            cell_id,
            "provider_stop_completion_fence_mismatch",
            true,
        )
        .await?;
        return Ok(());
    }
    let membership_update = if lease_id.is_some() {
        format!(
            "update sterile_pool_memberships set state = {}, provider_absent = 1, updated_at = {}
             where sandbox_id = {} and state in ('stopping', 'cleanup_pending') and lease_id = {}
               and generation = {} and requested_disposition = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4),
            db.placeholder(5),
            db.placeholder(6)
        )
    } else {
        format!(
            "update sterile_pool_memberships set state = {}, provider_absent = 1, updated_at = {}
             where sandbox_id = {} and state in ('stopping', 'cleanup_pending') and lease_id is null
               and generation = {} and requested_disposition = {}",
            db.placeholder(1),
            db.placeholder(2),
            db.placeholder(3),
            db.placeholder(4),
            db.placeholder(5)
        )
    };
    let mut membership_query = sqlx::query(&membership_update)
        .bind(cell_state.as_db_str())
        .bind(&now)
        .bind(cell_id.to_string());
    if let Some(lease_id) = lease_id {
        membership_query = membership_query.bind(lease_id.to_string());
    }
    let member = membership_query
        .bind(generation_i64)
        .bind(disposition.as_db_str())
        .execute(&mut *connection)
        .await?;
    if member.rows_affected() != 1 {
        mark_pool_cleanup_pending_on_connection(
            db,
            connection,
            cell_id,
            "provider_stop_membership_fence_mismatch",
            true,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn quarantine_failed_pool_job_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    job: &Job,
    error: &str,
) -> Result<(), ApiError> {
    if job.payload.get(POOL_JOB_MARKER).is_none() {
        return Ok(());
    }
    let cell_id = SterileCellId(sandbox_id_from_job(job)?.0);
    if job.kind == JobKind::StopSandbox {
        mark_pool_cleanup_pending_on_connection(db, connection, cell_id, error, false).await
    } else {
        quarantine_pool_cell_on_connection(db, connection, cell_id, error).await
    }
}

async fn mark_pool_cleanup_pending_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    cell_id: SterileCellId,
    reason: &str,
    clear_stop_job: bool,
) -> Result<(), ApiError> {
    quarantine_pool_cell_record_on_connection(db, connection, cell_id).await?;
    let now = Utc::now().to_rfc3339();
    let stop_job = if clear_stop_job {
        "stop_job_id = null, "
    } else {
        ""
    };
    let sql = format!(
        "update sterile_pool_memberships set state = 'cleanup_pending', {stop_job}
             requested_disposition = coalesce(requested_disposition, 'quarantined'),
             quarantine_reason = {}, updated_at = {}
         where sandbox_id = {} and state not in ('destroyed', 'quarantined')",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    sqlx::query(&sql)
        .bind(reason)
        .bind(&now)
        .bind(cell_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn quarantine_pool_cell_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    cell_id: SterileCellId,
    reason: &str,
) -> Result<(), ApiError> {
    quarantine_pool_cell_record_on_connection(db, connection, cell_id).await?;
    let now = Utc::now().to_rfc3339();
    let member = format!(
        "update sterile_pool_memberships set state = 'quarantined', quarantine_reason = {}, updated_at = {}
         where sandbox_id = {} and state not in ('destroyed', 'quarantined')",
        db.placeholder(1), db.placeholder(2), db.placeholder(3)
    );
    sqlx::query(&member)
        .bind(reason)
        .bind(&now)
        .bind(cell_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn quarantine_pool_cell_record_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    cell_id: SterileCellId,
) -> Result<(), ApiError> {
    let now = Utc::now().to_rfc3339();
    let cell = format!(
        "update sterile_cells set state = 'quarantined', disposition = 'quarantined', destroyed_at = {}, updated_at = {}
         where id = {} and state in ('ready', 'leased')",
        db.placeholder(1), db.placeholder(2), db.placeholder(3)
    );
    sqlx::query(&cell)
        .bind(&now)
        .bind(&now)
        .bind(cell_id.to_string())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn sandbox_is_pool_reserved(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select 1 from sterile_pool_memberships where sandbox_id = {} and state in ('provisioning', 'ready', 'leased', 'stopping', 'cleanup_pending')",
        db.placeholder(1)
    );
    Ok(sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .is_some())
}

pub(crate) async fn sandbox_has_pool_membership(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select 1 from sterile_pool_memberships where sandbox_id = {}",
        db.placeholder(1)
    );
    Ok(sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(db.read_pool())
        .await?
        .is_some())
}

/// Purpose-built escape hatch for sterile activation. Ordinary tenant
/// handlers must continue through `ensure_sandbox_tenant`, which hides every
/// nonterminal pool member. This lookup admits only the exact live lease
/// fence and never treats tenant ownership alone as sandbox authority.
#[allow(dead_code)]
pub(crate) async fn fetch_exact_leased_pool_sandbox(
    db: &Database,
    tenant_id: &str,
    sandbox_id: SandboxId,
    lease_id: Uuid,
    generation: u64,
) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select 1 from sterile_pool_memberships
         where sandbox_id = {} and tenant_id = {} and state = 'leased'
           and lease_id = {} and generation = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4)
    );
    let generation =
        i64::try_from(generation).map_err(|_| ApiError::bad_request("generation too large"))?;
    if sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .bind(tenant_id)
        .bind(lease_id.to_string())
        .bind(generation)
        .fetch_optional(db.read_pool())
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("resource not found"));
    }
    fetch_sandbox(db, sandbox_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::hash_worker_token;
    use crate::db::{Database, SqlDialect};
    use crate::handlers::jobs::fetch_job;
    use crate::handlers::leases::apply_completed_job_on_connection;
    use crate::handlers::workers::insert_worker;
    use sqlx::any::AnyPoolOptions;
    use std::collections::BTreeMap;

    async fn test_db() -> Database {
        test_db_url("sqlite::memory:").await
    }

    async fn test_db_url(url: &str) -> Database {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .unwrap();
        let db = Database::from_test_pool(pool, SqlDialect::Sqlite);
        sqlx::migrate!("./migrations").run(&db.pool).await.unwrap();
        db
    }

    fn pool_config(target: u32) -> SterilePoolConfig {
        SterilePoolConfig {
            target,
            ready_floor: 0,
            max_provisioning: target.max(1),
            tenant_id: "default".into(),
            release: SterileCellReleaseTrustClassV1 {
                release_set_id: "release-test".into(),
                runtime_class: SterileCellRuntimeClass::KataMicrovm,
                policy_digest: "a".repeat(64),
                signature: "swrs1_test".into(),
            },
            sandbox_profile: SandboxRuntimeProfile::Unprivileged,
            template: "ubuntu-dev@sha256:test".into(),
            agent_image: format!("agent@sha256:{}", "b".repeat(64)),
            maestro_image: format!("maestro@sha256:{}", "c".repeat(64)),
            ready_ttl: Duration::from_secs(300),
        }
    }

    async fn seed_worker_and_placement(db: &Database, sandbox_id: SandboxId) -> WorkerId {
        let now = Utc::now();
        let worker = Worker {
            id: WorkerId::new(),
            tenant_id: "default".into(),
            name: "pool-worker".into(),
            status: WorkerStatus::Online,
            provider: "kubernetes".into(),
            capabilities: vec![
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::VirtualMachine,
            ],
            max_concurrent_jobs: 4,
            labels: BTreeMap::from([("cluster".into(), "test-cluster".into())]),
            resource_envelope: None,
            registered_at: now,
            last_heartbeat_at: Some(now),
        };
        insert_worker(db, &worker, &hash_worker_token("pool-worker-token"))
            .await
            .unwrap();
        sqlx::query(
            "insert into sandbox_placements
             (sandbox_id, worker_id, provider, cluster, generation, created_at, updated_at)
             values (?, ?, 'kubernetes', 'test-cluster', 1, ?, ?)",
        )
        .bind(sandbox_id.to_string())
        .bind(worker.id.to_string())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();
        worker.id
    }

    async fn provision_one(db: &Database) -> (SandboxId, Job, WorkerId) {
        reconcile_sterile_pool(db, &pool_config(1)).await.unwrap();
        let row = sqlx::query(
            "select sandbox_id, provision_job_id from sterile_pool_memberships limit 1",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let sandbox_id = SandboxId(Uuid::parse_str(row.try_get("sandbox_id").unwrap()).unwrap());
        let job_id = JobId(Uuid::parse_str(row.try_get("provision_job_id").unwrap()).unwrap());
        let job = fetch_job(db, job_id).await.unwrap();
        let worker_id = seed_worker_and_placement(db, sandbox_id).await;
        let lease_id = LeaseId::new();
        let now = Utc::now();
        sqlx::query(
            "insert into job_leases
             (id, job_id, worker_id, status, attempt, leased_at, expires_at, completed_at, error)
             values (?, ?, ?, 'active', 1, ?, ?, null, null)",
        )
        .bind(lease_id.to_string())
        .bind(job.id.to_string())
        .bind(worker_id.to_string())
        .bind(now.to_rfc3339())
        .bind((now + chrono::Duration::minutes(5)).to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into provisioning_operations
             (sandbox_id, lease_id, lease_attempt, stage, stage_index, resource_kind,
              resource_namespace, resource_name, resource_uid, observed_generation,
              attempt_count, updated_at)
             values (?, ?, 1, 'pod_ready', 4, 'pod', 'sandboxwich-sandboxes', ?, ?, 1, 1, ?)",
        )
        .bind(sandbox_id.to_string())
        .bind(lease_id.to_string())
        .bind(format!("sandboxwich-{sandbox_id}"))
        .bind(format!("pod-uid-{sandbox_id}"))
        .bind(now.to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into provisioning_operation_resources
             (sandbox_id, stage, resource_kind, resource_namespace, resource_name,
              resource_uid, observed_generation, updated_at)
             values (?, 'pod_ready', 'pod', 'sandboxwich-sandboxes', ?, ?, 1, ?)",
        )
        .bind(sandbox_id.to_string())
        .bind(format!("sandboxwich-{sandbox_id}"))
        .bind(format!("pod-uid-{sandbox_id}"))
        .bind(now.to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();
        let mut tx = db.pool.begin().await.unwrap();
        apply_completed_job_on_connection(
            db,
            &mut tx,
            &job,
            WorkerJobResult::ProvisionSandbox {
                handle: ProviderSandboxHandle {
                    provider: "kubernetes".into(),
                    sandbox_id,
                    resources: Vec::new(),
                    metadata: json!({}),
                },
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        (sandbox_id, job, worker_id)
    }

    #[tokio::test]
    async fn concurrent_reconcilers_create_only_the_configured_kubernetes_reserve() {
        let db = test_db().await;
        let config = pool_config(2);
        let (left, right) = tokio::join!(
            reconcile_sterile_pool(&db, &config),
            reconcile_sterile_pool(&db, &config)
        );
        left.unwrap();
        right.unwrap();
        let count: i64 = sqlx::query_scalar("select count(*) from sterile_pool_memberships")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        let payloads: Vec<String> = sqlx::query_scalar(
            "select payload from jobs where sandbox_id in (select sandbox_id from sterile_pool_memberships)",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert!(payloads.iter().all(|payload| {
            let value: serde_json::Value = serde_json::from_str(payload).unwrap();
            value[POOL_JOB_MARKER]["providerCellId"] == value["sandboxId"]
                && value["provisionSpec"]["provider_preference"] == "kubernetes"
        }));
    }

    #[tokio::test]
    async fn hard_target_counts_every_nonterminal_membership_state() {
        let db = test_db().await;
        let config = pool_config(5);
        reconcile_sterile_pool(&db, &config).await.unwrap();
        let rows = sqlx::query(
            "select sandbox_id, provision_job_id from sterile_pool_memberships order by sandbox_id",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 5);
        let sandbox_ids: Vec<SandboxId> = rows
            .iter()
            .map(|row| SandboxId(Uuid::parse_str(row.try_get("sandbox_id").unwrap()).unwrap()))
            .collect();
        let worker_id = seed_worker_and_placement(&db, sandbox_ids[2]).await;
        let expires = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

        sqlx::query(
            "update sterile_pool_memberships
             set state = 'ready', worker_id = ?, generation = 1,
                 candidate_pod_name = ?, candidate_pod_uid = ?, cell_expires_at = ?,
                 lease_id = null, stop_job_id = null, requested_disposition = null
             where sandbox_id = ?",
        )
        .bind(worker_id.to_string())
        .bind("pool-ready-pod")
        .bind("pool-ready-uid")
        .bind(&expires)
        .bind(sandbox_ids[1].to_string())
        .execute(&db.pool)
        .await
        .unwrap();

        let leased_id = Uuid::now_v7();
        sqlx::query(
            "update sterile_pool_memberships
             set state = 'leased', worker_id = ?, generation = 2,
                 candidate_pod_name = ?, candidate_pod_uid = ?, cell_expires_at = ?,
                 lease_id = ?, stop_job_id = null, requested_disposition = null
             where sandbox_id = ?",
        )
        .bind(worker_id.to_string())
        .bind("pool-leased-pod")
        .bind("pool-leased-uid")
        .bind(&expires)
        .bind(leased_id.to_string())
        .bind(sandbox_ids[2].to_string())
        .execute(&db.pool)
        .await
        .unwrap();

        let stopping_id = Uuid::now_v7();
        let stopping_job_id: String = rows[3].try_get("provision_job_id").unwrap();
        sqlx::query(
            "update sterile_pool_memberships
             set state = 'stopping', worker_id = ?, generation = 2,
                 candidate_pod_name = ?, candidate_pod_uid = ?, cell_expires_at = ?,
                 lease_id = ?, stop_job_id = ?, requested_disposition = 'quarantined'
             where sandbox_id = ?",
        )
        .bind(worker_id.to_string())
        .bind("pool-stopping-pod")
        .bind("pool-stopping-uid")
        .bind(&expires)
        .bind(stopping_id.to_string())
        .bind(&stopping_job_id)
        .bind(sandbox_ids[3].to_string())
        .execute(&db.pool)
        .await
        .unwrap();

        let cleanup_id = Uuid::now_v7();
        sqlx::query(
            "update sterile_pool_memberships
             set state = 'cleanup_pending', worker_id = ?, generation = 2,
                 candidate_pod_name = ?, candidate_pod_uid = ?, cell_expires_at = ?,
                 lease_id = ?, stop_job_id = null, requested_disposition = 'quarantined'
             where sandbox_id = ?",
        )
        .bind(worker_id.to_string())
        .bind("pool-cleanup-pod")
        .bind("pool-cleanup-uid")
        .bind(&expires)
        .bind(cleanup_id.to_string())
        .bind(sandbox_ids[4].to_string())
        .execute(&db.pool)
        .await
        .unwrap();

        assert_eq!(reconcile_sterile_pool(&db, &config).await.unwrap(), 0);
        let live_count: i64 = sqlx::query_scalar(
            "select count(*) from sterile_pool_memberships
             where state in ('provisioning', 'ready', 'leased', 'stopping', 'cleanup_pending')",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(live_count, 5, "reconcile must not exceed the hard target");
    }

    #[tokio::test]
    async fn max_provisioning_caps_each_reconcile() {
        let db = test_db().await;
        let mut config = pool_config(5);
        config.max_provisioning = 2;

        assert_eq!(reconcile_sterile_pool(&db, &config).await.unwrap(), 2);
        assert_eq!(reconcile_sterile_pool(&db, &config).await.unwrap(), 0);
        let provisioning_count: i64 = sqlx::query_scalar(
            "select count(*) from sterile_pool_memberships where state = 'provisioning'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(provisioning_count, 2);
    }

    #[tokio::test]
    async fn provider_ready_admission_claim_replenishment_and_stop_are_exactly_fenced() {
        let db = test_db().await;
        let (sandbox_id, _job, worker_id) = provision_one(&db).await;
        let cell = sqlx::query(
            "select id, provider_cell_id, cell_expires_at from sterile_cells where id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            cell.try_get::<String, _>("id").unwrap(),
            sandbox_id.to_string()
        );
        assert_eq!(
            cell.try_get::<String, _>("provider_cell_id").unwrap(),
            sandbox_id.to_string()
        );
        let expires = chrono::DateTime::parse_from_rfc3339(
            cell.try_get::<String, _>("cell_expires_at")
                .unwrap()
                .as_str(),
        )
        .unwrap()
        .with_timezone(&Utc);
        assert!(expires > Utc::now() + chrono::Duration::seconds(295));

        let lease_id = Uuid::now_v7();
        let now = Utc::now().to_rfc3339();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update sterile_cells set state = 'leased', generation = 2, organization_id = 'o',
             workspace_id = 'w', thread_id = 't', runner_session_id = 'r', lease_id = ?,
             lease_attestation_sha256 = 'digest', lease_expires_at = ?, ever_tenant_exposed = 1,
             leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string())
        .bind(expires.to_rfc3339())
        .bind(&now)
        .bind(&now)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
        record_pool_claim_on_connection(&db, &mut tx, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        fetch_exact_leased_pool_sandbox(&db, "default", sandbox_id, lease_id, 2)
            .await
            .unwrap();
        assert!(sandbox_is_pool_reserved(&db, sandbox_id).await.unwrap());

        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let reserve: i64 = sqlx::query_scalar(
            "select count(*) from sterile_pool_memberships where state in ('provisioning', 'ready')",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            reserve, 0,
            "a live lease remains part of the hard target until provider cleanup"
        );

        let mut tx = db.pool.begin().await.unwrap();
        assert!(
            enqueue_pool_stop_on_connection(
                &db,
                &mut tx,
                worker_id,
                SterileCellId(sandbox_id.0),
                lease_id,
                2,
                SterileCellDisposition::Destroyed,
            )
            .await
            .unwrap()
        );
        tx.commit().await.unwrap();
        let stop_job_id: String = sqlx::query_scalar(
            "select stop_job_id from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let stop_job = fetch_job(&db, JobId(Uuid::parse_str(&stop_job_id).unwrap()))
            .await
            .unwrap();
        assert_eq!(
            stop_job.payload[POOL_JOB_MARKER]["leaseId"],
            lease_id.to_string()
        );
        assert_eq!(stop_job.payload[POOL_JOB_MARKER]["generation"], 2);
        let mut tx = db.pool.begin().await.unwrap();
        complete_pool_stop_on_connection(&db, &mut tx, &stop_job)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let state: String = sqlx::query_scalar("select state from sterile_cells where id = ?")
            .bind(sandbox_id.to_string())
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(state, "destroyed");
    }

    #[tokio::test]
    async fn stale_cleanup_fence_quarantines_authority_but_retains_teardown_work() {
        let db = test_db().await;
        let (sandbox_id, _job, worker_id) = provision_one(&db).await;
        let lease_id = Uuid::now_v7();
        let expires = (Utc::now() + chrono::Duration::minutes(2)).to_rfc3339();
        sqlx::query(
            "update sterile_cells set state = 'leased', generation = 2, organization_id = 'o', workspace_id = 'w',
             thread_id = 't', runner_session_id = 'r', lease_id = ?, lease_attestation_sha256 = 'digest',
             lease_expires_at = ?, ever_tenant_exposed = 1, leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string()).bind(&expires).bind(&expires).bind(&expires)
        .bind(sandbox_id.to_string()).execute(&db.pool).await.unwrap();
        let mut seed = db.pool.begin().await.unwrap();
        record_pool_claim_on_connection(&db, &mut seed, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        seed.commit().await.unwrap();

        let mut tx = db.pool.begin().await.unwrap();
        assert!(
            enqueue_pool_stop_on_connection(
                &db,
                &mut tx,
                worker_id,
                SterileCellId(sandbox_id.0),
                lease_id,
                3,
                SterileCellDisposition::Destroyed,
            )
            .await
            .is_err()
        );
        tx.commit().await.unwrap();
        let states: (String, String) = sqlx::query_as(
            "select p.state, c.state from sterile_pool_memberships p join sterile_cells c on c.id = p.sandbox_id where p.sandbox_id = ?",
        ).bind(sandbox_id.to_string()).fetch_one(&db.pool).await.unwrap();
        assert_eq!(states, ("cleanup_pending".into(), "quarantined".into()));
        reconcile_sterile_pool_cleanup(&db).await.unwrap();
        let retry: (String, String) = sqlx::query_as(
            "select p.state, j.status from sterile_pool_memberships p join jobs j on j.id = p.stop_job_id where p.sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(retry, ("stopping".into(), "queued".into()));
    }

    #[tokio::test]
    async fn failed_stop_is_reconciled_to_a_fresh_exact_job_then_provider_terminalizes() {
        let storage = tempfile::NamedTempFile::new().unwrap();
        let database_url = format!("sqlite://{}", storage.path().display());
        let db = test_db_url(&database_url).await;
        let (sandbox_id, _job, worker_id) = provision_one(&db).await;
        let lease_id = Uuid::now_v7();
        let expires = (Utc::now() + chrono::Duration::minutes(2)).to_rfc3339();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update sterile_cells set state = 'leased', generation = 2, organization_id = 'o', workspace_id = 'w',
             thread_id = 't', runner_session_id = 'r', lease_id = ?, lease_attestation_sha256 = 'digest',
             lease_expires_at = ?, ever_tenant_exposed = 1, leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string())
        .bind(&expires)
        .bind(&expires)
        .bind(&expires)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
        record_pool_claim_on_connection(&db, &mut tx, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        enqueue_pool_stop_on_connection(
            &db,
            &mut tx,
            worker_id,
            SterileCellId(sandbox_id.0),
            lease_id,
            2,
            SterileCellDisposition::Destroyed,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let first_id: String = sqlx::query_scalar(
            "select stop_job_id from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let first = fetch_job(&db, JobId(Uuid::parse_str(&first_id).unwrap()))
            .await
            .unwrap();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update jobs set status = 'failed', last_error = 'provider timeout' where id = ?",
        )
        .bind(&first_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        quarantine_failed_pool_job_on_connection(&db, &mut tx, &first, "provider timeout")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let pending: (String, String, String) = sqlx::query_as(
            "select state, requested_disposition, stop_job_id from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(pending.0, "cleanup_pending");
        assert_eq!(
            pending.1, "destroyed",
            "the requested disposition is immutable"
        );
        assert_eq!(pending.2, first_id);

        drop(db);
        let db = test_db_url(&database_url).await;
        reconcile_sterile_pool_cleanup(&db).await.unwrap();
        let retry_id: String = sqlx::query_scalar(
            "select stop_job_id from sterile_pool_memberships where sandbox_id = ? and state = 'stopping'",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_ne!(retry_id, first_id);
        let retry = fetch_job(&db, JobId(Uuid::parse_str(&retry_id).unwrap()))
            .await
            .unwrap();
        assert_eq!(
            retry.payload[POOL_JOB_MARKER]["leaseId"],
            lease_id.to_string()
        );
        assert_eq!(retry.payload[POOL_JOB_MARKER]["generation"], 2);
        assert_eq!(retry.payload[POOL_JOB_MARKER]["disposition"], "destroyed");
        let mut tx = db.pool.begin().await.unwrap();
        complete_pool_stop_on_connection(&db, &mut tx, &retry)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let terminal: (String, String) = sqlx::query_as(
            "select p.state, c.state from sterile_pool_memberships p join sterile_cells c on c.id = p.sandbox_id where p.sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(terminal, ("quarantined".into(), "quarantined".into()));
    }

    #[tokio::test]
    async fn sandbox_transition_ambiguity_keeps_exact_stop_job_queued() {
        let db = test_db().await;
        let (sandbox_id, _job, worker_id) = provision_one(&db).await;
        let lease_id = Uuid::now_v7();
        let expires = (Utc::now() + chrono::Duration::minutes(2)).to_rfc3339();
        let now = Utc::now().to_rfc3339();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update sterile_cells set state = 'leased', generation = 2, organization_id = 'o', workspace_id = 'w',
             thread_id = 't', runner_session_id = 'r', lease_id = ?, lease_attestation_sha256 = 'digest',
             lease_expires_at = ?, ever_tenant_exposed = 1, leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string()).bind(&expires).bind(&now).bind(&now)
        .bind(sandbox_id.to_string()).execute(&mut *tx).await.unwrap();
        record_pool_claim_on_connection(&db, &mut tx, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        sqlx::query("update sandboxes set state = 'archived' where id = ?")
            .bind(sandbox_id.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(
            enqueue_pool_stop_on_connection(
                &db,
                &mut tx,
                worker_id,
                SterileCellId(sandbox_id.0),
                lease_id,
                2,
                SterileCellDisposition::Destroyed,
            )
            .await
            .unwrap()
        );
        tx.commit().await.unwrap();
        let durable: (String, String, String) = sqlx::query_as(
            "select p.state, c.state, j.status from sterile_pool_memberships p join sterile_cells c on c.id = p.sandbox_id join jobs j on j.id = p.stop_job_id where p.sandbox_id = ?",
        ).bind(sandbox_id.to_string()).fetch_one(&db.pool).await.unwrap();
        assert_eq!(
            durable,
            ("stopping".into(), "quarantined".into(), "queued".into())
        );
    }

    #[tokio::test]
    async fn exact_completion_recovers_terminal_cell_with_pending_membership() {
        let db = test_db().await;
        let (sandbox_id, _job, worker_id) = provision_one(&db).await;
        let lease_id = Uuid::now_v7();
        let expires = (Utc::now() + chrono::Duration::minutes(2)).to_rfc3339();
        let now = Utc::now().to_rfc3339();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update sterile_cells set state = 'leased', generation = 2, organization_id = 'o', workspace_id = 'w',
             thread_id = 't', runner_session_id = 'r', lease_id = ?, lease_attestation_sha256 = 'digest',
             lease_expires_at = ?, ever_tenant_exposed = 1, leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string()).bind(&expires).bind(&now).bind(&now)
        .bind(sandbox_id.to_string()).execute(&mut *tx).await.unwrap();
        record_pool_claim_on_connection(&db, &mut tx, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        enqueue_pool_stop_on_connection(
            &db,
            &mut tx,
            worker_id,
            SterileCellId(sandbox_id.0),
            lease_id,
            2,
            SterileCellDisposition::Destroyed,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let stop_job_id: String = sqlx::query_scalar(
            "select stop_job_id from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let stop_job = fetch_job(&db, JobId(Uuid::parse_str(&stop_job_id).unwrap()))
            .await
            .unwrap();
        sqlx::query(
            "update sterile_cells set state = 'destroyed', disposition = 'destroyed', destroyed_at = ?, updated_at = ? where id = ?",
        ).bind(&now).bind(&now).bind(sandbox_id.to_string()).execute(&db.pool).await.unwrap();
        sqlx::query(
            "update sterile_pool_memberships set state = 'cleanup_pending', stop_job_id = null where sandbox_id = ?",
        ).bind(sandbox_id.to_string()).execute(&db.pool).await.unwrap();

        let mut tx = db.pool.begin().await.unwrap();
        complete_pool_stop_on_connection(&db, &mut tx, &stop_job)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let state: String =
            sqlx::query_scalar("select state from sterile_pool_memberships where sandbox_id = ?")
                .bind(sandbox_id.to_string())
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(state, "destroyed");
    }

    #[tokio::test]
    async fn expired_leased_cell_waits_for_provider_stop_before_quarantine() {
        let db = test_db().await;
        let (sandbox_id, _job, _worker_id) = provision_one(&db).await;
        let lease_id = Uuid::now_v7();
        let expired = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let now = Utc::now().to_rfc3339();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update sterile_cells set state = 'leased', generation = 2, organization_id = 'o',
             workspace_id = 'w', thread_id = 't', runner_session_id = 'r', lease_id = ?,
             lease_attestation_sha256 = 'digest', lease_expires_at = ?, ever_tenant_exposed = 1,
             leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string())
        .bind(&expired)
        .bind(&now)
        .bind(&now)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
        record_pool_claim_on_connection(&db, &mut tx, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            crate::handlers::sterile_cells::quarantine_expired_sterile_cells(&db)
                .await
                .unwrap(),
            0,
            "the generic sweeper must not DB-terminalize pool resources"
        );
        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let stop_job_id: String = sqlx::query_scalar(
            "select stop_job_id from sterile_pool_memberships where sandbox_id = ? and state = 'stopping'",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let before_provider: String =
            sqlx::query_scalar("select state from sterile_cells where id = ?")
                .bind(sandbox_id.to_string())
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(before_provider, "leased");
        let stop_job = fetch_job(&db, JobId(Uuid::parse_str(&stop_job_id).unwrap()))
            .await
            .unwrap();
        assert_eq!(
            stop_job.payload[POOL_JOB_MARKER]["disposition"],
            "quarantined"
        );
        assert_eq!(
            stop_job.payload[POOL_JOB_MARKER]["leaseId"],
            lease_id.to_string()
        );
        let mut tx = db.pool.begin().await.unwrap();
        complete_pool_stop_on_connection(&db, &mut tx, &stop_job)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let states: (String, String) = sqlx::query_as(
            "select p.state, c.state from sterile_pool_memberships p join sterile_cells c on c.id = p.sandbox_id where p.sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(states, ("quarantined".into(), "quarantined".into()));
    }

    #[tokio::test]
    async fn sweeper_first_quarantine_still_requires_and_accepts_provider_stop() {
        let db = test_db().await;
        let (sandbox_id, _job, _worker_id) = provision_one(&db).await;
        let lease_id = Uuid::now_v7();
        let expired = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let mut tx = db.pool.begin().await.unwrap();
        sqlx::query(
            "update sterile_cells set state = 'quarantined', generation = 2, organization_id = 'o',
             workspace_id = 'w', thread_id = 't', runner_session_id = 'r', lease_id = ?,
             lease_attestation_sha256 = 'digest', lease_expires_at = ?, ever_tenant_exposed = 1,
             disposition = 'quarantined', destroyed_at = ?, leased_at = ?, updated_at = ? where id = ?",
        )
        .bind(lease_id.to_string())
        .bind(&expired)
        .bind(&expired)
        .bind(&expired)
        .bind(&expired)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
        record_pool_claim_on_connection(&db, &mut tx, SterileCellId(sandbox_id.0), lease_id, 2)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let stop_job_id: String = sqlx::query_scalar(
            "select stop_job_id from sterile_pool_memberships where sandbox_id = ? and state = 'stopping'",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        let stop_job = fetch_job(&db, JobId(Uuid::parse_str(&stop_job_id).unwrap()))
            .await
            .unwrap();
        let mut tx = db.pool.begin().await.unwrap();
        complete_pool_stop_on_connection(&db, &mut tx, &stop_job)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let membership_state: String =
            sqlx::query_scalar("select state from sterile_pool_memberships where sandbox_id = ?")
                .bind(sandbox_id.to_string())
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(membership_state, "quarantined");
    }

    #[tokio::test]
    async fn expired_ready_cell_is_stopped_and_replaced_without_resource_reuse() {
        let db = test_db().await;
        let (sandbox_id, _job, _worker_id) = provision_one(&db).await;
        let expired = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        sqlx::query("update sterile_pool_memberships set cell_expires_at = ? where sandbox_id = ?")
            .bind(&expired)
            .bind(sandbox_id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("update sterile_cells set cell_expires_at = ? where id = ?")
            .bind(&expired)
            .bind(sandbox_id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();

        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let original: (String, String) = sqlx::query_as(
            "select state, stop_job_id from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(original.0, "stopping");
        let replacement_count: i64 = sqlx::query_scalar(
            "select count(*) from sterile_pool_memberships where sandbox_id != ? and state = 'provisioning'",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            replacement_count, 0,
            "a stopping member remains part of the hard target until provider cleanup"
        );
        let stop_job = fetch_job(&db, JobId(Uuid::parse_str(&original.1).unwrap()))
            .await
            .unwrap();
        assert!(stop_job.payload[POOL_JOB_MARKER]["leaseId"].is_null());
        let mut tx = db.pool.begin().await.unwrap();
        complete_pool_stop_on_connection(&db, &mut tx, &stop_job)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let state: String = sqlx::query_scalar("select state from sterile_cells where id = ?")
            .bind(sandbox_id.to_string())
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(state, "quarantined");
        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let replacement_count: i64 = sqlx::query_scalar(
            "select count(*) from sterile_pool_memberships where sandbox_id != ? and state = 'provisioning'",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(replacement_count, 1);
    }

    #[tokio::test]
    async fn ready_cell_without_guest_health_is_replaced_after_grace() {
        let db = test_db().await;
        let (sandbox_id, _job, _worker_id) = provision_one(&db).await;
        let aged = (Utc::now() - chrono::Duration::seconds(31)).to_rfc3339();
        sqlx::query("update sterile_pool_memberships set updated_at = ? where sandbox_id = ?")
            .bind(&aged)
            .bind(sandbox_id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();

        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let original: (String, String) = sqlx::query_as(
            "select state, quarantine_reason from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(original.0, "stopping");
        assert_eq!(original.1, "guest_health_unready");
    }

    #[tokio::test]
    async fn ready_cell_with_fresh_guest_health_is_kept() {
        let db = test_db().await;
        let (sandbox_id, _job, _worker_id) = provision_one(&db).await;
        let aged = (Utc::now() - chrono::Duration::seconds(31)).to_rfc3339();
        sqlx::query("update sterile_pool_memberships set updated_at = ? where sandbox_id = ?")
            .bind(&aged)
            .bind(sandbox_id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query(
            "insert into guest_health (sandbox_id, status, last_probe_at, agent_version, checks, message)
             values (?, 'ready', ?, 'sandboxwich-agent/test', '{}', null)",
        )
        .bind(sandbox_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await
        .unwrap();

        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let state: String =
            sqlx::query_scalar("select state from sterile_pool_memberships where sandbox_id = ?")
                .bind(sandbox_id.to_string())
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(state, "ready");
        let replacement_count: i64 = sqlx::query_scalar(
            "select count(*) from sterile_pool_memberships where sandbox_id != ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(replacement_count, 0);
    }

    #[tokio::test]
    async fn ready_cell_with_stale_guest_health_is_replaced() {
        let db = test_db().await;
        let (sandbox_id, _job, _worker_id) = provision_one(&db).await;
        let aged = (Utc::now() - chrono::Duration::seconds(31)).to_rfc3339();
        let stale = (Utc::now() - chrono::Duration::seconds(61)).to_rfc3339();
        sqlx::query("update sterile_pool_memberships set updated_at = ? where sandbox_id = ?")
            .bind(&aged)
            .bind(sandbox_id.to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query(
            "insert into guest_health (sandbox_id, status, last_probe_at, agent_version, checks, message)
             values (?, 'ready', ?, 'sandboxwich-agent/test', '{}', null)",
        )
        .bind(sandbox_id.to_string())
        .bind(&stale)
        .execute(&db.pool)
        .await
        .unwrap();

        reconcile_sterile_pool(&db, &pool_config(1)).await.unwrap();
        let original: (String, String) = sqlx::query_as(
            "select state, quarantine_reason from sterile_pool_memberships where sandbox_id = ?",
        )
        .bind(sandbox_id.to_string())
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(original.0, "stopping");
        assert_eq!(original.1, "guest_health_unready");
    }
}
