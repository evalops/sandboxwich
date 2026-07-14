use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::commands::*;
use crate::handlers::jobs::*;
use crate::handlers::operations::operation_from_job;
use crate::handlers::snapshots::*;
use crate::pagination::*;
use crate::reconcile::list_runtime_resources_for_sandbox;
use crate::rows::*;
use crate::state::*;
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use sandboxwich_core::*;
use serde_json::json;
use sqlx::AnyConnection;
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) fn provision_spec_from_request(
    request: &CreateSandboxRequest,
    parent: Option<&Sandbox>,
) -> Result<SandboxProvisionSpec, ApiError> {
    let memory_limit = request
        .memory_limit
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.memory_limit.clone()))
        .unwrap_or_default();
    let network_egress = request
        .network_egress
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.network_egress.clone()))
        .unwrap_or_default();
    let workspace_mode = request
        .workspace_mode
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.workspace_mode.clone()))
        .unwrap_or_default();
    let execution_class = request
        .execution_class
        .clone()
        .or_else(|| parent.map(|sandbox| sandbox.execution_class.clone()))
        .unwrap_or_default();
    validate_network_egress(&network_egress)?;
    Ok(SandboxProvisionSpec {
        execution_class,
        memory_limit,
        network_egress,
        workspace_mode,
    })
}

pub(crate) fn validate_network_egress(network_egress: &NetworkEgress) -> Result<(), ApiError> {
    match network_egress {
        NetworkEgress::DenyAll | NetworkEgress::AllowAll => Ok(()),
        NetworkEgress::Allowlist { rules } => {
            for rule in rules {
                let value = rule.value.trim();
                if value.is_empty() {
                    return Err(ApiError::bad_request(
                        "network allow rule value cannot be empty",
                    ));
                }
                if value.len() > 253 {
                    return Err(ApiError::bad_request(
                        "network allow rule value is too long",
                    ));
                }
                if rule.kind == NetworkAllowRuleKind::Cidr && !looks_like_cidr(value) {
                    return Err(ApiError::bad_request(
                        "cidr network allow rule must use CIDR notation",
                    ));
                }
                if rule.kind == NetworkAllowRuleKind::Host && !looks_like_host_rule(value) {
                    return Err(ApiError::bad_request(
                        "host network allow rule must be a lowercase DNS name or one leading-label wildcard",
                    ));
                }
            }
            Ok(())
        }
    }
}

pub(crate) fn looks_like_host_rule(value: &str) -> bool {
    if let Some(base) = value.strip_prefix("*.") {
        return base.contains('.') && !base.contains('*') && looks_like_dns_name(base);
    }
    !value.contains('*') && looks_like_dns_name(value)
}

pub(crate) fn looks_like_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.ends_with('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub(crate) fn provision_capability(network_egress: &NetworkEgress) -> WorkerCapability {
    if network_egress
        .rules()
        .iter()
        .any(|rule| rule.kind == NetworkAllowRuleKind::Host)
    {
        WorkerCapability::FqdnEgress
    } else {
        WorkerCapability::ProvisionSandbox
    }
}

pub(crate) fn fork_capability(network_egress: &NetworkEgress) -> WorkerCapability {
    if network_egress
        .rules()
        .iter()
        .any(|rule| rule.kind == NetworkAllowRuleKind::Host)
    {
        WorkerCapability::FqdnEgress
    } else {
        WorkerCapability::Snapshot
    }
}

pub(crate) fn looks_like_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => prefix <= 32,
        Ok(std::net::IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

#[utoipa::path(post, path = "/v1/sandboxes", responses((status = 202, description = "Sandbox provisioning accepted"), (status = 400, body = ErrorEnvelope)))]
pub(crate) async fn create_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let now = Utc::now();
    let provision_spec = provision_spec_from_request(&request, None)?;
    let sandbox = Sandbox {
        execution_class: provision_spec.execution_class.clone(),
        id: SandboxId::new(),
        tenant_id: ctx.tenant_id.clone(),
        name: request.name.unwrap_or_else(|| "fresh-sandwich".to_string()),
        state: SandboxState::Planning,
        template: request.template.unwrap_or_else(|| "ubuntu-dev".to_string()),
        memory_limit: provision_spec.memory_limit.clone(),
        network_egress: provision_spec.network_egress.clone(),
        workspace_mode: provision_spec.workspace_mode.clone(),
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(Some(3600)),
        parent_snapshot_id: None,
    };

    let job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::ProvisionSandbox,
        status: JobStatus::Queued,
        payload: json!({"sandboxId": sandbox.id, "provisionSpec": provision_spec}),
        required_capability: provision_capability(&sandbox.network_egress),
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    let mut tx = state.db.pool.begin().await?;
    insert_sandbox_on_connection(&state.db, &mut tx, &sandbox).await?;
    replace_sandbox_network_rules_on_connection(
        &state.db,
        &mut tx,
        sandbox.id,
        sandbox.network_egress.rules(),
    )
    .await?;
    insert_event_on_connection(
        &state.db,
        &mut tx,
        sandbox.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": sandbox.state,
            "reason": "created",
            "memoryLimit": sandbox.memory_limit,
            "networkEgress": sandbox.network_egress
        }),
    )
    .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox,
            operation: Some(operation_from_job(&job)?),
        }),
    ))
}

pub(crate) async fn list_sandboxes(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Query(page): Query<PageParams>,
) -> Result<Json<SandboxListResponse>, ApiError> {
    let limit = resolve_page_limit(page.limit)?;
    let cursor = resolve_page_cursor(&page)?;

    let base_sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, execution_class,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where tenant_id = {}",
        state.db.placeholder(1)
    );
    let (mut sandboxes, next_cursor) = fetch_keyset_page(
        &state.db,
        &base_sql,
        std::slice::from_ref(&ctx.tenant_id),
        limit,
        &cursor,
        row_to_sandbox,
    )
    .await?;
    hydrate_sandboxes_network_egress(&state.db, &mut sandboxes).await?;

    Ok(Json(SandboxListResponse {
        ok: true,
        sandboxes,
        next_cursor,
    }))
}

pub(crate) async fn get_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    let sandbox = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    Ok(Json(SandboxResponse {
        ok: true,
        sandbox,
        operation: None,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/sandboxes/{sandbox_id}/observed-state",
    params(("sandbox_id" = Uuid, Path)),
    responses((status = 200, body = SandboxObservedState), (status = 404, body = ErrorEnvelope))
)]
pub(crate) async fn get_sandbox_observed_state(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxObservedState>, ApiError> {
    let sandbox = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    Ok(Json(SandboxObservedState {
        sandbox_id,
        tenant_id: sandbox.tenant_id,
        state: sandbox.state,
        observed_at: Utc::now(),
    }))
}

pub(crate) async fn stop_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    let mut sandbox = ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let delete_gke_fqdn_policy = list_runtime_resources_for_sandbox(&state.db, sandbox_id)
        .await?
        .iter()
        .any(|resource| {
            resource.provider == "kubernetes"
                && resource.resource_kind == RuntimeResourceKind::NetworkPolicy
                && resource.resource_name == format!("sandboxwich-fqdn-egress-{sandbox_id}")
        });
    let now = Utc::now();
    let job = Job {
        id: JobId::new(),
        tenant_id: sandbox.tenant_id.clone(),
        kind: JobKind::StopSandbox,
        status: JobStatus::Queued,
        payload: json!({
            "sandboxId": sandbox_id,
            "deleteGkeFqdnPolicy": delete_gke_fqdn_policy,
        }),
        required_capability: WorkerCapability::ProvisionSandbox,
        priority: 100,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    let mut tx = state.db.pool.begin().await?;
    set_sandbox_state_on_connection(
        &state.db,
        &mut tx,
        sandbox_id,
        SandboxState::STOP_LEGAL_FROM,
        SandboxState::Archiving,
        json!({"state": SandboxState::Archiving, "reason": "stop_requested"}),
    )
    .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    let revoke_sql = format!(
        "update guest_tokens set revoked_at = {}
         where tenant_id = {} and sandbox_id = {} and revoked_at is null",
        state.db.placeholder(1),
        state.db.placeholder(2),
        state.db.placeholder(3)
    );
    sqlx::query(&revoke_sql)
        .bind(now.to_rfc3339())
        .bind(&ctx.tenant_id)
        .bind(sandbox_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    sandbox.state = SandboxState::Archiving;
    sandbox.updated_at = now;
    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox,
            operation: Some(operation_from_job(&job)?),
        }),
    ))
}

pub(crate) async fn resume_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<SandboxResponse>, ApiError> {
    ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    Err(ApiError::unsupported(format!(
        "resume is not supported for sandbox {sandbox_id}; create or fork a sandbox instead"
    )))
}

#[utoipa::path(post, path = "/v1/sandboxes/{sandbox_id}/fork", params(("sandbox_id" = Uuid, Path), ("Idempotency-Key" = Option<String>, Header, description = "Tenant-scoped replay key"), ("X-Request-Id" = Option<String>, Header), ("traceparent" = Option<String>, Header)), request_body = CreateSandboxRequest, responses((status = 202, description = "Fork accepted with child sandbox and asynchronous operation", body = SandboxResponse), (status = 404, body = ErrorEnvelope)))]
pub(crate) async fn fork_sandbox(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
    Json(request): Json<CreateSandboxRequest>,
) -> Result<(StatusCode, Json<SandboxResponse>), ApiError> {
    let parent = ensure_sandbox_tenant(&state.db, SandboxId(sandbox_id), &ctx).await?;
    let provision_spec = provision_spec_from_request(&request, Some(&parent))?;
    if parent.workspace_mode != WorkspaceMode::Persistent
        || provision_spec.workspace_mode != WorkspaceMode::Persistent
    {
        return Err(ApiError::conflict_code(
            "workspace_mode_fork_unsupported",
            "fork requires persistent source and child workspaces",
        ));
    }
    let now = Utc::now();
    let snapshot = Snapshot {
        id: SnapshotId::new(),
        sandbox_id: parent.id,
        status: SnapshotStatus::Pending,
        label: format!("fork-source-{}", now.timestamp_millis()),
        inventory: json!({
            "sourceSandboxId": parent.id,
            "template": parent.template
        }),
        provider_metadata: json!({
            "source": "fork_request"
        }),
        created_at: now,
        ready_at: None,
        expires_at: None,
        error: None,
    };
    let child = Sandbox {
        execution_class: provision_spec.execution_class,
        id: SandboxId::new(),
        tenant_id: parent.tenant_id.clone(),
        name: request
            .name
            .unwrap_or_else(|| format!("{}-fork", parent.name)),
        state: SandboxState::Planning,
        template: request.template.unwrap_or_else(|| parent.template.clone()),
        memory_limit: provision_spec.memory_limit,
        network_egress: provision_spec.network_egress,
        workspace_mode: provision_spec.workspace_mode,
        created_at: now,
        updated_at: now,
        ttl_seconds: request.ttl_seconds.or(parent.ttl_seconds),
        parent_snapshot_id: Some(snapshot.id),
    };

    let job = Job {
        id: JobId::new(),
        tenant_id: parent.tenant_id.clone(),
        kind: JobKind::CreateSnapshot,
        status: JobStatus::Queued,
        payload: json!({"sandboxId": parent.id, "snapshotId": snapshot.id,
        "operation": { "kind": OperationKind::ForkSandbox, "resourceId": child.id },
        "provisionSpec": SandboxProvisionSpec {
            execution_class: parent.execution_class.clone(),
            memory_limit: parent.memory_limit.clone(),
            network_egress: parent.network_egress.clone(),
            workspace_mode: parent.workspace_mode.clone(),
        }}),
        required_capability: WorkerCapability::Snapshot,
        priority: 0,
        attempts: 0,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    };
    let mut tx = state.db.pool.begin().await?;
    insert_snapshot_on_connection(&state.db, &mut tx, &snapshot).await?;
    insert_sandbox_on_connection(&state.db, &mut tx, &child).await?;
    replace_sandbox_network_rules_on_connection(
        &state.db,
        &mut tx,
        child.id,
        child.network_egress.rules(),
    )
    .await?;
    insert_event_on_connection(
        &state.db,
        &mut tx,
        child.id,
        SandboxEventKind::LifecycleChanged,
        json!({
            "state": child.state,
            "reason": "fork_planned",
            "parentSandboxId": parent.id,
            "parentSnapshotId": snapshot.id,
            "memoryLimit": child.memory_limit,
            "networkEgress": child.network_egress
        }),
    )
    .await?;
    insert_job_on_connection(&state.db, &mut tx, &job).await?;
    tx.commit().await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxResponse {
            ok: true,
            sandbox: child,
            operation: Some(operation_from_job(&job)?),
        }),
    ))
}

/// Drives a user-initiated sandbox state change (stop/resume) via a
/// compare-and-swap update. `allowed_from` is the exact set of states this
/// specific action may legally transition out of (e.g.
/// [`SandboxState::RESUME_LEGAL_FROM`]) -- callers must pick the constant for
/// their action rather than deriving one from `next_state` alone, since more
/// than one action can legally target the same state with different
/// preconditions (see [`SandboxState::can_transition_to`]'s docs).
///
/// If the sandbox is not currently in one of `allowed_from`, this returns a
/// 409 Conflict describing the sandbox's actual state rather than silently
/// clobbering it.
#[cfg(test)]
pub(crate) async fn transition_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: SandboxState,
    reason: &'static str,
) -> Result<Json<SandboxResponse>, ApiError> {
    fetch_sandbox(db, sandbox_id).await?;
    let event_state = next_state.clone();
    set_sandbox_state(
        db,
        sandbox_id,
        allowed_from,
        next_state,
        json!({
            "state": event_state,
            "reason": reason
        }),
    )
    .await?;

    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    Ok(Json(SandboxResponse {
        ok: true,
        sandbox,
        operation: None,
    }))
}

#[cfg(test)]
pub(crate) async fn set_sandbox_state(
    db: &Database,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: SandboxState,
    event_data: serde_json::Value,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let allowed_values: Vec<&str> = allowed_from.iter().map(state_to_str).collect();
    let sql = format!(
        "update sandboxes set state = {}, updated_at = {} where id = {} and state in ({})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        sql_literal_list(&allowed_values)
    );
    let result = sqlx::query(&sql)
        .bind(state)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&db.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(sandbox_state_conflict(db, sandbox_id, allowed_from, &next_state).await?);
    }

    insert_event(
        db,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        event_data,
    )
    .await?;
    Ok(())
}

/// Builds the 404/409 error for a failed user-facing compare-and-swap state
/// update: 404 if the sandbox no longer exists at all, otherwise 409 with the
/// sandbox's actual current state so the caller understands what conflicted.
#[cfg(test)]
pub(crate) async fn sandbox_state_conflict(
    db: &Database,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: &SandboxState,
) -> Result<ApiError, ApiError> {
    let current = fetch_sandbox_state(db, sandbox_id).await?;
    Ok(match current {
        None => ApiError::not_found("sandbox not found"),
        Some(actual) => {
            let allowed = allowed_from
                .iter()
                .map(state_to_str)
                .collect::<Vec<_>>()
                .join(", ");
            ApiError::conflict(format!(
                "cannot transition sandbox {sandbox_id} to {}: sandbox is currently {} (expected one of [{allowed}])",
                state_to_str(next_state),
                state_to_str(&actual),
            ))
        }
    })
}

#[cfg(test)]
pub(crate) async fn fetch_sandbox_state(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Option<SandboxState>, ApiError> {
    let sql = format!(
        "select state from sandboxes where id = {}",
        db.placeholder(1)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(None);
    };
    let raw: String = row.try_get("state")?;
    Ok(Some(parse_state(&raw)?))
}

/// Drives a worker/job-completion-triggered sandbox state change via a
/// compare-and-swap update, mirroring [`set_sandbox_state`]. Unlike the
/// user-facing routes, a job-completion path must never error out or clobber
/// a sandbox that has moved on since the job started -- e.g. a
/// `ProvisionSandbox`/`ForkSandbox` job completing after the sandbox was
/// concurrently archived must leave it archived, not resurrect it. So on a
/// compare-and-swap miss this logs a warning and returns `Ok(())` instead of
/// applying the write or raising an error.
pub(crate) async fn set_sandbox_state_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    allowed_from: &'static [SandboxState],
    next_state: SandboxState,
    event_data: serde_json::Value,
) -> Result<(), ApiError> {
    let now = Utc::now();
    let state = state_to_str(&next_state);
    let allowed_values: Vec<&str> = allowed_from.iter().map(state_to_str).collect();
    let sql = format!(
        "update sandboxes set state = {}, updated_at = {} where id = {} and state in ({})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        sql_literal_list(&allowed_values)
    );
    let result = sqlx::query(&sql)
        .bind(state)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    if result.rows_affected() == 0 {
        tracing::warn!(
            %sandbox_id,
            next_state = state,
            allowed_from = ?allowed_values,
            "skipping sandbox state transition: sandbox is no longer in an expected \
             predecessor state (likely concurrently stopped/resumed by another request)"
        );
        return Ok(());
    }

    insert_event_on_connection(
        db,
        connection,
        sandbox_id,
        SandboxEventKind::LifecycleChanged,
        event_data,
    )
    .await?;
    Ok(())
}

pub(crate) async fn fetch_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, execution_class,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress(db, &mut sandbox).await?;
    Ok(sandbox)
}

pub(crate) async fn fetch_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Sandbox, ApiError> {
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, execution_class,
                created_at, updated_at, ttl_seconds, parent_snapshot_id
         from sandboxes
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("sandbox not found"))?;

    let mut sandbox = row_to_sandbox(row)?;
    hydrate_sandbox_network_egress_on_connection(db, connection, &mut sandbox).await?;
    Ok(sandbox)
}

pub(crate) async fn ensure_sandbox_tenant_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    tenant_id: &str,
) -> Result<Sandbox, ApiError> {
    let sandbox = fetch_sandbox_on_connection(db, connection, sandbox_id).await?;
    if sandbox.tenant_id != tenant_id {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(sandbox)
}

#[cfg(test)]
pub(crate) async fn insert_sandbox(db: &Database, sandbox: &Sandbox) -> Result<(), ApiError> {
    validate_network_egress(&sandbox.network_egress)?;
    let mut tx = db.pool.begin().await?;
    let inserted = async {
        insert_sandbox_on_connection(db, &mut tx, sandbox).await?;
        replace_sandbox_network_rules_on_connection(
            db,
            &mut tx,
            sandbox.id,
            sandbox.network_egress.rules(),
        )
        .await
    }
    .await;
    match inserted {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back sandbox insert");
            }
            Err(error)
        }
    }
}

pub(crate) async fn insert_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &Sandbox,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into sandboxes
         (id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, execution_class,
          created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        db.placeholders(13)
    );
    sqlx::query(&sql)
        .bind(sandbox.id.to_string())
        .bind(&sandbox.tenant_id)
        .bind(&sandbox.name)
        .bind(state_to_str(&sandbox.state))
        .bind(&sandbox.template)
        .bind(memory_limit_to_str(&sandbox.memory_limit))
        .bind(network_egress_mode_to_str(&sandbox.network_egress.mode()))
        .bind(sandbox.workspace_mode.as_db_str())
        .bind(sandbox.execution_class.as_db_str())
        .bind(sandbox.created_at.to_rfc3339())
        .bind(sandbox.updated_at.to_rfc3339())
        .bind(sandbox.ttl_seconds.map(|ttl| ttl as i64))
        .bind(
            sandbox
                .parent_snapshot_id
                .map(|snapshot| snapshot.0.to_string()),
        )
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) async fn replace_sandbox_network_rules_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    rules: &[NetworkAllowRule],
) -> Result<(), ApiError> {
    let delete_sql = format!(
        "delete from sandbox_network_egress_rules where sandbox_id = {}",
        db.placeholder(1)
    );
    sqlx::query(&delete_sql)
        .bind(sandbox_id.to_string())
        .execute(&mut *connection)
        .await?;

    for rule in rules {
        let sql = format!(
            "insert into sandbox_network_egress_rules (id, sandbox_id, kind, value, created_at)
             values ({})",
            db.placeholders(5)
        );
        sqlx::query(&sql)
            .bind(EventId::new().to_string())
            .bind(sandbox_id.to_string())
            .bind(network_allow_rule_kind_to_str(&rule.kind))
            .bind(&rule.value)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *connection)
            .await?;
    }

    Ok(())
}

pub(crate) fn sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(job, "sandboxId", "run command job is missing sandbox id").map(SandboxId)
}

pub(crate) fn parent_sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(
        job,
        "parentSandboxId",
        "fork job is missing parent sandbox id",
    )
    .map(SandboxId)
}

pub(crate) fn child_sandbox_id_from_job(job: &Job) -> Result<SandboxId, ApiError> {
    uuid_from_job_payload(
        job,
        "childSandboxId",
        "fork job is missing child sandbox id",
    )
    .map(SandboxId)
}

/// Hydrate every `Allowlist` sandbox's network egress rules with a single batched query instead
/// of one `select` per sandbox, so listing a full page (up to `MAX_PAGE_LIMIT` sandboxes) never
/// issues more than one extra round-trip regardless of how many of them are on the allowlist tier.
pub(crate) async fn hydrate_sandboxes_network_egress(
    db: &Database,
    sandboxes: &mut [Sandbox],
) -> Result<(), ApiError> {
    let allowlist_ids: Vec<SandboxId> = sandboxes
        .iter()
        .filter(|sandbox| matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }))
        .map(|sandbox| sandbox.id)
        .collect();
    if allowlist_ids.is_empty() {
        return Ok(());
    }

    let mut rules_by_sandbox = list_network_allow_rules_for_sandboxes(db, &allowlist_ids).await?;
    for sandbox in sandboxes {
        if matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
            let rules = rules_by_sandbox.remove(&sandbox.id).unwrap_or_default();
            sandbox.network_egress = NetworkEgress::Allowlist { rules };
        }
    }
    Ok(())
}

/// Batched counterpart to [`list_network_allow_rules`]: fetches rules for every id in
/// `sandbox_ids` with a single `sandbox_id in (...)` query and groups them in memory, rather than
/// issuing one query per sandbox.
pub(crate) async fn list_network_allow_rules_for_sandboxes(
    db: &Database,
    sandbox_ids: &[SandboxId],
) -> Result<HashMap<SandboxId, Vec<NetworkAllowRule>>, ApiError> {
    let mut query = db.query_builder(
        "select sandbox_id, kind, value
         from sandbox_network_egress_rules
         where sandbox_id in (",
    );
    {
        let mut ids = query.separated(", ");
        for sandbox_id in sandbox_ids {
            ids.push_bind(sandbox_id.to_string());
        }
    }
    query.push(") order by sandbox_id asc, kind asc, value asc");
    let rows = query.build().fetch_all(&db.pool).await?;

    let mut grouped: HashMap<SandboxId, Vec<NetworkAllowRule>> = HashMap::new();
    for row in rows {
        let sandbox_id: String = row.try_get("sandbox_id")?;
        let sandbox_id = SandboxId(parse_uuid(&sandbox_id)?);
        let rule = row_to_network_allow_rule(row)?;
        grouped.entry(sandbox_id).or_default().push(rule);
    }
    Ok(grouped)
}

pub(crate) async fn hydrate_sandbox_network_egress(
    db: &Database,
    sandbox: &mut Sandbox,
) -> Result<(), ApiError> {
    if !matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
        return Ok(());
    }
    let rules = list_network_allow_rules(db, sandbox.id).await?;
    sandbox.network_egress = NetworkEgress::Allowlist { rules };
    Ok(())
}

pub(crate) async fn hydrate_sandbox_network_egress_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox: &mut Sandbox,
) -> Result<(), ApiError> {
    if !matches!(sandbox.network_egress, NetworkEgress::Allowlist { .. }) {
        return Ok(());
    }
    let rules = list_network_allow_rules_on_connection(db, connection, sandbox.id).await?;
    sandbox.network_egress = NetworkEgress::Allowlist { rules };
    Ok(())
}

pub(crate) async fn list_network_allow_rules(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<NetworkAllowRule>, ApiError> {
    let sql = format!(
        "select kind, value
         from sandbox_network_egress_rules
         where sandbox_id = {}
         order by kind asc, value asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    rows.into_iter().map(row_to_network_allow_rule).collect()
}

pub(crate) async fn list_network_allow_rules_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
) -> Result<Vec<NetworkAllowRule>, ApiError> {
    let sql = format!(
        "select kind, value
         from sandbox_network_egress_rules
         where sandbox_id = {}
         order by kind asc, value asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&mut *connection)
        .await?;
    rows.into_iter().map(row_to_network_allow_rule).collect()
}
