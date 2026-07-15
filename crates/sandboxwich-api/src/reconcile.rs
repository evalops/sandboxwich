use crate::auth::*;
use crate::db::*;
use crate::error::*;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::rows::*;
use crate::state::*;
use axum::Json;
use axum::extract::{Extension, Path, State};
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use sqlx::AnyConnection;
use sqlx::Row;
use uuid::Uuid;

pub(crate) async fn list_runtime_resources(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(sandbox_id): Path<Uuid>,
) -> Result<Json<RuntimeResourceListResponse>, ApiError> {
    let sandbox_id = SandboxId(sandbox_id);
    ensure_sandbox_tenant(&state.db, sandbox_id, &ctx).await?;
    let resources = list_runtime_resources_for_sandbox(&state.db, sandbox_id).await?;
    Ok(Json(RuntimeResourceListResponse {
        ok: true,
        resources,
    }))
}

pub(crate) async fn reconcile_runtime_resources(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Path(worker_id): Path<Uuid>,
    Json(request): Json<ReconcileRuntimeResourcesRequest>,
) -> Result<Json<ReconcileRuntimeResourcesResponse>, ApiError> {
    let worker = ensure_worker_tenant(&state.db, WorkerId(worker_id), &ctx).await?;
    if worker.provider != request.provider {
        return Err(ApiError::bad_request(
            "runtime resource provider must match worker provider",
        ));
    }
    validate_reconcile_runtime_resources_request(&request)?;

    let observed_at = Utc::now();
    let mut tx = state.db.pool.begin().await?;
    let reconciled = reconcile_runtime_resources_on_connection(
        &state.db,
        &mut tx,
        &request,
        &ctx.tenant_id,
        observed_at,
    )
    .await;

    match reconciled {
        Ok((upserted, deleted)) => {
            tx.commit().await?;
            Ok(Json(ReconcileRuntimeResourcesResponse {
                ok: true,
                observed_at,
                upserted,
                deleted,
            }))
        }
        Err(error) => {
            if let Err(rollback_error) = tx.rollback().await {
                tracing::warn!(%rollback_error, "failed to roll back runtime resource reconcile");
            }
            Err(error)
        }
    }
}

pub(crate) async fn list_runtime_resources_for_sandbox(
    db: &Database,
    sandbox_id: SandboxId,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where sandbox_id = {}
         order by provider asc, namespace asc, resource_kind asc, purpose asc, resource_name asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&db.pool)
        .await?;

    rows.into_iter().map(row_to_runtime_resource).collect()
}

pub(crate) async fn upsert_provider_runtime_resources_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resources: &[ProviderRuntimeResource],
    tenant_id: &str,
) -> Result<(), ApiError> {
    let observed_at = Utc::now();
    for resource in resources {
        upsert_provider_runtime_resource_on_connection(
            db,
            connection,
            resource,
            Some(observed_at),
            None,
            Some(tenant_id),
        )
        .await?;
    }

    Ok(())
}

pub(crate) async fn reconcile_runtime_resources_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    request: &ReconcileRuntimeResourcesRequest,
    tenant_id: &str,
    observed_at: DateTime<Utc>,
) -> Result<(Vec<RuntimeResource>, Vec<RuntimeResource>), ApiError> {
    let mut upserted = Vec::new();
    let mut observed = Vec::new();

    for resource in &request.resources {
        ensure_sandbox_tenant_on_connection(db, connection, resource.sandbox_id, tenant_id).await?;
        if let Some(snapshot_id) = resource.snapshot_id {
            let snapshot = fetch_snapshot_on_connection(db, connection, snapshot_id).await?;
            if snapshot.sandbox_id != resource.sandbox_id {
                return Err(ApiError::bad_request(
                    "runtime resource snapshot must belong to the resource sandbox",
                ));
            }
        }
        let resource = upsert_provider_runtime_resource_on_connection(
            db,
            connection,
            resource,
            Some(observed_at),
            Some(observed_at),
            Some(tenant_id),
        )
        .await?;
        observed.push(ObservedRuntimeResourceIdentity {
            resource_kind: resource.resource_kind.clone(),
            resource_name: resource.resource_name.clone(),
        });
        upserted.push(resource);
    }

    let deleted = if request.mark_missing_deleted {
        mark_missing_runtime_resources_deleted_on_connection(
            db,
            connection,
            request,
            tenant_id,
            &observed,
            observed_at,
        )
        .await?
    } else {
        Vec::new()
    };

    Ok((upserted, deleted))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedRuntimeResourceIdentity {
    pub(crate) resource_kind: RuntimeResourceKind,
    pub(crate) resource_name: String,
}

pub(crate) fn validate_reconcile_runtime_resources_request(
    request: &ReconcileRuntimeResourcesRequest,
) -> Result<(), ApiError> {
    if request.provider.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource provider is required",
        ));
    }
    if request.namespace.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource namespace is required",
        ));
    }
    if request
        .cluster
        .as_ref()
        .is_some_and(|cluster| cluster.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "runtime resource cluster cannot be empty",
        ));
    }

    for resource in &request.resources {
        validate_provider_runtime_resource(resource)?;
        if resource.provider != request.provider {
            return Err(ApiError::bad_request(
                "observed runtime resource provider must match reconcile provider",
            ));
        }
        if resource.namespace != request.namespace {
            return Err(ApiError::bad_request(
                "observed runtime resource namespace must match reconcile namespace",
            ));
        }
        if resource.cluster != request.cluster {
            return Err(ApiError::bad_request(
                "observed runtime resource cluster must match reconcile cluster",
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_provider_runtime_resource(
    resource: &ProviderRuntimeResource,
) -> Result<(), ApiError> {
    if resource.provider.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource provider is required",
        ));
    }
    if resource.namespace.trim().is_empty() {
        return Err(ApiError::bad_request(
            "runtime resource namespace is required",
        ));
    }
    if resource
        .cluster
        .as_ref()
        .is_some_and(|cluster| cluster.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "runtime resource cluster cannot be empty",
        ));
    }
    if resource.resource_name.trim().is_empty() {
        return Err(ApiError::bad_request("runtime resource name is required"));
    }
    if resource.service_port == Some(0) {
        return Err(ApiError::bad_request(
            "runtime resource service_port must be greater than 0",
        ));
    }
    Ok(())
}

pub(crate) async fn fetch_runtime_resource_id_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    provider: &str,
    resource_kind: &RuntimeResourceKind,
    namespace: &str,
    cluster: &Option<String>,
    resource_name: &str,
) -> Result<Option<RuntimeResourceId>, ApiError> {
    let (sql, bind_cluster) = if cluster.is_some() {
        (
            format!(
                "select id
                 from runtime_resources
                 where provider = {} and resource_kind = {} and namespace = {} and cluster = {}
                   and resource_name = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4),
                db.placeholder(5)
            ),
            true,
        )
    } else {
        (
            format!(
                "select id
                 from runtime_resources
                 where provider = {} and resource_kind = {} and namespace = {} and cluster is null
                   and resource_name = {}",
                db.placeholder(1),
                db.placeholder(2),
                db.placeholder(3),
                db.placeholder(4)
            ),
            false,
        )
    };
    let mut query = sqlx::query(&sql)
        .bind(provider)
        .bind(runtime_resource_kind_to_str(resource_kind))
        .bind(namespace);
    if bind_cluster {
        query = query.bind(cluster);
    }
    let row = query
        .bind(resource_name)
        .fetch_optional(&mut *connection)
        .await?;
    row.map(|row| {
        let id: String = row.try_get("id")?;
        Ok(RuntimeResourceId(parse_uuid(&id)?))
    })
    .transpose()
}

pub(crate) async fn fetch_runtime_resource_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource_id: RuntimeResourceId,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(resource_id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| ApiError::not_found("runtime resource not found"))?;

    row_to_runtime_resource(row)
}

pub(crate) async fn upsert_provider_runtime_resource_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource: &ProviderRuntimeResource,
    observed_at: Option<DateTime<Utc>>,
    last_reconciled_at: Option<DateTime<Utc>>,
    tenant_id: Option<&str>,
) -> Result<RuntimeResource, ApiError> {
    validate_provider_runtime_resource(resource)?;
    if let Some(tenant_id) = tenant_id {
        ensure_sandbox_tenant_on_connection(db, connection, resource.sandbox_id, tenant_id).await?;
    }
    let existing_id = fetch_runtime_resource_id_on_connection(
        db,
        connection,
        &resource.provider,
        &resource.resource_kind,
        &resource.namespace,
        &resource.cluster,
        &resource.resource_name,
    )
    .await?;
    if let Some(resource_id) = existing_id {
        if let Some(tenant_id) = tenant_id {
            let existing =
                fetch_runtime_resource_on_connection(db, connection, resource_id).await?;
            ensure_sandbox_tenant_on_connection(db, connection, existing.sandbox_id, tenant_id)
                .await?;
        }
        update_runtime_resource_from_provider_on_connection(
            db,
            connection,
            resource_id,
            resource,
            observed_at,
            last_reconciled_at,
        )
        .await
    } else {
        insert_runtime_resource_from_provider_on_connection(
            db,
            connection,
            resource,
            observed_at,
            last_reconciled_at,
        )
        .await
    }
}

pub(crate) async fn insert_runtime_resource_from_provider_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource: &ProviderRuntimeResource,
    observed_at: Option<DateTime<Utc>>,
    last_reconciled_at: Option<DateTime<Utc>>,
) -> Result<RuntimeResource, ApiError> {
    let now = Utc::now();
    let resource_id = RuntimeResourceId::new();
    let deleted_at = deleted_at_for_runtime_resource(&resource.status, now);
    let sql = format!(
        "insert into runtime_resources
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, observed_at, last_reconciled_at,
          ready_at, deleted_at, error)
         values ({})",
        db.placeholders(24)
    );
    sqlx::query(&sql)
        .bind(resource_id.to_string())
        .bind(resource.sandbox_id.to_string())
        .bind(
            resource
                .snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(&resource.provider)
        .bind(runtime_resource_kind_to_str(&resource.resource_kind))
        .bind(runtime_resource_purpose_to_str(&resource.purpose))
        .bind(&resource.resource_name)
        .bind(&resource.namespace)
        .bind(runtime_resource_status_to_str(&resource.status))
        .bind(&resource.cluster)
        .bind(&resource.storage_class)
        .bind(&resource.snapshot_class)
        .bind(&resource.storage_size)
        .bind(&resource.runtime_image)
        .bind(resource.service_port.map(i64::from))
        .bind(&resource.target_port)
        .bind(
            resource
                .source_snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(observed_at.map(|time| time.to_rfc3339()))
        .bind(last_reconciled_at.map(|time| time.to_rfc3339()))
        .bind(resource.ready_at.map(|time| time.to_rfc3339()))
        .bind(deleted_at.map(|time| time.to_rfc3339()))
        .bind(&resource.error)
        .execute(&mut *connection)
        .await?;
    fetch_runtime_resource_on_connection(db, connection, resource_id).await
}

pub(crate) async fn update_runtime_resource_from_provider_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource_id: RuntimeResourceId,
    resource: &ProviderRuntimeResource,
    observed_at: Option<DateTime<Utc>>,
    last_reconciled_at: Option<DateTime<Utc>>,
) -> Result<RuntimeResource, ApiError> {
    let now = Utc::now();
    let deleted_at = deleted_at_for_runtime_resource(&resource.status, now);
    let sql = format!(
        "update runtime_resources
         set sandbox_id = {}, snapshot_id = {}, provider = {}, resource_kind = {}, purpose = {},
             resource_name = {}, namespace = {}, status = {}, cluster = {}, storage_class = {},
             snapshot_class = {}, storage_size = {}, runtime_image = {}, service_port = {},
             target_port = {}, source_snapshot_id = {}, updated_at = {}, ready_at = {},
             deleted_at = {}, error = {}, observed_at = {}, last_reconciled_at = coalesce({}, last_reconciled_at)
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9),
        db.placeholder(10),
        db.placeholder(11),
        db.placeholder(12),
        db.placeholder(13),
        db.placeholder(14),
        db.placeholder(15),
        db.placeholder(16),
        db.placeholder(17),
        db.placeholder(18),
        db.placeholder(19),
        db.placeholder(20),
        db.placeholder(21),
        db.placeholder(22),
        db.placeholder(23)
    );
    let result = sqlx::query(&sql)
        .bind(resource.sandbox_id.to_string())
        .bind(
            resource
                .snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(&resource.provider)
        .bind(runtime_resource_kind_to_str(&resource.resource_kind))
        .bind(runtime_resource_purpose_to_str(&resource.purpose))
        .bind(&resource.resource_name)
        .bind(&resource.namespace)
        .bind(runtime_resource_status_to_str(&resource.status))
        .bind(&resource.cluster)
        .bind(&resource.storage_class)
        .bind(&resource.snapshot_class)
        .bind(&resource.storage_size)
        .bind(&resource.runtime_image)
        .bind(resource.service_port.map(i64::from))
        .bind(&resource.target_port)
        .bind(
            resource
                .source_snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(now.to_rfc3339())
        .bind(resource.ready_at.map(|time| time.to_rfc3339()))
        .bind(deleted_at.map(|time| time.to_rfc3339()))
        .bind(&resource.error)
        .bind(observed_at.map(|time| time.to_rfc3339()))
        .bind(last_reconciled_at.map(|time| time.to_rfc3339()))
        .bind(resource_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("runtime resource not found"));
    }
    fetch_runtime_resource_on_connection(db, connection, resource_id).await
}

pub(crate) async fn mark_missing_runtime_resources_deleted_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    request: &ReconcileRuntimeResourcesRequest,
    tenant_id: &str,
    observed: &[ObservedRuntimeResourceIdentity],
    reconciled_at: DateTime<Utc>,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let mut placeholder_index = 1;
    let provider_placeholder = db.placeholder(placeholder_index);
    placeholder_index += 1;
    let namespace_placeholder = db.placeholder(placeholder_index);
    placeholder_index += 1;
    let cluster_filter = if request.cluster.is_some() {
        let cluster_placeholder = db.placeholder(placeholder_index);
        placeholder_index += 1;
        format!("runtime_resources.cluster = {cluster_placeholder}")
    } else {
        "runtime_resources.cluster is null".to_string()
    };
    let tenant_placeholder = db.placeholder(placeholder_index);
    placeholder_index += 1;

    let mut observed_filters = Vec::new();
    for _ in observed {
        let kind_placeholder = db.placeholder(placeholder_index);
        placeholder_index += 1;
        let name_placeholder = db.placeholder(placeholder_index);
        placeholder_index += 1;
        observed_filters.push(format!(
            "(runtime_resources.resource_kind = {kind_placeholder} and runtime_resources.resource_name = {name_placeholder})"
        ));
    }
    let missing_filter = if observed_filters.is_empty() {
        String::new()
    } else {
        format!(" and not ({})", observed_filters.join(" or "))
    };

    let sql = format!(
        "select runtime_resources.id, runtime_resources.sandbox_id, runtime_resources.snapshot_id,
                runtime_resources.provider, runtime_resources.resource_kind, runtime_resources.purpose,
                runtime_resources.resource_name, runtime_resources.namespace, runtime_resources.status,
                runtime_resources.cluster, runtime_resources.storage_class, runtime_resources.snapshot_class,
                runtime_resources.storage_size, runtime_resources.runtime_image, runtime_resources.service_port,
                runtime_resources.target_port, runtime_resources.source_snapshot_id, runtime_resources.created_at,
                runtime_resources.updated_at, runtime_resources.observed_at, runtime_resources.last_reconciled_at,
                runtime_resources.ready_at, runtime_resources.deleted_at, runtime_resources.error
         from runtime_resources
         join sandboxes on sandboxes.id = runtime_resources.sandbox_id
         where runtime_resources.provider = {provider_placeholder}
           and runtime_resources.namespace = {namespace_placeholder}
           and {cluster_filter}
           and sandboxes.tenant_id = {tenant_placeholder}
           and runtime_resources.status not in ('deleted', 'destroyed')
           {missing_filter}
         order by runtime_resources.resource_kind asc, runtime_resources.resource_name asc, runtime_resources.id asc"
    );
    let mut query = sqlx::query(&sql)
        .bind(&request.provider)
        .bind(&request.namespace);
    if request.cluster.is_some() {
        query = query.bind(&request.cluster);
    }
    query = query.bind(tenant_id);
    for identity in observed {
        query = query
            .bind(runtime_resource_kind_to_str(&identity.resource_kind))
            .bind(&identity.resource_name);
    }
    let candidates = query.fetch_all(&mut *connection).await?;

    let mut deleted = Vec::new();
    for row in candidates {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(
            mark_runtime_resource_deleted_on_connection(
                db,
                connection,
                resource.id,
                reconciled_at,
                RuntimeResourceStatus::Deleted,
                "missing from runtime resource reconcile observation",
            )
            .await?,
        );
    }

    Ok(deleted)
}

pub(crate) async fn mark_runtime_resource_deleted_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource_id: RuntimeResourceId,
    deleted_at: DateTime<Utc>,
    status: RuntimeResourceStatus,
    error: &str,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "update runtime_resources
         set status = {}, updated_at = {}, last_reconciled_at = {}, deleted_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let result = sqlx::query(&sql)
        .bind(runtime_resource_status_to_str(&status))
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(error)
        .bind(resource_id.to_string())
        .execute(&mut *connection)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("runtime resource not found"));
    }

    fetch_runtime_resource_on_connection(db, connection, resource_id).await
}

pub(crate) async fn mark_runtime_resource_deleted(
    db: &Database,
    resource_id: RuntimeResourceId,
    deleted_at: DateTime<Utc>,
    error: &str,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "update runtime_resources
         set status = {}, updated_at = {}, last_reconciled_at = {}, deleted_at = {}, error = {}
         where id = {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6)
    );
    let result = sqlx::query(&sql)
        .bind(runtime_resource_status_to_str(
            &RuntimeResourceStatus::Deleted,
        ))
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(deleted_at.to_rfc3339())
        .bind(error)
        .bind(resource_id.to_string())
        .execute(&db.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("runtime resource not found"));
    }

    fetch_runtime_resource(db, resource_id).await
}

pub(crate) async fn mark_runtime_resources_deleted_for_sandbox_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    sandbox_id: SandboxId,
    deleted_at: DateTime<Utc>,
    error: &str,
) -> Result<Vec<RuntimeResource>, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where sandbox_id = {} and status not in ('deleted', 'destroyed')
         order by updated_at asc, id asc",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(sandbox_id.to_string())
        .fetch_all(&mut *connection)
        .await?;

    let mut deleted = Vec::new();
    for row in rows {
        let resource = row_to_runtime_resource(row)?;
        deleted.push(
            mark_runtime_resource_deleted_on_connection(
                db,
                connection,
                resource.id,
                deleted_at,
                RuntimeResourceStatus::Destroyed,
                error,
            )
            .await?,
        );
    }

    Ok(deleted)
}

pub(crate) async fn insert_runtime_resource_tombstone_on_connection(
    db: &Database,
    connection: &mut AnyConnection,
    resource: &RuntimeResource,
    tombstoned_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let sql = format!(
        "insert into runtime_resource_tombstones
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, observed_at, last_reconciled_at,
          ready_at, deleted_at, error, tombstoned_at)
         values ({})
         on conflict (id) do update set
             status = excluded.status,
             updated_at = excluded.updated_at,
             last_reconciled_at = excluded.last_reconciled_at,
             deleted_at = excluded.deleted_at,
             error = excluded.error,
             tombstoned_at = excluded.tombstoned_at",
        db.placeholders(25)
    );
    sqlx::query(&sql)
        .bind(resource.id.to_string())
        .bind(resource.sandbox_id.to_string())
        .bind(
            resource
                .snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(&resource.provider)
        .bind(runtime_resource_kind_to_str(&resource.resource_kind))
        .bind(runtime_resource_purpose_to_str(&resource.purpose))
        .bind(&resource.resource_name)
        .bind(&resource.namespace)
        .bind(runtime_resource_status_to_str(&resource.status))
        .bind(&resource.cluster)
        .bind(&resource.storage_class)
        .bind(&resource.snapshot_class)
        .bind(&resource.storage_size)
        .bind(&resource.runtime_image)
        .bind(resource.service_port.map(i64::from))
        .bind(&resource.target_port)
        .bind(
            resource
                .source_snapshot_id
                .map(|snapshot_id| snapshot_id.to_string()),
        )
        .bind(resource.created_at.to_rfc3339())
        .bind(resource.updated_at.to_rfc3339())
        .bind(resource.observed_at.map(|time| time.to_rfc3339()))
        .bind(resource.last_reconciled_at.map(|time| time.to_rfc3339()))
        .bind(resource.ready_at.map(|time| time.to_rfc3339()))
        .bind(resource.deleted_at.map(|time| time.to_rfc3339()))
        .bind(&resource.error)
        .bind(tombstoned_at.to_rfc3339())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub(crate) fn deleted_at_for_runtime_resource(
    status: &RuntimeResourceStatus,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if matches!(
        status,
        RuntimeResourceStatus::Deleted | RuntimeResourceStatus::Destroyed
    ) {
        Some(now)
    } else {
        None
    }
}

pub(crate) async fn fetch_runtime_resource(
    db: &Database,
    resource_id: RuntimeResourceId,
) -> Result<RuntimeResource, ApiError> {
    let sql = format!(
        "select id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name,
                namespace, status, cluster, storage_class, snapshot_class, storage_size,
                runtime_image, service_port, target_port, source_snapshot_id, created_at,
                updated_at, observed_at, last_reconciled_at, ready_at, deleted_at, error
         from runtime_resources
         where id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(resource_id.to_string())
        .fetch_optional(&db.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("runtime resource not found"))?;

    row_to_runtime_resource(row)
}
