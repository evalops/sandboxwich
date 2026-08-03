-- Composite indexes for the two high-volume observability paths:
-- runtime inventory reconciliation and provisioning-stage metrics.  Both
-- queries are read-only but run frequently on every worker heartbeat/metrics
-- scrape, so their join/filter/order keys must be seekable instead of forcing
-- a full scan and sort.
create index if not exists idx_provisioning_resources_namespace_updated
    on provisioning_operation_resources(resource_namespace, updated_at, resource_uid, sandbox_id);

create index if not exists idx_provisioning_operations_lease_sandbox
    on provisioning_operations(lease_id, sandbox_id);

create index if not exists idx_provisioning_stage_observations_lease_order
    on provisioning_stage_observations(lease_id, observed_at, stage_index);

create index if not exists idx_provisioning_stage_observations_tenant_lease_order
    on provisioning_stage_observations(tenant_id, lease_id, observed_at, stage_index);
