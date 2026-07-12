create table if not exists provisioning_operations (
    sandbox_id text primary key references sandboxes(id) on delete cascade,
    lease_id text not null references job_leases(id) on delete cascade,
    lease_attempt integer not null check (lease_attempt > 0),
    stage text not null check (stage in (
        'workspace_planned',
        'workspace_ready',
        'network_policy_ready',
        'credentials_ready',
        'pod_ready',
        'service_ready',
        'sandbox_ready'
    )),
    resource_kind text check (resource_kind is null or resource_kind in (
        'pod',
        'persistent_volume_claim',
        'service',
        'secret',
        'network_policy',
        'volume_snapshot'
    )),
    resource_namespace text,
    resource_name text,
    resource_uid text,
    observed_generation integer,
    attempt_count integer not null check (attempt_count > 0),
    last_error_class text check (last_error_class is null or last_error_class in (
        'retryable_provider',
        'retryable_capacity',
        'terminal_contract',
        'terminal_security'
    )),
    last_error text,
    updated_at text not null
);

create index if not exists idx_provisioning_operations_lease
    on provisioning_operations(lease_id, lease_attempt);

create index if not exists idx_provisioning_operations_stage_updated
    on provisioning_operations(stage, updated_at);
