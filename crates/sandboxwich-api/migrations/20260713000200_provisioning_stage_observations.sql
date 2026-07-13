create table if not exists provisioning_stage_observations (
    sandbox_id text not null references sandboxes(id) on delete cascade,
    lease_id text not null references job_leases(id) on delete cascade,
    stage text not null check (stage in (
        'workspace_planned', 'workspace_ready', 'network_policy_ready',
        'credentials_ready', 'pod_ready', 'service_ready', 'sandbox_ready'
    )),
    stage_index integer not null check (stage_index between 0 and 6),
    lease_attempt integer not null check (lease_attempt > 0),
    error_class text check (error_class is null or error_class in (
        'retryable_provider', 'retryable_capacity', 'terminal_contract', 'terminal_security'
    )),
    observed_at text not null,
    primary key (lease_id, stage)
);

create index if not exists idx_provisioning_stage_observations_time
    on provisioning_stage_observations(observed_at);
