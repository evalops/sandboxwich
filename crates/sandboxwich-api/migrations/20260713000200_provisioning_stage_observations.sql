create table if not exists provisioning_stage_observations (
    sandbox_id text not null,
    lease_id text not null,
    tenant_id text not null,
    workspace_mode text not null,
    stage text not null check (stage in (
        'workspace_planned', 'workspace_ready', 'network_policy_ready',
        'credentials_ready', 'pod_ready', 'service_ready', 'sandbox_ready'
    )),
    stage_index integer not null check (stage_index between 0 and 6),
    lease_attempt integer not null check (lease_attempt > 0),
    error_class text check (error_class is null or error_class in (
        'retryable_provider', 'retryable_capacity', 'terminal_contract', 'terminal_security'
    )),
    started_at text not null,
    observed_at text not null,
    primary key (lease_id, stage)
);

create index if not exists idx_provisioning_stage_observations_time
    on provisioning_stage_observations(observed_at);

create table if not exists terminal_slo_observations (
    source_id text not null,
    tenant_id text not null,
    metric_kind text not null check (metric_kind in ('sandbox_creation', 'command', 'cleanup')),
    outcome text not null check (outcome in ('success', 'failure')),
    workspace_mode text,
    start_type text check (start_type is null or start_type in ('warm', 'cold')),
    duration_ms integer not null check (duration_ms >= 0),
    observed_at text not null,
    primary key (source_id, metric_kind)
);

create index if not exists idx_terminal_slo_observations_time
    on terminal_slo_observations(observed_at);
