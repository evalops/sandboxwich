create table if not exists resident_processes (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    tenant_id text not null,
    name text not null,
    argv text not null,
    cwd text,
    env text not null,
    bootstrap_sha256 text,
    bootstrap_byte_count integer,
    bootstrap_target_file text,
    bootstrap_mode integer,
    restart_policy text not null,
    desired_state text not null,
    observed_state text not null,
    generation integer not null,
    active_lease_id text,
    pid integer,
    started_at text,
    ready_at text,
    exited_at text,
    exit_code integer,
    last_error text,
    created_at text not null,
    updated_at text not null,
    unique (sandbox_id, name)
);

create index if not exists idx_resident_processes_tenant_sandbox
    on resident_processes(tenant_id, sandbox_id);

create index if not exists idx_resident_processes_desired_observed
    on resident_processes(desired_state, observed_state);
