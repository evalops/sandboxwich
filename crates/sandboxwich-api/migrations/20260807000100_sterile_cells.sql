create table if not exists sterile_cells (
    id text primary key not null,
    worker_id text not null references workers(id) on delete restrict,
    provider_cell_id text not null,
    state text not null check (state in ('ready', 'leased', 'destroyed', 'quarantined')),
    generation integer not null check (generation >= 1),
    release_set_id text not null,
    runtime_class text not null check (runtime_class in ('kata_microvm', 'gvisor_lower_risk')),
    policy_digest text not null,
    release_signature text not null,
    tenant_id text,
    organization_id text,
    workspace_id text,
    thread_id text,
    runner_session_id text,
    lease_id text unique,
    lease_attestation_sha256 text,
    lease_expires_at text,
    cell_expires_at text not null,
    disposition text check (disposition in ('destroyed', 'quarantined')),
    ever_tenant_exposed integer not null default 0 check (ever_tenant_exposed in (0, 1)),
    created_at text not null,
    leased_at text,
    destroyed_at text,
    updated_at text not null,
    unique (worker_id, provider_cell_id),
    check (
        (state = 'ready' and generation = 1 and ever_tenant_exposed = 0
            and tenant_id is not null and lease_id is null and disposition is null)
        or (state = 'leased' and generation >= 2 and ever_tenant_exposed = 1
            and tenant_id is not null and organization_id is not null
            and workspace_id is not null and thread_id is not null
            and runner_session_id is not null and lease_id is not null
            and lease_attestation_sha256 is not null and lease_expires_at is not null
            and disposition is null)
        or (state in ('destroyed', 'quarantined'))
    )
);

create index if not exists idx_sterile_cells_ready_release
    on sterile_cells(tenant_id, state, release_set_id, runtime_class, policy_digest,
        release_signature, created_at, id);
create index if not exists idx_sterile_cells_worker_state
    on sterile_cells(worker_id, state, updated_at);
create index if not exists idx_sterile_cells_tenant_lease
    on sterile_cells(tenant_id, lease_id);
create index if not exists idx_sterile_cells_cell_expiry
    on sterile_cells(state, cell_expires_at);
create index if not exists idx_sterile_cells_lease_expiry
    on sterile_cells(state, lease_expires_at);
