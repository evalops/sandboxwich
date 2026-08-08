create table if not exists sterile_pool_memberships (
    sandbox_id text primary key not null references sandboxes(id) on delete restrict,
    tenant_id text not null,
    state text not null check (state in ('provisioning', 'ready', 'leased', 'stopping', 'cleanup_pending', 'destroyed', 'quarantined')),
    worker_id text references workers(id) on delete restrict,
    provision_job_id text not null unique references jobs(id) on delete restrict,
    stop_job_id text unique references jobs(id) on delete restrict,
    release_set_id text not null,
    runtime_class text not null check (runtime_class in ('kata_microvm', 'gvisor_lower_risk')),
    policy_digest text not null,
    release_signature text not null,
    candidate_agent_image text not null,
    candidate_maestro_image text not null,
    candidate_service_name text not null,
    candidate_pod_name text,
    candidate_pod_uid text,
    ready_ttl_seconds integer not null check (ready_ttl_seconds > 0),
    cell_expires_at text,
    lease_id text,
    generation integer check (generation is null or generation >= 1),
    requested_disposition text check (requested_disposition in ('destroyed', 'quarantined')),
    quarantine_reason text,
    provider_absent integer not null default 0 check (provider_absent in (0, 1)),
    created_at text not null,
    updated_at text not null,
    check (
        (state = 'provisioning' and worker_id is null and lease_id is null and generation is null
            and candidate_pod_name is null and candidate_pod_uid is null
            and cell_expires_at is null)
        or (state = 'ready' and worker_id is not null and lease_id is null and generation = 1
            and candidate_pod_name is not null and candidate_pod_uid is not null
            and cell_expires_at is not null)
        or (state = 'leased' and worker_id is not null and lease_id is not null and generation >= 2
            and candidate_pod_name is not null and candidate_pod_uid is not null)
        or (state = 'stopping' and worker_id is not null and stop_job_id is not null
            and generation >= 1 and requested_disposition is not null
            and ((generation = 1 and lease_id is null and requested_disposition = 'quarantined')
                 or (generation >= 2 and lease_id is not null)))
        or (state = 'cleanup_pending' and worker_id is not null and generation >= 1
            and requested_disposition is not null
            and ((generation = 1 and lease_id is null and requested_disposition = 'quarantined')
                 or (generation >= 2 and lease_id is not null)))
        or (state in ('destroyed', 'quarantined'))
    )
);

create index if not exists idx_sterile_pool_target
    on sterile_pool_memberships(tenant_id, release_set_id, runtime_class, policy_digest,
        release_signature, state, created_at, sandbox_id);
create index if not exists idx_sterile_pool_stop_job
    on sterile_pool_memberships(stop_job_id);

-- One durable row gives concurrent API replicas a portable transaction lock
-- before they count and replenish the pool.
create table if not exists sterile_pool_controller_lock (
    singleton integer primary key not null check (singleton = 1),
    updated_at text not null
);
insert into sterile_pool_controller_lock (singleton, updated_at)
values (1, '1970-01-01T00:00:00Z')
on conflict (singleton) do nothing;
