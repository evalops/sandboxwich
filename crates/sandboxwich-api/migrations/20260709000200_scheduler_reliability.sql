drop index if exists idx_jobs_tenant_claimable_priority;

create index if not exists idx_jobs_tenant_capability_claimable
    on jobs(tenant_id, status, required_capability, scheduled_at, priority desc, created_at, id);

create index if not exists idx_job_leases_active_expiry
    on job_leases(status, expires_at, id);

create index if not exists idx_workers_status_heartbeat
    on workers(status, last_heartbeat_at, id);

create index if not exists idx_worker_heartbeats_created
    on worker_heartbeats(created_at, id);

create table if not exists lease_claim_operations (
    worker_id text not null references workers(id) on delete cascade,
    operation_id text not null,
    lease_id text not null references job_leases(id) on delete cascade,
    created_at text not null,
    primary key(worker_id, operation_id)
);

create table if not exists command_output_operations (
    lease_id text not null references job_leases(id) on delete cascade,
    operation_id text not null,
    chunk_id text not null references command_output_chunks(id) on delete cascade,
    created_at text not null,
    primary key(lease_id, operation_id)
);

create unique index if not exists idx_workers_logical_identity
    on workers(tenant_id, name, provider);

create table if not exists worker_sessions (
    worker_id text primary key not null references workers(id) on delete cascade,
    generation integer not null,
    started_at text not null
);
