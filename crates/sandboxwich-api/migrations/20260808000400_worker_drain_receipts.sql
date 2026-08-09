create table if not exists worker_drain_receipts (
    shutdown_id text primary key not null,
    worker_id text not null references workers(id) on delete cascade,
    tenant_id text not null,
    hard_deadline text not null,
    created_at text not null,
    retired_at text
);

create index if not exists idx_worker_drain_receipts_worker_created
    on worker_drain_receipts(worker_id, created_at desc);

create index if not exists idx_worker_drain_receipts_due
    on worker_drain_receipts(retired_at, hard_deadline, worker_id);

create table if not exists worker_drain_lease_fences (
    shutdown_id text not null references worker_drain_receipts(shutdown_id) on delete cascade,
    lease_id text not null references job_leases(id) on delete cascade,
    worker_id text not null references workers(id) on delete cascade,
    job_id text not null references jobs(id) on delete cascade,
    attempt integer not null,
    hard_deadline text not null,
    outcome text,
    resolved_at text,
    primary key (shutdown_id, lease_id),
    check (
        (outcome is null and resolved_at is null)
        or (outcome is not null and resolved_at is not null)
    )
);

create index if not exists idx_worker_drain_fences_due
    on worker_drain_lease_fences(resolved_at, hard_deadline, lease_id);
