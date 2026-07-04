create table if not exists jobs (
    id text primary key not null,
    kind text not null,
    status text not null,
    payload text not null,
    required_capability text not null,
    priority integer not null default 0,
    attempts integer not null default 0,
    max_attempts integer not null default 3,
    scheduled_at text not null,
    created_at text not null,
    updated_at text not null,
    last_error text
);

create index if not exists idx_jobs_claimable
    on jobs(status, scheduled_at, priority, created_at);

create table if not exists job_leases (
    id text primary key not null,
    job_id text not null references jobs(id) on delete cascade,
    worker_id text not null references workers(id) on delete cascade,
    status text not null,
    attempt integer not null,
    leased_at text not null,
    expires_at text not null,
    completed_at text,
    error text
);

create index if not exists idx_job_leases_job_id on job_leases(job_id);
create index if not exists idx_job_leases_worker_id_status on job_leases(worker_id, status);
create index if not exists idx_job_leases_status_expires_at on job_leases(status, expires_at);
