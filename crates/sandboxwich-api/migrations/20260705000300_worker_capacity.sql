alter table workers add column max_concurrent_jobs integer not null default 1;

create index if not exists idx_workers_capacity
    on workers(status, max_concurrent_jobs);
