create table if not exists workers (
    id text primary key not null,
    name text not null,
    status text not null,
    provider text not null,
    capabilities text not null,
    labels text not null default '{}',
    registered_at text not null,
    last_heartbeat_at text
);

create index if not exists idx_workers_status on workers(status);
create index if not exists idx_workers_provider on workers(provider);

create table if not exists worker_heartbeats (
    id text primary key not null,
    worker_id text not null references workers(id) on delete cascade,
    labels text not null default '{}',
    created_at text not null
);

create index if not exists idx_worker_heartbeats_worker_id_created_at
    on worker_heartbeats(worker_id, created_at);
