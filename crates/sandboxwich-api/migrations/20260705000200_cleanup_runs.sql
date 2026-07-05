create table if not exists cleanup_runs (
    id text primary key not null,
    status text not null,
    started_at text not null,
    finished_at text,
    expired_snapshots integer not null default 0,
    archived_sandboxes_deleted integer not null default 0,
    archived_sandboxes_skipped integer not null default 0,
    runtime_resources_deleted integer not null default 0,
    error text
);

create index if not exists idx_cleanup_runs_started_at
    on cleanup_runs(started_at);
