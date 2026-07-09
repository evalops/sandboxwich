create table if not exists sandbox_placements (
    sandbox_id text primary key not null references sandboxes(id) on delete cascade,
    worker_id text not null references workers(id),
    provider text not null,
    cluster text,
    generation integer not null default 1,
    created_at text not null,
    updated_at text not null
);

create index if not exists idx_sandbox_placements_worker
    on sandbox_placements(worker_id, sandbox_id);
