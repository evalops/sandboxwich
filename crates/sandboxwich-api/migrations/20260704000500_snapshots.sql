create table if not exists snapshots (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    status text not null,
    label text not null,
    inventory text not null default '{}',
    provider_metadata text not null default '{}',
    created_at text not null,
    ready_at text,
    expires_at text,
    error text
);

create index if not exists idx_snapshots_sandbox_id_status
    on snapshots(sandbox_id, status);

create index if not exists idx_snapshots_expires_at
    on snapshots(expires_at);

create index if not exists idx_sandboxes_parent_snapshot_id
    on sandboxes(parent_snapshot_id);
