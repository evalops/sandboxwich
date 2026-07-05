create table if not exists runtime_resources (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    snapshot_id text references snapshots(id) on delete cascade,
    provider text not null,
    resource_kind text not null,
    purpose text not null,
    resource_name text not null,
    namespace text not null,
    status text not null,
    cluster text,
    storage_class text,
    snapshot_class text,
    storage_size text,
    runtime_image text,
    service_port integer,
    target_port text,
    source_snapshot_id text references snapshots(id) on delete set null,
    created_at text not null,
    updated_at text not null,
    ready_at text,
    deleted_at text,
    error text
);

create unique index if not exists idx_runtime_resources_identity
    on runtime_resources(provider, resource_kind, namespace, resource_name);

create index if not exists idx_runtime_resources_sandbox_id
    on runtime_resources(sandbox_id);

create index if not exists idx_runtime_resources_snapshot_id
    on runtime_resources(snapshot_id);

create index if not exists idx_runtime_resources_status
    on runtime_resources(status);
