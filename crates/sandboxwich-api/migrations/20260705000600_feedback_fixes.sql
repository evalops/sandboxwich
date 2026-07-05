create index if not exists idx_runtime_resources_reconcile_scope_coalesced
    on runtime_resources(provider, namespace, coalesce(cluster, ''), status);

create index if not exists idx_jobs_tenant_claimable_priority
    on jobs(tenant_id, status, priority desc, scheduled_at, created_at, id);

alter table jobs add column sandbox_id text;
alter table jobs add column command_id text;
alter table jobs add column snapshot_id text;
alter table jobs add column parent_sandbox_id text;
alter table jobs add column child_sandbox_id text;
alter table jobs add column prompt_event_id text;

create index if not exists idx_jobs_snapshot_queued
    on jobs(kind, status, snapshot_id);

create index if not exists idx_jobs_child_sandbox
    on jobs(child_sandbox_id);

create table if not exists runtime_resource_tombstones (
    id text primary key not null,
    sandbox_id text not null,
    snapshot_id text,
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
    source_snapshot_id text,
    created_at text not null,
    updated_at text not null,
    observed_at text,
    last_reconciled_at text,
    ready_at text,
    deleted_at text,
    error text,
    tombstoned_at text not null
);

create index if not exists idx_runtime_resource_tombstones_sandbox_id
    on runtime_resource_tombstones(sandbox_id);
