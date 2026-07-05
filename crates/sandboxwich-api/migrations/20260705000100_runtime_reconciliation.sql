alter table runtime_resources add column observed_at text;
alter table runtime_resources add column last_reconciled_at text;

drop index if exists idx_runtime_resources_identity;

create unique index if not exists idx_runtime_resources_identity
    on runtime_resources(provider, resource_kind, namespace, coalesce(cluster, ''), resource_name);

create index if not exists idx_runtime_resources_reconcile_scope
    on runtime_resources(provider, namespace, cluster, status);
