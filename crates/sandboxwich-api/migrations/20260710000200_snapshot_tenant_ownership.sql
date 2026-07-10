alter table snapshots add column tenant_id text;

update snapshots
set tenant_id = (
    select sandboxes.tenant_id
    from sandboxes
    where sandboxes.id = snapshots.sandbox_id
)
where tenant_id is null;

create index if not exists idx_snapshots_tenant_id_id
    on snapshots(tenant_id, id);
