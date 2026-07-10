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

-- Restore identity and lifecycle are retained independently from the source
-- sandbox row. The provider can therefore fork a ready snapshot after the
-- source sandbox and its tenant-facing snapshot record have been cleaned up.
create table if not exists snapshot_restore_sources (
    snapshot_id text primary key not null,
    tenant_id text not null,
    source_sandbox_id text not null,
    status text not null,
    expires_at text
);

insert into snapshot_restore_sources
    (snapshot_id, tenant_id, source_sandbox_id, status, expires_at)
select id, tenant_id, sandbox_id, status, expires_at
from snapshots
where tenant_id is not null;

create index if not exists idx_snapshot_restore_sources_tenant_id
    on snapshot_restore_sources(tenant_id, snapshot_id);
