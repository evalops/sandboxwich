alter table sandboxes add column tenant_id text not null default 'default';
alter table workers add column tenant_id text not null default 'default';
alter table jobs add column tenant_id text not null default 'default';

create index if not exists idx_sandboxes_tenant_state
    on sandboxes(tenant_id, state);

create index if not exists idx_workers_tenant_status
    on workers(tenant_id, status);

create index if not exists idx_jobs_tenant_claimable
    on jobs(tenant_id, status, scheduled_at, priority, created_at);
