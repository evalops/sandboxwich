create table if not exists homes (
    id text primary key not null,
    tenant_id text not null,
    state text not null default 'ready',
    created_at text not null,
    updated_at text not null,
    error text,
    constraint homes_state_check check (state in ('ready', 'deleting', 'delete_failed'))
);

create index if not exists idx_homes_tenant_state on homes(tenant_id, state);

create table if not exists sandbox_home_mounts (
    sandbox_id text primary key not null references sandboxes(id) on delete cascade,
    home_id text not null references homes(id) on delete restrict,
    tenant_id text not null,
    created_at text not null,
    unique(home_id)
);

create index if not exists idx_sandbox_home_mounts_tenant_home
    on sandbox_home_mounts(tenant_id, home_id);
