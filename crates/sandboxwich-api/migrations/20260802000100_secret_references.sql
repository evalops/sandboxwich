-- Durable, tenant-scoped references to long-lived user and model
-- credentials. The material itself lives in an operator-owned backend; this
-- table never holds a secret value, and there is deliberately no column that
-- could hold one.
create table if not exists secret_refs (
    id text primary key not null,
    tenant_id text not null,
    workspace_id text not null,
    name text not null,
    backend text not null,
    source_object_name text not null,
    source_object_key text not null,
    delivery text not null,
    state text not null default 'active',
    created_at text not null,
    updated_at text not null,
    revoked_at text,
    constraint secret_refs_backend_check check (backend in ('kubernetes_secret')),
    constraint secret_refs_delivery_check check (delivery in ('file')),
    constraint secret_refs_state_check check (state in ('active', 'revoked'))
);

-- One live name per (organization, workspace): the name becomes the guest
-- mount path, so two active references may not resolve to the same file.
create unique index if not exists idx_secret_refs_scope_name
    on secret_refs(tenant_id, workspace_id, name)
    where state = 'active';

create index if not exists idx_secret_refs_scope
    on secret_refs(tenant_id, workspace_id, state);
