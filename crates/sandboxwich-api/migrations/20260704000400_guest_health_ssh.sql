create table if not exists guest_health (
    sandbox_id text primary key not null references sandboxes(id) on delete cascade,
    status text not null,
    last_probe_at text not null,
    agent_version text,
    checks text not null default '{}',
    message text
);

create index if not exists idx_guest_health_status on guest_health(status);

create table if not exists ssh_keys (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    public_key text not null,
    principal text not null,
    status text not null,
    requested_at text not null,
    updated_at text not null,
    applied_at text,
    error text
);

create index if not exists idx_ssh_keys_sandbox_id_status
    on ssh_keys(sandbox_id, status);
