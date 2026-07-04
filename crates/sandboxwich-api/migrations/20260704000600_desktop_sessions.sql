create table if not exists desktop_sessions (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    status text not null,
    broker text not null,
    broker_url text,
    access_mode text not null,
    connection_metadata text not null default '{}',
    created_at text not null,
    updated_at text not null,
    expires_at text,
    error text
);

create index if not exists idx_desktop_sessions_sandbox_id_status
    on desktop_sessions(sandbox_id, status);

create index if not exists idx_desktop_sessions_expires_at
    on desktop_sessions(expires_at);
