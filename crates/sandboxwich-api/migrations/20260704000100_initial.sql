create table if not exists sandboxes (
    id text primary key not null,
    name text not null,
    state text not null,
    template text not null,
    created_at text not null,
    updated_at text not null,
    ttl_seconds integer,
    parent_snapshot_id text
);

create index if not exists idx_sandboxes_state on sandboxes(state);
create index if not exists idx_sandboxes_created_at on sandboxes(created_at);

create table if not exists commands (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    status text not null,
    argv text not null,
    cwd text,
    exit_code integer,
    stdout text not null default '',
    stderr text not null default '',
    created_at text not null,
    finished_at text
);

create index if not exists idx_commands_sandbox_id on commands(sandbox_id);

create table if not exists sandbox_events (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    kind text not null,
    data text not null,
    created_at text not null
);

create index if not exists idx_sandbox_events_sandbox_id_created_at
    on sandbox_events(sandbox_id, created_at);
