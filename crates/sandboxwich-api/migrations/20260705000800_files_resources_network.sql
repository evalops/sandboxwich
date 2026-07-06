alter table sandboxes add column memory_limit text not null default '1g';
alter table sandboxes add column network_egress_mode text not null default 'deny_all';

create table if not exists sandbox_network_egress_rules (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    kind text not null,
    value text not null,
    created_at text not null
);

create index if not exists idx_sandbox_network_egress_rules_sandbox_id
    on sandbox_network_egress_rules(sandbox_id);

create unique index if not exists idx_sandbox_network_egress_rules_identity
    on sandbox_network_egress_rules(sandbox_id, kind, value);

create table if not exists sandbox_files (
    id text primary key not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    path text not null,
    size_bytes integer not null,
    mime_type text,
    content_base64 text not null,
    created_at text not null,
    updated_at text not null
);

create unique index if not exists idx_sandbox_files_sandbox_path
    on sandbox_files(sandbox_id, path);

create index if not exists idx_sandbox_files_sandbox_updated
    on sandbox_files(sandbox_id, updated_at);

alter table command_output_chunks add column annotations text not null default '[]';
