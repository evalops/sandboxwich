create table if not exists guest_tokens (
    id text primary key,
    tenant_id text not null,
    worker_id text not null,
    sandbox_id text not null,
    token_hash text not null unique,
    expires_at text not null,
    revoked_at text,
    created_at text not null,
    foreign key (worker_id) references workers(id) on delete cascade,
    foreign key (sandbox_id) references sandboxes(id) on delete cascade
);

create index if not exists idx_guest_tokens_sandbox
    on guest_tokens(tenant_id, sandbox_id, expires_at);
