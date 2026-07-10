create table tenant_limit_policies (
    tenant_id text primary key,
    request_limit integer not null check (request_limit > 0),
    mutation_limit integer not null check (mutation_limit > 0),
    window_seconds integer not null check (window_seconds > 0),
    updated_at text not null
);

create table tenant_limit_counters (
    tenant_id text not null,
    kind text not null check (kind in ('request', 'mutation')),
    used integer not null check (used >= 0),
    window_started_at text not null,
    window_expires_at text not null,
    primary key (tenant_id, kind)
);

create index idx_tenant_limit_counters_expiry
    on tenant_limit_counters(window_expires_at);
