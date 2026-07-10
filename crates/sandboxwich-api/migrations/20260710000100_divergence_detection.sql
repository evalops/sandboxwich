create table if not exists tool_call_ledger (
    id text primary key,
    tenant_id text not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    external_id text not null,
    session_id text not null,
    receipt_id text not null,
    started_at text not null,
    ended_at text not null,
    revoked_at text,
    created_at text not null,
    unique (tenant_id, external_id),
    check (ended_at >= started_at)
);

create table if not exists tool_call_receipt_scopes (
    ledger_id text not null references tool_call_ledger(id) on delete cascade,
    activity_class text not null check (activity_class in ('process_spawn', 'network_connect', 'file_write')),
    resource_prefix text not null,
    primary key (ledger_id, activity_class, resource_prefix)
);

create table if not exists sensor_observations (
    id text primary key,
    tenant_id text not null,
    external_id text not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    session_id text not null,
    activity_class text not null check (activity_class in ('process_spawn', 'network_connect', 'file_write')),
    resource text not null,
    observed_at text not null,
    reconciliation_status text not null default 'pending' check (reconciliation_status in ('pending', 'matched', 'divergent')),
    attempts integer not null default 0,
    next_attempt_at text,
    last_error text,
    created_at text not null,
    unique (tenant_id, external_id)
);

create table if not exists divergence_findings (
    id text primary key,
    tenant_id text not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    observation_external_id text not null,
    session_id text not null,
    receipt_id text,
    kind text not null check (kind in ('unaccounted_activity', 'receipt_scope_mismatch')),
    activity_class text not null check (activity_class in ('process_spawn', 'network_connect', 'file_write')),
    resource text not null,
    status text not null default 'open' check (status in ('open', 'resolved')),
    detected_at text not null,
    resolved_at text,
    unique (tenant_id, observation_external_id)
);

create index if not exists idx_ledger_session_window
    on tool_call_ledger(tenant_id, sandbox_id, session_id, started_at, ended_at);
create index if not exists idx_observations_retry
    on sensor_observations(reconciliation_status, next_attempt_at);
