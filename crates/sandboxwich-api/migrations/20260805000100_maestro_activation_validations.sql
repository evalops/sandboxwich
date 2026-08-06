create table if not exists maestro_activation_validations (
    tenant_id text not null,
    activation_id text not null,
    sandbox_id text not null,
    tuple_sha256 text not null check (length(tuple_sha256) = 64),
    binding_json text not null,
    validated_at text not null,
    primary key (tenant_id, activation_id),
    foreign key (sandbox_id) references sandboxes(id) on delete cascade
);

create index if not exists idx_maestro_activation_validations_sandbox
    on maestro_activation_validations(tenant_id, sandbox_id, validated_at desc);

create table if not exists maestro_activation_validation_metrics (
    tenant_id text not null,
    outcome text not null check (outcome in ('accepted', 'rejected', 'error')),
    reason text not null check (reason in (
        'validated', 'replayed', 'binding_mismatch', 'replay_mismatch',
        'stale_generation', 'expired_lease', 'not_live', 'not_found',
        'invalid_request', 'internal'
    )),
    sample_count bigint not null check (sample_count >= 0),
    sum_ms bigint not null check (sum_ms >= 0),
    b0 bigint not null check (b0 >= 0),
    b1 bigint not null check (b1 >= 0),
    b2 bigint not null check (b2 >= 0),
    b3 bigint not null check (b3 >= 0),
    b4 bigint not null check (b4 >= 0),
    b5 bigint not null check (b5 >= 0),
    b6 bigint not null check (b6 >= 0),
    b7 bigint not null check (b7 >= 0),
    primary key (tenant_id, outcome, reason)
);
