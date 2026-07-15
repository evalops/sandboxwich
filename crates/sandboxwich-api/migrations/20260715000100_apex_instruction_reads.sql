create table if not exists apex_instruction_reads (
    id text primary key,
    tenant_id text not null,
    sandbox_id text not null,
    job_id text not null unique,
    idempotency_key text not null,
    callback_nonce text not null unique,
    claim_lease_generation integer not null check (claim_lease_generation > 0),
    request_id text not null,
    lease_id text,
    lease_attempt integer not null default 0 check (lease_attempt >= 0),
    provider_apply_id text not null,
    expected_sha256 text not null,
    expected_byte_count integer not null check (expected_byte_count >= 1 and expected_byte_count <= 1048576),
    observed_sha256 text,
    observed_byte_count integer,
    state text not null check (state in ('pending', 'completed', 'unavailable', 'failed')),
    created_at text not null,
    completed_at text,
    expires_at text not null,
    unique (tenant_id, idempotency_key),
    check ((lease_id is null and lease_attempt = 0) or (lease_id is not null and lease_attempt > 0))
);

create index if not exists idx_apex_instruction_reads_expiry
    on apex_instruction_reads(expires_at, tenant_id, idempotency_key);
