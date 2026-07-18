alter table resident_processes add column provider_pod_name text;
alter table resident_processes add column provider_pod_uid text;

create table if not exists resident_placement_attestations (
    id text primary key not null,
    tenant_id text not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    resident_process_id text not null references resident_processes(id) on delete cascade,
    resident_process_generation integer not null,
    lease_id text not null references job_leases(id) on delete cascade,
    lease_attempt integer not null,
    job_id text not null references jobs(id) on delete cascade,
    worker_id text not null references workers(id),
    placement_generation integer not null,
    provider_pod_name text,
    provider_pod_uid text,
    provider_mode text not null,
    runtime_image text not null,
    provider_isolation_version integer not null,
    token_sha256 text not null unique,
    issued_at text not null,
    attestation_expires_at text not null,
    lease_expires_at text not null,
    consumed_at text,
    redeem_idempotency_key text,
    created_at text not null,
    updated_at text not null,
    unique (resident_process_id, resident_process_generation, lease_id),
    unique (tenant_id, redeem_idempotency_key)
);

create index if not exists idx_resident_placement_attestations_live
    on resident_placement_attestations(tenant_id, id, attestation_expires_at);

create index if not exists idx_resident_placement_attestations_process_fence
    on resident_placement_attestations(resident_process_id, resident_process_generation, lease_id);
