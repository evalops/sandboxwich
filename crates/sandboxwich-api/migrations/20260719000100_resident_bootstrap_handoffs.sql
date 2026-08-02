-- Shared ephemeral bootstrap handoff.
--
-- Resident-process bootstrap bytes used to live only in the publishing API
-- process, so an API restart or a read that landed on another replica
-- stranded the resident executor. This table carries the bytes between
-- processes, and only ever as AEAD ciphertext sealed under an operator-held
-- key that is never stored in the database: the plaintext columns stay at
-- the digest and byte count that `resident_processes` already records
-- durably.
--
-- Rows are ephemeral by construction: they expire at `expires_at`, are
-- deleted the moment the bootstrap is acknowledged or reclaimed, and cascade
-- away with their resident process.
create table if not exists resident_bootstrap_handoffs (
    resident_process_id text primary key not null
        references resident_processes(id) on delete cascade,
    sandbox_id text not null,
    tenant_id text not null,
    generation bigint not null,
    sha256 text not null,
    byte_count bigint not null,
    target_file text not null,
    mode bigint not null,
    key_id text not null,
    nonce text not null,
    ciphertext text not null,
    created_at text not null,
    expires_at text not null
);

create index if not exists idx_resident_bootstrap_handoffs_expires_at
    on resident_bootstrap_handoffs(expires_at);

create index if not exists idx_resident_bootstrap_handoffs_tenant
    on resident_bootstrap_handoffs(tenant_id);
