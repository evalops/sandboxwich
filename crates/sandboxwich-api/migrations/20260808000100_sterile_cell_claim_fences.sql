create table if not exists sterile_cell_claims (
    tenant_id text not null,
    claim_id text not null,
    request_sha256 text not null,
    cell_id text unique references sterile_cells(id) on delete restrict,
    lease_id text unique,
    created_at text not null,
    primary key (tenant_id, claim_id),
    check (
        (cell_id is null and lease_id is null)
        or (cell_id is not null and lease_id is not null)
    )
);

create index if not exists idx_sterile_cell_claims_cell
    on sterile_cell_claims(cell_id);
