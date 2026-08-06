-- Deterministic home identity: a caller-supplied external key resolves the
-- same logical home on every request, so a client that loses its response (or
-- its own state) can re-resolve the identical home instead of minting a
-- duplicate. Uniqueness is per tenant; NULL keys remain unconstrained for
-- homes created without one.
alter table homes add column external_key text;

create unique index if not exists idx_homes_tenant_external_key
    on homes(tenant_id, external_key)
    where external_key is not null;
