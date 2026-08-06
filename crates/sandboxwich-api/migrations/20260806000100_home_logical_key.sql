alter table homes add column logical_key text;

create unique index if not exists idx_homes_tenant_logical_key
    on homes(tenant_id, logical_key);
