create table if not exists idempotency_records (
    tenant_id text not null,
    idempotency_key text not null,
    request_fingerprint text not null,
    state text not null,
    response_status integer,
    response_content_type text,
    response_location text,
    response_retry_after text,
    response_body_base64 text,
    created_at text not null,
    completed_at text,
    expires_at text not null,
    primary key (tenant_id, idempotency_key)
);

create index if not exists idx_idempotency_records_expiry
    on idempotency_records(expires_at, tenant_id, idempotency_key);
