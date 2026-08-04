-- Keep tenant-scoped keyset pagination on the index instead of sorting every
-- matching sandbox. The list endpoint filters by tenant_id and orders by the
-- stable cursor keys (created_at, id).
create index if not exists idx_sandboxes_tenant_created_id
    on sandboxes(tenant_id, created_at, id);

-- The expiry sweeper only considers lifetime-configured sandboxes. Keep that
-- candidate scan selective while preserving its deterministic processing
-- order.
create index if not exists idx_sandboxes_reap_candidates
    on sandboxes(state, created_at, id)
    where max_lifetime_seconds is not null
       or idle_ttl_seconds is not null;

-- SLO scrapes select terminal observations by metric family, optionally
-- scoped to a tenant. Retain the observed_at index for time-based inspection,
-- but make the hot scrape predicates seekable too.
create index if not exists idx_terminal_slo_observations_kind_tenant
    on terminal_slo_observations(metric_kind, tenant_id);

-- Output append is serialized on the command row. Keep the aggregate bounds
-- and each stream's last sequence beside that lock so the hot path does not
-- rescan every prior output chunk.
alter table commands add column output_chunk_count integer not null default 0;
alter table commands add column output_byte_count integer not null default 0;
alter table commands add column stdout_output_sequence integer not null default 0;
alter table commands add column stderr_output_sequence integer not null default 0;
