-- Support O(recent) /metrics scrapes that filter observation tables by
-- observed_at (and leased_at for claim latency). Existing single-column
-- time indexes remain; these composites match the scrape predicates.

create index if not exists idx_terminal_slo_observations_kind_observed
    on terminal_slo_observations(metric_kind, observed_at desc);

create index if not exists idx_terminal_slo_observations_kind_tenant_observed
    on terminal_slo_observations(metric_kind, tenant_id, observed_at desc);

create index if not exists idx_job_leases_leased_at
    on job_leases(leased_at);
