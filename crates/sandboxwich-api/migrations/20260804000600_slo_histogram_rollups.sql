-- Hourly histogram rollups for terminal SLO families (#262). Raw rows stay
-- for a short recent window; older events fold into fixed buckets so scrapes
-- stay O(cardinality + recent), not O(lifetime history).

create table if not exists slo_histogram_rollups (
    bucket_start text not null,
    tenant_id text not null,
    metric_kind text not null,
    label_a text not null default '',
    label_b text not null default '',
    label_c text not null default '',
    sample_count integer not null,
    sum_ms integer not null,
    b0 integer not null default 0,
    b1 integer not null default 0,
    b2 integer not null default 0,
    b3 integer not null default 0,
    b4 integer not null default 0,
    b5 integer not null default 0,
    b6 integer not null default 0,
    b7 integer not null default 0,
    primary key (bucket_start, tenant_id, metric_kind, label_a, label_b, label_c)
);

create index if not exists idx_slo_histogram_rollups_kind_bucket
    on slo_histogram_rollups(metric_kind, bucket_start);

create index if not exists idx_slo_histogram_rollups_kind_tenant_bucket
    on slo_histogram_rollups(metric_kind, tenant_id, bucket_start);
