-- Keep cumulative SLO histogram counters wide enough for long-lived tenants.
-- The original rollup table used 32-bit INTEGER counters, which overflowed
-- during the terminal-observation scheduler's additive upserts.

create table slo_histogram_rollups_bigint (
    bucket_start text not null,
    tenant_id text not null,
    metric_kind text not null,
    label_a text not null default '',
    label_b text not null default '',
    label_c text not null default '',
    sample_count bigint not null,
    sum_ms bigint not null,
    b0 bigint not null default 0,
    b1 bigint not null default 0,
    b2 bigint not null default 0,
    b3 bigint not null default 0,
    b4 bigint not null default 0,
    b5 bigint not null default 0,
    b6 bigint not null default 0,
    b7 bigint not null default 0,
    primary key (bucket_start, tenant_id, metric_kind, label_a, label_b, label_c)
);

insert into slo_histogram_rollups_bigint (
    bucket_start,
    tenant_id,
    metric_kind,
    label_a,
    label_b,
    label_c,
    sample_count,
    sum_ms,
    b0,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7
)
select
    bucket_start,
    tenant_id,
    metric_kind,
    label_a,
    label_b,
    label_c,
    sample_count,
    sum_ms,
    b0,
    b1,
    b2,
    b3,
    b4,
    b5,
    b6,
    b7
from slo_histogram_rollups;

drop table slo_histogram_rollups;
alter table slo_histogram_rollups_bigint rename to slo_histogram_rollups;

create index idx_slo_histogram_rollups_kind_bucket
    on slo_histogram_rollups(metric_kind, bucket_start);

create index idx_slo_histogram_rollups_kind_tenant_bucket
    on slo_histogram_rollups(metric_kind, tenant_id, bucket_start);
