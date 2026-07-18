create table if not exists sidecar_bootstrap_block_rollups (
    tenant_id text not null,
    reason text not null check (
        reason in ('not_running', 'no_active_lease', 'inactive_lease', 'expired_lease')
    ),
    total bigint not null check (total >= 0),
    primary key (tenant_id, reason)
);

-- Preserve counters accumulated before this rollup existed. API-generated
-- event JSON is compact, so these bounded literal matches are portable
-- across both SQLite and PostgreSQL without database-specific JSON syntax.
insert into sidecar_bootstrap_block_rollups (tenant_id, reason, total)
select tenant_id, reason, count(*)
from (
    select sandboxes.tenant_id,
           case
               when sandbox_events.data like '%"reason":"not_running"%'
                   then 'not_running'
               when sandbox_events.data like '%"reason":"no_active_lease"%'
                   then 'no_active_lease'
               when sandbox_events.data like '%"reason":"inactive_lease"%'
                   then 'inactive_lease'
               when sandbox_events.data like '%"reason":"expired_lease"%'
                   then 'expired_lease'
           end as reason
    from sandbox_events
    join sandboxes on sandboxes.id = sandbox_events.sandbox_id
    where sandbox_events.kind = 'sidecar_bootstrap_blocked'
) as historical_blocks
where reason is not null
group by tenant_id, reason;
