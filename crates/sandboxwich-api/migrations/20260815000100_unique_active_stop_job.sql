-- Every provider teardown for one sandbox shares the same lifecycle fence.
-- Enforce the invariant below all ordinary and reconciliation enqueue paths so
-- concurrent API replicas cannot create competing active teardown authority.
create unique index if not exists idx_jobs_one_active_stop_per_sandbox
    on jobs(sandbox_id)
    where sandbox_id is not null
      and kind = 'stop_sandbox'
      and status in ('queued', 'leased');
