-- A provision completion can arrive after the sandbox has already been
-- archived. The reconciliation sweeper must be safe to run on every API
-- replica without queueing duplicate provider teardowns.
create unique index if not exists idx_jobs_archived_runtime_cleanup_active
    on jobs(sandbox_id)
    where kind = 'stop_sandbox'
      and status in ('queued', 'leased')
      and payload like '%"archivedRuntimeCleanup":true%';
