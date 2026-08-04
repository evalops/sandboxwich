-- Stop cancels queued jobs and active leases for a sandbox in one transaction.
-- These indexes keep the cancel UPDATEs from scanning the tenant's full job
-- table when sandbox_id / parent / child columns are set.

create index if not exists idx_jobs_sandbox_status
    on jobs(sandbox_id, status);

create index if not exists idx_jobs_parent_sandbox_status
    on jobs(parent_sandbox_id, status);

create index if not exists idx_jobs_child_sandbox_status
    on jobs(child_sandbox_id, status);

create index if not exists idx_job_leases_active_job
    on job_leases(job_id, status);
