-- Cancellation + capacity envelope columns for release-blocking lifecycle work.
--
-- cancel_requested_at / cancel_reason on jobs and leases let stop/archive fence
-- in-flight work so renew returns lease_cancelled and workers abort kubectl waits.
-- resource_envelope on workers stores the last observed schedulable capacity
-- report (JSON WorkerResourceEnvelope) for admission and claim-time matching.

alter table jobs add column deadline_at text;
alter table jobs add column cancel_requested_at text;
alter table jobs add column cancel_reason text;

alter table job_leases add column cancel_requested_at text;
alter table job_leases add column cancel_reason text;

alter table workers add column resource_envelope text;

create index if not exists idx_jobs_cancel_requested
    on jobs(status, cancel_requested_at)
    where cancel_requested_at is not null;

create index if not exists idx_job_leases_cancel_requested
    on job_leases(status, cancel_requested_at)
    where cancel_requested_at is not null;
