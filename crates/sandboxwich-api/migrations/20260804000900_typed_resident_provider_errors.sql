-- Preserve the existing provider classification on resident-process failures so
-- tenant reads and connection binding do not have to infer terminal state from
-- an opaque last_error string.
alter table resident_processes add column last_error_class text;
alter table resident_processes add column last_error_code text;
