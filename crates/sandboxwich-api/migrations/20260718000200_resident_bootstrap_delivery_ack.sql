alter table resident_processes add column bootstrap_delivered_generation integer;
alter table resident_processes add column bootstrap_delivered_lease_id text;
alter table resident_processes add column bootstrap_delivered_sha256 text;
alter table resident_processes add column bootstrap_acknowledged_at text;
