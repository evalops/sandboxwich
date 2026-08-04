-- Denormalized allowlist rules for GET /sandboxes. The normalized
-- sandbox_network_egress_rules table remains the write-time source of truth;
-- list pages read this column so they avoid a second round-trip under
-- allowlist-heavy tenants (see scripts/perf-harness.py matrix / allowlist).
--
-- Backfill is dialect-specific and runs from migrate_database in db.rs
-- (SQLite json_group_array vs Postgres json_agg).

alter table sandboxes add column network_egress_rules_json text;
