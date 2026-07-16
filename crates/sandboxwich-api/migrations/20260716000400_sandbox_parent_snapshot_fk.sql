-- `sandboxes.parent_snapshot_id` (set when a sandbox is forked from a
-- snapshot; see `fork_sandbox` / `fork_snapshot`) has never had a foreign key
-- -- only the index added alongside it in 20260704000500_snapshots.sql. The
-- actual constraint is added just after migrations run, in
-- `ensure_postgres_constraints` / `ensure_sqlite_constraints`
-- (crates/sandboxwich-api/src/db.rs), because the two backends need
-- genuinely different DDL here: Postgres can `ALTER TABLE ... ADD
-- CONSTRAINT` directly, but SQLite cannot add a foreign key to an existing
-- column via `ALTER TABLE` at all and needs the documented
-- create-copy-drop-rename table rebuild instead. Every other migration in
-- this directory is plain, dialect-portable SQL run verbatim against
-- whichever backend is connected, so there was nowhere to branch on dialect
-- inside a single migration file.
--
-- The constraint's target is `snapshot_restore_sources(snapshot_id)`, not
-- `snapshots(id)` -- see the long comment on
-- `postgres_sandbox_parent_snapshot_fk_statements` in `db.rs` for why: the
-- `snapshots` row a `parent_snapshot_id` points at can legitimately be gone
-- (cascade-deleted along with its own source sandbox) while the fork it
-- produced is still perfectly valid, because `snapshot_restore_sources` is
-- the durable, never-deleted record of that snapshot id's existence.
--
-- This migration only does the part that *is* portable: with no foreign key
-- ever enforced on this column, some installations may already have
-- `parent_snapshot_id` values with no corresponding `snapshot_restore_sources`
-- row at all (never created, or the snapshot predates that table and was
-- never backfilled into it -- see 20260710000200_snapshot_tenant_ownership.sql,
-- whose backfill only covers snapshots whose owning sandbox still existed at
-- the time). Null those out now so the constraint added right after
-- migrations run doesn't fail applying to pre-existing data.
update sandboxes
set parent_snapshot_id = null
where parent_snapshot_id is not null
  and parent_snapshot_id not in (select snapshot_id from snapshot_restore_sources);
