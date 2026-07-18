-- Adds a server-maintained "last seen doing something" signal, separate
-- from the pre-existing `updated_at` (which only moves on lifecycle-state
-- transitions) and `commands.created_at` (queued guest commands). SSH
-- access, desktop access, and resident-process observation requests bump
-- this column (throttled -- see `crates/sandboxwich-api/src/activity.rs`),
-- completing the idle-TTL activity signal the reaper in `reap.rs` uses.
-- Additive and nullable: existing rows, and any sandbox never touched
-- through one of those three surfaces, simply have `last_activity_at is
-- null` and fall back to the pre-existing updated_at/commands signal.
alter table sandboxes add column last_activity_at text;
