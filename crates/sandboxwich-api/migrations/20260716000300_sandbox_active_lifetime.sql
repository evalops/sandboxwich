-- Adds the two active-lifetime reaping knobs to `sandboxes`. Both are
-- additive and nullable, so existing rows (and callers that never send
-- either field) are unaffected.
--
-- Deliberately distinct from the pre-existing `ttl_seconds` column: that one
-- only governs how long an *already-archived* sandbox's record is retained
-- before `run_cleanup_controller` deletes it (see `cleanup.rs`). These two
-- govern whether a *live* sandbox ever gets stopped in the first place --
-- see the new `reap` module and `docs/capabilities.md` for the distinction.
alter table sandboxes add column max_lifetime_seconds integer;
alter table sandboxes add column idle_ttl_seconds integer;
