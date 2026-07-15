alter table snapshots add column runtime_image text;
alter table snapshots add column provision_spec text;
alter table snapshot_restore_sources add column runtime_image text;
alter table snapshot_restore_sources add column provision_spec text;

-- Existing snapshots can recover their immutable image. Full provision specs
-- are intentionally left null: silently inventing allowlist rules or profile
-- state would make legacy restores fail open. New writes always populate both.
update snapshots
set runtime_image = (
    select sandboxes.template from sandboxes where sandboxes.id = snapshots.sandbox_id
)
where runtime_image is null;

update snapshot_restore_sources
set runtime_image = (
    select sandboxes.template
    from sandboxes
    where sandboxes.id = snapshot_restore_sources.source_sandbox_id
)
where runtime_image is null;
