alter table snapshot_restore_sources
    add column execution_class text not null default 'development_container'
    check (execution_class in ('development_container', 'sandboxed_container', 'virtual_machine'));

update snapshot_restore_sources
set execution_class = coalesce(
    (select sandboxes.execution_class
     from sandboxes
     where sandboxes.id = snapshot_restore_sources.source_sandbox_id
       and sandboxes.tenant_id = snapshot_restore_sources.tenant_id),
    execution_class
);
