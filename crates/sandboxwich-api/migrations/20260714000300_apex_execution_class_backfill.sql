-- Execution classes landed before runtime profiles when the APEX branch was
-- composed with main. Repair trusted APEX rows that received the earlier
-- development-container default during that upgrade sequence.
update sandboxes
set execution_class = 'sandboxed_container'
where runtime_profile = 'apex_trusted_supervisor_v1'
  and execution_class <> 'sandboxed_container';

update jobs
set required_execution_class = 'sandboxed_container'
where required_execution_class <> 'sandboxed_container'
  and exists (
      select 1
      from sandboxes
      where sandboxes.tenant_id = jobs.tenant_id
        and sandboxes.runtime_profile = 'apex_trusted_supervisor_v1'
        and sandboxes.id = coalesce(jobs.child_sandbox_id, jobs.sandbox_id)
  );

update snapshot_restore_sources
set execution_class = 'sandboxed_container'
where execution_class <> 'sandboxed_container'
  and (
      exists (
          select 1
          from sandboxes
          where sandboxes.id = snapshot_restore_sources.source_sandbox_id
            and sandboxes.tenant_id = snapshot_restore_sources.tenant_id
            and sandboxes.runtime_profile = 'apex_trusted_supervisor_v1'
      )
      or provision_spec like '%"runtime_profile":"apex_trusted_supervisor_v1"%'
  );
