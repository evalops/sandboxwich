alter table sandboxes
    add column runtime_profile text not null default 'unprivileged'
    check (runtime_profile in ('unprivileged', 'apex_trusted_supervisor_v1'));

create index if not exists idx_sandboxes_runtime_profile
    on sandboxes(runtime_profile);
