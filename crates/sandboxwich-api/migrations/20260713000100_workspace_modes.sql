alter table sandboxes
    add column workspace_mode text not null default 'persistent'
    check (workspace_mode in ('ephemeral', 'generic_ephemeral', 'persistent'));

create index if not exists idx_sandboxes_workspace_mode
    on sandboxes(workspace_mode);
