alter table sandboxes
    add column execution_class text not null default 'development_container'
    check (execution_class in ('development_container', 'sandboxed_container', 'virtual_machine'));

alter table jobs
    add column required_execution_class text not null default 'development_container'
    check (required_execution_class in ('development_container', 'sandboxed_container', 'virtual_machine'));
