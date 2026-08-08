alter table resident_processes add column sterile_cell_id text references sterile_cells(id) on delete restrict;
alter table resident_processes add column sterile_lease_id text;
alter table resident_processes add column sterile_lease_generation integer;

alter table sterile_cells add column activated_resident_process_id text;
alter table sterile_cells add column activated_resident_generation integer;

create unique index if not exists idx_resident_processes_sterile_lease
    on resident_processes(sterile_lease_id)
    where sterile_lease_id is not null;

create index if not exists idx_resident_processes_sterile_cell
    on resident_processes(sterile_cell_id, sterile_lease_generation)
    where sterile_cell_id is not null;

create unique index if not exists idx_sterile_cells_activated_resident
    on sterile_cells(activated_resident_process_id)
    where activated_resident_process_id is not null;

