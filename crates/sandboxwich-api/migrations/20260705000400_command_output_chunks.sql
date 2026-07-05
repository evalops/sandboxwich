create table if not exists command_output_chunks (
    id text primary key not null,
    command_id text not null references commands(id) on delete cascade,
    stream text not null,
    sequence integer not null,
    chunk text not null,
    created_at text not null
);

create unique index if not exists idx_command_output_chunks_sequence
    on command_output_chunks(command_id, stream, sequence);

create index if not exists idx_command_output_chunks_command_created
    on command_output_chunks(command_id, created_at);
