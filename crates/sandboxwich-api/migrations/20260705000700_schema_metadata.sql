create table if not exists schema_metadata (
    key text primary key not null,
    value text not null,
    updated_at text not null
);
