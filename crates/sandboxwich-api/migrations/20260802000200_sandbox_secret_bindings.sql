-- Resolved secret deliveries for a sandbox. Every column is a locator: the
-- material stays in the external store and is fetched by the kubelet's CSI
-- driver, so there is nothing here (or anywhere in the control plane) to
-- redact.
--
-- The locator is snapshotted at bind time rather than joined from
-- `secret_refs` on every read: a sandbox's provisioning spec must stay
-- byte-stable for the life of the Pod, because `RunCommand` re-derives the
-- spec and a drifted spec applies against immutable Pod fields.
create table if not exists sandbox_secret_bindings (
    sandbox_id text not null references sandboxes(id) on delete cascade,
    secret_ref_id text not null references secret_refs(id),
    name text not null,
    backend text not null,
    source_object_name text not null,
    source_object_key text not null,
    delivery text not null,
    mount_dir text not null,
    file_path text not null,
    env_file_variable text not null,
    created_at text not null,
    primary key (sandbox_id, secret_ref_id),
    constraint sandbox_secret_bindings_backend_check
        check (backend in ('csi_secret_provider_class')),
    constraint sandbox_secret_bindings_delivery_check check (delivery in ('file'))
);

-- One mount path per sandbox: two bindings resolving to the same in-guest
-- file would be rejected by the Kubernetes API server only after the sandbox
-- row already exists.
create unique index if not exists idx_sandbox_secret_bindings_file_path
    on sandbox_secret_bindings(sandbox_id, file_path);
