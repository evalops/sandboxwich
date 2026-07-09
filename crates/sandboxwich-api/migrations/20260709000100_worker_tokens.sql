-- GH-64: the guest agent running inside an untrusted sandbox previously
-- authenticated with the same tenant-wide bearer token used by the CLI, so a
-- compromised sandbox could act as the whole tenant (claim/forge any lease,
-- post guest-health for any sandbox, etc).
--
-- This adds a per-worker credential distinct from tenant tokens: minted once
-- at worker registration, stored here only as a SHA-256 hash (never the raw
-- token), and resolved by the API to (tenant_id, worker_id) rather than to a
-- tenant alone. Nullable because existing workers registered before this
-- migration have no token until they next re-register; unique so a hash
-- collision (or bug) can never let one worker impersonate another.
alter table workers add column token_hash text;

create unique index if not exists idx_workers_token_hash on workers(token_hash);
