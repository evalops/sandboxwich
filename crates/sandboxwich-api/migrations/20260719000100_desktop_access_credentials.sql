-- Short-lived, sandbox-bound credentials minted for the brokered desktop
-- transport (ROADMAP "Next work" #3). Mirrors `guest_tokens`: only the
-- SHA-256 hash of the raw token is stored, the credential is bound to one
-- tenant/sandbox/desktop session, it expires, and minting a new one revokes
-- the session's previous active credential (rotate-by-revocation).
create table if not exists desktop_access_credentials (
    id text primary key not null,
    tenant_id text not null,
    sandbox_id text not null references sandboxes(id) on delete cascade,
    desktop_session_id text not null references desktop_sessions(id) on delete cascade,
    token_hash text not null unique,
    expires_at text not null,
    revoked_at text,
    created_at text not null
);

create index if not exists idx_desktop_access_credentials_session
    on desktop_access_credentials(tenant_id, desktop_session_id, expires_at);

create index if not exists idx_desktop_access_credentials_expires_at
    on desktop_access_credentials(expires_at);
