use crate::config::*;
use crate::db::*;
use sandboxwich_core::*;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: Database,
    pub(crate) auth: AuthConfig,
    pub(crate) default_tenant_id: String,
}

#[derive(Clone, Debug)]
pub(crate) struct TenantContext {
    pub(crate) tenant_id: String,
    /// Set when the request authenticated with a worker-scoped token (see
    /// GH-64), identifying exactly which worker it is bound to. `None` for
    /// tenant-wide, shared, or (if allowed) unauthenticated dev access. Guest-
    /// facing routes (lease claim/renew/complete/fail/output, guest-health)
    /// require this to be `Some` and matched against the resource being acted
    /// on, so a tenant-wide token can never be used to impersonate a worker
    /// and a worker-scoped token can never reach past its own worker.
    pub(crate) worker_id: Option<WorkerId>,
}
