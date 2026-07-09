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
    pub(crate) principal: Principal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Principal {
    Tenant,
    Operator,
    Worker(WorkerId),
}

impl TenantContext {
    pub(crate) fn worker_id(&self) -> Option<WorkerId> {
        match self.principal {
            Principal::Worker(worker_id) => Some(worker_id),
            Principal::Tenant | Principal::Operator => None,
        }
    }
}
