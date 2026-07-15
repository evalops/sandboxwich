use crate::config::*;
use crate::db::*;
use sandboxwich_core::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::oneshot;
use uuid::Uuid;

pub(crate) const APEX_INSTRUCTION_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const MAX_APEX_INSTRUCTION_WAITERS: usize = 256;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ApexWaiterInsertError {
    Full,
    Duplicate,
}

pub(crate) struct ApexInstructionDelivery {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: String,
    pub(crate) request_id: Uuid,
    pub(crate) sandbox_id: SandboxId,
    pub(crate) lease_id: Uuid,
    pub(crate) lease_attempt: u64,
    pub(crate) provider_apply_id: Uuid,
}

#[derive(Clone, Default)]
pub(crate) struct ApexInstructionWaiters(
    Arc<Mutex<HashMap<Uuid, oneshot::Sender<ApexInstructionDelivery>>>>,
);

impl ApexInstructionWaiters {
    pub(crate) fn try_insert(
        &self,
        nonce: Uuid,
        sender: oneshot::Sender<ApexInstructionDelivery>,
    ) -> Result<(), ApexWaiterInsertError> {
        let mut waiters = self.0.lock().expect("APEX waiter mutex poisoned");
        if waiters.contains_key(&nonce) {
            return Err(ApexWaiterInsertError::Duplicate);
        }
        if waiters.len() >= MAX_APEX_INSTRUCTION_WAITERS {
            return Err(ApexWaiterInsertError::Full);
        }
        waiters.insert(nonce, sender);
        Ok(())
    }
    pub(crate) fn take(&self, nonce: &Uuid) -> Option<oneshot::Sender<ApexInstructionDelivery>> {
        self.0
            .lock()
            .expect("APEX waiter mutex poisoned")
            .remove(nonce)
    }

    pub(crate) fn has_sender(&self, nonce: &Uuid) -> bool {
        self.0
            .lock()
            .expect("APEX waiter mutex poisoned")
            .contains_key(nonce)
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, nonce: &Uuid) -> bool {
        self.0
            .lock()
            .expect("APEX waiter mutex poisoned")
            .contains_key(nonce)
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ApexCallbackTestHook {
    armed: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) reached: Arc<Semaphore>,
    pub(crate) release: Arc<Semaphore>,
}

#[cfg(test)]
impl Default for ApexCallbackTestHook {
    fn default() -> Self {
        Self {
            armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reached: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }
}

#[cfg(test)]
impl ApexCallbackTestHook {
    pub(crate) async fn pause_once(&self) {
        if !self.armed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.reached.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("callback test hook release semaphore closed")
                .forget();
        }
    }
}

pub(crate) struct ApexWaiterGuard {
    waiters: ApexInstructionWaiters,
    nonce: Uuid,
}

impl ApexWaiterGuard {
    pub(crate) fn new(waiters: ApexInstructionWaiters, nonce: Uuid) -> Self {
        Self { waiters, nonce }
    }
}

impl Drop for ApexWaiterGuard {
    fn drop(&mut self) {
        self.waiters.take(&self.nonce);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiter_guard_removes_instance_local_nonce_on_disconnect() {
        let waiters = ApexInstructionWaiters::default();
        let nonce = Uuid::now_v7();
        let (sender, _receiver) = oneshot::channel();
        assert_eq!(waiters.try_insert(nonce, sender), Ok(()));
        assert!(waiters.contains(&nonce));
        drop(ApexWaiterGuard::new(waiters.clone(), nonce));
        assert!(!waiters.contains(&nonce));
    }

    #[test]
    fn waiter_registries_are_instance_affine_and_bounded() {
        let first = ApexInstructionWaiters::default();
        let other_instance = ApexInstructionWaiters::default();
        let nonce = Uuid::now_v7();
        let (sender, _receiver) = oneshot::channel();
        first.try_insert(nonce, sender).unwrap();
        assert!(first.contains(&nonce));
        assert!(other_instance.take(&nonce).is_none());

        for _ in 1..MAX_APEX_INSTRUCTION_WAITERS {
            let (sender, _receiver) = oneshot::channel();
            first.try_insert(Uuid::now_v7(), sender).unwrap();
        }
        let (sender, _receiver) = oneshot::channel();
        assert_eq!(
            first.try_insert(Uuid::now_v7(), sender),
            Err(ApexWaiterInsertError::Full)
        );
    }

    #[tokio::test]
    async fn timeout_cleanup_removes_waiter_without_delivery() {
        let waiters = ApexInstructionWaiters::default();
        let nonce = Uuid::now_v7();
        let (sender, receiver) = oneshot::channel();
        waiters.try_insert(nonce, sender).unwrap();
        let guard = ApexWaiterGuard::new(waiters.clone(), nonce);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), receiver)
                .await
                .is_err()
        );
        drop(guard);
        assert!(!waiters.contains(&nonce));
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: Database,
    pub(crate) auth: AuthConfig,
    pub(crate) default_tenant_id: String,
    pub(crate) apex_callback_base_url: Option<String>,
    pub(crate) apex_waiters: ApexInstructionWaiters,
    #[cfg(test)]
    pub(crate) apex_callback_test_hook: Option<ApexCallbackTestHook>,
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
    Guest {
        worker_id: WorkerId,
        sandbox_id: SandboxId,
    },
}

impl TenantContext {
    pub(crate) fn worker_id(&self) -> Option<WorkerId> {
        match self.principal {
            Principal::Worker(worker_id) | Principal::Guest { worker_id, .. } => Some(worker_id),
            Principal::Tenant | Principal::Operator => None,
        }
    }

    pub(crate) fn guest_sandbox_id(&self) -> Option<SandboxId> {
        match self.principal {
            Principal::Guest { sandbox_id, .. } => Some(sandbox_id),
            Principal::Tenant | Principal::Operator | Principal::Worker(_) => None,
        }
    }
}
