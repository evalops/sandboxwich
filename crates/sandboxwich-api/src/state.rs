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
pub(crate) const MAX_RESIDENT_BOOTSTRAPS: usize = 256;

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
    read_timeout: Option<Duration>,
}

#[cfg(test)]
impl Default for ApexCallbackTestHook {
    fn default() -> Self {
        Self {
            armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reached: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
            read_timeout: None,
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

    pub(crate) fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    pub(crate) fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
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

#[derive(Clone)]
pub(crate) struct LiveResidentBootstrap {
    pub(crate) content: Vec<u8>,
    pub(crate) sha256: String,
    pub(crate) target_file: String,
    pub(crate) mode: u32,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentBootstrapFence {
    pub(crate) generation: u64,
    pub(crate) lease_id: Uuid,
    pub(crate) sha256: String,
}

enum ResidentBootstrapEntry {
    Ready(LiveResidentBootstrap),
    InFlight {
        fence: ResidentBootstrapFence,
        acknowledged: bool,
    },
    Delivered {
        bootstrap: LiveResidentBootstrap,
        fence: ResidentBootstrapFence,
    },
}

struct ResidentBootstrapStoreInner {
    values: HashMap<ResidentProcessId, ResidentBootstrapEntry>,
    reserved: usize,
    capacity: usize,
}

#[derive(Clone)]
pub(crate) struct ResidentBootstrapStore(Arc<Mutex<ResidentBootstrapStoreInner>>);

impl Default for ResidentBootstrapStore {
    fn default() -> Self {
        Self::with_capacity(MAX_RESIDENT_BOOTSTRAPS)
    }
}

impl ResidentBootstrapStore {
    fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(ResidentBootstrapStoreInner {
            values: HashMap::new(),
            reserved: 0,
            capacity,
        })))
    }

    pub(crate) fn reserve(
        &self,
        bootstrap: LiveResidentBootstrap,
    ) -> Result<ResidentBootstrapReservation, ()> {
        let mut inner = self.0.lock().expect("resident bootstrap mutex poisoned");
        if inner.values.len() + inner.reserved >= inner.capacity {
            return Err(());
        }
        inner.reserved += 1;
        Ok(ResidentBootstrapReservation {
            store: self.clone(),
            bootstrap: Some(bootstrap),
        })
    }

    pub(crate) fn begin_delivery(
        &self,
        id: &ResidentProcessId,
        fence: ResidentBootstrapFence,
    ) -> Result<ResidentBootstrapDelivery, ResidentBootstrapDeliveryError> {
        let mut inner = self.0.lock().expect("resident bootstrap mutex poisoned");
        let entry = inner
            .values
            .remove(id)
            .ok_or(ResidentBootstrapDeliveryError::Unavailable)?;
        let (bootstrap, restore_as_delivered) = match entry {
            ResidentBootstrapEntry::Ready(bootstrap) => (bootstrap, false),
            ResidentBootstrapEntry::Delivered {
                bootstrap,
                fence: delivered_fence,
            } if delivered_fence == fence => (bootstrap, true),
            ResidentBootstrapEntry::Delivered {
                bootstrap,
                fence: delivered_fence,
            } => {
                inner.values.insert(
                    *id,
                    ResidentBootstrapEntry::Delivered {
                        bootstrap,
                        fence: delivered_fence,
                    },
                );
                return Err(ResidentBootstrapDeliveryError::FenceMismatch);
            }
            ResidentBootstrapEntry::InFlight {
                fence: in_flight_fence,
                acknowledged,
            } => {
                inner.values.insert(
                    *id,
                    ResidentBootstrapEntry::InFlight {
                        fence: in_flight_fence,
                        acknowledged,
                    },
                );
                return Err(ResidentBootstrapDeliveryError::InFlight);
            }
        };
        inner.values.insert(
            *id,
            ResidentBootstrapEntry::InFlight {
                fence: fence.clone(),
                acknowledged: false,
            },
        );
        Ok(ResidentBootstrapDelivery {
            store: self.clone(),
            id: *id,
            fence,
            bootstrap: Some(bootstrap),
            restore_as_delivered,
        })
    }

    pub(crate) fn acknowledge(
        &self,
        id: &ResidentProcessId,
        fence: &ResidentBootstrapFence,
    ) -> bool {
        let mut inner = self.0.lock().expect("resident bootstrap mutex poisoned");
        match inner.values.get_mut(id) {
            Some(ResidentBootstrapEntry::Delivered {
                fence: delivered_fence,
                ..
            }) if delivered_fence == fence => {
                inner.values.remove(id);
                true
            }
            Some(ResidentBootstrapEntry::InFlight {
                fence: in_flight_fence,
                acknowledged,
            }) if in_flight_fence == fence => {
                *acknowledged = true;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn reclaim(
        &self,
        id: &ResidentProcessId,
        generation: u64,
        sha256: &str,
        fence: Option<&ResidentBootstrapFence>,
    ) -> bool {
        let mut inner = self.0.lock().expect("resident bootstrap mutex poisoned");
        let should_remove = matches!(
            inner.values.get(id),
            Some(ResidentBootstrapEntry::Ready(bootstrap))
                if bootstrap.generation == generation && bootstrap.sha256 == sha256
        ) || matches!(
            (inner.values.get(id), fence),
            (
                Some(ResidentBootstrapEntry::Delivered {
                    fence: delivered_fence,
                    ..
                }),
                Some(expected_fence),
            ) if *delivered_fence == *expected_fence
        );
        if should_remove {
            inner.values.remove(id);
            return true;
        }
        match (inner.values.get_mut(id), fence) {
            (
                Some(ResidentBootstrapEntry::InFlight {
                    fence: in_flight_fence,
                    acknowledged,
                }),
                Some(expected_fence),
            ) if in_flight_fence == expected_fence => {
                *acknowledged = true;
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidentBootstrapDeliveryError {
    Unavailable,
    InFlight,
    FenceMismatch,
}

pub(crate) struct ResidentBootstrapReservation {
    store: ResidentBootstrapStore,
    bootstrap: Option<LiveResidentBootstrap>,
}

impl ResidentBootstrapReservation {
    pub(crate) fn publish(mut self, id: ResidentProcessId) {
        let bootstrap = self
            .bootstrap
            .take()
            .expect("resident bootstrap reservation already published");
        let mut inner = self
            .store
            .0
            .lock()
            .expect("resident bootstrap mutex poisoned");
        inner.reserved -= 1;
        let previous = inner
            .values
            .insert(id, ResidentBootstrapEntry::Ready(bootstrap));
        debug_assert!(previous.is_none(), "resident bootstrap published twice");
    }
}

impl Drop for ResidentBootstrapReservation {
    fn drop(&mut self) {
        if self.bootstrap.is_some() {
            let mut inner = self
                .store
                .0
                .lock()
                .expect("resident bootstrap mutex poisoned");
            inner.reserved -= 1;
        }
    }
}

pub(crate) struct ResidentBootstrapDelivery {
    store: ResidentBootstrapStore,
    id: ResidentProcessId,
    fence: ResidentBootstrapFence,
    bootstrap: Option<LiveResidentBootstrap>,
    restore_as_delivered: bool,
}

impl ResidentBootstrapDelivery {
    pub(crate) fn bootstrap(&self) -> &LiveResidentBootstrap {
        self.bootstrap
            .as_ref()
            .expect("resident bootstrap delivery already completed")
    }

    pub(crate) fn mark_delivered(
        mut self,
    ) -> Result<LiveResidentBootstrap, ResidentBootstrapDeliveryError> {
        let bootstrap = self
            .bootstrap
            .take()
            .expect("resident bootstrap delivery already completed");
        let response = bootstrap.clone();
        let mut inner = self
            .store
            .0
            .lock()
            .expect("resident bootstrap mutex poisoned");
        let previous = inner.values.remove(&self.id);
        let acknowledged = matches!(
            &previous,
            Some(ResidentBootstrapEntry::InFlight {
                acknowledged: true,
                ..
            })
        );
        debug_assert!(matches!(
            &previous,
            Some(ResidentBootstrapEntry::InFlight { .. })
        ));
        if !acknowledged {
            inner.values.insert(
                self.id,
                ResidentBootstrapEntry::Delivered {
                    bootstrap,
                    fence: self.fence.clone(),
                },
            );
            return Ok(response);
        }
        Err(ResidentBootstrapDeliveryError::Unavailable)
    }
}

impl Drop for ResidentBootstrapDelivery {
    fn drop(&mut self) {
        if let Some(bootstrap) = self.bootstrap.take() {
            let mut inner = self
                .store
                .0
                .lock()
                .expect("resident bootstrap mutex poisoned");
            let previous = inner.values.remove(&self.id);
            let acknowledged = matches!(
                &previous,
                Some(ResidentBootstrapEntry::InFlight {
                    acknowledged: true,
                    ..
                })
            );
            debug_assert!(matches!(
                &previous,
                Some(ResidentBootstrapEntry::InFlight { .. })
            ));
            if acknowledged {
                return;
            }
            let restored = if self.restore_as_delivered {
                ResidentBootstrapEntry::Delivered {
                    bootstrap,
                    fence: self.fence.clone(),
                }
            } else {
                ResidentBootstrapEntry::Ready(bootstrap)
            };
            inner.values.insert(self.id, restored);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resident_bootstrap(generation: u64) -> LiveResidentBootstrap {
        LiveResidentBootstrap {
            content: b"secret".to_vec(),
            sha256: "digest".into(),
            target_file: "/run/secret".into(),
            mode: 0o600,
            generation,
        }
    }

    fn resident_bootstrap_fence(lease_id: Uuid) -> ResidentBootstrapFence {
        ResidentBootstrapFence {
            generation: 1,
            lease_id,
            sha256: "digest".into(),
        }
    }

    #[test]
    fn resident_bootstrap_reservation_holds_capacity_until_publish_or_drop() {
        let store = ResidentBootstrapStore::with_capacity(1);
        let reservation = store.reserve(resident_bootstrap(1)).unwrap();
        assert!(store.reserve(resident_bootstrap(1)).is_err());

        drop(reservation);
        let reservation = store.reserve(resident_bootstrap(1)).unwrap();
        let id = ResidentProcessId::new();
        reservation.publish(id);
        assert!(store.reserve(resident_bootstrap(1)).is_err());
        assert!(
            store
                .begin_delivery(&id, resident_bootstrap_fence(Uuid::now_v7()))
                .is_ok()
        );
    }

    #[test]
    fn resident_bootstrap_delivery_retries_until_exact_fence_is_acknowledged() {
        let store = ResidentBootstrapStore::with_capacity(1);
        let id = ResidentProcessId::new();
        let lease_id = Uuid::now_v7();
        let fence = resident_bootstrap_fence(lease_id);
        store.reserve(resident_bootstrap(1)).unwrap().publish(id);

        drop(store.begin_delivery(&id, fence.clone()).unwrap());
        let delivery = store.begin_delivery(&id, fence.clone()).unwrap();
        assert_eq!(delivery.bootstrap().content, b"secret");
        assert!(matches!(
            store.begin_delivery(&id, fence.clone()),
            Err(ResidentBootstrapDeliveryError::InFlight)
        ));
        delivery.mark_delivered().unwrap();

        assert!(matches!(
            store.begin_delivery(&id, resident_bootstrap_fence(Uuid::now_v7())),
            Err(ResidentBootstrapDeliveryError::FenceMismatch)
        ));
        assert!(store.reserve(resident_bootstrap(2)).is_err());

        let replacement_fence = ResidentBootstrapFence {
            generation: fence.generation + 1,
            lease_id: Uuid::now_v7(),
            sha256: fence.sha256.clone(),
        };
        assert!(!store.acknowledge(&id, &replacement_fence));
        assert!(
            store.reserve(resident_bootstrap(2)).is_err(),
            "a stale fence must not reclaim a replacement's capacity"
        );

        let retry = store.begin_delivery(&id, fence.clone()).unwrap();
        assert_eq!(retry.bootstrap().content, b"secret");
        assert!(store.acknowledge(&id, &fence));
        assert!(matches!(
            retry.mark_delivered(),
            Err(ResidentBootstrapDeliveryError::Unavailable)
        ));
        assert!(matches!(
            store.begin_delivery(&id, fence),
            Err(ResidentBootstrapDeliveryError::Unavailable)
        ));
        assert!(store.reserve(resident_bootstrap(2)).is_ok());
    }

    #[test]
    fn resident_bootstrap_reclaim_is_generation_digest_and_fence_scoped() {
        let store = ResidentBootstrapStore::with_capacity(1);
        let id = ResidentProcessId::new();
        store.reserve(resident_bootstrap(2)).unwrap().publish(id);

        assert!(!store.reclaim(&id, 1, "digest", None));
        assert!(!store.reclaim(&id, 2, "wrong-digest", None));
        assert!(store.reserve(resident_bootstrap(3)).is_err());
        assert!(store.reclaim(&id, 2, "digest", None));
        assert!(store.reserve(resident_bootstrap(3)).is_ok());

        let replacement = ResidentProcessId::new();
        let fence = ResidentBootstrapFence {
            generation: 4,
            lease_id: Uuid::now_v7(),
            sha256: "digest".into(),
        };
        store
            .reserve(resident_bootstrap(4))
            .unwrap()
            .publish(replacement);
        store
            .begin_delivery(&replacement, fence.clone())
            .unwrap()
            .mark_delivered()
            .unwrap();
        let stale_fence = ResidentBootstrapFence {
            generation: 3,
            lease_id: Uuid::now_v7(),
            sha256: "digest".into(),
        };
        assert!(!store.reclaim(&replacement, 3, "digest", Some(&stale_fence)));
        assert!(store.reserve(resident_bootstrap(5)).is_err());
        assert!(store.reclaim(&replacement, 4, "digest", Some(&fence)));
        assert!(store.reserve(resident_bootstrap(5)).is_ok());
    }

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
    pub(crate) resident_bootstraps: ResidentBootstrapStore,
    pub(crate) sandbox_lifetime: SandboxLifetimeConfig,
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
