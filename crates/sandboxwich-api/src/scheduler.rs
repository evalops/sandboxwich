use crate::db::*;
use crate::handlers::desktop::*;
use crate::handlers::leases::*;
use crate::handlers::snapshots::*;
use crate::handlers::workers::*;
use crate::idempotency::expire_idempotency_records;
use crate::limits::expire_tenant_limit_counters;
use crate::reap::reap_expired_active_sandboxes;
use crate::state::ResidentBootstrapStore;
use std::time::Duration;

/// Runs the lease/snapshot/desktop-session expiry sweeps on a fixed interval in
/// a single background task, instead of on every tenant-scoped read request.
/// This keeps read handlers O(1) in tenant data instead of doing global,
/// mutating work proportional to total table size on every GET, and it means
/// only one caller (this task) ever performs a given sweep at a time instead of
/// every concurrent reader racing to expire the same rows.
///
/// Set `SANDBOXWICH_DISABLE_EXPIRY_SWEEPER=true` to skip spawning this task
/// entirely. Integration tests that don't assert on sweep-driven expiry
/// disable it by default so the sweeper's periodic writes can't race with
/// foreground test assertions against the same server.
///
/// This is also what makes active-lifetime reaping (`reap_expired_active_
/// sandboxes`) run at all: disabling this sweeper means `max_lifetime_seconds`
/// and `idle_ttl_seconds` are stored but never enforced on this instance,
/// exactly as leases/snapshots/desktop-sessions/idempotency/tenant-limits
/// already behave when disabled.
pub(crate) fn spawn_expiry_sweeper(
    db: Database,
    resident_bootstraps: ResidentBootstrapStore,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The first tick fires immediately; that's fine, it just means the
        // first sweep runs right away instead of waiting a full interval.
        loop {
            ticker.tick().await;
            if let Err(error) = expire_due_leases(&db).await {
                tracing::warn!(?error, "lease expiry sweep failed");
            }
            if let Err(error) = expire_due_snapshots(&db).await {
                tracing::warn!(?error, "snapshot expiry sweep failed");
            }
            if let Err(error) = expire_due_desktop_sessions(&db).await {
                tracing::warn!(?error, "desktop session expiry sweep failed");
            }
            if let Err(error) = reconcile_worker_liveness(&db).await {
                tracing::warn!(?error, "worker liveness reconciliation failed");
            }
            if let Err(error) = expire_idempotency_records(&db).await {
                tracing::warn!(?error, "idempotency retention sweep failed");
            }
            if let Err(error) = expire_tenant_limit_counters(&db).await {
                tracing::warn!(?error, "tenant limit counter retention sweep failed");
            }
            match reap_expired_active_sandboxes(&db, &resident_bootstraps).await {
                Ok(reaped) => {
                    for reaped in &reaped {
                        tracing::info!(
                            sandbox_id = %reaped.sandbox.id,
                            tenant_id = %reaped.sandbox.tenant_id,
                            // Use the same `reason` string the reaped
                            // sandbox's `LifecycleChanged` event carries
                            // (rather than `?reaped.trigger`'s `Debug`
                            // spelling of the enum variant) so a log line and
                            // its corresponding event always say the exact
                            // same thing and can be correlated by grepping
                            // for one string.
                            reason = reaped.trigger.reason(),
                            deadline = %reaped.deadline,
                            "reaped sandbox past its active-lifetime deadline"
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(?error, "active sandbox lifetime reap sweep failed");
                }
            }
        }
    })
}
