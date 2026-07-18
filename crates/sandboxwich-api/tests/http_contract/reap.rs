//! Contract coverage for active-lifetime reaping (`max_lifetime_seconds`):
//! a sandbox past its deadline must actually be stopped by the background
//! sweeper, and a sandbox with no lifetime knobs configured -- in particular
//! a `workspace_mode: persistent` one, with no operator default configured
//! either -- must never be touched. See `sandboxwich_api::reap` and the
//! "Sandbox lifetime: three separate knobs" section of the README for the
//! design this proves out.

use crate::common::*;
use sandboxwich_core::*;
use sqlx::AnyPool;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;
use std::time::Duration;

/// Reads a sandbox's raw `state` column directly, bypassing
/// `GET /sandboxes/{id}`. That endpoint requires a `sandbox_placements` row
/// once a sandbox leaves `Planning`/`Archiving`/`Archived` (see
/// `fetch_sandbox_placement_proof`), which only a worker completing a real
/// `ProvisionSandbox` lease would create -- this test fast-forwards state
/// directly via SQL instead of running a full provisioning round trip, so no
/// such row exists. Asserting on the row directly sidesteps that entirely
/// and is a closer match for what the reaper itself actually reads.
async fn sandbox_state(pool: &AnyPool, sandbox_id: sandboxwich_core::SandboxId) -> String {
    sqlx::query("select state from sandboxes where id = ?")
        .bind(sandbox_id.to_string())
        .fetch_one(pool)
        .await
        .unwrap()
        .try_get("state")
        .unwrap()
}

#[tokio::test]
async fn max_lifetime_reaps_a_live_sandbox_but_never_touches_an_unconfigured_persistent_one() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("active-lifetime-reap.db").display()
    );
    // The expiry sweeper is what drives active-lifetime reaping (see
    // `scheduler::spawn_expiry_sweeper`), so this needs the sweeper-enabled
    // variant, same as the lease/snapshot/desktop-session expiry contract.
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    let client = server.client();

    // Created with *no* lifetime cap yet -- see below for why the cap is
    // added in a second step instead of at creation.
    let reapable: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("reap-me".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            workspace_mode: Some(WorkspaceMode::Ephemeral),
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Persistent sandbox with no lifetime knobs set at all, on a server with
    // no operator-configured default either. The reaper must never touch
    // it -- this is the "opt-in only" guarantee from the README, not
    // incidental behavior.
    let untouched: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("never-reap-me".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            workspace_mode: Some(WorkspaceMode::Persistent),
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Neither sandbox reaches `ready` through the real provisioning flow in
    // this test (no worker ever claims the provision job). The reaper acts
    // on any of `ready`/`running`/`idle` alike (it reuses
    // `SandboxState::STOP_LEGAL_FROM`), so directly fast-forward both to
    // `ready` the same way other sweep tests fabricate expired rows via
    // direct SQL (see e.g. `idempotency.rs`, `snapshots.rs`, `limits.rs`).
    // `ready` specifically (not `running`/`idle`) because the database-level
    // transition-guard trigger enforces `SandboxState::legal_predecessors`,
    // and nothing in the currently-shipped lifecycle ever transitions a
    // sandbox into `running`/`idle` -- see docs/capabilities.md. `planning
    // -> ready` is a legal transition (`PROVISION_COMPLETED_LEGAL_FROM`), so
    // this is also a more honest stand-in for the sandboxes actually at risk
    // in production today than an unreachable state would be.
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();
    for sandbox in [&reapable, &untouched] {
        sqlx::query("update sandboxes set state = 'ready' where id = ?")
            .bind(sandbox.sandbox.id.to_string())
            .execute(&pool)
            .await
            .unwrap();
    }

    // Only *now* set the reapable sandbox's cap to something already due
    // (`0`, mirroring the existing `ttl_seconds: Some(0)` idiom for
    // immediate eligibility), as a separate write from the state change
    // above. Setting it at creation time instead would race the sweeper,
    // which ticks every 25ms under `start_with_expiry_sweeper`: `Planning`
    // is itself in `STOP_LEGAL_FROM`, so a sweep landing between creation and
    // the `state = 'ready'` update above could reap the sandbox straight out
    // of `Planning`, and the subsequent `state = 'ready'` write would then
    // hit the transition-guard trigger (`archiving -> ready` is not a legal
    // pair) instead of racing this test's own assertions. Updating a
    // non-`state` column is exempt from that trigger entirely (it only fires
    // `before update of state`), so this step can't race it.
    sqlx::query("update sandboxes set max_lifetime_seconds = 0 where id = ?")
        .bind(reapable.sandbox.id.to_string())
        .execute(&pool)
        .await
        .unwrap();

    poll_until(|| async {
        (sandbox_state(&pool, reapable.sandbox.id).await == "archiving").then_some(())
    })
    .await
    .expect(
        "a sandbox past its max_lifetime_seconds deadline should be reaped \
             (stopped) by the background sweep",
    );

    let events: EventListResponse = client
        .get(format!(
            "{}/sandboxes/{}/events",
            server.base_url, reapable.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        events.events.iter().any(|event| {
            event.kind == SandboxEventKind::LifecycleChanged
                && event.data.get("reason").and_then(|value| value.as_str())
                    == Some("reaped_max_lifetime")
        }),
        "a reaped sandbox's lifecycle event must record *why* it was reaped, \
         distinct from a user-initiated stop's \"stop_requested\" reason"
    );

    // Give the sweeper several more cycles (it ticks every 25ms under
    // `start_with_expiry_sweeper`) to make sure the persistent, unconfigured
    // sandbox staying `ready` is a durable negative, not a race we got lucky
    // on.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        sandbox_state(&pool, untouched.sandbox.id).await,
        "ready",
        "a persistent sandbox with no lifetime knobs set, and no operator \
         default configured, must never be reaped"
    );
}
