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
///
/// The sandbox id is embedded directly into the query string (a UUID, no
/// injection concern) rather than bound as a `?` placeholder: this file's
/// Postgres-configured tests share this helper, and a bound `?` is a
/// SQLite-only placeholder spelling that `sqlx`'s `Any` driver does not
/// translate to Postgres's `$1` -- see `limits.rs`/`divergence.rs` for the
/// same established convention on every other dual-backend test in this
/// suite.
async fn sandbox_state(pool: &AnyPool, sandbox_id: sandboxwich_core::SandboxId) -> String {
    sqlx::query(&format!(
        "select state from sandboxes where id = '{sandbox_id}'"
    ))
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
        sqlx::query(&format!(
            "update sandboxes set state = 'ready' where id = '{}'",
            sandbox.sandbox.id
        ))
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
    sqlx::query(&format!(
        "update sandboxes set max_lifetime_seconds = 0 where id = '{}'",
        reapable.sandbox.id
    ))
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

/// Contract coverage for evalops/sandboxwich#173: the idle-TTL sweep folds
/// its "most recently queued command" lookup into the candidate query
/// itself (a correlated scalar subquery), instead of one
/// `select max(created_at) from commands` per candidate. That subquery
/// needs to be valid, and semantically correct, on **both** the SQLite and
/// Postgres query paths -- the two thin wrappers below run this same body
/// against each (Postgres only when `SANDBOXWICH_TEST_POSTGRES_URL` is
/// configured), the same dual-dispatch pattern `common.rs` uses for the
/// main lifecycle contract.
///
/// A real `commands` row is queued through the actual `POST .../commands`
/// route (not fabricated via direct SQL) so this exercises the exact
/// `commands` table shape and timestamps a live command creates.
async fn assert_idle_ttl_reap_join_is_correct_on(server: TestServer) {
    let client = server.client();

    // idle_ttl_seconds is set from creation (not raced into place after the
    // fact like `max_lifetime_seconds` above) because nothing here depends
    // on the sandbox reaching a particular state before the deadline value
    // is visible -- unlike the max-lifetime test's `Planning`-is-itself-
    // reapable race, there's no window here where an incomplete write could
    // cause a spurious reap.
    let has_recent_command: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("idle-but-has-recent-command".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            workspace_mode: Some(WorkspaceMode::Ephemeral),
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: Some(3600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let truly_idle: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("truly-idle".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            workspace_mode: Some(WorkspaceMode::Ephemeral),
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: None,
            max_lifetime_seconds: None,
            idle_ttl_seconds: Some(3600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(2)
        .connect(&server.database_url)
        .await
        .unwrap();

    // Queue the real, recent command *before* either sandbox looks stale
    // (see below), not after. The background sweeper is already running
    // and ticking every 25ms at this point; if the command were queued only
    // after `updated_at` had already been pushed into the past, there would
    // be a real window -- `has_recent_command` looking idle-due with no
    // protective command yet -- for a sweep tick to reap it before the
    // command lands, especially over the network+subprocess round trips a
    // Postgres-backed run adds versus in-process SQLite. Queuing it first
    // means the sandbox never exists in an idle-due-and-unprotected state at
    // all.
    client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, has_recent_command.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["true".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: None,
            timeout_secs: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // *Now* fast-forward both to `ready` (see the sibling test above for why
    // `ready`, not `running`/`idle`) and push `updated_at` for both far
    // enough into the past that the 3600s idle window is already blown on
    // `updated_at` alone -- the only thing distinguishing them from here is
    // whether a real, recently-queued command resets the clock.
    let long_ago = (chrono::Utc::now() - chrono::Duration::seconds(7_200)).to_rfc3339();
    for sandbox in [&has_recent_command, &truly_idle] {
        sqlx::query(&format!(
            "update sandboxes set state = 'ready', updated_at = '{long_ago}' where id = '{}'",
            sandbox.sandbox.id
        ))
        .execute(&pool)
        .await
        .unwrap();
    }

    poll_until(|| async {
        (sandbox_state(&pool, truly_idle.sandbox.id).await == "archiving").then_some(())
    })
    .await
    .expect(
        "the sandbox with no recent command activity, past its idle_ttl_seconds \
         deadline on updated_at alone, should be reaped",
    );

    // Several more sweep cycles so "still ready" for the other sandbox is a
    // durable negative rather than a race won by luck.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        sandbox_state(&pool, has_recent_command.sandbox.id).await,
        "ready",
        "a real, recently queued command must reset the idle clock via the \
         correlated subquery and prevent reaping, even though updated_at \
         alone would already be past the idle_ttl_seconds deadline"
    );
}

#[tokio::test]
async fn idle_ttl_reap_join_is_correct_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("idle-ttl-reap-join.db").display()
    );
    let server = TestServer::start_with_expiry_sweeper(database_url, Some(data_dir)).await;
    assert_idle_ttl_reap_join_is_correct_on(server).await;
}

#[tokio::test]
async fn idle_ttl_reap_join_is_correct_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };
    let server = TestServer::start_with_expiry_sweeper(database_url, None).await;
    assert_idle_ttl_reap_join_is_correct_on(server).await;
}
