//! Active-lifetime reaping: the background sweep that stops sandboxes past
//! their `max_lifetime_seconds` or `idle_ttl_seconds` deadline.
//!
//! This is a distinct concern from `cleanup::cleanup_archived_sandboxes`,
//! which only ever acts on sandboxes *already* in `state = 'archived'` and
//! governs how long that already-torn-down record is retained
//! (`ttl_seconds`). This module is what decides a *live* sandbox has run too
//! long in the first place. A reaped sandbox is driven through the exact
//! same [`stop_sandbox_via_job`] path a user-initiated
//! `POST /sandboxes/{id}/stop` uses, so it flows into the pre-existing
//! archived-retention sweep afterward instead of getting a parallel deletion
//! path. See `docs/capabilities.md` for the three-knob distinction
//! (`ttl_seconds` / `max_lifetime_seconds` / `idle_ttl_seconds`).

use crate::db::*;
use crate::error::*;
use crate::handlers::sandboxes::*;
use crate::rows::*;
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::Row;

/// Why a sandbox's active-lifetime deadline fired. Surfaced in the reaped
/// sandbox's `LifecycleChanged` event (`reason` field) so its audit trail
/// says *why* it was stopped, not just that it was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReapTrigger {
    MaxLifetime,
    IdleTtl,
}

impl ReapTrigger {
    /// The exact `reason` string this trigger writes into the reaped
    /// sandbox's `LifecycleChanged` event. `pub(crate)` (not just used
    /// internally by `reap_expired_active_sandboxes`) so callers outside
    /// this module -- currently `scheduler::spawn_expiry_sweeper`'s log line
    /// -- can report the *same* string instead of a `Debug`-derived
    /// spelling of the enum variant, which would silently drift from the
    /// event's `reason` field and make logs and events hard to correlate.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            ReapTrigger::MaxLifetime => "reaped_max_lifetime",
            ReapTrigger::IdleTtl => "reaped_idle_ttl",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ReapedSandbox {
    pub(crate) sandbox: Sandbox,
    pub(crate) trigger: ReapTrigger,
    pub(crate) deadline: DateTime<Utc>,
}

/// Adds `ttl_seconds` (interpreted as a plain seconds offset) to `anchor`.
/// Saturates rather than panics if the value is absurdly large -- matches
/// the failure mode `expires_at_from_ttl` already treats as a caller error
/// elsewhere in this crate, but a deadline computed during a background
/// sweep has no request to reject, so this saturates instead of erroring.
pub(crate) fn deadline_from(anchor: DateTime<Utc>, ttl_seconds: u64) -> DateTime<Utc> {
    let seconds = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
    anchor + chrono::Duration::seconds(seconds)
}

/// Pure "is `max_lifetime_seconds` past due" check, split out from the
/// database-touching sweep below so the deadline math itself is unit
/// testable without a `Database`.
pub(crate) fn max_lifetime_expired(
    created_at: DateTime<Utc>,
    max_lifetime_seconds: u64,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let deadline = deadline_from(created_at, max_lifetime_seconds);
    (deadline <= now).then_some(deadline)
}

/// Pure "is `idle_ttl_seconds` past due" check given an already-resolved
/// last-activity timestamp; see [`last_known_activity`] for what feeds this.
pub(crate) fn idle_ttl_expired(
    last_activity_at: DateTime<Utc>,
    idle_ttl_seconds: u64,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let deadline = deadline_from(last_activity_at, idle_ttl_seconds);
    (deadline <= now).then_some(deadline)
}

/// States eligible for active-lifetime reaping: reuses
/// `SandboxState::STOP_LEGAL_FROM` -- the exact set a user-initiated stop may
/// act on -- rather than a hand-maintained list, so this sweep and
/// `stop_sandbox` can never silently drift apart on which states still count
/// as "alive". In the currently-shipped lifecycle only `Planning`,
/// `Provisioning`, `Ready`, and `Error` are ever actually reached (nothing
/// yet transitions a sandbox into `Running`/`Idle` -- see
/// `docs/capabilities.md`), but including them here costs nothing and means
/// this sweep does not need to change the day something starts using them.
fn reapable_states() -> Vec<&'static str> {
    SandboxState::STOP_LEGAL_FROM
        .iter()
        .map(state_to_str)
        .collect()
}

/// Best-known "last activity" signal for idle-TTL purposes: the more recent
/// of the sandbox's own last lifecycle-state transition (`updated_at`) and
/// its most recently *queued* guest command (`commands.created_at`). This is
/// a real, recorded timestamp, not a guess -- but it is not a complete
/// activity signal. SSH sessions, desktop sessions, and resident-process
/// output do not currently touch either column, so a sandbox used
/// exclusively through those surfaces can still be reaped as idle. See
/// `docs/capabilities.md` for this documented as a known limitation rather
/// than silently overclaiming true idle detection.
async fn last_known_activity(db: &Database, sandbox: &Sandbox) -> Result<DateTime<Utc>, ApiError> {
    let sql = format!(
        "select max(created_at) as last_command_at from commands where sandbox_id = {}",
        db.placeholder(1)
    );
    let row = sqlx::query(&sql)
        .bind(sandbox.id.to_string())
        .fetch_one(&db.pool)
        .await?;
    let last_command_at: Option<String> = row.try_get("last_command_at")?;
    let last_command_at = last_command_at
        .map(|value| parse_timestamp(&value))
        .transpose()?;
    Ok(match last_command_at {
        Some(value) if value > sandbox.updated_at => value,
        _ => sandbox.updated_at,
    })
}

async fn expired_deadline(
    db: &Database,
    sandbox: &Sandbox,
    now: DateTime<Utc>,
) -> Result<Option<(ReapTrigger, DateTime<Utc>)>, ApiError> {
    if let Some(max_lifetime_seconds) = sandbox.max_lifetime_seconds
        && let Some(deadline) = max_lifetime_expired(sandbox.created_at, max_lifetime_seconds, now)
    {
        return Ok(Some((ReapTrigger::MaxLifetime, deadline)));
    }
    if let Some(idle_ttl_seconds) = sandbox.idle_ttl_seconds {
        let last_activity_at = last_known_activity(db, sandbox).await?;
        if let Some(deadline) = idle_ttl_expired(last_activity_at, idle_ttl_seconds, now) {
            return Ok(Some((ReapTrigger::IdleTtl, deadline)));
        }
    }
    Ok(None)
}

/// Outcome of attempting to reap one candidate sandbox. A distinct enum
/// (rather than folding everything into `Option<ReapedSandbox>`) so tests
/// can assert on exactly which branch [`attempt_reap_candidate`] took --
/// in particular [`CandidateOutcome::Skipped`], which is returned from the
/// *same* match arm that emits the "reap skipped" log line, making the
/// returned variant a reliable stand-in for "that log fired" without
/// needing a tracing-capture test harness this codebase has no other use
/// for.
#[derive(Debug)]
pub(crate) enum CandidateOutcome {
    /// Not past either deadline; nothing to do.
    NotDue,
    /// Past a deadline and successfully driven into `Archiving`. Boxed
    /// because `ReapedSandbox` embeds a full `Sandbox`, which otherwise
    /// makes this the dominant, size-setting variant of the enum for every
    /// caller regardless of which variant they actually get back.
    Reaped(Box<ReapedSandbox>),
    /// Past a deadline, but a concurrent actor (a manual stop, or another
    /// sweep tick) already moved the sandbox out of `STOP_LEGAL_FROM` by the
    /// time `stop_sandbox_via_job`'s CAS ran.
    Skipped,
    /// `stop_sandbox_via_job` itself failed (already logged here).
    Failed,
}

/// Attempts to reap one candidate sandbox (already fetched by the caller --
/// see [`reap_expired_active_sandboxes`]), driving it through
/// [`stop_sandbox_via_job`] if it's past a deadline. Split out from the
/// sweep loop so a test can exercise the CAS-miss race deterministically: by
/// calling this directly with a candidate snapshot fetched *before* a
/// concurrent stop won the race, instead of relying on real timing.
pub(crate) async fn attempt_reap_candidate(
    db: &Database,
    mut sandbox: Sandbox,
    now: DateTime<Utc>,
) -> Result<CandidateOutcome, ApiError> {
    hydrate_sandbox_network_egress(db, &mut sandbox).await?;
    let Some((trigger, deadline)) = expired_deadline(db, &sandbox, now).await? else {
        return Ok(CandidateOutcome::NotDue);
    };
    let stop = stop_sandbox_via_job(
        db,
        &sandbox,
        json!({
            "state": SandboxState::Archiving,
            "reason": trigger.reason(),
            "deadline": deadline,
            "triggeredBy": "expiry_sweeper",
        }),
    )
    .await;
    Ok(match stop {
        Ok(Some(_job)) => {
            sandbox.state = SandboxState::Archiving;
            CandidateOutcome::Reaped(Box::new(ReapedSandbox {
                sandbox,
                trigger,
                deadline,
            }))
        }
        Ok(None) => {
            // Selected as a candidate by the caller's query, but by the time
            // `stop_sandbox_via_job`'s own CAS ran, a concurrent actor (a
            // manual stop, or another sweep tick racing this one) had
            // already moved the sandbox out of `STOP_LEGAL_FROM`. Not a
            // failure -- the sandbox is already being (or already was)
            // stopped, which is the outcome this sweep wants; there is just
            // nothing left for *this* attempt to do. Logged separately from
            // a successful reap (and from the error branch below) so
            // "reaped" in a log search means a reap this sweep actually
            // drove, not one it merely observed.
            tracing::info!(
                sandbox_id = %sandbox.id,
                reason = trigger.reason(),
                "reap skipped: sandbox concurrently transitioned out of a stoppable \
                 state before this sweep's stop attempt landed"
            );
            CandidateOutcome::Skipped
        }
        Err(error) => {
            tracing::warn!(
                sandbox_id = %sandbox.id,
                reason = trigger.reason(),
                ?error,
                "failed to reap sandbox past its active-lifetime deadline"
            );
            CandidateOutcome::Failed
        }
    })
}

/// Finds every reapable-state sandbox with a `max_lifetime_seconds` and/or
/// `idle_ttl_seconds` set, stops the ones past their deadline through
/// [`stop_sandbox_via_job`], and returns what it reaped. Called from
/// `scheduler::spawn_expiry_sweeper` alongside the lease/snapshot/desktop-
/// session sweeps; a per-sandbox failure is logged and skipped rather than
/// aborting the rest of the sweep, matching how `cleanup_archived_sandboxes`
/// treats per-row failures.
pub(crate) async fn reap_expired_active_sandboxes(
    db: &Database,
) -> Result<Vec<ReapedSandbox>, ApiError> {
    let reapable = reapable_states();
    let sql = format!(
        "select id, tenant_id, name, state, template, memory_limit, network_egress_mode, workspace_mode, runtime_profile, execution_class,
                created_at, updated_at, ttl_seconds, max_lifetime_seconds, idle_ttl_seconds, parent_snapshot_id
         from sandboxes
         where state in ({}) and (max_lifetime_seconds is not null or idle_ttl_seconds is not null)
         order by created_at asc, id asc",
        sql_literal_list(&reapable)
    );
    let rows = sqlx::query(&sql).fetch_all(&db.pool).await?;

    let now = Utc::now();
    let mut reaped = Vec::new();
    for row in rows {
        let sandbox = row_to_sandbox(row)?;
        if let CandidateOutcome::Reaped(reaped_sandbox) =
            attempt_reap_candidate(db, sandbox, now).await?
        {
            reaped.push(*reaped_sandbox);
        }
    }
    Ok(reaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(seconds_from_epoch: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds_from_epoch, 0).unwrap()
    }

    #[test]
    fn deadline_from_adds_ttl_seconds_to_the_anchor() {
        let anchor = ts(1_000);
        assert_eq!(deadline_from(anchor, 60), ts(1_060));
        assert_eq!(
            deadline_from(anchor, 0),
            anchor,
            "a zero TTL must be immediately due, mirroring the existing \
             `ttl_seconds: Some(0)` idiom"
        );
    }

    #[test]
    fn max_lifetime_expired_fires_exactly_at_and_past_the_deadline() {
        let created_at = ts(1_000);
        assert_eq!(
            max_lifetime_expired(created_at, 60, ts(1_059)),
            None,
            "one second before the deadline must not be expired"
        );
        assert_eq!(
            max_lifetime_expired(created_at, 60, ts(1_060)),
            Some(ts(1_060)),
            "exactly at the deadline must be expired"
        );
        assert_eq!(
            max_lifetime_expired(created_at, 60, ts(2_000)),
            Some(ts(1_060)),
            "long past the deadline must still report the original deadline"
        );
    }

    #[test]
    fn idle_ttl_expired_measures_from_last_activity_not_creation() {
        let last_activity_at = ts(5_000);
        assert_eq!(idle_ttl_expired(last_activity_at, 300, ts(5_299)), None);
        assert_eq!(
            idle_ttl_expired(last_activity_at, 300, ts(5_300)),
            Some(ts(5_300))
        );
    }
}
