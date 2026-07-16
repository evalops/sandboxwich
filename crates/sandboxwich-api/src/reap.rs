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
/// last-activity timestamp; see [`resolve_last_activity`] for what feeds
/// this.
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
/// its most recently *queued* guest command (`commands.created_at`, passed
/// in as `last_command_at` -- see [`reap_expired_active_sandboxes`], which
/// resolves it for every candidate in the same query as the candidates
/// themselves, rather than one `select max(created_at) ...` per sandbox).
/// This is a real, recorded timestamp, not a guess -- but it is not a
/// complete activity signal. SSH sessions, desktop sessions, and
/// resident-process output do not currently touch either column, so a
/// sandbox used exclusively through those surfaces can still be reaped as
/// idle. See `docs/capabilities.md` for this documented as a known
/// limitation rather than silently overclaiming true idle detection.
fn resolve_last_activity(
    updated_at: DateTime<Utc>,
    last_command_at: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    match last_command_at {
        Some(value) if value > updated_at => value,
        _ => updated_at,
    }
}

/// Pure deadline check for one candidate, given its already-resolved
/// `last_command_at` (see [`resolve_last_activity`]). No longer touches the
/// database itself -- see [`reap_expired_active_sandboxes`] for why.
fn expired_deadline(
    sandbox: &Sandbox,
    last_command_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<(ReapTrigger, DateTime<Utc>)> {
    if let Some(max_lifetime_seconds) = sandbox.max_lifetime_seconds
        && let Some(deadline) = max_lifetime_expired(sandbox.created_at, max_lifetime_seconds, now)
    {
        return Some((ReapTrigger::MaxLifetime, deadline));
    }
    if let Some(idle_ttl_seconds) = sandbox.idle_ttl_seconds {
        let last_activity_at = resolve_last_activity(sandbox.updated_at, last_command_at);
        if let Some(deadline) = idle_ttl_expired(last_activity_at, idle_ttl_seconds, now) {
            return Some((ReapTrigger::IdleTtl, deadline));
        }
    }
    None
}

/// Finds every reapable-state sandbox with a `max_lifetime_seconds` and/or
/// `idle_ttl_seconds` set, stops the ones past their deadline through
/// [`stop_sandbox_via_job`], and returns what it reaped. Called from
/// `scheduler::spawn_expiry_sweeper` alongside the lease/snapshot/desktop-
/// session sweeps; a per-sandbox failure is logged and skipped rather than
/// aborting the rest of the sweep, matching how `cleanup_archived_sandboxes`
/// treats per-row failures.
///
/// Resolves each candidate's most recently queued command via a correlated
/// scalar subquery in this same `select`, instead of issuing a separate
/// `select max(created_at) from commands where sandbox_id = ?` per
/// candidate after the fact (see evalops/sandboxwich#173): one round trip
/// per sweep tick regardless of how many sandboxes have `idle_ttl_seconds`
/// configured, portable across both the SQLite and Postgres backends since
/// a correlated scalar subquery is standard SQL on both.
pub(crate) async fn reap_expired_active_sandboxes(
    db: &Database,
) -> Result<Vec<ReapedSandbox>, ApiError> {
    let reapable = reapable_states();
    let sql = format!(
        "select s.id, s.tenant_id, s.name, s.state, s.template, s.memory_limit, s.network_egress_mode, s.workspace_mode, s.runtime_profile, s.execution_class,
                s.created_at, s.updated_at, s.ttl_seconds, s.max_lifetime_seconds, s.idle_ttl_seconds, s.parent_snapshot_id,
                (select max(c.created_at) from commands c where c.sandbox_id = s.id) as last_command_at
         from sandboxes s
         where s.state in ({}) and (s.max_lifetime_seconds is not null or s.idle_ttl_seconds is not null)
         order by s.created_at asc, s.id asc",
        sql_literal_list(&reapable)
    );
    let rows = sqlx::query(&sql).fetch_all(&db.pool).await?;

    let now = Utc::now();
    let mut reaped = Vec::new();
    for row in rows {
        // Read the joined-in column before `row_to_sandbox` consumes `row`
        // by value; `try_get` only borrows, so this ordering is safe and
        // `row_to_sandbox` itself doesn't need to know this extra column
        // exists (it only looks up the specific columns it needs by name).
        let last_command_at: Option<String> = row.try_get("last_command_at")?;
        let last_command_at = last_command_at
            .map(|value| parse_timestamp(&value))
            .transpose()?;
        let mut sandbox = row_to_sandbox(row)?;
        hydrate_sandbox_network_egress(db, &mut sandbox).await?;
        let Some((trigger, deadline)) = expired_deadline(&sandbox, last_command_at, now) else {
            continue;
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
        match stop {
            Ok(_job) => {
                sandbox.state = SandboxState::Archiving;
                reaped.push(ReapedSandbox {
                    sandbox,
                    trigger,
                    deadline,
                });
            }
            Err(error) => {
                tracing::warn!(
                    sandbox_id = %sandbox.id,
                    trigger = trigger.reason(),
                    ?error,
                    "failed to reap sandbox past its active-lifetime deadline"
                );
            }
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
