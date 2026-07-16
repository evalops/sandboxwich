//! Server-maintained "last seen doing something" signal for sandboxes,
//! completing the idle-TTL activity picture `reap.rs`'s `last_known_activity`
//! previously had to leave incomplete (see `docs/capabilities.md`). SSH
//! access, desktop access, and resident-process observation requests all
//! call [`bump_sandbox_activity_best_effort`] after doing their real work.
//!
//! Throttled to at most one write per sandbox per
//! [`ACTIVITY_BUMP_THROTTLE_SECONDS`]: a chatty resident process can call
//! `observe_resident_process` every few seconds, and unconditionally writing
//! `sandboxes` -- the busiest table in the schema -- on every one of those
//! would turn "did anything happen" into a write-amplification problem.
//! `idle_ttl_seconds` deployments are realistically configured in the
//! hundreds-to-thousands-of-seconds range (a sub-minute idle timeout would
//! reap sandboxes mid-use), so a minute of slop on the activity signal
//! itself is far finer-grained than anything that would actually change a
//! reap decision, while bounding writes to at most one per sandbox per
//! minute regardless of how chatty the underlying traffic is.

use crate::db::*;
use crate::error::*;
use chrono::{DateTime, Utc};
use sandboxwich_core::SandboxId;

/// See module docs for the write-amplification reasoning behind this value.
const ACTIVITY_BUMP_THROTTLE_SECONDS: i64 = 60;

/// Bumps `sandboxes.last_activity_at` for `sandbox_id` to `now`, but only if
/// the last recorded bump (if any) is more than
/// [`ACTIVITY_BUMP_THROTTLE_SECONDS`] old. A no-op write (zero rows
/// affected, because the throttle window hasn't elapsed yet, or the
/// sandbox no longer exists) is expected and not an error.
pub(crate) async fn bump_sandbox_activity(
    db: &Database,
    sandbox_id: SandboxId,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let throttle_boundary = now - chrono::Duration::seconds(ACTIVITY_BUMP_THROTTLE_SECONDS);
    let sql = format!(
        "update sandboxes set last_activity_at = {}
         where id = {} and (last_activity_at is null or last_activity_at < {})",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3)
    );
    sqlx::query(&sql)
        .bind(now.to_rfc3339())
        .bind(sandbox_id.to_string())
        .bind(throttle_boundary.to_rfc3339())
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// The call pattern every activity touchpoint (SSH access, desktop access,
/// resident-process observation) actually uses: this is best-effort
/// telemetry, not part of any of those requests' correctness, so a failure
/// here is logged and swallowed rather than propagated as `?` and failing
/// the caller's real request.
pub(crate) async fn bump_sandbox_activity_best_effort(
    db: &Database,
    sandbox_id: SandboxId,
    now: DateTime<Utc>,
) {
    if let Err(error) = bump_sandbox_activity(db, sandbox_id, now).await {
        tracing::warn!(
            %sandbox_id,
            ?error,
            "failed to bump sandbox last_activity_at (best-effort; request proceeds)"
        );
    }
}
