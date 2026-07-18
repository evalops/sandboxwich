use crate::error::*;
use chrono::{DateTime, Utc};

pub(crate) fn expires_at_from_ttl(
    now: DateTime<Utc>,
    ttl_seconds: Option<u64>,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    let Some(ttl_seconds) = ttl_seconds else {
        return Ok(None);
    };
    let ttl_seconds = i64::try_from(ttl_seconds)
        .map_err(|_| ApiError::bad_request("ttl_seconds is too large"))?;
    Ok(Some(now + chrono::Duration::seconds(ttl_seconds)))
}

pub(crate) fn count_to_i64(count: u64) -> Result<i64, ApiError> {
    i64::try_from(count).map_err(|_| ApiError::internal("cleanup count is too large"))
}

pub(crate) fn count_to_u32(count: i64) -> Result<u32, ApiError> {
    u32::try_from(count).map_err(|_| ApiError::internal("database count is out of range"))
}

/// Applies the operator-configured default/ceiling to one active-lifetime
/// knob (`max_lifetime_seconds` or `idle_ttl_seconds`).
///
/// - `requested` always wins over `default` when present, including
///   `Some(0)` (mirrors the existing `ttl_seconds: Some(0)`
///   immediately-eligible idiom used by the archived-retention sweep).
/// - `default` only applies when the caller omits the field entirely, so an
///   operator that hasn't set a default changes nothing for existing
///   callers.
/// - `max` clamps the effective value down (never up, and never rejects the
///   request); `None` means no ceiling is configured.
///
/// Returns `None` when both `requested` and `default` are `None`, which is
/// the default, behavior-preserving case for every caller and every
/// unconfigured operator: no lifetime is ever enforced unless someone --
/// caller or operator -- opts in.
pub(crate) fn clamp_optional_lifetime(
    requested: Option<u64>,
    default: Option<u64>,
    max: Option<u64>,
) -> Option<u64> {
    let value = requested.or(default)?;
    Some(match max {
        Some(max) => value.min(max),
        None => value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_request_and_unset_default_enforce_nothing() {
        assert_eq!(clamp_optional_lifetime(None, None, None), None);
        assert_eq!(clamp_optional_lifetime(None, None, Some(3600)), None);
    }

    #[test]
    fn server_default_only_applies_when_caller_omits_the_field() {
        assert_eq!(clamp_optional_lifetime(None, Some(600), None), Some(600));
        assert_eq!(
            clamp_optional_lifetime(Some(120), Some(600), None),
            Some(120),
            "an explicit request must win over the server default"
        );
    }

    #[test]
    fn explicit_zero_is_preserved_not_treated_as_absent() {
        // Mirrors the `ttl_seconds: Some(0)` idiom: `Some(0)` is a real,
        // deliberate "expire immediately" value, not "no opinion".
        assert_eq!(clamp_optional_lifetime(Some(0), Some(600), None), Some(0));
        assert_eq!(clamp_optional_lifetime(Some(0), None, Some(600)), Some(0));
    }

    #[test]
    fn max_clamps_down_but_never_up_and_never_rejects() {
        assert_eq!(
            clamp_optional_lifetime(Some(7_200), None, Some(3_600)),
            Some(3_600),
            "a request above the operator ceiling must be clamped, not rejected"
        );
        assert_eq!(
            clamp_optional_lifetime(Some(60), None, Some(3_600)),
            Some(60),
            "a request under the ceiling must pass through unchanged"
        );
        assert_eq!(
            clamp_optional_lifetime(None, Some(7_200), Some(3_600)),
            Some(3_600),
            "the server default itself is subject to the ceiling"
        );
    }
}
