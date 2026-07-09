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
