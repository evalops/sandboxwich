use crate::db::*;
use crate::error::*;
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use sqlx::Row;
use sqlx::any::AnyRow;

// ---- List pagination helpers ----
//
// List endpoints share a single keyset pagination scheme: every paginated table is ordered by
// `(created_at, id)` ascending, and callers page through it with `limit` plus an opaque `after`
// (or `before`) cursor produced by a previous response's `next_cursor`. The cursor encodes the
// `(created_at, id)` of a row so pagination is stable even when new rows are inserted concurrently
// (unlike offset/page-number pagination).

pub(crate) const DEFAULT_PAGE_LIMIT: u32 = 100;
pub(crate) const MAX_PAGE_LIMIT: u32 = 200;
pub(crate) const PAGE_CURSOR_SEP: char = '|';

#[derive(Debug, Deserialize)]
pub(crate) struct PageParams {
    pub(crate) limit: Option<u32>,
    pub(crate) before: Option<String>,
    pub(crate) after: Option<String>,
}

pub(crate) enum PageDirection {
    After,
    Before,
}

pub(crate) struct PageCursor {
    pub(crate) created_at: String,
    pub(crate) id: String,
}

impl PageCursor {
    pub(crate) fn encode(&self) -> String {
        general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{}{PAGE_CURSOR_SEP}{}", self.created_at, self.id))
    }

    pub(crate) fn decode(raw: &str) -> Result<Self, ApiError> {
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| ApiError::bad_request("invalid pagination cursor"))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ApiError::bad_request("invalid pagination cursor"))?;
        let (created_at, id) = text
            .split_once(PAGE_CURSOR_SEP)
            .ok_or_else(|| ApiError::bad_request("invalid pagination cursor"))?;
        Ok(Self {
            created_at: created_at.to_string(),
            id: id.to_string(),
        })
    }
}

/// Resolve the requested page size, clamped to `MAX_PAGE_LIMIT` and defaulting to
/// `DEFAULT_PAGE_LIMIT` so a single list request can never pull an unbounded result set.
pub(crate) fn resolve_page_limit(limit: Option<u32>) -> Result<u32, ApiError> {
    match limit {
        None => Ok(DEFAULT_PAGE_LIMIT),
        Some(0) => Err(ApiError::bad_request("limit must be greater than 0")),
        Some(value) => Ok(value.min(MAX_PAGE_LIMIT)),
    }
}

pub(crate) fn resolve_page_cursor(
    params: &PageParams,
) -> Result<Option<(PageDirection, PageCursor)>, ApiError> {
    match (&params.before, &params.after) {
        (Some(_), Some(_)) => Err(ApiError::bad_request(
            "only one of before or after may be set",
        )),
        (Some(raw), None) => Ok(Some((PageDirection::Before, PageCursor::decode(raw)?))),
        (None, Some(raw)) => Ok(Some((PageDirection::After, PageCursor::decode(raw)?))),
        (None, None) => Ok(None),
    }
}

/// Run a keyset-paginated query against a table ordered by `(created_at, id)`.
///
/// `base_sql` must already contain a `select ... from ... where <fixed predicate>` clause using
/// `db.placeholder(1..=fixed_binds.len())` for its own bind values (mirroring the existing
/// non-paginated queries in this file); this helper appends the cursor predicate, `order by`, and
/// `limit` clauses, and binds `fixed_binds` followed by the single cursor bind (if any).
pub(crate) async fn fetch_keyset_page<T>(
    db: &Database,
    base_sql: &str,
    fixed_binds: &[String],
    limit: u32,
    cursor: &Option<(PageDirection, PageCursor)>,
    row_map: impl Fn(AnyRow) -> Result<T, ApiError>,
) -> Result<(Vec<T>, Option<String>), ApiError> {
    let next_placeholder = db.placeholder(fixed_binds.len() + 1);
    let (predicate, order_dir, cursor_bind) = match cursor {
        None => (String::new(), "asc", None),
        Some((PageDirection::After, c)) => (
            format!(" and (created_at || '{PAGE_CURSOR_SEP}' || id) > {next_placeholder}"),
            "asc",
            Some(format!("{}{PAGE_CURSOR_SEP}{}", c.created_at, c.id)),
        ),
        Some((PageDirection::Before, c)) => (
            format!(" and (created_at || '{PAGE_CURSOR_SEP}' || id) < {next_placeholder}"),
            "desc",
            Some(format!("{}{PAGE_CURSOR_SEP}{}", c.created_at, c.id)),
        ),
    };

    // Fetch one extra row so we can tell whether another page follows without a second query.
    let fetch_limit = i64::from(limit) + 1;
    let sql = format!(
        "{base_sql}{predicate} order by created_at {order_dir}, id {order_dir} limit {fetch_limit}"
    );

    let mut query = sqlx::query(&sql);
    for bind in fixed_binds {
        query = query.bind(bind.clone());
    }
    if let Some(bind) = cursor_bind {
        query = query.bind(bind);
    }

    let mut rows = query.fetch_all(&db.pool).await?;
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);

    let mut keyed_items = Vec::with_capacity(rows.len());
    for row in rows {
        let created_at: String = row.try_get("created_at")?;
        let id: String = row.try_get("id")?;
        let item = row_map(row)?;
        keyed_items.push((created_at, id, item));
    }

    if matches!(cursor, Some((PageDirection::Before, _))) {
        keyed_items.reverse();
    }

    // For `before` pages, the boundary row supplied by the caller necessarily follows the last
    // item we return, so a forward cursor is always safe to hand back. For the default/`after`
    // direction, only advertise a next page when the peeked extra row confirmed one exists.
    let is_before = matches!(cursor, Some((PageDirection::Before, _)));
    let next_cursor = keyed_items.last().and_then(|(created_at, id, _)| {
        if is_before || has_more {
            Some(
                PageCursor {
                    created_at: created_at.clone(),
                    id: id.clone(),
                }
                .encode(),
            )
        } else {
            None
        }
    });

    let items = keyed_items.into_iter().map(|(_, _, item)| item).collect();
    Ok((items, next_cursor))
}
