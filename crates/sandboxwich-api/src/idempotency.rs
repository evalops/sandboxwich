use crate::db::Database;
use crate::error::ApiError;
use crate::state::{AppState, Principal, TenantContext};
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use sandboxwich_core::ErrorEnvelope;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::time::Duration;

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const IDEMPOTENCY_RETENTION_HOURS: i64 = 24;
// This lease bounds how long a duplicate request will be told
// `409 idempotency_in_progress` (see `replay_or_wait`) before the sweeper
// (`expire_idempotency_records`) reclaims an abandoned "processing" row and
// lets a fresh attempt through. It is *not* a timeout on the handler itself
// -- nothing here cancels `next.run(request)` -- so it is only safe as long
// as no handler this middleware wraps can plausibly still be running after
// five minutes. That holds today: `enforce_idempotency` is only mounted on
// `tenant_routes` (see `routes.rs`), and every one of those handlers does a
// bounded number of local DB reads/writes and, for anything long-running
// (provisioning, commands, snapshots, forks), enqueues a `Job` and returns
// `202` immediately rather than waiting on worker/provider execution. If a
// future route under this middleware can legitimately run long, this lease
// needs to be renewed periodically instead of left as a fixed bound.
const PROCESSING_LEASE_MINUTES: i64 = 5;
const MAX_IDEMPOTENT_REQUEST_BYTES: usize = crate::routes::DEFAULT_BODY_LIMIT_BYTES;
const MAX_STORED_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const CONCURRENT_REPLAY_POLLS: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordState {
    Processing,
    Completed,
}

impl RecordState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "processing" => Ok(Self::Processing),
            "completed" => Ok(Self::Completed),
            _ => Err(ApiError::internal(
                "database contains invalid idempotency state",
            )),
        }
    }
}

struct StoredResponse {
    status: StatusCode,
    content_type: Option<String>,
    location: Option<String>,
    retry_after: Option<String>,
    body: Vec<u8>,
}

pub(crate) async fn enforce_idempotency(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !is_mutating(request.method()) {
        return next.run(request).await;
    }
    let Some(context) = request.extensions().get::<TenantContext>().cloned() else {
        return next.run(request).await;
    };
    if matches!(
        context.principal,
        Principal::Operator | Principal::Worker(_)
    ) {
        return next.run(request).await;
    }
    let Some(key_header) = request.headers().get(IDEMPOTENCY_KEY_HEADER) else {
        return next.run(request).await;
    };
    let key = match key_header.to_str() {
        Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
        _ => {
            return coded_error(
                StatusCode::BAD_REQUEST,
                "invalid_idempotency_key",
                "Idempotency-Key must contain valid non-empty text",
                None,
            );
        }
    };
    if key.len() > 128 {
        return coded_error(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "Idempotency-Key must be at most 128 characters",
            None,
        );
    }

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_IDEMPOTENT_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return coded_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "idempotency_payload_too_large",
                "idempotent requests are limited to 1 MiB",
                None,
            );
        }
    };
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let fingerprint =
        fingerprint_request(&parts.method, &parts.uri.to_string(), content_type, &body);
    let request = Request::from_parts(parts, Body::from(body));
    let now = Utc::now();
    let expires_at = now + ChronoDuration::minutes(PROCESSING_LEASE_MINUTES);
    let insert_sql = format!(
        "insert into idempotency_records
         (tenant_id, idempotency_key, request_fingerprint, state, created_at, expires_at)
         values ({}) on conflict (tenant_id, idempotency_key) do nothing",
        state.db.placeholders(6)
    );
    let inserted = match sqlx::query(&insert_sql)
        .bind(&context.tenant_id)
        .bind(&key)
        .bind(&fingerprint)
        .bind(RecordState::Processing.as_str())
        .bind(now.to_rfc3339())
        .bind(expires_at.to_rfc3339())
        .execute(&state.db.pool)
        .await
    {
        Ok(result) => result.rows_affected() == 1,
        Err(error) => return ApiError::from(error).into_response(),
    };

    if !inserted {
        return replay_or_wait(&state.db, &context.tenant_id, &key, &fingerprint).await;
    }

    let response = next.run(request).await;
    let stored = capture_response(response).await;
    if stored.status == StatusCode::TOO_MANY_REQUESTS {
        if let Err(error) = abandon_record(&state.db, &context.tenant_id, &key).await {
            tracing::error!(?error, tenant_id = %context.tenant_id, "failed to release throttled idempotency claim");
        }
        return stored.into_response();
    }
    finalize_completed_record(&state.db, &context.tenant_id, &key, &stored).await;
    stored.into_response()
}

/// Persists the response for a request that finished executing so a
/// duplicate can replay it later. If that persist fails, the mutation this
/// request performed has already committed (we're past `next.run`), but
/// without a stored response there's nothing valid to replay -- so instead
/// of leaving the record `processing` (which would make every duplicate
/// wait out the rest of `PROCESSING_LEASE_MINUTES` behind `409
/// idempotency_in_progress` only to *still* trigger a second, unreplayed
/// execution once the sweeper reclaims it), delete the record immediately.
/// A duplicate that arrives after this will insert a fresh `processing` row
/// and re-execute right away instead of blocking first. That is still a
/// second execution -- there is no cached response to fall back to -- but
/// it is immediate and logged instead of silently delayed, and callers that
/// care about that risk can already tell from the error rate on this path.
async fn finalize_completed_record(
    db: &Database,
    tenant: &str,
    key: &str,
    stored: &StoredResponse,
) {
    let Err(error) = complete_record(db, tenant, key, stored).await else {
        return;
    };
    tracing::error!(
        ?error,
        tenant_id = %tenant,
        idempotency_key = %key,
        "failed to persist idempotent response after the request executed; deleting the \
         processing record so a retry re-executes immediately instead of waiting out a stale lease"
    );
    if let Err(cleanup_error) = abandon_record(db, tenant, key).await {
        tracing::error!(
            ?cleanup_error,
            tenant_id = %tenant,
            idempotency_key = %key,
            "failed to delete idempotency record after a completion-persist failure; it will \
             fall back to expiring naturally via the sweeper"
        );
    }
}

async fn abandon_record(db: &Database, tenant: &str, key: &str) -> Result<(), ApiError> {
    let sql = format!(
        "delete from idempotency_records where tenant_id = {} and idempotency_key = {} and state = 'processing'",
        db.placeholder(1),
        db.placeholder(2)
    );
    sqlx::query(&sql)
        .bind(tenant)
        .bind(key)
        .execute(&db.pool)
        .await?;
    Ok(())
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn fingerprint_request(
    method: &Method,
    uri: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> String {
    let mut digest = Sha256::new();
    digest.update(method.as_str().as_bytes());
    digest.update([0]);
    digest.update(uri.as_bytes());
    digest.update([0]);
    if let Some(content_type) = content_type {
        digest.update(content_type.as_bytes());
    }
    digest.update([0]);
    digest.update(body);
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

async fn replay_or_wait(db: &Database, tenant: &str, key: &str, fingerprint: &str) -> Response {
    for _ in 0..CONCURRENT_REPLAY_POLLS {
        match fetch_record(db, tenant, key).await {
            Ok((seen_fingerprint, RecordState::Completed, Some(response))) => {
                if seen_fingerprint != fingerprint {
                    return fingerprint_conflict();
                }
                return response.into_response();
            }
            Ok((seen_fingerprint, RecordState::Processing, _)) => {
                if seen_fingerprint != fingerprint {
                    return fingerprint_conflict();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok((_, RecordState::Completed, None)) => {
                return coded_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "idempotency_record_incomplete",
                    "stored idempotency response is incomplete",
                    None,
                );
            }
            Err(error) => return error.into_response(),
        }
    }
    coded_error(
        StatusCode::CONFLICT,
        "idempotency_in_progress",
        "an identical request is still in progress",
        Some("1"),
    )
}

async fn fetch_record(
    db: &Database,
    tenant: &str,
    key: &str,
) -> Result<(String, RecordState, Option<StoredResponse>), ApiError> {
    let sql = format!(
        "select request_fingerprint, state, response_status, response_content_type,
                response_location, response_retry_after, response_body_base64
         from idempotency_records where tenant_id = {} and idempotency_key = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(tenant)
        .bind(key)
        .fetch_one(&db.pool)
        .await?;
    let state = RecordState::parse(&row.try_get::<String, _>("state")?)?;
    let status: Option<i64> = row.try_get("response_status")?;
    let response = match status {
        Some(status) => Some(StoredResponse {
            status: StatusCode::from_u16(
                u16::try_from(status)
                    .map_err(|_| ApiError::internal("invalid stored response status"))?,
            )
            .map_err(|_| ApiError::internal("invalid stored response status"))?,
            content_type: row.try_get("response_content_type")?,
            location: row.try_get("response_location")?,
            retry_after: row.try_get("response_retry_after")?,
            body: URL_SAFE_NO_PAD
                .decode(row.try_get::<String, _>("response_body_base64")?)
                .map_err(|_| ApiError::internal("invalid stored response body"))?,
        }),
        None => None,
    };
    Ok((row.try_get("request_fingerprint")?, state, response))
}

async fn capture_response(response: Response) -> StoredResponse {
    let status = response.status();
    let content_type = header_value(&response, header::CONTENT_TYPE);
    let location = header_value(&response, header::LOCATION);
    let retry_after = header_value(&response, header::RETRY_AFTER);
    let (_, body) = response.into_parts();
    match to_bytes(body, MAX_STORED_RESPONSE_BYTES).await {
        Ok(body) => StoredResponse {
            status,
            content_type,
            location,
            retry_after,
            body: body.to_vec(),
        },
        Err(_) => StoredResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            content_type: Some("application/json".to_string()),
            location: None,
            retry_after: None,
            body: serde_json::to_vec(&ErrorEnvelope::new(
                "idempotency_response_too_large",
                "response is too large for idempotent replay",
            ))
            .expect("error envelope serializes"),
        },
    }
}

fn header_value(response: &Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn complete_record(
    db: &Database,
    tenant: &str,
    key: &str,
    response: &StoredResponse,
) -> Result<(), ApiError> {
    let sql = format!(
        "update idempotency_records set state = {}, response_status = {}, response_content_type = {},
         response_location = {}, response_retry_after = {}, response_body_base64 = {}, completed_at = {}, expires_at = {}
         where tenant_id = {} and idempotency_key = {} and state = 'processing'",
        db.placeholder(1), db.placeholder(2), db.placeholder(3), db.placeholder(4),
        db.placeholder(5), db.placeholder(6), db.placeholder(7), db.placeholder(8),
        db.placeholder(9), db.placeholder(10)
    );
    sqlx::query(&sql)
        .bind(RecordState::Completed.as_str())
        .bind(i64::from(response.status.as_u16()))
        .bind(&response.content_type)
        .bind(&response.location)
        .bind(&response.retry_after)
        .bind(URL_SAFE_NO_PAD.encode(&response.body))
        .bind(Utc::now().to_rfc3339())
        .bind((Utc::now() + ChronoDuration::hours(IDEMPOTENCY_RETENTION_HOURS)).to_rfc3339())
        .bind(tenant)
        .bind(key)
        .execute(&db.pool)
        .await?;
    Ok(())
}

impl StoredResponse {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        for (name, value) in [
            (header::CONTENT_TYPE, self.content_type),
            (header::LOCATION, self.location),
            (header::RETRY_AFTER, self.retry_after),
        ] {
            if let Some(value) = value.and_then(|value| HeaderValue::from_str(&value).ok()) {
                response.headers_mut().insert(name, value);
            }
        }
        response
    }
}

fn fingerprint_conflict() -> Response {
    coded_error(
        StatusCode::CONFLICT,
        "idempotency_key_reused",
        "Idempotency-Key was already used with a different request",
        None,
    )
}

fn coded_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retry_after: Option<&str>,
) -> Response {
    let mut response = (status, axum::Json(ErrorEnvelope::new(code, message))).into_response();
    if let Some(value) = retry_after {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(value).expect("static retry-after is valid"),
        );
    }
    response
}

pub(crate) async fn expire_idempotency_records(db: &Database) -> Result<u64, ApiError> {
    let sql = format!(
        "delete from idempotency_records where (tenant_id, idempotency_key) in (
             select tenant_id, idempotency_key from idempotency_records where expires_at <= {}
             order by expires_at asc, tenant_id asc, idempotency_key asc limit 1000
         )",
        db.placeholder(1)
    );
    Ok(sqlx::query(&sql)
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await?
        .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{SqlDialect, ensure_database_constraints};
    use sqlx::any::AnyPoolOptions;

    async fn test_sqlite_db() -> Database {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        let db = Database {
            pool,
            dialect: SqlDialect::Sqlite,
        };
        sqlx::migrate!("./migrations")
            .run(&db.pool)
            .await
            .expect("run migrations");
        ensure_database_constraints(&db)
            .await
            .expect("reconcile enum constraints");
        db
    }

    async fn insert_processing_record(db: &Database, tenant: &str, key: &str) {
        let now = Utc::now();
        let sql = format!(
            "insert into idempotency_records
             (tenant_id, idempotency_key, request_fingerprint, state, created_at, expires_at)
             values ({})",
            db.placeholders(6)
        );
        sqlx::query(&sql)
            .bind(tenant)
            .bind(key)
            .bind("fingerprint")
            .bind(RecordState::Processing.as_str())
            .bind(now.to_rfc3339())
            .bind((now + ChronoDuration::minutes(PROCESSING_LEASE_MINUTES)).to_rfc3339())
            .execute(&db.pool)
            .await
            .expect("insert processing record");
    }

    async fn record_exists(db: &Database, tenant: &str, key: &str) -> bool {
        let sql = format!(
            "select 1 from idempotency_records where tenant_id = {} and idempotency_key = {}",
            db.placeholder(1),
            db.placeholder(2)
        );
        sqlx::query(&sql)
            .bind(tenant)
            .bind(key)
            .fetch_optional(&db.pool)
            .await
            .expect("query idempotency_records")
            .is_some()
    }

    #[tokio::test]
    async fn complete_record_failure_deletes_the_processing_record_instead_of_leaving_it_stuck() {
        // Regresses the bug this change fixes: if persisting the completed
        // response fails (here forced with a trigger standing in for any
        // real database error) after the underlying mutation already
        // committed, the record must not be left `processing` -- that would
        // make every duplicate request wait out the rest of
        // `PROCESSING_LEASE_MINUTES` behind `409 idempotency_in_progress`
        // and *still* re-execute once the sweeper reclaimed it. Deleting it
        // immediately instead lets a retry re-execute right away.
        let db = test_sqlite_db().await;
        let tenant = "tenant-a";
        let key = "poison";
        insert_processing_record(&db, tenant, key).await;
        assert!(record_exists(&db, tenant, key).await);

        // Force `complete_record`'s UPDATE to fail deterministically, without
        // reaching into sqlx internals: a trigger that aborts specifically
        // when this key is updated stands in for a real database error
        // (lock timeout, connection drop, ...) on that one statement, while
        // leaving every other statement (including the cleanup delete this
        // test is asserting on) unaffected.
        sqlx::query(
            "create trigger poison_complete before update on idempotency_records
             when new.idempotency_key = 'poison'
             begin select raise(abort, 'forced failure for test'); end",
        )
        .execute(&db.pool)
        .await
        .expect("install poison trigger");

        let stored = StoredResponse {
            status: StatusCode::OK,
            content_type: Some("application/json".to_string()),
            location: None,
            retry_after: None,
            body: b"{}".to_vec(),
        };
        finalize_completed_record(&db, tenant, key, &stored).await;

        assert!(
            !record_exists(&db, tenant, key).await,
            "a completion-persist failure must delete the processing record rather than leave it \
             stuck, so a retry does not have to wait out a stale lease before re-executing"
        );
    }

    #[tokio::test]
    async fn finalize_completed_record_persists_the_response_on_the_happy_path() {
        let db = test_sqlite_db().await;
        let tenant = "tenant-a";
        let key = "happy-path";
        insert_processing_record(&db, tenant, key).await;

        let stored = StoredResponse {
            status: StatusCode::CREATED,
            content_type: Some("application/json".to_string()),
            location: Some("/v1/sandboxes/1".to_string()),
            retry_after: None,
            body: b"{\"ok\":true}".to_vec(),
        };
        finalize_completed_record(&db, tenant, key, &stored).await;

        let (fingerprint, state, response) = fetch_record(&db, tenant, key)
            .await
            .expect("fetch completed record");
        assert_eq!(fingerprint, "fingerprint");
        assert_eq!(state, RecordState::Completed);
        let response = response.expect("completed record must carry a stored response");
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.body, b"{\"ok\":true}");
    }
}
