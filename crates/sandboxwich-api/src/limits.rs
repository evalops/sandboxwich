use crate::auth::ensure_operator_authorized;
use crate::db::Database;
use crate::error::ApiError;
use crate::state::{AppState, Principal, TenantContext};
use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::{Duration as ChronoDuration, Utc};
use sandboxwich_core::ErrorEnvelope;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;

#[derive(Clone, Copy)]
enum CounterKind {
    Request,
    Mutation,
}

impl CounterKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Mutation => "mutation",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TenantLimitPolicy {
    pub(crate) tenant_id: String,
    pub(crate) request_limit: u32,
    pub(crate) mutation_limit: u32,
    pub(crate) window_seconds: u32,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PutTenantLimitPolicy {
    pub(crate) request_limit: u32,
    pub(crate) mutation_limit: u32,
    pub(crate) window_seconds: u32,
}

pub(crate) async fn enforce_tenant_limits(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(context) = request.extensions().get::<TenantContext>().cloned() else {
        return next.run(request).await;
    };
    if context.principal == Principal::Operator {
        return next.run(request).await;
    }
    let policy = match fetch_policy(&state.db, &context.tenant_id).await {
        Ok(Some(policy)) => policy,
        Ok(None) => return next.run(request).await,
        Err(error) => return error.into_response(),
    };
    if let Err(response) = consume(
        &state.db,
        &context.tenant_id,
        CounterKind::Request,
        policy.request_limit,
        policy.window_seconds,
    )
    .await
    {
        return response;
    }
    if is_mutating(request.method())
        && let Err(response) = consume(
            &state.db,
            &context.tenant_id,
            CounterKind::Mutation,
            policy.mutation_limit,
            policy.window_seconds,
        )
        .await
    {
        return response;
    }
    next.run(request).await
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

async fn consume(
    db: &Database,
    tenant: &str,
    kind: CounterKind,
    limit: u32,
    window_seconds: u32,
) -> Result<(), Response> {
    let now = Utc::now();
    let expires = now + ChronoDuration::seconds(i64::from(window_seconds));
    let sql = format!(
        "insert into tenant_limit_counters
         (tenant_id, kind, used, window_started_at, window_expires_at)
         values ({})
         on conflict (tenant_id, kind) do update set
           used = case when window_expires_at <= excluded.window_started_at then 1 else used + 1 end,
           window_started_at = case when window_expires_at <= excluded.window_started_at then excluded.window_started_at else window_started_at end,
           window_expires_at = case when window_expires_at <= excluded.window_started_at then excluded.window_expires_at else window_expires_at end
         where window_expires_at <= excluded.window_started_at or used < {}
         returning window_expires_at",
        db.placeholders(5),
        db.placeholder(6)
    );
    let row = sqlx::query(&sql)
        .bind(tenant)
        .bind(kind.as_str())
        .bind(1_i64)
        .bind(now.to_rfc3339())
        .bind(expires.to_rfc3339())
        .bind(i64::from(limit))
        .fetch_optional(&db.pool)
        .await
        .map_err(|error| ApiError::from(error).into_response())?;
    if row.is_some() {
        return Ok(());
    }
    let retry_after = counter_retry_after(db, tenant, kind).await.unwrap_or(1);
    let (code, message) = match kind {
        CounterKind::Request => (
            "tenant_rate_limit_exceeded",
            "tenant request rate limit exceeded",
        ),
        CounterKind::Mutation => (
            "tenant_mutation_quota_exceeded",
            "tenant mutation quota exceeded",
        ),
    };
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorEnvelope::new(code, message)),
    )
        .into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string())
            .expect("positive seconds are a valid header"),
    );
    Err(response)
}

async fn counter_retry_after(db: &Database, tenant: &str, kind: CounterKind) -> Option<i64> {
    let sql = format!(
        "select window_expires_at from tenant_limit_counters where tenant_id = {} and kind = {}",
        db.placeholder(1),
        db.placeholder(2)
    );
    let row = sqlx::query(&sql)
        .bind(tenant)
        .bind(kind.as_str())
        .fetch_optional(&db.pool)
        .await
        .ok()??;
    let expires: String = row.try_get("window_expires_at").ok()?;
    let expires = chrono::DateTime::parse_from_rfc3339(&expires)
        .ok()?
        .with_timezone(&Utc);
    Some((expires - Utc::now()).num_seconds().max(0) + 1)
}

async fn fetch_policy(db: &Database, tenant: &str) -> Result<Option<TenantLimitPolicy>, ApiError> {
    let sql = format!(
        "select tenant_id, request_limit, mutation_limit, window_seconds from tenant_limit_policies where tenant_id = {}",
        db.placeholder(1)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(tenant)
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(TenantLimitPolicy {
        tenant_id: row.try_get("tenant_id")?,
        request_limit: u32::try_from(row.try_get::<i64, _>("request_limit")?)
            .map_err(|_| ApiError::internal("invalid tenant request limit"))?,
        mutation_limit: u32::try_from(row.try_get::<i64, _>("mutation_limit")?)
            .map_err(|_| ApiError::internal("invalid tenant mutation limit"))?,
        window_seconds: u32::try_from(row.try_get::<i64, _>("window_seconds")?)
            .map_err(|_| ApiError::internal("invalid tenant limit window"))?,
    }))
}

#[utoipa::path(get, path = "/v1/operator/tenant-policies/{tenant_id}", tag = "operator", params(("tenant_id" = String, Path)), responses((status = 200, body = TenantLimitPolicy), (status = 404, body = ErrorEnvelope)))]
pub(crate) async fn get_tenant_limit_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> Result<Json<TenantLimitPolicy>, ApiError> {
    ensure_operator_authorized(&state, &headers)?;
    fetch_policy(&state.db, &tenant)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("tenant limit policy not found"))
}

#[utoipa::path(put, path = "/v1/operator/tenant-policies/{tenant_id}", tag = "operator", params(("tenant_id" = String, Path)), request_body = PutTenantLimitPolicy, responses((status = 200, body = TenantLimitPolicy), (status = 400, body = ErrorEnvelope)))]
pub(crate) async fn put_tenant_limit_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
    Json(input): Json<PutTenantLimitPolicy>,
) -> Result<Json<TenantLimitPolicy>, ApiError> {
    ensure_operator_authorized(&state, &headers)?;
    if tenant.trim().is_empty()
        || input.request_limit == 0
        || input.mutation_limit == 0
        || input.window_seconds == 0
    {
        return Err(ApiError::bad_request(
            "tenant and all tenant limit values must be non-zero",
        ));
    }
    let sql = format!(
        "insert into tenant_limit_policies (tenant_id, request_limit, mutation_limit, window_seconds, updated_at) values ({})
         on conflict (tenant_id) do update set request_limit = excluded.request_limit, mutation_limit = excluded.mutation_limit,
         window_seconds = excluded.window_seconds, updated_at = excluded.updated_at",
        state.db.placeholders(5)
    );
    sqlx::query(&sql)
        .bind(&tenant)
        .bind(i64::from(input.request_limit))
        .bind(i64::from(input.mutation_limit))
        .bind(i64::from(input.window_seconds))
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db.pool)
        .await?;
    Ok(Json(TenantLimitPolicy {
        tenant_id: tenant,
        request_limit: input.request_limit,
        mutation_limit: input.mutation_limit,
        window_seconds: input.window_seconds,
    }))
}

pub(crate) async fn expire_tenant_limit_counters(db: &Database) -> Result<u64, ApiError> {
    let sql = format!(
        "delete from tenant_limit_counters where (tenant_id, kind) in (
           select tenant_id, kind from tenant_limit_counters where window_expires_at <= {} order by window_expires_at limit 1000
         )", db.placeholder(1)
    );
    Ok(sqlx::query(&sql)
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await?
        .rows_affected())
}
