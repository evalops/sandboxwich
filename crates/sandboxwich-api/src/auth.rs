use crate::db::*;
use crate::error::*;
use crate::handlers::leases::*;
use crate::handlers::sandboxes::*;
use crate::handlers::workers::*;
use crate::rows::*;
use crate::state::*;
use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sandboxwich_core::*;
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub(crate) const PROBE_PATHS: &[&str] = &["/healthz", "/readyz"];

/// Prefix on every minted worker-scoped token (see GH-64), used to route an
/// incoming bearer token to hash-based worker lookup instead of the static
/// tenant/shared-token lists without needing to try both on every request.
pub(crate) const WORKER_TOKEN_PREFIX: &str = "sbw_wtok_";

pub(crate) async fn auth_and_tenant(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let (tenant_id, worker_id) = if PROBE_PATHS.contains(&path) {
        (state.default_tenant_id.clone(), None)
    } else if let Some(token) =
        bearer_token(&request).filter(|token| token.starts_with(WORKER_TOKEN_PREFIX))
    {
        // Worker-scoped credential (GH-64): resolves to (tenant_id,
        // worker_id) rather than to a tenant alone, by looking up the
        // SHA-256 hash stored at registration (the raw token itself is
        // never persisted). A token with this prefix that fails to resolve
        // is always unauthorized here -- it must never silently fall
        // through to the tenant-token checks below, which would let a
        // rejected worker-token attempt be retried as a tenant-wide lookup.
        match resolve_worker_token(&state.db, token).await {
            Ok(Some((tenant_id, worker_id))) => (tenant_id, Some(worker_id)),
            Ok(None) => {
                return ApiError::unauthorized("valid worker bearer token is required")
                    .into_response();
            }
            Err(error) => return error.into_response(),
        }
    } else if !state.auth.tenant_tokens.is_empty() {
        let Some(token) = bearer_token(&request) else {
            return ApiError::unauthorized("valid bearer token is required").into_response();
        };
        let Some(tenant) = state
            .auth
            .tenant_tokens
            .iter()
            .find(|candidate| constant_time_eq(token.as_bytes(), candidate.token.as_bytes()))
        else {
            return ApiError::unauthorized("valid tenant bearer token is required").into_response();
        };
        (tenant.tenant_id.clone(), None)
    } else if let Some(expected_token) = &state.auth.shared_token {
        let authorized = bearer_token(&request)
            .is_some_and(|token| constant_time_eq(token.as_bytes(), expected_token.as_bytes()));
        if !authorized {
            return ApiError::unauthorized("valid bearer token is required").into_response();
        }
        (state.default_tenant_id.clone(), None)
    } else if state.auth.allow_insecure_no_auth {
        // Explicit, off-by-default opt-out (SANDBOXWICH_ALLOW_INSECURE_NO_AUTH) for
        // local development and benchmark harnesses: with no credential configured,
        // trust the client-supplied tenant header. Never enable this in a shared
        // deployment.
        let tenant_id = request
            .headers()
            .get("x-sandboxwich-tenant")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty())
            .unwrap_or(&state.default_tenant_id)
            .to_string();
        (tenant_id, None)
    } else {
        // Fail closed: with no SANDBOXWICH_API_TOKEN and no SANDBOXWICH_TENANT_TOKENS
        // configured, there is no credential to authenticate against, so we must
        // never trust a client-supplied tenant header to select tenant identity.
        // Refuse to serve any non-probe route rather than silently running open.
        return ApiError::internal(
            "sandboxwich-api has no authentication configured; set SANDBOXWICH_API_TOKEN \
             (single-tenant) or SANDBOXWICH_TENANT_TOKENS (multi-tenant) to serve \
             authenticated routes (or SANDBOXWICH_ALLOW_INSECURE_NO_AUTH=true for local \
             development only)",
        )
        .into_response();
    };
    let principal = match worker_id {
        Some(worker_id) => Principal::Worker(worker_id),
        None if is_operator_request(&state, request.headers()) => Principal::Operator,
        None => Principal::Tenant,
    };
    request.extensions_mut().insert(TenantContext {
        tenant_id,
        principal,
    });

    next.run(request).await
}

/// Resolves a worker-scoped bearer token (see GH-64) to the `(tenant_id,
/// worker_id)` it was minted for by looking it up via its SHA-256 hash.
/// Unlike the small, static, in-memory tenant/operator token lists (which
/// use [`constant_time_eq`] to compare the raw secret directly), worker
/// tokens are dynamic per-worker DB rows, so the lookup key is the
/// cryptographic hash rather than the token itself -- the security property
/// here comes from SHA-256 preimage resistance, not timing-safe comparison,
/// so a plain indexed equality lookup is the correct and standard approach
/// (the same pattern used for hashed API keys generally).
pub(crate) async fn resolve_worker_token(
    db: &Database,
    token: &str,
) -> Result<Option<(String, WorkerId)>, ApiError> {
    let hash = hash_worker_token(token);
    let sql = format!(
        "select id, tenant_id from workers where token_hash = {}",
        db.placeholder(1)
    );
    let Some(row) = sqlx::query(&sql)
        .bind(hash)
        .fetch_optional(&db.pool)
        .await?
    else {
        return Ok(None);
    };
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    Ok(Some((tenant_id, WorkerId(parse_uuid(&id)?))))
}

/// Mints a new worker-scoped credential (see GH-64): high-entropy (256 bits),
/// prefixed so the auth middleware can route it to hash-based worker lookup,
/// and never persisted in this form -- only [`hash_worker_token`]'s output is
/// stored, in `workers.token_hash`.
pub(crate) fn generate_worker_token() -> String {
    format!(
        "{WORKER_TOKEN_PREFIX}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

/// Hex-encoded SHA-256 digest of a worker token, used both to persist it
/// (`workers.token_hash`) and to look it up (`resolve_worker_token`).
pub(crate) fn hash_worker_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Requires the request to have authenticated with a worker-scoped token
/// bound to exactly `worker_id` (see GH-64). Used on every guest-facing route
/// (lease claim/renew/complete/fail/output, guest-health) to reject
/// tenant-wide tokens outright and to stop a worker-scoped token from acting
/// on any worker other than its own. Mirrors [`ensure_tenant`]'s convention
/// of returning `not_found` (rather than a distinct "forbidden") for
/// cross-worker ownership violations, so the response never confirms or
/// denies that a given worker/lease/sandbox id exists.
pub(crate) fn ensure_worker_scope(
    ctx: &TenantContext,
    worker_id: WorkerId,
) -> Result<(), ApiError> {
    match ctx.worker_id() {
        Some(bound) if bound == worker_id => Ok(()),
        Some(_) => Err(ApiError::not_found("resource not found")),
        None => Err(ApiError::unauthorized(
            "this route requires a worker-scoped token; tenant-wide tokens are not accepted",
        )),
    }
}

pub(crate) fn bearer_token(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

/// Timing-safe byte comparison, backed by the `subtle` crate's
/// [`ConstantTimeEq`] rather than a hand-rolled loop. `[u8]::ct_eq` still
/// rejects unequal-length inputs (a cheap, non-secret-dependent length
/// check), but for equal-length inputs it walks every byte and combines the
/// per-byte differences without branching or returning early on the first
/// mismatch -- unlike a naive loop over `0..max(left.len(), right.len())`,
/// whose iteration count is itself a function of the attacker-supplied
/// input length.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

pub(crate) fn ensure_tenant(resource_tenant_id: &str, ctx: &TenantContext) -> Result<(), ApiError> {
    if resource_tenant_id != ctx.tenant_id {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(())
}

pub(crate) async fn ensure_sandbox_tenant(
    db: &Database,
    sandbox_id: SandboxId,
    ctx: &TenantContext,
) -> Result<Sandbox, ApiError> {
    let sandbox = fetch_sandbox(db, sandbox_id).await?;
    ensure_tenant(&sandbox.tenant_id, ctx)?;
    Ok(sandbox)
}

pub(crate) async fn ensure_worker_tenant(
    db: &Database,
    worker_id: WorkerId,
    ctx: &TenantContext,
) -> Result<Worker, ApiError> {
    let worker = fetch_worker(db, worker_id).await?;
    ensure_tenant(&worker.tenant_id, ctx)?;
    Ok(worker)
}

pub(crate) fn ensure_job_tenant(job: &Job, ctx: &TenantContext) -> Result<(), ApiError> {
    ensure_tenant(&job.tenant_id, ctx)
}

pub(crate) async fn ensure_lease_tenant(
    db: &Database,
    lease_id: LeaseId,
    ctx: &TenantContext,
) -> Result<JobLease, ApiError> {
    let lease = fetch_lease(db, lease_id).await?;
    ensure_job_tenant(&lease.job, ctx)?;
    Ok(lease)
}

/// Like [`ensure_lease_tenant`], but additionally requires (see GH-64) that
/// the request authenticated as the worker that actually holds `lease_id`:
/// used on every guest-facing lease route (renew/complete/fail/output) so a
/// worker-scoped token can only touch its own leases, and a tenant-wide token
/// is rejected outright rather than being allowed to act on any worker's
/// lease.
pub(crate) async fn ensure_lease_worker_scope(
    db: &Database,
    lease_id: LeaseId,
    ctx: &TenantContext,
) -> Result<JobLease, ApiError> {
    let lease = ensure_lease_tenant(db, lease_id, ctx).await?;
    ensure_worker_scope(ctx, lease.worker_id)?;
    Ok(lease)
}

/// Like [`ensure_sandbox_tenant`], but additionally requires (see GH-64) that
/// the request authenticated as the worker that provisioned or forked
/// `sandbox_id` (determined from completed provision/fork job leases, the
/// only source of truth for "which worker is running this sandbox's guest").
/// Used on the guest-facing guest-health route so a worker-scoped token can
/// only report health for sandboxes it actually owns, and a tenant-wide
/// token is rejected outright.
pub(crate) async fn ensure_sandbox_worker_scope(
    db: &Database,
    sandbox_id: SandboxId,
    ctx: &TenantContext,
) -> Result<Sandbox, ApiError> {
    let sandbox = ensure_sandbox_tenant(db, sandbox_id, ctx).await?;
    let Some(worker_id) = ctx.worker_id() else {
        return Err(ApiError::unauthorized(
            "this route requires a worker-scoped token; tenant-wide tokens are not accepted",
        ));
    };
    if !worker_owns_sandbox(db, worker_id, sandbox_id).await? {
        return Err(ApiError::not_found("resource not found"));
    }
    Ok(sandbox)
}

pub(crate) async fn require_tenant_principal(
    Extension(ctx): Extension<TenantContext>,
    request: Request,
    next: Next,
) -> Response {
    match ctx.principal {
        Principal::Tenant | Principal::Operator => next.run(request).await,
        Principal::Worker(_) => ApiError::unauthorized(
            "worker-scoped tokens are not accepted on tenant or operator routes",
        )
        .into_response(),
    }
}

pub(crate) async fn require_worker_principal(
    Extension(ctx): Extension<TenantContext>,
    request: Request,
    next: Next,
) -> Response {
    match ctx.principal {
        Principal::Worker(_) => next.run(request).await,
        Principal::Tenant | Principal::Operator => ApiError::unauthorized(
            "this route requires a worker-scoped token; tenant-wide tokens are not accepted",
        )
        .into_response(),
    }
}

/// Whether `worker_id` has ever successfully completed a `provision_sandbox`
/// or `fork_sandbox` job lease that produced (or targeted, for a fork) this
/// exact sandbox. Sandboxes carry no persistent "owning worker" column;
/// completed-lease history is the source of truth for which worker's guest
/// environment a sandbox's agent actually runs in, and it can never name two
/// different current workers for the same sandbox id (re-provisioning always
/// mints a new sandbox id).
pub(crate) async fn worker_owns_sandbox(
    db: &Database,
    worker_id: WorkerId,
    sandbox_id: SandboxId,
) -> Result<bool, ApiError> {
    let sql = format!(
        "select j.kind, j.payload
         from job_leases jl
         join jobs j on j.id = jl.job_id
         where jl.worker_id = {} and jl.status = 'completed'
           and j.kind in ('provision_sandbox', 'fork_sandbox')",
        db.placeholder(1)
    );
    let rows = sqlx::query(&sql)
        .bind(worker_id.to_string())
        .fetch_all(&db.pool)
        .await?;
    let sandbox_id_str = sandbox_id.to_string();
    for row in rows {
        let kind: String = row.try_get("kind")?;
        let payload_raw: String = row.try_get("payload")?;
        let payload: serde_json::Value = serde_json::from_str(&payload_raw)?;
        let field = if kind == "fork_sandbox" {
            "childSandboxId"
        } else {
            "sandboxId"
        };
        if payload.get(field).and_then(serde_json::Value::as_str) == Some(sandbox_id_str.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Header carrying the operator credential required by [`cleanup_snapshots`].
/// Deliberately distinct from the `Authorization` bearer token used for
/// tenant auth: cleanup acts across every tenant's data, so an ordinary
/// tenant credential (whichever tenant it belongs to) must never be
/// sufficient to run it. See issue #65.
pub(crate) const OPERATOR_TOKEN_HEADER: &str = "x-sandboxwich-operator-token";

/// Whether `headers` carries a valid operator credential, if one is configured at all. Unlike
/// [`ensure_operator_authorized`], a missing/unconfigured operator token is not an error here --
/// callers (e.g. [`metrics`]) treat that as "not an operator" and fall back to tenant-scoped
/// behavior instead of failing the request.
pub(crate) fn is_operator_request(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected_token) = &state.auth.operator_token else {
        return false;
    };
    headers
        .get(OPERATOR_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|token| constant_time_eq(token.as_bytes(), expected_token.as_bytes()))
}

pub(crate) fn ensure_operator_authorized(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    ensure_operator_authorized_for(state, headers, "snapshot cleanup", "/snapshots/cleanup")
}

pub(crate) fn ensure_operator_authorized_for(
    state: &AppState,
    headers: &HeaderMap,
    operation: &str,
    endpoint: &str,
) -> Result<(), ApiError> {
    if state.auth.operator_token.is_none() {
        return Err(ApiError::internal(format!(
            "{operation} is disabled: set SANDBOXWICH_OPERATOR_TOKEN to a dedicated operator              credential (distinct from tenant tokens) to enable {endpoint}"
        )));
    }
    if !is_operator_request(state, headers) {
        return Err(ApiError::unauthorized(format!(
            "a valid {OPERATOR_TOKEN_HEADER} header is required to run {operation}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn equal_bytes_match() {
        assert!(constant_time_eq(
            b"local-development-token",
            b"local-development-token"
        ));
    }

    #[test]
    fn unequal_content_same_length_does_not_match() {
        assert!(!constant_time_eq(
            b"local-development-token",
            b"local-development-tokeN"
        ));
    }

    #[test]
    fn different_lengths_never_match() {
        assert!(!constant_time_eq(
            b"short",
            b"a-much-longer-candidate-token"
        ));
        assert!(!constant_time_eq(
            b"a-much-longer-candidate-token",
            b"short"
        ));
    }

    #[test]
    fn empty_inputs() {
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"x", b""));
    }

    #[test]
    fn single_byte_prefix_difference() {
        // A naive early-exit comparison would return as soon as it hits the
        // first differing byte; this only checks correctness (not timing),
        // but it does confirm a differing first byte on otherwise-matching
        // longer inputs is still detected as unequal.
        assert!(!constant_time_eq(
            b"Xandboxwich-token-value",
            b"sandboxwich-token-value"
        ));
    }
}
