use crate::api_contract::openapi;
use crate::auth::*;
use crate::handlers::commands::*;
use crate::handlers::desktop::*;
use crate::handlers::files::*;
use crate::handlers::jobs::*;
use crate::handlers::leases::*;
use crate::handlers::operations::*;
use crate::handlers::sandboxes::*;
use crate::handlers::snapshots::*;
use crate::handlers::ssh::*;
use crate::handlers::workers::*;
use crate::health::*;
use crate::idempotency::enforce_idempotency;
use crate::reconcile::*;
use crate::request_id::{attach_request_id, normalize_framework_errors};
use crate::state::*;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::{self};
use axum::routing::{get, post};
use sandboxwich_core::*;

/// Default request body limit applied to every route. Kept small (1 MiB) because most endpoints
/// only ever accept small JSON payloads; the file upload route below opts into a much larger,
/// explicit limit instead of every route inheriting one sized for 512 MB file bodies.
pub(crate) const DEFAULT_BODY_LIMIT_BYTES: usize = 1024 * 1024;

pub(crate) fn app(state: AppState) -> Router {
    let upload_body_limit = usize::try_from(MAX_SANDBOX_FILE_BYTES + 1024 * 1024)
        .expect("file upload limit should fit usize");

    let tenant_routes = Router::new()
        .route("/metrics", get(metrics))
        .route("/sandboxes", get(list_sandboxes).post(create_sandbox))
        .route("/sandboxes/{sandbox_id}", get(get_sandbox))
        .route(
            "/sandboxes/{sandbox_id}/files",
            get(list_files)
                .post(upload_file)
                // Only this route needs to accept large (multipart file) bodies; every other
                // route falls back to the small DEFAULT_BODY_LIMIT_BYTES layer below.
                .layer(DefaultBodyLimit::max(upload_body_limit)),
        )
        .route(
            "/sandboxes/{sandbox_id}/files/{file_id}",
            get(download_file),
        )
        .route(
            "/sandboxes/{sandbox_id}/runtime-resources",
            get(list_runtime_resources),
        )
        .route("/sandboxes/{sandbox_id}/stop", post(stop_sandbox))
        .route("/sandboxes/{sandbox_id}/resume", post(resume_sandbox))
        .route("/sandboxes/{sandbox_id}/fork", post(fork_sandbox))
        .route(
            "/sandboxes/{sandbox_id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route(
            "/sandboxes/{sandbox_id}/desktop",
            get(list_desktop_sessions),
        )
        .route(
            "/sandboxes/{sandbox_id}/desktop-sessions",
            get(list_desktop_sessions).post(create_desktop_session),
        )
        .route(
            "/sandboxes/{sandbox_id}/commands",
            get(list_commands).post(queue_command),
        )
        .route("/sandboxes/{sandbox_id}/prompt", post(queue_prompt))
        .route("/sandboxes/{sandbox_id}/events", get(list_events))
        .route(
            "/desktop-sessions/{desktop_session_id}",
            get(get_desktop_session),
        )
        .route(
            "/desktop-sessions/{desktop_session_id}/status",
            post(update_desktop_session_status),
        )
        .route(
            "/desktop-sessions/{desktop_session_id}/access",
            post(create_desktop_access),
        )
        .route("/snapshots/cleanup", post(cleanup_snapshots))
        .route("/snapshots/{snapshot_id}", get(get_snapshot))
        .route("/commands/{command_id}", get(get_command))
        .route("/commands/{command_id}/output", get(list_command_output))
        .route("/workers", get(list_workers))
        .route("/capacity", get(get_capacity))
        .route("/workers/register", post(register_worker))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/{job_id}", get(get_job))
        .route("/operations/{operation_id}", get(get_operation))
        .route("/operations/{operation_id}/events", get(operation_events))
        .route("/operations/{operation_id}/cancel", post(cancel_operation))
        .route(
            "/sandboxes/{sandbox_id}/guest-health",
            get(get_guest_health),
        )
        .route(
            "/sandboxes/{sandbox_id}/ssh-keys",
            get(list_ssh_keys).post(request_ssh_key),
        )
        .route(
            "/sandboxes/{sandbox_id}/ssh-access",
            post(create_ssh_access),
        )
        .route("/ssh-keys/{ssh_key_id}/status", post(update_ssh_key_status))
        .route_layer(middleware::from_fn(require_tenant_principal));

    let worker_routes = Router::new()
        .route("/workers/{worker_id}/heartbeat", post(heartbeat_worker))
        .route("/workers/{worker_id}/drain", post(drain_worker))
        .route(
            "/workers/{worker_id}/runtime-resources/reconcile",
            post(reconcile_runtime_resources),
        )
        .route("/workers/{worker_id}/leases/claim", post(claim_lease))
        .route("/leases/{lease_id}/renew", post(renew_lease))
        .route("/leases/{lease_id}/output", post(append_lease_output))
        .route("/leases/{lease_id}/complete", post(complete_lease))
        .route("/leases/{lease_id}/fail", post(fail_lease))
        .route(
            "/sandboxes/{sandbox_id}/guest-health",
            post(update_guest_health),
        )
        .route_layer(middleware::from_fn(require_worker_principal));

    let versioned_routes = Router::new()
        .merge(tenant_routes.clone())
        .merge(worker_routes.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_idempotency,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/openapi.json", get(openapi))
        .route("/v1/healthz", get(healthz))
        .route("/v1/readyz", get(readyz))
        .nest("/v1", versioned_routes)
        .merge(tenant_routes)
        .merge(worker_routes)
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT_BYTES))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_and_tenant))
        .layer(middleware::from_fn(normalize_framework_errors))
        .layer(middleware::from_fn(attach_request_id))
}
