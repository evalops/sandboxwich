//! Integration contract test for the `sandboxwich-api` HTTP surface,
//! split by resource area (see GH-82). `common` holds the shared
//! `TestServer` harness plus generic seed/assert helpers; the other
//! modules each cover one resource family's request/response contract.
//!
//! Submodules live under `http_contract/` (rather than flat in `tests/`)
//! and are pulled in via `#[path]` so Cargo doesn't also auto-register
//! each one as its own separate integration-test binary.
#[path = "http_contract/auth.rs"]
mod auth;
#[path = "http_contract/commands.rs"]
mod commands;
#[path = "http_contract/common.rs"]
mod common;
#[path = "http_contract/desktop.rs"]
mod desktop;
#[path = "http_contract/divergence.rs"]
mod divergence;
#[path = "http_contract/idempotency.rs"]
mod idempotency;
#[path = "http_contract/jobs.rs"]
mod jobs;
#[path = "http_contract/limits.rs"]
mod limits;
#[path = "http_contract/metrics.rs"]
mod metrics;
#[path = "http_contract/public_api.rs"]
mod public_api;
#[path = "http_contract/sandboxes.rs"]
mod sandboxes;
#[path = "http_contract/snapshots.rs"]
mod snapshots;
#[path = "http_contract/types.rs"]
mod types;
#[path = "http_contract/workers.rs"]
mod workers;
