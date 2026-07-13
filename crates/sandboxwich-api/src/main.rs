mod api_contract;
mod auth;
mod cleanup;
mod config;
mod db;
mod error;
mod handlers;
mod health;
mod idempotency;
mod limits;
mod pagination;
mod reconcile;
mod request_id;
mod routes;
mod rows;
mod scheduler;
mod slo_metrics;
mod state;
#[cfg(test)]
mod tests;
mod util;

use std::time::Duration;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::api_contract::openapi_document;
use crate::config::AuthConfig;
use crate::config::{ApiCommand, load_api_config};
use crate::db::connect_database;
use crate::db::migrate_database;
use crate::db::verify_database_schema;
use crate::routes::app;
use crate::scheduler::spawn_expiry_sweeper;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = load_api_config()?;
    if matches!(config.command, ApiCommand::OpenApi) {
        serde_json::to_writer_pretty(std::io::stdout().lock(), &openapi_document())?;
        println!();
        return Ok(());
    }
    let db = connect_database(&config.database_url, config.database_max_connections).await?;

    match config.command {
        ApiCommand::Migrate => {
            migrate_database(&db).await?;
            tracing::info!(database_url = %config.database_url, "database migrations complete");
            return Ok(());
        }
        ApiCommand::CheckSchema => {
            verify_database_schema(&db).await?;
            tracing::info!(database_url = %config.database_url, "database schema ready");
            return Ok(());
        }
        ApiCommand::Serve => {
            if config.auto_migrate {
                migrate_database(&db).await?;
            } else {
                verify_database_schema(&db).await?;
            }
        }
        ApiCommand::OpenApi => unreachable!("OpenAPI exits before database connection"),
    }

    if config.allow_insecure_no_auth
        && config.shared_token.is_none()
        && config.tenant_tokens.is_empty()
    {
        tracing::warn!(
            "SANDBOXWICH_ALLOW_INSECURE_NO_AUTH is set: serving with no authentication and \
             trusting the client-supplied tenant header. Do not use this in a shared deployment."
        );
    }

    if config.disable_expiry_sweeper {
        tracing::info!(
            "SANDBOXWICH_DISABLE_EXPIRY_SWEEPER is set: not spawning the lease/snapshot/desktop-\
             session expiry sweeper. Nothing will expire leases, snapshots, or desktop sessions \
             on this instance except explicit callers of /snapshots/cleanup."
        );
    } else {
        spawn_expiry_sweeper(db.clone(), Duration::from_millis(config.sweep_interval_ms));
    }

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to bind SANDBOXWICH_BIND={}", config.bind))?;
    tracing::info!(addr = %config.bind, database_url = %config.database_url, "sandboxwich-api listening");
    axum::serve(
        listener,
        app(AppState {
            db,
            auth: AuthConfig {
                shared_token: config.shared_token,
                tenant_tokens: config.tenant_tokens,
                operator_token: config.operator_token,
                allow_insecure_no_auth: config.allow_insecure_no_auth,
            },
            default_tenant_id: config.default_tenant_id,
        }),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Waits for whichever shutdown signal the runtime environment sends first.
///
/// Kubernetes sends SIGTERM (not SIGINT) to stop a pod, so graceful shutdown
/// never fired in the shipped deployment when this only awaited `ctrl_c()`.
/// On Unix, race SIGTERM and SIGINT (dev/local `Ctrl-C`) together; non-Unix
/// targets fall back to `ctrl_c()` alone since `tokio::signal::unix` isn't
/// available there.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::warn!(%error, "failed to install SIGTERM handler");
                // Fall back to ctrl_c() alone rather than returning immediately
                // (which would make graceful shutdown a no-op).
                if let Err(error) = tokio::signal::ctrl_c().await {
                    tracing::warn!(%error, "failed to install shutdown signal handler");
                }
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, starting graceful shutdown");
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "failed to install shutdown signal handler");
                } else {
                    tracing::info!("received SIGINT, starting graceful shutdown");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to install shutdown signal handler");
        }
    }
}
