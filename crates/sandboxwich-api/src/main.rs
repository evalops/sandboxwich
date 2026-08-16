mod activity;
mod api_contract;
mod auth;
mod authz;
mod bootstrap_handoff;
mod cleanup;
mod config;
mod db;
mod error;
mod handlers;
mod health;
mod idempotency;
mod identity_mtls;
mod lifecycle_contract;
mod limits;
mod maestro_observation;
mod pagination;
mod reap;
mod reconcile;
mod rejection_log;
mod request_id;
mod routes;
mod rows;
mod scheduler;
mod slo_metrics;
mod state;
mod sterile_pool;
#[cfg(test)]
mod tests;
mod util;

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::api_contract::openapi_document;
use crate::bootstrap_handoff::SharedBootstrapHandoff;
use crate::config::AuthConfig;
use crate::config::{ApiCommand, load_api_config};
use crate::db::connect_database;
use crate::db::migrate_database;
use crate::db::verify_database_schema;
use crate::identity_mtls::{identity_app, identity_tls_config};
use crate::maestro_observation::ActivationObservationSink;
use crate::routes::app;
use crate::scheduler::spawn_expiry_sweeper;
use crate::state::{AppState, ResidentBootstrapStore};
use crate::sterile_pool::spawn_sterile_pool_reconciler;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    sandboxwich_core::lifecycle_contract::verify_configured_lifecycle_contract()?;
    lifecycle_contract::configure_lifecycle_contract_header()?;

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
        && config.provider_routing_tokens.is_empty()
    {
        tracing::warn!(
            "SANDBOXWICH_ALLOW_INSECURE_NO_AUTH is set: serving with no authentication and \
             trusting the client-supplied tenant header. Do not use this in a shared deployment."
        );
    }

    let resident_bootstraps = match config.bootstrap_handoff_key {
        Some(key) => {
            let handoff = SharedBootstrapHandoff::new(key, config.bootstrap_handoff_ttl);
            tracing::info!(
                key_id = handoff.key_id(),
                ttl_seconds = handoff.ttl().as_secs(),
                "resident bootstrap handoff is shared: bootstrap delivery survives API restart \
                 and replica failover"
            );
            ResidentBootstrapStore::default().with_shared_handoff(handoff)
        }
        None => {
            tracing::info!(
                "SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY is not set: resident bootstrap bytes stay in \
                 this process, so an API restart or a read served by another replica cannot \
                 complete a pending bootstrap"
            );
            ResidentBootstrapStore::default()
        }
    };
    if config.disable_expiry_sweeper {
        tracing::info!(
            "SANDBOXWICH_DISABLE_EXPIRY_SWEEPER is set: not spawning the lease/snapshot/desktop-\
             session expiry or archived-runtime reconciliation sweeper. Nothing will expire \
             leases, snapshots, or desktop sessions on this instance except explicit callers of \
             /snapshots/cleanup, and archived provider resources will not be repaired."
        );
    } else {
        spawn_expiry_sweeper(
            db.clone(),
            resident_bootstraps.clone(),
            Duration::from_millis(config.sweep_interval_ms),
            config.sterile_cell_signing_key.is_some(),
        );
    }
    spawn_sterile_pool_reconciler(
        db.clone(),
        config.sterile_pool.clone(),
        Duration::from_millis(config.sweep_interval_ms),
    );

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to bind SANDBOXWICH_BIND={}", config.bind))?;
    tracing::info!(addr = %config.bind, database_url = %config.database_url, "sandboxwich-api listening");
    let maestro_observation_sink = ActivationObservationSink::new(db.clone());
    let state = AppState {
        db,
        auth: AuthConfig {
            shared_token: config.shared_token,
            tenant_tokens: config.tenant_tokens,
            provider_routing_tokens: config.provider_routing_tokens,
            operator_token: config.operator_token,
            allow_insecure_no_auth: config.allow_insecure_no_auth,
        },
        default_tenant_id: config.default_tenant_id,
        apex_callback_base_url: config.apex_callback_base_url,
        placement_attestation_derivation_key: config
            .placement_attestation_derivation_key
            .map(Arc::<str>::from),
        apex_waiters: Default::default(),
        maestro_observation_sink,
        resident_bootstraps,
        sandbox_lifetime: config.sandbox_lifetime,
        sterile_pool: config.sterile_pool,
        sterile_cell_signing_key: config.sterile_cell_signing_key.map(Arc::<str>::from),
        sterile_resident_activation_enabled: config.sterile_resident_activation_enabled,
        #[cfg(test)]
        apex_callback_test_hook: None,
    };

    if let Some(identity_mtls) = config.identity_mtls {
        let tls = identity_tls_config(&identity_mtls)?;
        let identity_listener =
            std::net::TcpListener::bind(identity_mtls.bind).with_context(|| {
                format!(
                    "failed to bind SANDBOXWICH_IDENTITY_MTLS_BIND={}",
                    identity_mtls.bind
                )
            })?;
        let identity_address = identity_listener
            .local_addr()
            .context("failed to inspect Identity mTLS listener address")?;
        tracing::info!(addr = %identity_address, "sandboxwich-api Identity mTLS fence listening");

        let (shutdown_tx, tenant_shutdown) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        });

        let identity_handle = axum_server::Handle::new();
        let identity_shutdown_handle = identity_handle.clone();
        let identity_shutdown = tenant_shutdown.clone();
        tokio::spawn(async move {
            wait_for_shutdown(identity_shutdown).await;
            identity_shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });

        let tenant_server = axum::serve(listener, app(state.clone()))
            .with_graceful_shutdown(wait_for_shutdown(tenant_shutdown));
        let identity_server = axum_server::from_tcp_rustls(identity_listener, tls)
            .handle(identity_handle)
            .serve(identity_app(state).into_make_service());
        tokio::try_join!(tenant_server, identity_server)?;
    } else {
        axum::serve(listener, app(state))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }
    Ok(())
}

async fn wait_for_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
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
