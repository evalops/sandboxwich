use crate::common::*;
use crate::types::placeholders;
use reqwest::StatusCode;
use sandboxwich_core::*;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;

pub(crate) async fn assert_desktop_session_lifecycle(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
) {
    let rejected_secret_url = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: Some("https://broker.example.test/connect?token=secret".to_string()),
            access_mode: Some(DesktopAccessMode::Browser),
            connection_metadata: None,
            ttl_seconds: Some(300),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(rejected_secret_url.status(), StatusCode::BAD_REQUEST);

    let desktop: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: Some("https://broker.example.test".to_string()),
            access_mode: Some(DesktopAccessMode::Browser),
            connection_metadata: Some(serde_json::json!({
                "cluster": "k3s-dev",
                "namespace": "sandboxwich-contract",
                "service": "novnc"
            })),
            ttl_seconds: Some(600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        desktop.desktop_session.status,
        DesktopSessionStatus::Pending
    );
    assert_eq!(desktop.desktop_session.sandbox_id, sandbox.sandbox.id);

    let discovery: DesktopSessionListResponse = client
        .get(format!(
            "{}/sandboxes/{}/desktop",
            server.base_url, sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(discovery.desktop_sessions.iter().any(|seen| {
        seen.id == desktop.desktop_session.id && seen.status == DesktopSessionStatus::Pending
    }));
    assert_no_access_url(&serde_json::to_value(&discovery).unwrap());

    let not_ready = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(not_ready.status(), StatusCode::BAD_REQUEST);

    let ready: DesktopSessionResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/status",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&UpdateDesktopSessionRequest {
            status: DesktopSessionStatus::Ready,
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: Some(serde_json::json!({
                "cluster": "k3s-dev",
                "namespace": "sandboxwich-contract",
                "service": "novnc",
                "pod": "desktop-a"
            })),
            ttl_seconds: Some(600),
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ready.desktop_session.status, DesktopSessionStatus::Ready);

    let fetched: DesktopSessionResponse = client
        .get(format!(
            "{}/desktop-sessions/{}",
            server.base_url, desktop.desktop_session.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched.desktop_session.id, desktop.desktop_session.id);
    assert_no_access_url(&serde_json::to_value(&fetched).unwrap());

    let access: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(access.access.session_id, desktop.desktop_session.id);
    assert_eq!(access.access.access_mode, DesktopAccessMode::Browser);
    assert!(
        access
            .access
            .access_url
            .starts_with("https://broker.example.test/sessions/")
    );
    // Every access mint now also returns a one-time, sandbox-bound brokered
    // transport credential (ROADMAP #3).
    assert!(
        access.credential.token.starts_with("sbw_dtok_"),
        "desktop credential must carry the typed transport-token prefix"
    );
    assert_eq!(access.credential.sandbox_id, sandbox.sandbox.id);
    assert_eq!(access.credential.session_id, desktop.desktop_session.id);
    assert_eq!(access.credential.expires_at, access.access.expires_at);

    let events: EventListResponse = client
        .get(format!(
            "{}/sandboxes/{}/events",
            server.base_url, sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::DesktopRequested
            && event
                .data
                .get("desktopSessionId")
                .and_then(|value| value.as_str())
                == Some(&desktop.desktop_session.id.to_string())
    }));
    assert!(events.events.iter().any(|event| {
        event.kind == SandboxEventKind::DesktopReady
            && event
                .data
                .get("desktopSessionId")
                .and_then(|value| value.as_str())
                == Some(&desktop.desktop_session.id.to_string())
    }));
    for event in &events.events {
        assert_no_access_url(&event.data);
    }

    let expiring: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: None,
            access_mode: Some(DesktopAccessMode::Vnc),
            connection_metadata: None,
            ttl_seconds: Some(0),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    // Desktop session expiry now runs on the background sweep interval instead
    // of inline on this GET, so poll for it instead of asserting synchronously.
    let expired_seen = poll_until(|| async {
        let discovered: DesktopSessionListResponse = client
            .get(format!(
                "{}/sandboxes/{}/desktop-sessions",
                server.base_url, sandbox.sandbox.id
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        discovered
            .desktop_sessions
            .iter()
            .any(|seen| {
                seen.id == expiring.desktop_session.id
                    && seen.status == DesktopSessionStatus::Expired
            })
            .then_some(())
    })
    .await;
    assert!(
        expired_seen.is_some(),
        "expired desktop session should be reported via the background sweep"
    );
}

/// Covers the ROADMAP #3 brokered desktop transport: an access mint now
/// resolves the sandbox's persisted desktop `Service` runtime resource into a
/// typed [`DesktopTransport`] and issues a short-lived, sandbox-bound
/// credential that is stored only as a hash and rotates by revocation.
pub(crate) async fn assert_desktop_brokered_transport(
    client: &reqwest::Client,
    server: &TestServer,
    sandbox: &SandboxResponse,
    worker: &WorkerResponse,
) {
    let worker_api = worker_client(worker);

    // Persist a Ready desktop Service the way the provider reconcile loop
    // would, so the access mint has a live tunnel resource to reference.
    let mut desktop_resource = provider_resource(
        sandbox.sandbox.id,
        None,
        RuntimeResourceKind::Service,
        RuntimeResourcePurpose::Desktop,
        format!("sandboxwich-desktop-{}", sandbox.sandbox.id),
    );
    desktop_resource.service_port = Some(6080);
    desktop_resource.target_port = Some("desktop".to_string());
    worker_api
        .post(format!(
            "{}/workers/{}/runtime-resources/reconcile",
            server.base_url, worker.worker.id
        ))
        .json(&ReconcileRuntimeResourcesRequest {
            provider: "kubernetes".to_string(),
            namespace: "sandboxwich-contract".to_string(),
            cluster: Some("k3s-dev".to_string()),
            resources: vec![desktop_resource],
            mark_missing_deleted: false,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let resources: RuntimeResourceListResponse = client
        .get(format!(
            "{}/sandboxes/{}/runtime-resources",
            server.base_url, sandbox.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let desktop_service = resources
        .resources
        .iter()
        .find(|resource| {
            resource.resource_kind == RuntimeResourceKind::Service
                && resource.purpose == RuntimeResourcePurpose::Desktop
        })
        .expect("provider desktop Service must be persisted as a runtime resource");

    let desktop: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, sandbox.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: Some("https://broker.example.test".to_string()),
            access_mode: Some(DesktopAccessMode::Browser),
            connection_metadata: None,
            ttl_seconds: Some(600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Fail closed: no credential row is written for a session that is not yet
    // Ready, and the mint is rejected.
    let denied = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        count_desktop_credentials(&server.database_url, desktop.desktop_session.id).await,
        0,
        "a non-ready session must not have a persisted credential"
    );

    let ready: DesktopSessionResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/status",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&UpdateDesktopSessionRequest {
            status: DesktopSessionStatus::Ready,
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: None,
            ttl_seconds: Some(600),
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Requesting more than the 900s ceiling clamps the credential's lifetime,
    // and it can never outlive the session.
    let access: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(100_000),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let transport = access
        .access
        .transport
        .as_ref()
        .expect("access must reference the live desktop tunnel");
    assert_eq!(transport.kind, DesktopTransportKind::NovncWebsocket);
    assert_eq!(transport.runtime_resource_id, desktop_service.id);
    assert_eq!(
        transport.service_name,
        format!("sandboxwich-desktop-{}", sandbox.sandbox.id)
    );
    assert_eq!(transport.namespace, "sandboxwich-contract");
    assert_eq!(transport.service_port, 6080);
    assert_eq!(transport.status, RuntimeResourceStatus::Ready);
    assert!(transport.ready);

    assert!(access.credential.token.starts_with("sbw_dtok_"));
    assert_eq!(access.credential.sandbox_id, sandbox.sandbox.id);
    assert_eq!(access.credential.session_id, desktop.desktop_session.id);
    assert_eq!(access.credential.expires_at, access.access.expires_at);
    let session_expires_at = ready
        .desktop_session
        .expires_at
        .expect("session created with a ttl has an expiry");
    assert!(
        access.credential.expires_at <= session_expires_at,
        "credential must never outlive its desktop session"
    );
    assert!(
        access.credential.expires_at <= chrono::Utc::now() + chrono::Duration::seconds(905),
        "credential ttl must be clamped to the 900s ceiling"
    );

    // The raw token is never persisted: only a hash is stored, and it is not
    // the token itself.
    let stored = desktop_credential_rows(&server.database_url, desktop.desktop_session.id).await;
    assert_eq!(stored.len(), 1);
    let (first_hash, first_revoked) = &stored[0];
    assert_ne!(first_hash, &access.credential.token);
    assert!(!first_hash.starts_with("sbw_dtok_"));
    assert_eq!(first_hash.len(), 64);
    assert!(first_revoked.is_none());

    // Re-minting rotates by revocation: a new token, and the prior credential
    // is revoked so a session has at most one live credential.
    let rotated: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(rotated.credential.token, access.credential.token);
    assert_ne!(rotated.credential.id, access.credential.id);
    let after_rotation =
        desktop_credential_rows(&server.database_url, desktop.desktop_session.id).await;
    assert_eq!(after_rotation.len(), 2);
    assert_eq!(
        after_rotation
            .iter()
            .filter(|(_, revoked)| revoked.is_none())
            .count(),
        1,
        "exactly one desktop credential stays live after rotation"
    );

    // The one-time raw credential must never be persisted for idempotent
    // replay: minting under an Idempotency-Key must not leave the token in
    // `idempotency_records.response_body_base64`, and a duplicate re-mints
    // (fresh token) rather than replaying the stored secret.
    let idempotency_key = uuid::Uuid::now_v7().to_string();
    let keyed: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .header("idempotency-key", &idempotency_key)
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(keyed.credential.token.starts_with("sbw_dtok_"));
    assert!(
        !stored_idempotency_bodies(&server.database_url)
            .await
            .iter()
            .any(|body| body.contains("sbw_dtok_") || body.contains(&keyed.credential.token)),
        "raw desktop credential must never be persisted in idempotency_records"
    );
    let keyed_replay: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, desktop.desktop_session.id
        ))
        .header("idempotency-key", &idempotency_key)
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(
        keyed_replay.credential.token, keyed.credential.token,
        "a secret-bearing response must re-mint on replay, never return a stored token"
    );

    // Closing the session is terminal: every credential bound to it is revoked
    // immediately rather than lingering until its <=900s expiry.
    client
        .post(format!(
            "{}/desktop-sessions/{}/status",
            server.base_url, desktop.desktop_session.id
        ))
        .json(&UpdateDesktopSessionRequest {
            status: DesktopSessionStatus::Closed,
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: None,
            ttl_seconds: None,
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let after_close =
        desktop_credential_rows(&server.database_url, desktop.desktop_session.id).await;
    assert!(
        !after_close.is_empty() && after_close.iter().all(|(_, revoked)| revoked.is_some()),
        "closing a desktop session must revoke all of its access credentials"
    );

    // A sandbox with no persisted desktop Service still mints a credential but
    // reports no transport, so callers cannot mistake it for a reachable
    // desktop.
    let bare: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            execution_class: None,
            workspace_mode: None,
            runtime_profile: None,
            name: Some("desktop-no-tunnel".to_string()),
            template: None,
            memory_limit: None,
            network_egress: None,
            ttl_seconds: Some(120),
            max_lifetime_seconds: None,
            idle_ttl_seconds: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let bare_session: DesktopSessionResponse = client
        .post(format!(
            "{}/sandboxes/{}/desktop-sessions",
            server.base_url, bare.sandbox.id
        ))
        .json(&CreateDesktopSessionRequest {
            broker: Some("k3s-broker".to_string()),
            broker_url: None,
            access_mode: Some(DesktopAccessMode::Vnc),
            connection_metadata: None,
            ttl_seconds: Some(300),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    client
        .post(format!(
            "{}/desktop-sessions/{}/status",
            server.base_url, bare_session.desktop_session.id
        ))
        .json(&UpdateDesktopSessionRequest {
            status: DesktopSessionStatus::Ready,
            broker: None,
            broker_url: None,
            access_mode: None,
            connection_metadata: None,
            ttl_seconds: Some(300),
            error: None,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let bare_access: DesktopAccessResponse = client
        .post(format!(
            "{}/desktop-sessions/{}/access",
            server.base_url, bare_session.desktop_session.id
        ))
        .json(&DesktopAccessRequest {
            ttl_seconds: Some(60),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        bare_access.access.transport.is_none(),
        "a sandbox with no desktop Service must not report a transport"
    );
    assert!(bare_access.credential.token.starts_with("sbw_dtok_"));
}

async fn desktop_credential_rows(
    database_url: &str,
    desktop_session_id: DesktopSessionId,
) -> Vec<(String, Option<String>)> {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap();
    let sql = format!(
        "select token_hash, revoked_at from desktop_access_credentials
         where desktop_session_id = {} order by created_at asc",
        placeholders(database_url, 1)
    );
    let rows = sqlx::query(&sql)
        .bind(desktop_session_id.to_string())
        .fetch_all(&pool)
        .await
        .unwrap();
    rows.into_iter()
        .map(|row| {
            (
                row.try_get::<String, _>("token_hash").unwrap(),
                row.try_get::<Option<String>, _>("revoked_at").unwrap(),
            )
        })
        .collect()
}

/// Every non-null persisted idempotent-replay body, base64-decoded to its raw
/// UTF-8, so a test can assert a one-time secret never landed there.
async fn stored_idempotency_bodies(database_url: &str) -> Vec<String> {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap();
    let rows = sqlx::query(
        "select response_body_base64 from idempotency_records
         where response_body_base64 is not null",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    rows.into_iter()
        .filter_map(|row| {
            row.try_get::<Option<String>, _>("response_body_base64")
                .unwrap()
        })
        .map(|encoded| {
            String::from_utf8_lossy(&BASE64_URL_SAFE_NO_PAD.decode(encoded).unwrap()).into_owned()
        })
        .collect()
}

async fn count_desktop_credentials(
    database_url: &str,
    desktop_session_id: DesktopSessionId,
) -> usize {
    desktop_credential_rows(database_url, desktop_session_id)
        .await
        .len()
}
