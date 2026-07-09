use crate::common::*;
use reqwest::StatusCode;
use sandboxwich_core::*;

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
