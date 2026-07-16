use crate::common::*;
use sandboxwich_core::*;
use std::collections::BTreeMap;

#[tokio::test]
pub(crate) async fn resident_process_create_is_idempotent_tenant_scoped_and_redacted() {
    let data_dir = tempfile::tempdir().unwrap();
    let server = TestServer::start(
        format!(
            "sqlite://{}",
            data_dir.path().join("resident-process.db").display()
        ),
        Some(data_dir),
    )
    .await;
    let client = server.client();
    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("resident-process".into()),
            template: Some("ubuntu-dev".into()),
            memory_limit: None,
            network_egress: Some(NetworkEgress::DenyAll),
            workspace_mode: None,
            runtime_profile: None,
            execution_class: None,
            ttl_seconds: Some(3600),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let request = ResidentProcessRequest {
        argv: vec!["/usr/local/bin/orb-executor".into()],
        cwd: Some("/workspace".into()),
        env: BTreeMap::from([(
            "ORB_TOKEN_FILE".into(),
            "/run/sandboxwich/bootstrap/orb-token".into(),
        )]),
        restart_policy: ResidentProcessRestartPolicy::OnFailure,
        expected_generation: 0,
        bootstrap: Some(ResidentProcessBootstrap {
            content: b"resident-canary-secret".to_vec(),
            target_file: "/run/sandboxwich/bootstrap/orb-token".into(),
            mode: 0o600,
        }),
    };
    let url = format!(
        "{}/sandboxes/{}/resident-processes/orb-executor",
        server.base_url, created.sandbox.id
    );
    let first = client
        .put(&url)
        .header("Idempotency-Key", "resident-process-create")
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let first_body = first.text().await.unwrap();
    assert!(!first_body.contains("resident-canary-secret"));
    let first: ResidentProcessResponse = serde_json::from_str(&first_body).unwrap();
    assert_eq!(first.resident_process.generation, 1);

    let replay: ResidentProcessResponse = client
        .put(&url)
        .header("Idempotency-Key", "resident-process-create")
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay.resident_process.id, first.resident_process.id);

    let fetched: ResidentProcessResponse = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched.resident_process.id, first.resident_process.id);

    let tenant_b = reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {TEST_TENANT_B_TOKEN}").parse().unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    assert_eq!(
        tenant_b.get(&url).send().await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND
    );
}
