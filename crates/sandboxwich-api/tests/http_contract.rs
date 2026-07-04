use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::StatusCode;
use sandboxwich_core::{
    CommandListResponse, CommandRequest, CommandResponse, CreateSandboxRequest, EventListResponse,
    HealthResponse, SandboxListResponse, SandboxResponse,
};
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    child: Child,
    _data_dir: TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn lifecycle_command_and_event_contracts_work_over_http() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    let health: HealthResponse = client
        .get(format!("{}/healthz", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(health.ok);

    let created: SandboxResponse = client
        .post(format!("{}/sandboxes", server.base_url))
        .json(&CreateSandboxRequest {
            name: Some("contract-test".to_string()),
            template: None,
            ttl_seconds: Some(120),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.sandbox.name, "contract-test");

    let listed: SandboxListResponse = client
        .get(format!("{}/sandboxes", server.base_url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed.sandboxes.len(), 1);

    let command: CommandResponse = client
        .post(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .json(&CommandRequest {
            argv: vec!["echo".to_string(), "hello".to_string()],
            cwd: None,
            env: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(command.command.argv, ["echo", "hello"]);

    let commands: CommandListResponse = client
        .get(format!(
            "{}/sandboxes/{}/commands",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(commands.commands.len(), 1);
    assert_eq!(commands.commands[0].id, command.command.id);

    let fetched_command: CommandResponse = client
        .get(format!(
            "{}/commands/{}",
            server.base_url, command.command.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched_command.command.id, command.command.id);

    let stopped: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/stop",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(stopped.sandbox.state).unwrap(),
        "archived"
    );

    let resumed: SandboxResponse = client
        .post(format!(
            "{}/sandboxes/{}/resume",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(resumed.sandbox.state).unwrap(),
        "ready"
    );

    let events: EventListResponse = client
        .get(format!(
            "{}/sandboxes/{}/events",
            server.base_url, created.sandbox.id
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(events.events.len() >= 5);

    let missing = client
        .get(format!(
            "{}/commands/00000000-0000-0000-0000-000000000000",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

impl TestServer {
    async fn start() -> Self {
        let data_dir = tempfile::tempdir().unwrap();
        let database_url = format!(
            "sqlite://{}",
            data_dir.path().join("sandboxwich-test.db").display()
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bind = listener.local_addr().unwrap();
        drop(listener);

        let mut child = Command::new(env!("CARGO_BIN_EXE_sandboxwich-api"))
            .env("SANDBOXWICH_DATABASE_URL", database_url)
            .env("SANDBOXWICH_BIND", bind.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();
        for _ in 0..100 {
            if let Ok(response) = client.get(format!("{base_url}/healthz")).send().await {
                if response.status().is_success() {
                    return Self {
                        base_url,
                        child,
                        _data_dir: data_dir,
                    };
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited before becoming healthy: {status}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = child.kill();
        let _ = child.wait();
        panic!("server did not become healthy");
    }
}
