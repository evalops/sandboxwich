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
use sqlx::any::AnyPoolOptions;
use tempfile::TempDir;
use uuid::Uuid;

struct TestServer {
    base_url: String,
    database_url: String,
    child: Child,
    _data_dir: Option<TempDir>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn lifecycle_command_and_event_contracts_work_over_sqlite() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("sandboxwich-test.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    run_contract(server).await;
}

#[tokio::test]
async fn lifecycle_command_and_event_contracts_work_over_postgres_when_configured() {
    let Ok(database_url) = std::env::var("SANDBOXWICH_TEST_POSTGRES_URL") else {
        return;
    };

    let server = TestServer::start(database_url, None).await;
    run_contract(server).await;
}

async fn run_contract(server: TestServer) {
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
    assert_database_rejects_invalid_typed_values(
        &server.database_url,
        &created.sandbox.id.to_string(),
    )
    .await;

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
    assert!(
        listed
            .sandboxes
            .iter()
            .any(|sandbox| sandbox.id == created.sandbox.id)
    );

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
    async fn start(database_url: String, data_dir: Option<TempDir>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bind = listener.local_addr().unwrap();
        drop(listener);

        let mut child = Command::new(env!("CARGO_BIN_EXE_sandboxwich-api"))
            .env("SANDBOXWICH_DATABASE_URL", &database_url)
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
                        database_url,
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

async fn assert_database_rejects_invalid_typed_values(database_url: &str, sandbox_id: &str) {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .unwrap();

    let invalid_sandbox_id = Uuid::now_v7().to_string();
    let invalid_command_id = Uuid::now_v7().to_string();
    let invalid_event_id = Uuid::now_v7().to_string();
    let now = "2026-07-04T00:00:00Z";

    let sandbox_result = sqlx::query(&insert_sandbox_sql(database_url))
        .bind(invalid_sandbox_id)
        .bind("invalid")
        .bind("not_real")
        .bind("ubuntu-dev")
        .bind(now)
        .bind(now)
        .bind(120_i64)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        sandbox_result.is_err(),
        "invalid sandbox state was accepted"
    );

    let command_result = sqlx::query(&insert_command_sql(database_url))
        .bind(invalid_command_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind(r#"["echo","nope"]"#)
        .bind(Option::<String>::None)
        .bind(Option::<i32>::None)
        .bind("")
        .bind("")
        .bind(now)
        .bind(Option::<String>::None)
        .execute(&pool)
        .await;
    assert!(
        command_result.is_err(),
        "invalid command status was accepted"
    );

    let event_result = sqlx::query(&insert_event_sql(database_url))
        .bind(invalid_event_id)
        .bind(sandbox_id)
        .bind("not_real")
        .bind("{}")
        .bind(now)
        .execute(&pool)
        .await;
    assert!(event_result.is_err(), "invalid event kind was accepted");
}

fn insert_sandbox_sql(database_url: &str) -> String {
    format!(
        "insert into sandboxes
         (id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        placeholders(database_url, 8)
    )
}

fn insert_command_sql(database_url: &str) -> String {
    format!(
        "insert into commands
         (id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at)
         values ({})",
        placeholders(database_url, 10)
    )
}

fn insert_event_sql(database_url: &str) -> String {
    format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values ({})",
        placeholders(database_url, 5)
    )
}

fn placeholders(database_url: &str, count: usize) -> String {
    (1..=count)
        .map(|index| {
            if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
                format!("${index}")
            } else {
                "?".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
