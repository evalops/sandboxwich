use crate::common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn rpc(server: &TestServer, body: Value) -> (StatusCode, Value) {
    let response = server
        .client()
        .post(format!("{}/mcp", server.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let json = response.json().await.unwrap();
    (status, json)
}

async fn call_tool(server: &TestServer, name: &str, arguments: Value) -> Value {
    let (status, body) = rpc(
        server,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn tool_payload(body: &Value) -> Value {
    if body["result"]["isError"].as_bool() == Some(true) {
        let text = body["result"]["content"][0]["text"]
            .as_str()
            .expect("error text");
        return serde_json::from_str(text).expect("error payload json");
    }
    body["result"]["structuredContent"].clone()
}

#[tokio::test]
async fn mcp_rejects_missing_bearer() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("mcp-unauth.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let response = reqwest::Client::new()
        .post(format!("{}/mcp", server.base_url))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_initialize_and_lists_box_tools() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!("sqlite://{}", data_dir.path().join("mcp-init.db").display());
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let (status, body) = rpc(
        &server,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["serverInfo"]["name"], "sandboxwich");
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");

    let (status, body) = rpc(
        &server,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "box_create",
            "box_list",
            "box_get",
            "box_exec",
            "box_snapshot",
            "box_fork",
            "box_sleep",
            "box_wake",
            "box_destroy",
            "box_sizes"
        ]
    );
}

#[tokio::test]
async fn mcp_box_sizes_and_create_requires_lifetime() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("mcp-create.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;

    let sizes = call_tool(&server, "box_sizes", json!({})).await;
    assert_eq!(tool_payload(&sizes)["sizes"].as_array().unwrap().len(), 4);

    let missing = call_tool(&server, "box_create", json!({ "name": "demo" })).await;
    let error = tool_payload(&missing);
    assert_eq!(error["code"], "box_lifetime_required");

    let created = call_tool(
        &server,
        "box_create",
        json!({
            "name": "demo",
            "size": "4g",
            "idle_ttl_seconds": 3600
        }),
    )
    .await;
    let payload = tool_payload(&created);
    assert_eq!(payload["http_status"], 202);
    assert_eq!(payload["result"]["sandbox"]["name"], "demo");
    assert_eq!(payload["result"]["sandbox"]["workspace_mode"], "persistent");
    assert_eq!(payload["result"]["sandbox"]["memory_limit"], "4g");
    assert_eq!(payload["result"]["sandbox"]["idle_ttl_seconds"], 3600);
    let box_id = payload["result"]["sandbox"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let listed = call_tool(&server, "box_list", json!({})).await;
    assert_eq!(tool_payload(&listed)["boxes"].as_array().unwrap().len(), 1);

    let got = call_tool(&server, "box_get", json!({ "box_id": box_id })).await;
    assert_eq!(tool_payload(&got)["sandbox"]["id"], box_id);

    let refused = call_tool(
        &server,
        "box_destroy",
        json!({ "box_id": box_id, "confirm": false }),
    )
    .await;
    assert_eq!(tool_payload(&refused)["code"], "confirm_required");

    let destroyed = call_tool(
        &server,
        "box_destroy",
        json!({ "box_id": box_id, "confirm": true }),
    )
    .await;
    assert_eq!(tool_payload(&destroyed)["http_status"], 202);
    assert_eq!(
        tool_payload(&destroyed)["result"]["sandbox"]["state"],
        "archiving"
    );
}

#[tokio::test]
async fn mcp_box_get_is_tenant_scoped() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("mcp-tenant.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let created = call_tool(
        &server,
        "box_create",
        json!({
            "name": "owned",
            "idle_ttl_seconds": 60
        }),
    )
    .await;
    let box_id = tool_payload(&created)["result"]["sandbox"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let foreign = reqwest::Client::new()
        .post(format!("{}/mcp", server.base_url))
        .bearer_auth(TEST_TENANT_B_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "box_get",
                "arguments": { "box_id": box_id }
            }
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let error = tool_payload(&foreign);
    assert_eq!(error["code"], "not_found");
}

#[tokio::test]
async fn mcp_unknown_method_and_tool() {
    let data_dir = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        data_dir.path().join("mcp-unknown.db").display()
    );
    let server = TestServer::start(database_url, Some(data_dir)).await;
    let (status, body) = rpc(
        &server,
        json!({"jsonrpc":"2.0","id":1,"method":"nope","params":{}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], -32601);

    let unknown = call_tool(&server, "box_explode", json!({})).await;
    assert_eq!(tool_payload(&unknown)["code"], "unknown_tool");
}
