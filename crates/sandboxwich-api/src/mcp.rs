//! Tenant-authenticated MCP facade over the existing `/v1` sandbox lifecycle.
//!
//! `POST /mcp` accepts Streamable-HTTP JSON-RPC (`initialize`, `tools/list`,
//! `tools/call`, `ping`). Tools call the same handlers as the REST routes and
//! force `workspace_mode=persistent` plus an explicit live-lifetime cap so an
//! agent cannot create an uncapped box through this surface.

use crate::auth::ProviderRoutingScope;
use crate::authz::AuthorizationContext;
use crate::error::ApiError;
use crate::handlers::commands::queue_command;
use crate::handlers::sandboxes::{
    create_sandbox, fork_sandbox, get_sandbox, list_sandboxes_payload, resume_sandbox, stop_sandbox,
};
use crate::handlers::snapshots::create_snapshot;
use crate::pagination::PageParams;
use crate::request_id::RequestTrace;
use crate::state::{AppState, TenantContext};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sandboxwich_core::*;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

const PROTOCOL_VERSION: &str = "2025-06-18";
const SERVICE_NAME: &str = "sandboxwich";

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
}

pub(crate) async fn mcp_post(
    State(state): State<AppState>,
    Extension(ctx): Extension<TenantContext>,
    Extension(provider_routing_scope): Extension<ProviderRoutingScope>,
    Extension(authorization): Extension<AuthorizationContext>,
    Extension(trace): Extension<RequestTrace>,
    Json(body): Json<Value>,
) -> Response {
    let request: JsonRpcRequest = match serde_json::from_value(body) {
        Ok(request) => request,
        Err(error) => {
            return json_rpc_error(None, -32700, format!("parse error: {error}"));
        }
    };
    if request.jsonrpc.as_deref() != Some("2.0") {
        return json_rpc_error(request.id, -32600, "jsonrpc must be \"2.0\"");
    }
    let Some(method) = request.method else {
        return json_rpc_error(request.id, -32600, "method is required");
    };
    if request.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let id = request.id;
    let params = request.params.unwrap_or(Value::Null);
    match method.as_str() {
        "initialize" => json_rpc_result(id, initialize_result()),
        "notifications/initialized" => json_rpc_result(id, json!({})),
        "ping" => json_rpc_result(id, json!({})),
        "tools/list" => json_rpc_result(id, json!({ "tools": tool_descriptors() })),
        "tools/call" => {
            match dispatch_tool(
                state,
                ctx,
                provider_routing_scope,
                authorization,
                trace,
                params,
            )
            .await
            {
                Ok(result) => json_rpc_result(id, result),
                Err(error) => json_rpc_result(id, tool_error(error)),
            }
        }
        _ => json_rpc_error(id, -32601, format!("method not found: {method}")),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": SERVICE_NAME,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Use box_* tools to create, inspect, exec, snapshot, fork, sleep, wake, and destroy persistent sandboxes. box_create requires a name and a live lifetime (max_lifetime_seconds or idle_ttl_seconds, unless the operator set a default). Destroy requires confirm=true."
    })
}

fn tool_descriptors() -> Vec<Value> {
    vec![
        tool(
            "box_create",
            "Create a persistent sandbox (a box). Requires name and a live lifetime unless the operator configured SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS or SANDBOXWICH_DEFAULT_IDLE_TTL_SECONDS.",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "minLength": 1 },
                    "size": { "type": "string", "enum": ["1g", "4g", "16g", "64g"], "description": "Memory tier. Default 4g." },
                    "max_lifetime_seconds": { "type": "integer", "minimum": 1 },
                    "idle_ttl_seconds": { "type": "integer", "minimum": 1 },
                    "template": { "type": "string" },
                    "secret_ref_ids": {
                        "type": "array",
                        "items": { "type": "string", "format": "uuid" }
                    },
                    "execution_class": {
                        "type": "string",
                        "enum": ["development_container", "sandboxed_container", "virtual_machine"]
                    }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_list",
            "List boxes for the authenticated tenant.",
            json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                    "after": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        tool(
            "box_get",
            "Get one box by id.",
            json!({
                "type": "object",
                "properties": { "box_id": { "type": "string", "format": "uuid" } },
                "required": ["box_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_exec",
            "Queue a command on a box. Returns the queued command and operation; it does not wait for the guest to finish.",
            json!({
                "type": "object",
                "properties": {
                    "box_id": { "type": "string", "format": "uuid" },
                    "argv": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
                    "cwd": { "type": "string" },
                    "timeout_secs": { "type": "integer", "minimum": 1 }
                },
                "required": ["box_id", "argv"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_snapshot",
            "Create a workspace snapshot of a persistent box.",
            json!({
                "type": "object",
                "properties": {
                    "box_id": { "type": "string", "format": "uuid" },
                    "label": { "type": "string" }
                },
                "required": ["box_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_fork",
            "Fork a persistent box into a new box. Secret bindings are not copied.",
            json!({
                "type": "object",
                "properties": {
                    "box_id": { "type": "string", "format": "uuid" },
                    "name": { "type": "string" },
                    "size": { "type": "string", "enum": ["1g", "4g", "16g", "64g"] },
                    "max_lifetime_seconds": { "type": "integer", "minimum": 1 },
                    "idle_ttl_seconds": { "type": "integer", "minimum": 1 }
                },
                "required": ["box_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_sleep",
            "Snapshot a box, then stop it. Resume later with box_wake. Restores disk, not live process memory.",
            json!({
                "type": "object",
                "properties": { "box_id": { "type": "string", "format": "uuid" } },
                "required": ["box_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_wake",
            "Resume an archived box from one of its snapshots.",
            json!({
                "type": "object",
                "properties": {
                    "box_id": { "type": "string", "format": "uuid" },
                    "snapshot_id": { "type": "string", "format": "uuid" }
                },
                "required": ["box_id"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_destroy",
            "Stop a box. Requires confirm=true. This archives the sandbox; operator cleanup deletes retained rows later.",
            json!({
                "type": "object",
                "properties": {
                    "box_id": { "type": "string", "format": "uuid" },
                    "confirm": { "type": "boolean" }
                },
                "required": ["box_id", "confirm"],
                "additionalProperties": false
            }),
        ),
        tool(
            "box_sizes",
            "List memory tiers this MCP will create. There is no GPU catalog.",
            json!({ "type": "object", "additionalProperties": false }),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema
    })
}

async fn dispatch_tool(
    state: AppState,
    ctx: TenantContext,
    provider_routing_scope: ProviderRoutingScope,
    authorization: AuthorizationContext,
    trace: RequestTrace,
    params: Value,
) -> Result<Value, ApiError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("tools/call requires params.name"))?;
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    match name {
        "box_create" => {
            box_create(
                state,
                ctx,
                provider_routing_scope,
                authorization,
                trace,
                arguments,
            )
            .await
        }
        "box_list" => box_list(state, ctx, arguments).await,
        "box_get" => box_get(state, ctx, arguments).await,
        "box_exec" => box_exec(state, ctx, arguments).await,
        "box_snapshot" => box_snapshot(state, ctx, arguments).await,
        "box_fork" => box_fork(state, ctx, arguments).await,
        "box_sleep" => box_sleep(state, ctx, authorization, trace, arguments).await,
        "box_wake" => box_wake(state, ctx, arguments).await,
        "box_destroy" => box_destroy(state, ctx, authorization, trace, arguments).await,
        "box_sizes" => Ok(tool_text(json!({
            "sizes": [
                { "size": "1g", "memory": "1Gi", "cpu": "500m", "disk": "2Gi" },
                { "size": "4g", "memory": "4Gi", "cpu": "1", "disk": "8Gi" },
                { "size": "16g", "memory": "16Gi", "cpu": "4", "disk": "32Gi" },
                { "size": "64g", "memory": "64Gi", "cpu": "16", "disk": "128Gi" }
            ]
        }))),
        other => Err(ApiError::bad_request_code(
            "unknown_tool",
            format!("unknown tool: {other}"),
        )),
    }
}

async fn box_create(
    state: AppState,
    ctx: TenantContext,
    provider_routing_scope: ProviderRoutingScope,
    authorization: AuthorizationContext,
    trace: RequestTrace,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: CreateArgs = parse_args(arguments)?;
    let name = require_name(&args.name)?;
    require_lifetime(args.max_lifetime_seconds, args.idle_ttl_seconds, &state)?;
    let request = CreateSandboxRequest {
        name: Some(name),
        template: args.template,
        memory_limit: Some(parse_size(args.size.as_deref().unwrap_or("4g"))?),
        network_egress: None,
        workspace_mode: Some(WorkspaceMode::Persistent),
        runtime_profile: None,
        execution_class: parse_execution_class(args.execution_class.as_deref())?,
        provider_preference: None,
        ttl_seconds: None,
        max_lifetime_seconds: args.max_lifetime_seconds,
        idle_ttl_seconds: args.idle_ttl_seconds,
        secret_ref_ids: parse_secret_refs(args.secret_ref_ids)?,
    };
    let (status, Json(body)) = create_sandbox(
        State(state),
        Extension(ctx),
        Extension(provider_routing_scope),
        Extension(authorization),
        Extension(trace),
        Json(request),
    )
    .await?;
    Ok(tool_accepted(status, body))
}

async fn box_list(
    state: AppState,
    ctx: TenantContext,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: ListArgs = parse_args(arguments)?;
    let page = PageParams {
        limit: args.limit,
        before: None,
        after: args.after,
    };
    let body = list_sandboxes_payload(state, ctx, Query(page)).await?;
    Ok(tool_text(json!({
        "boxes": body.sandboxes,
        "next_cursor": body.next_cursor
    })))
}

async fn box_get(state: AppState, ctx: TenantContext, arguments: Value) -> Result<Value, ApiError> {
    let args: BoxIdArgs = parse_args(arguments)?;
    let Json(body) = get_sandbox(
        State(state),
        Extension(ctx),
        Path(parse_box_id(&args.box_id)?),
    )
    .await?;
    Ok(tool_text(body))
}

async fn box_exec(
    state: AppState,
    ctx: TenantContext,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: ExecArgs = parse_args(arguments)?;
    if args.argv.is_empty() {
        return Err(ApiError::bad_request("argv must contain at least one item"));
    }
    let request = CommandRequest {
        argv: args.argv,
        cwd: args.cwd,
        env: Default::default(),
        stdin: None,
        timeout_secs: args.timeout_secs,
    };
    let (status, Json(body)) = queue_command(
        State(state),
        Extension(ctx),
        Path(parse_box_id(&args.box_id)?),
        Json(request),
    )
    .await?;
    Ok(tool_accepted(status, body))
}

async fn box_snapshot(
    state: AppState,
    ctx: TenantContext,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: SnapshotArgs = parse_args(arguments)?;
    let request = CreateSnapshotRequest {
        label: args.label,
        inventory: None,
        provider_metadata: None,
        ttl_seconds: None,
    };
    let (status, Json(body)) = create_snapshot(
        State(state),
        Extension(ctx),
        Path(parse_box_id(&args.box_id)?),
        Json(request),
    )
    .await?;
    Ok(tool_accepted(status, body))
}

async fn box_fork(
    state: AppState,
    ctx: TenantContext,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: ForkArgs = parse_args(arguments)?;
    require_lifetime(args.max_lifetime_seconds, args.idle_ttl_seconds, &state)?;
    let request = CreateSandboxRequest {
        name: args.name,
        template: None,
        memory_limit: args.size.as_deref().map(parse_size).transpose()?,
        network_egress: None,
        workspace_mode: Some(WorkspaceMode::Persistent),
        runtime_profile: None,
        execution_class: None,
        provider_preference: None,
        ttl_seconds: None,
        max_lifetime_seconds: args.max_lifetime_seconds,
        idle_ttl_seconds: args.idle_ttl_seconds,
        secret_ref_ids: Vec::new(),
    };
    let (status, Json(body)) = fork_sandbox(
        State(state),
        Extension(ctx),
        Path(parse_box_id(&args.box_id)?),
        Json(request),
    )
    .await?;
    Ok(tool_accepted(status, body))
}

async fn box_sleep(
    state: AppState,
    ctx: TenantContext,
    authorization: AuthorizationContext,
    trace: RequestTrace,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: BoxIdArgs = parse_args(arguments)?;
    let box_id = parse_box_id(&args.box_id)?;
    let snapshot = create_snapshot(
        State(state.clone()),
        Extension(ctx.clone()),
        Path(box_id),
        Json(CreateSnapshotRequest {
            label: Some("box_sleep".to_string()),
            inventory: None,
            provider_metadata: None,
            ttl_seconds: None,
        }),
    )
    .await;
    let snapshot_body = match snapshot {
        Ok((_status, Json(body))) => Some(body),
        Err(error) if error.code == "sandbox_stop_already_in_progress" => None,
        Err(error) => return Err(error),
    };
    let (status, Json(stopped)) = stop_sandbox(
        State(state),
        Extension(ctx),
        Extension(authorization),
        Extension(trace),
        Path(box_id),
    )
    .await?;
    Ok(tool_accepted(
        status,
        json!({
            "sandbox": stopped,
            "snapshot": snapshot_body
        }),
    ))
}

async fn box_wake(
    state: AppState,
    ctx: TenantContext,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: WakeArgs = parse_args(arguments)?;
    let request = ResumeSandboxRequest {
        snapshot_id: args
            .snapshot_id
            .as_deref()
            .map(parse_snapshot_id)
            .transpose()?,
    };
    let (status, Json(body)) = resume_sandbox(
        State(state),
        Extension(ctx),
        Path(parse_box_id(&args.box_id)?),
        Some(Json(request)),
    )
    .await?;
    Ok(tool_accepted(status, body))
}

async fn box_destroy(
    state: AppState,
    ctx: TenantContext,
    authorization: AuthorizationContext,
    trace: RequestTrace,
    arguments: Value,
) -> Result<Value, ApiError> {
    let args: DestroyArgs = parse_args(arguments)?;
    if args.confirm != Some(true) {
        return Err(ApiError::bad_request_code(
            "confirm_required",
            "box_destroy requires confirm=true",
        ));
    }
    let (status, Json(body)) = stop_sandbox(
        State(state),
        Extension(ctx),
        Extension(authorization),
        Extension(trace),
        Path(parse_box_id(&args.box_id)?),
    )
    .await?;
    Ok(tool_accepted(status, body))
}

#[derive(Debug, Deserialize)]
struct CreateArgs {
    name: Option<String>,
    size: Option<String>,
    max_lifetime_seconds: Option<u64>,
    idle_ttl_seconds: Option<u64>,
    template: Option<String>,
    secret_ref_ids: Option<Vec<String>>,
    execution_class: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListArgs {
    limit: Option<u32>,
    after: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BoxIdArgs {
    box_id: String,
}

#[derive(Debug, Deserialize)]
struct ExecArgs {
    box_id: String,
    argv: Vec<String>,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SnapshotArgs {
    box_id: String,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ForkArgs {
    box_id: String,
    name: Option<String>,
    size: Option<String>,
    max_lifetime_seconds: Option<u64>,
    idle_ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct WakeArgs {
    box_id: String,
    snapshot_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DestroyArgs {
    box_id: String,
    confirm: Option<bool>,
}

fn parse_args<T: for<'de> Deserialize<'de>>(arguments: Value) -> Result<T, ApiError> {
    serde_json::from_value(arguments).map_err(|error| {
        ApiError::bad_request_code(
            "invalid_arguments",
            format!("invalid tool arguments: {error}"),
        )
    })
}

fn require_name(name: &Option<String>) -> Result<String, ApiError> {
    let name = name.as_deref().unwrap_or("").trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    Ok(name.to_string())
}

fn require_lifetime(
    max_lifetime_seconds: Option<u64>,
    idle_ttl_seconds: Option<u64>,
    state: &AppState,
) -> Result<(), ApiError> {
    if max_lifetime_seconds.is_some() || idle_ttl_seconds.is_some() {
        return Ok(());
    }
    if state
        .sandbox_lifetime
        .default_max_lifetime_seconds
        .is_some()
        || state.sandbox_lifetime.default_idle_ttl_seconds.is_some()
    {
        return Ok(());
    }
    Err(ApiError::bad_request_code(
        "box_lifetime_required",
        "box_create requires max_lifetime_seconds or idle_ttl_seconds unless the operator set SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS or SANDBOXWICH_DEFAULT_IDLE_TTL_SECONDS",
    ))
}

fn parse_size(size: &str) -> Result<MemoryLimit, ApiError> {
    MemoryLimit::parse_db_str(size).map_err(|_| {
        ApiError::bad_request_code(
            "invalid_size",
            format!("size must be one of 1g, 4g, 16g, 64g (got {size})"),
        )
    })
}

fn parse_execution_class(value: Option<&str>) -> Result<Option<ExecutionClass>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    ExecutionClass::parse_db_str(value).map(Some).map_err(|_| {
        ApiError::bad_request(format!(
            "execution_class must be development_container, sandboxed_container, or virtual_machine (got {value})"
        ))
    })
}

fn parse_secret_refs(values: Option<Vec<String>>) -> Result<Vec<SecretRefId>, ApiError> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    values
        .into_iter()
        .map(|value| {
            Uuid::parse_str(&value)
                .map(SecretRefId)
                .map_err(|_| ApiError::bad_request(format!("invalid secret_ref_id: {value}")))
        })
        .collect()
}

fn parse_box_id(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::bad_request(format!("invalid box_id: {value}")))
}

fn parse_snapshot_id(value: &str) -> Result<SnapshotId, ApiError> {
    Uuid::parse_str(value)
        .map(SnapshotId)
        .map_err(|_| ApiError::bad_request(format!("invalid snapshot_id: {value}")))
}

fn tool_accepted<T: serde::Serialize>(status: StatusCode, body: T) -> Value {
    tool_text(json!({
        "http_status": status.as_u16(),
        "result": body
    }))
}

fn tool_text<T: serde::Serialize>(body: T) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string())
        }],
        "structuredContent": body
    })
}

fn tool_error(error: ApiError) -> Value {
    json!({
        "isError": true,
        "content": [{
            "type": "text",
            "text": serde_json::to_string(&json!({
                "ok": false,
                "code": error.code,
                "message": error.message,
                "details": error.details
            })).unwrap_or_else(|_| "{\"ok\":false,\"code\":\"internal\"}".to_string())
        }]
    })
}

fn json_rpc_result(id: Option<Value>, result: Value) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
    .into_response()
}

fn json_rpc_error(id: Option<Value>, code: i64, message: impl Into<String>) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    }))
    .into_response()
}
