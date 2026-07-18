use axum::Json;
use utoipa::{
    OpenApi,
    openapi::{
        OpenApi as OpenApiDocument,
        path::{HttpMethod, OperationBuilder, PathItem},
        response::{Response, ResponsesBuilder},
    },
};

use sandboxwich_core::{
    CommandRequest, DivergenceFinding, DivergenceFindingListResponse, DivergenceReconcileRequest,
    DivergenceReconcileResponse, ErrorEnvelope, Operation, OperationResponse, ReceiptScope,
    SandboxObservedState, SensorObservation, ToolCallLedgerEntryRequest,
};

#[derive(OpenApi)]
#[openapi(
    info(title = "Sandboxwich API", version = "1.0.0"),
    paths(
        crate::handlers::sandboxes::create_sandbox,
        crate::handlers::sandboxes::get_sandbox_observed_state,
        crate::handlers::commands::queue_command,
        crate::handlers::commands::get_command,
        crate::handlers::commands::list_command_output,
        crate::handlers::snapshots::create_snapshot,
        crate::handlers::snapshots::get_snapshot,
        crate::handlers::snapshots::fork_snapshot,
        crate::handlers::sandboxes::fork_sandbox,
        crate::handlers::commands::queue_prompt,
        crate::handlers::resident_processes::put_resident_process,
        crate::handlers::operations::get_operation,
        crate::handlers::operations::cancel_operation,
        crate::handlers::divergence::append_tool_call_ledger,
        crate::handlers::divergence::reconcile_divergence,
        crate::handlers::divergence::list_divergence_findings,
        crate::limits::get_tenant_limit_policy,
        crate::limits::put_tenant_limit_policy
    ),
    components(schemas(
        CommandRequest,
        sandboxwich_core::QueueCommandResponse,
        sandboxwich_core::CommandResponse,
        sandboxwich_core::CommandOutputListResponse,
        sandboxwich_core::CreateSnapshotRequest,
        sandboxwich_core::ForkSnapshotRequest,
        sandboxwich_core::SnapshotResponse,
        sandboxwich_core::SandboxResponse,
        ErrorEnvelope,
        Operation,
        OperationResponse,
        SandboxObservedState,
        ReceiptScope,
        ToolCallLedgerEntryRequest,
        SensorObservation,
        DivergenceFinding,
        DivergenceReconcileRequest,
        DivergenceReconcileResponse,
        DivergenceFindingListResponse,
        crate::limits::TenantLimitPolicy,
        crate::limits::PutTenantLimitPolicy,
        sandboxwich_core::ResidentProcess,
        sandboxwich_core::ResidentProcessRequest,
        sandboxwich_core::ResidentProcessResponse,
        sandboxwich_core::ResidentProcessBootstrapReadRequest,
        sandboxwich_core::ResidentProcessBootstrapReadResponse,
        sandboxwich_core::ResidentProcessObservationRequest
    )),
    tags((name = "operations", description = "Asynchronous operation lifecycle"))
)]
pub(crate) struct ApiDoc;

const PUBLIC_V1_OPERATIONS: &[(&str, &str)] = &[
    ("get", "/v1/metrics"),
    ("get", "/v1/sandboxes"),
    ("post", "/v1/sandboxes"),
    ("get", "/v1/sandboxes/{sandbox_id}"),
    ("get", "/v1/sandboxes/{sandbox_id}/observed-state"),
    ("get", "/v1/sandboxes/{sandbox_id}/files"),
    ("post", "/v1/sandboxes/{sandbox_id}/files"),
    ("get", "/v1/sandboxes/{sandbox_id}/files/{file_id}"),
    ("get", "/v1/sandboxes/{sandbox_id}/runtime-resources"),
    ("post", "/v1/sandboxes/{sandbox_id}/stop"),
    (
        "get",
        "/v1/sandboxes/{sandbox_id}/resident-processes/{name}",
    ),
    (
        "put",
        "/v1/sandboxes/{sandbox_id}/resident-processes/{name}",
    ),
    (
        "post",
        "/v1/sandboxes/{sandbox_id}/resident-processes/{name}/stop",
    ),
    (
        "get",
        "/v1/sandboxes/{sandbox_id}/resident-processes/{name}/events",
    ),
    ("post", "/v1/sandboxes/{sandbox_id}/resume"),
    ("post", "/v1/sandboxes/{sandbox_id}/fork"),
    ("get", "/v1/sandboxes/{sandbox_id}/snapshots"),
    ("post", "/v1/sandboxes/{sandbox_id}/snapshots"),
    ("get", "/v1/sandboxes/{sandbox_id}/desktop"),
    ("get", "/v1/sandboxes/{sandbox_id}/desktop-sessions"),
    ("post", "/v1/sandboxes/{sandbox_id}/desktop-sessions"),
    ("get", "/v1/sandboxes/{sandbox_id}/commands"),
    ("post", "/v1/sandboxes/{sandbox_id}/commands"),
    ("post", "/v1/sandboxes/{sandbox_id}/prompt"),
    ("get", "/v1/sandboxes/{sandbox_id}/events"),
    ("get", "/v1/desktop-sessions/{desktop_session_id}"),
    ("post", "/v1/desktop-sessions/{desktop_session_id}/status"),
    ("post", "/v1/desktop-sessions/{desktop_session_id}/access"),
    ("post", "/v1/snapshots/cleanup"),
    ("get", "/v1/snapshots/{snapshot_id}"),
    ("post", "/v1/snapshots/{snapshot_id}/fork"),
    ("get", "/v1/commands/{command_id}"),
    ("get", "/v1/commands/{command_id}/output"),
    ("get", "/v1/workers"),
    ("post", "/v1/workers/register"),
    ("get", "/v1/capacity"),
    ("get", "/v1/jobs"),
    ("post", "/v1/jobs"),
    ("get", "/v1/jobs/{job_id}"),
    ("post", "/v1/divergence/reconcile"),
    ("post", "/v1/sandboxes/{sandbox_id}/tool-call-ledger"),
    ("get", "/v1/sandboxes/{sandbox_id}/divergence-findings"),
    ("get", "/v1/operations/{operation_id}"),
    ("get", "/v1/operations/{operation_id}/events"),
    ("post", "/v1/operations/{operation_id}/cancel"),
    ("get", "/v1/sandboxes/{sandbox_id}/guest-health"),
    ("post", "/v1/sandboxes/{sandbox_id}/guest-health"),
    ("get", "/v1/sandboxes/{sandbox_id}/ssh-keys"),
    ("post", "/v1/sandboxes/{sandbox_id}/ssh-keys"),
    ("post", "/v1/sandboxes/{sandbox_id}/ssh-access"),
    ("post", "/v1/ssh-keys/{ssh_key_id}/status"),
    ("post", "/v1/workers/{worker_id}/heartbeat"),
    ("post", "/v1/workers/{worker_id}/drain"),
    (
        "post",
        "/v1/workers/{worker_id}/sandboxes/{sandbox_id}/guest-token",
    ),
    (
        "post",
        "/v1/workers/{worker_id}/runtime-resources/reconcile",
    ),
    ("post", "/v1/workers/{worker_id}/leases/claim"),
    ("post", "/v1/resident-processes/{process_id}/bootstrap"),
    ("post", "/v1/resident-processes/{process_id}/observations"),
    ("post", "/v1/leases/{lease_id}/renew"),
    ("get", "/v1/leases/{lease_id}/materialization"),
    ("post", "/v1/leases/{lease_id}/output"),
    ("post", "/v1/leases/{lease_id}/complete"),
    ("post", "/v1/leases/{lease_id}/fail"),
    ("get", "/v1/operator/tenant-policies/{tenant_id}"),
    ("put", "/v1/operator/tenant-policies/{tenant_id}"),
];

pub(crate) fn openapi_document() -> OpenApiDocument {
    let mut document = ApiDoc::openapi();
    for (method, path) in PUBLIC_V1_OPERATIONS {
        let http_method = match *method {
            "get" => HttpMethod::Get,
            "post" => HttpMethod::Post,
            "put" => HttpMethod::Put,
            _ => unreachable!("operation catalog contains an unsupported method"),
        };
        let operation = OperationBuilder::new()
            .operation_id(Some(format!(
                "{}_{}",
                method,
                path.trim_start_matches("/v1/")
                    .replace(['/', '{', '}', '-'], "_")
            )))
            .responses(
                ResponsesBuilder::new().response("200", Response::new("Successful response")),
            )
            .build();
        let addition = PathItem::new(http_method, operation);
        match document.paths.paths.get_mut(*path) {
            Some(existing) => existing.merge_operations(addition),
            None => {
                document.paths.paths.insert((*path).to_string(), addition);
            }
        }
    }
    document
}

pub(crate) async fn openapi() -> Json<OpenApiDocument> {
    Json(openapi_document())
}

#[cfg(test)]
mod tests {
    #[test]
    fn completed_openapi_document_serializes() {
        serde_json::to_value(super::openapi_document()).unwrap();
    }

    #[test]
    fn resident_put_documents_typed_body_and_sidecar_bootstrap_requirement() {
        let document = serde_json::to_value(super::openapi_document()).unwrap();
        let operation =
            &document["paths"]["/v1/sandboxes/{sandbox_id}/resident-processes/{name}"]["put"];
        assert!(operation["requestBody"]["content"]["application/json"]["schema"].is_object());
        assert!(operation["responses"]["200"].is_object());
        assert_eq!(
            operation["responses"]["400"]["description"],
            "Invalid request, including a missing or empty orb-sidecar bootstrap"
        );
        assert!(operation["responses"]["503"].is_object());
    }
}
