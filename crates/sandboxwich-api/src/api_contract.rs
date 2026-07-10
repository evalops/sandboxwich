use axum::Json;
use utoipa::{OpenApi, openapi::OpenApi as OpenApiDocument};

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
        crate::limits::PutTenantLimitPolicy
    )),
    tags((name = "operations", description = "Asynchronous operation lifecycle"))
)]
pub(crate) struct ApiDoc;

pub(crate) async fn openapi() -> Json<OpenApiDocument> {
    Json(ApiDoc::openapi())
}
