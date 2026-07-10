use axum::Json;
use utoipa::{OpenApi, openapi::OpenApi as OpenApiDocument};

use sandboxwich_core::{CommandRequest, ErrorEnvelope, Operation, OperationResponse};

#[derive(OpenApi)]
#[openapi(
    info(title = "Sandboxwich API", version = "1.0.0"),
    paths(
        crate::handlers::sandboxes::create_sandbox,
        crate::handlers::commands::queue_command,
        crate::handlers::commands::queue_prompt,
        crate::handlers::operations::get_operation,
        crate::handlers::operations::cancel_operation
        ,crate::limits::get_tenant_limit_policy
        ,crate::limits::put_tenant_limit_policy
    ),
    components(schemas(CommandRequest, ErrorEnvelope, Operation, OperationResponse, crate::limits::TenantLimitPolicy, crate::limits::PutTenantLimitPolicy)),
    tags((name = "operations", description = "Asynchronous operation lifecycle"))
)]
pub(crate) struct ApiDoc;

pub(crate) async fn openapi() -> Json<OpenApiDocument> {
    Json(ApiDoc::openapi())
}
