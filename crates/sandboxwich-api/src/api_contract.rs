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
        crate::handlers::secrets::create_secret_ref,
        crate::handlers::secrets::list_secret_refs,
        crate::handlers::secrets::get_secret_ref,
        crate::handlers::secrets::revoke_secret_ref,
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
        crate::handlers::apex_instructions::read_apex_task_instructions,
        crate::handlers::resident_attestations::get_maestro_connection_binding,
        crate::handlers::resident_attestations::redeem_resident_placement_attestation,
        crate::handlers::resident_attestations::validate_resident_placement_attestation,
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
        ,sandboxwich_core::ResidentPlacementAttestationBootstrap
        ,sandboxwich_core::RedeemResidentPlacementAttestationRequest
        ,sandboxwich_core::ValidateResidentPlacementAttestationRequest
        ,sandboxwich_core::ResidentPlacementClaims
        ,sandboxwich_core::ResidentPlacementAttestationResponse
        ,sandboxwich_core::ValidateMaestroWorkloadIdentityRequest
        ,sandboxwich_core::MaestroWorkloadIdentityResponse
        ,sandboxwich_core::MaestroHostedRunnerConnectionBindingResponse
        ,sandboxwich_core::SecretSource
        ,sandboxwich_core::SecretRef
        ,sandboxwich_core::CreateSecretRefRequest
        ,sandboxwich_core::SecretRefResponse
        ,sandboxwich_core::SecretRefListResponse
        ,sandboxwich_core::SandboxSecretMount
        ,sandboxwich_core::CreateSandboxRequest
        ,sandboxwich_core::ApexTaskInstructionsReadRequest
        ,sandboxwich_core::ApexTaskInstructionsReadResponse
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
        "get",
        "/v1/sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/connection-binding",
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
    ("get", "/v1/secret-refs"),
    ("post", "/v1/secret-refs"),
    ("get", "/v1/secret-refs/{secret_ref_id}"),
    ("delete", "/v1/secret-refs/{secret_ref_id}"),
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
    ("post", "/v1/sandboxes/{sandbox_id}/apex-task-instructions"),
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
    ("post", "/v1/resident-placement-attestations/redeem"),
    ("post", "/v1/resident-placement-attestations/validate"),
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
            "delete" => HttpMethod::Delete,
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
    use std::path::PathBuf;

    /// Path of the committed OpenAPI export, relative to the repository root.
    const OPENAPI_EXPORT_PATH: &str = "contracts/openapi.v1.json";

    /// Environment variable that turns the staleness test into a writer.
    const OPENAPI_EXPORT_UPDATE_ENV: &str = "SANDBOXWICH_UPDATE_OPENAPI_EXPORT";

    /// Renders the OpenAPI document exactly as it is committed to
    /// `contracts/openapi.v1.json`.
    ///
    /// The document is round-tripped through [`serde_json::Value`] before being
    /// pretty-printed. This workspace does not enable serde_json's
    /// `preserve_order` feature, so `Value` object keys are a `BTreeMap` and the
    /// rendering is byte-stable across compilations. Without that round-trip the
    /// export would inherit utoipa's insertion ordering and could produce
    /// spurious staleness failures.
    fn render_openapi_export() -> Result<String, serde_json::Error> {
        let value = serde_json::to_value(super::openapi_document())?;
        let mut rendered = serde_json::to_string_pretty(&value)?;
        rendered.push('\n');
        Ok(rendered)
    }

    fn export_path() -> PathBuf {
        // CARGO_MANIFEST_DIR is crates/sandboxwich-api.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(OPENAPI_EXPORT_PATH)
    }

    #[test]
    fn completed_openapi_document_serializes() {
        serde_json::to_value(super::openapi_document()).unwrap();
    }

    /// Downstream services hand-mirror this API's request and response types.
    /// evalops/platform's runner-host keeps serde mirrors in
    /// `rust/services/runner-host/src/sandboxwich.rs` and pins this exported
    /// document so those mirrors can be validated against the real contract.
    /// The export is a published artifact: it must never drift from the code
    /// that serves `/v1/openapi.json`.
    #[test]
    fn committed_openapi_export_is_current() {
        let rendered = render_openapi_export().expect("render OpenAPI export");
        let path = export_path();

        if std::env::var_os(OPENAPI_EXPORT_UPDATE_ENV).is_some() {
            std::fs::write(&path, &rendered).expect("write OpenAPI export");
            return;
        }

        let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read {}: {error}\nRefresh it with:\n    {}=1 cargo test \
                 -p sandboxwich-api --lib \
                 api_contract::tests::committed_openapi_export_is_current",
                OPENAPI_EXPORT_PATH, OPENAPI_EXPORT_UPDATE_ENV,
            )
        });

        assert!(
            committed == rendered,
            "{} is stale: it no longer matches the document served at \
             /v1/openapi.json.\nRefresh it with:\n    {}=1 cargo test \
             -p sandboxwich-api --lib \
             api_contract::tests::committed_openapi_export_is_current\nand \
             commit the result. Downstream mirrors (evalops/platform \
             runner-host) validate their hand-written serde structs against \
             this file.",
            OPENAPI_EXPORT_PATH,
            OPENAPI_EXPORT_UPDATE_ENV,
        );
    }

    /// `MemoryLimit` implements `Serialize`/`Deserialize` by hand, so the
    /// derived `ToSchema` cannot see the real wire values and has to be told
    /// them with `#[schema(rename = ...)]`. Until 2026-08-03 it was not, and
    /// the exported document advertised `OneG`/`FourG`/`SixteenG`/`SixtyFourG`
    /// for a field that only accepts `1g`/`4g`/`16g`/`64g`. A wrong schema is
    /// worse than no schema: downstream mirror gates validate against it.
    #[test]
    fn memory_limit_schema_matches_serialized_values() {
        use sandboxwich_core::{DbVariant, MemoryLimit};

        let document = serde_json::to_value(super::openapi_document()).unwrap();
        let documented = document["components"]["schemas"]["MemoryLimit"]["enum"]
            .as_array()
            .expect("MemoryLimit must be documented as an enum")
            .iter()
            .map(|value| value.as_str().expect("enum values are strings").to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            documented,
            MemoryLimit::VALUES,
            "the documented MemoryLimit values differ from the values MemoryLimit \
             serializes to; add or correct #[schema(rename = ...)] on its variants"
        );

        for value in MemoryLimit::VALUES {
            let round_tripped: MemoryLimit = serde_json::from_value(serde_json::json!(value))
                .unwrap_or_else(|error| panic!("MemoryLimit rejects documented {value}: {error}"));
            assert_eq!(
                serde_json::to_value(&round_tripped).unwrap(),
                serde_json::json!(value)
            );
        }
    }

    /// The export only protects downstream mirrors for the routes it actually
    /// documents. These are the routes evalops/platform's runner-host calls;
    /// dropping any of them from the document silently removes the schema a
    /// downstream mirror gate validates against, which turns that gate green
    /// while it verifies nothing.
    #[test]
    fn export_documents_every_runner_host_route() {
        let document = serde_json::to_value(super::openapi_document()).unwrap();
        for (path, method) in [
            ("/v1/sandboxes", "post"),
            ("/v1/sandboxes/{sandbox_id}/apex-task-instructions", "post"),
            ("/v1/sandboxes/{sandbox_id}/commands", "post"),
            ("/v1/commands/{command_id}", "get"),
            ("/v1/sandboxes/{sandbox_id}/snapshots", "post"),
            (
                "/v1/sandboxes/{sandbox_id}/resident-processes/{name}",
                "put",
            ),
            (
                "/v1/sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/connection-binding",
                "get",
            ),
            ("/v1/operations/{operation_id}", "get"),
        ] {
            let operation = &document["paths"][path][method];
            assert!(
                operation.is_object(),
                "runner-host calls {method} {path}, but the OpenAPI export does not document it"
            );
        }

        // A request body schema is the only thing that pins field casing for a
        // downstream request mirror. The 2026-08-03 hosted-Maestro outage was a
        // request mirror that serialized `restart_policy` where this schema
        // says `restartPolicy`.
        let resident_put =
            &document["paths"]["/v1/sandboxes/{sandbox_id}/resident-processes/{name}"]["put"];
        assert!(
            resident_put["requestBody"]["content"]["application/json"]["schema"].is_object(),
            "the resident-process PUT must document a request body schema"
        );
        let resident_request =
            &document["components"]["schemas"]["ResidentProcessRequest"]["properties"];
        assert!(
            resident_request["restartPolicy"].is_object(),
            "ResidentProcessRequest must expose restartPolicy in camelCase: {resident_request}"
        );
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
