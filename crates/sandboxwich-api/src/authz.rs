//! Request-scoped authorization receipts.
//!
//! Authentication and the route/resource checks live in [`crate::auth`] and
//! its handlers. This module does not replace those checks. It gives every
//! successfully authenticated request a safe, stable receipt that can be
//! joined across HTTP logs, traces, and caller reports without logging bearer
//! credentials or raw resource identifiers.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use uuid::Uuid;

use crate::request_id::{REQUEST_ID_HEADER, RequestTrace};
use crate::state::Principal;

pub(crate) const AUTHORIZATION_POLICY_ID: &str = "sandboxwich-api-authz";
pub(crate) const AUTHORIZATION_POLICY_VERSION: &str = "v2";
pub(crate) static AUTHORIZATION_DECISION_ID_HEADER: HeaderName =
    HeaderName::from_static("x-authorization-decision-id");

pub(crate) const AUTHORIZATION_RECEIPT_SCHEMA: &str = "authz_receipt_v2";

pub(crate) static AUTHORIZATION_RECEIPT_ID_HEADER: HeaderName =
    HeaderName::from_static("x-authorization-receipt-id");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrincipalRequirement {
    TenantOrOperator,
    Operator,
    Worker,
    WorkerOrGuest,
    Deny,
    NotExposed,
}

impl PrincipalRequirement {
    fn allows(self, principal: Principal) -> bool {
        matches!(
            (self, principal),
            (
                Self::TenantOrOperator,
                Principal::Tenant | Principal::Operator
            ) | (Self::Operator, Principal::Operator)
                | (Self::Worker, Principal::Worker(_))
                | (
                    Self::WorkerOrGuest,
                    Principal::Worker(_) | Principal::Guest { .. }
                )
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RoutePolicy {
    pub(crate) resource_kind: &'static str,
    pub(crate) action: &'static str,
    pub(crate) requirement: PrincipalRequirement,
}

const AUTHORIZATION_POLICY_RULES: &[&str] = &[
    "operator|operator|/operator/*",
    "operator|cleanup|/snapshots/cleanup",
    "worker|heartbeat|/workers/*/heartbeat",
    "worker|drain|/workers/*/drain",
    "worker|read|/workers/*/runtime-resource-inventory",
    "worker|reconcile|/workers/*/runtime-resources/reconcile",
    "worker|create|/workers/*/sandboxes/*/guest-token",
    "worker|callback|/workers/*/apex-instruction-callbacks/*",
    "worker_or_guest|claim|/workers/*/leases/claim",
    "worker_or_guest|write|/resident-processes/*",
    "worker_or_guest|write|/leases/*",
    "worker_or_guest|write|/sandboxes/*/guest-health",
    "worker_or_guest|refresh|/sandboxes/*/guest-token/refresh",
    "deny|unknown_worker|/workers/*",
    "deny|unclassified_route|*",
    "not_exposed|identity_only|/maestro-workload-identities/validate",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizationContext {
    pub(crate) request_id: String,
    pub(crate) decision_id: String,
    pub(crate) authorization_lineage_id: String,
    pub(crate) authorization_fingerprint: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) policy_id: &'static str,
    pub(crate) policy_version: &'static str,
    pub(crate) principal_class: &'static str,
    pub(crate) receipt_id: String,
    pub(crate) policy_digest: String,
    pub(crate) resource_kind: &'static str,
    pub(crate) action: &'static str,
    pub(crate) decision_reason: &'static str,
    pub(crate) requirement: PrincipalRequirement,
}

impl AuthorizationContext {
    pub(crate) fn from_request(request: &Request, tenant_id: &str, principal: Principal) -> Self {
        let request_trace = request.extensions().get::<RequestTrace>();
        let request_id = request_trace
            .map(|trace| trace.request_id.as_str())
            .filter(|request_id| valid_request_id(request_id))
            .or_else(|| {
                request
                    .headers()
                    .get(&REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .filter(|request_id| valid_request_id(request_id))
            })
            .map(str::to_owned)
            .unwrap_or_else(|| format!("sandboxwich-authz-{}", Uuid::now_v7()));
        let trace_id = request_trace
            .and_then(|trace| (!trace.trace_id.is_empty()).then(|| trace.trace_id.clone()));

        let lineage_id = request
            .headers()
            .get(&AUTHORIZATION_LINEAGE_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| valid_request_id(value))
            .unwrap_or(&request_id);

        Self::new_with_lineage(
            lineage_id,
            &request_id,
            trace_id.as_deref(),
            request.method().as_str(),
            request.uri().path(),
            tenant_id,
            principal,
        )
    }

    #[cfg(test)]
    fn new(
        request_id: &str,
        trace_id: Option<&str>,
        method: &str,
        path: &str,
        tenant_id: &str,
        principal: Principal,
    ) -> Self {
        Self::new_with_lineage(
            request_id, request_id, trace_id, method, path, tenant_id, principal,
        )
    }

    fn new_with_lineage(
        lineage_id: &str,
        request_id: &str,
        trace_id: Option<&str>,
        method: &str,
        path: &str,
        tenant_id: &str,
        principal: Principal,
    ) -> Self {
        let policy = route_policy(method, path);
        let policy_digest = authorization_policy_digest();
        let decision_reason = if matches!(
            policy.requirement,
            PrincipalRequirement::Deny | PrincipalRequirement::NotExposed
        ) {
            if policy.requirement == PrincipalRequirement::NotExposed {
                "route_not_exposed"
            } else {
                "unknown_route"
            }
        } else if policy.requirement.allows(principal) {
            "allowed"
        } else {
            "principal_class_not_allowed"
        };
        let decision_id = decision_id(
            request_id,
            method,
            path,
            tenant_id,
            principal,
            &policy,
            &policy_digest,
        );
        let authorization_fingerprint =
            authorization_fingerprint(method, path, tenant_id, principal, &policy, &policy_digest);
        Self {
            request_id: request_id.to_owned(),
            decision_id: decision_id.clone(),
            authorization_lineage_id: lineage_id.to_owned(),
            authorization_fingerprint,
            trace_id: trace_id.map(str::to_owned),
            policy_id: AUTHORIZATION_POLICY_ID,
            policy_version: AUTHORIZATION_POLICY_VERSION,
            principal_class: principal_class(principal),
            receipt_id: receipt_id(&decision_id, &policy_digest),
            policy_digest,
            resource_kind: policy.resource_kind,
            action: policy.action,
            decision_reason,
            requirement: policy.requirement,
        }
    }

    pub(crate) fn decision_header(&self) -> HeaderValue {
        HeaderValue::from_str(&self.decision_id)
            .expect("authorization decision id is a valid header value")
    }

    pub(crate) fn lineage_header(&self) -> HeaderValue {
        HeaderValue::from_str(&self.authorization_lineage_id)
            .expect("authorization lineage id is a valid header value")
    }

    pub(crate) fn receipt_header(&self) -> HeaderValue {
        HeaderValue::from_str(&self.receipt_id)
            .expect("authorization receipt id is a valid header value")
    }

    pub(crate) fn principal_allowed(&self, principal: Principal) -> bool {
        self.requirement.allows(principal)
    }

    pub(crate) fn add_to_payload(&self, payload: &mut serde_json::Value) {
        let serde_json::Value::Object(fields) = payload else {
            return;
        };
        fields.insert(
            "_authorization".to_string(),
            serde_json::json!({
                "schema": AUTHORIZATION_RECEIPT_SCHEMA,
                "requestId": self.request_id,
                "decisionId": self.decision_id,
                "receiptId": self.receipt_id,
                "lineageId": self.authorization_lineage_id,
                "fingerprint": self.authorization_fingerprint,
                "policyId": self.policy_id,
                "policyVersion": self.policy_version,
                "policyDigest": self.policy_digest,
                "resourceKind": self.resource_kind,
                "action": self.action,
                "principalClass": self.principal_class,
                "decision": "allow",
                "reason": self.decision_reason,
            }),
        );
    }
}

fn valid_request_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn principal_class(principal: Principal) -> &'static str {
    match principal {
        Principal::Tenant => "tenant",
        Principal::Operator => "operator",
        Principal::Worker(_) => "worker",
        Principal::Guest { .. } => "guest",
    }
}

fn principal_binding(principal: Principal) -> String {
    match principal {
        Principal::Tenant => "tenant".to_owned(),
        Principal::Operator => "operator".to_owned(),
        Principal::Worker(worker_id) => format!("worker:{worker_id}"),
        Principal::Guest {
            worker_id,
            sandbox_id,
        } => format!("guest:{worker_id}:{sandbox_id}"),
    }
}

fn update_field(hasher: &mut Sha256, name: &str, value: &str) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn normalized_path(path: &str) -> &str {
    let path = path.strip_prefix("/v1").unwrap_or(path);
    if path.is_empty() { "/" } else { path }
}

fn known_route(path: &str) -> bool {
    AUTHORIZATION_ROUTE_MANIFEST
        .iter()
        .any(|template| path_matches_template(path, template))
}
fn known_non_tenant_route(path: &str) -> bool {
    AUTHORIZATION_NON_TENANT_ROUTE_MANIFEST
        .iter()
        .any(|template| path_matches_template(path, template))
}

fn path_matches_template(path: &str, template: &str) -> bool {
    let path_parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    let template_parts = template.trim_matches('/').split('/').collect::<Vec<_>>();
    path_parts.len() == template_parts.len()
        && path_parts
            .iter()
            .zip(template_parts)
            .all(|(part, expected)| expected == "*" || part == &expected)
}

pub(crate) fn route_policy(method: &str, path: &str) -> RoutePolicy {
    let path = normalized_path(path);
    let requirement = if known_non_tenant_route(path) {
        PrincipalRequirement::NotExposed
    } else if path == "/workers/register" && known_route(path) {
        PrincipalRequirement::TenantOrOperator
    } else if (path == "/snapshots/cleanup"
        || path == "/operator"
        || path.starts_with("/operator/"))
        && known_route(path)
    {
        PrincipalRequirement::Operator
    } else if worker_route(path) && known_route(path) {
        PrincipalRequirement::Worker
    } else if worker_or_guest_route(method, path) && known_route(path) {
        PrincipalRequirement::WorkerOrGuest
    } else if path.starts_with("/workers/") || !known_route(path) {
        PrincipalRequirement::Deny
    } else {
        PrincipalRequirement::TenantOrOperator
    };

    RoutePolicy {
        resource_kind: resource_kind(path),
        action: action(method, path),
        requirement,
    }
}

fn worker_route(path: &str) -> bool {
    path.starts_with("/workers/")
        && (path.ends_with("/heartbeat")
            || path.ends_with("/drain")
            || path.ends_with("/runtime-resource-inventory")
            || path.ends_with("/runtime-resources/reconcile")
            || path.ends_with("/guest-token")
            || path.contains("/apex-instruction-callbacks/"))
}

fn worker_or_guest_route(method: &str, path: &str) -> bool {
    (path.starts_with("/workers/") && path.contains("/leases/claim"))
        || path.starts_with("/resident-processes/")
        || path.starts_with("/leases/")
        || (method == "POST"
            && (path.ends_with("/guest-health") || path.ends_with("/guest-token/refresh")))
}

fn resource_kind(path: &str) -> &'static str {
    if path == "/operator" || path.starts_with("/operator/") {
        "operator"
    } else if path.contains("/sandboxes") {
        "sandbox"
    } else if path.starts_with("/workers") {
        "worker"
    } else if path.starts_with("/resident-processes") {
        "resident_process"
    } else if path.starts_with("/leases") {
        "lease"
    } else if path.starts_with("/snapshots") {
        "snapshot"
    } else if path.starts_with("/homes") {
        "home"
    } else if path.starts_with("/jobs") {
        "job"
    } else if path.starts_with("/operations") {
        "operation"
    } else if path.starts_with("/desktop") {
        "desktop"
    } else {
        "platform"
    }
}

fn action(method: &str, path: &str) -> &'static str {
    if path == "/snapshots/cleanup" {
        "cleanup"
    } else if path.starts_with("/operator") {
        "operator"
    } else if path.ends_with("/stop") {
        "stop"
    } else if path.ends_with("/resume") {
        "resume"
    } else if path.ends_with("/fork") {
        "fork"
    } else if path.ends_with("/heartbeat") {
        "heartbeat"
    } else if path.ends_with("/drain") {
        "drain"
    } else if path.ends_with("/claim") {
        "claim"
    } else if path.ends_with("/refresh") {
        "refresh"
    } else if path.ends_with("/renew") {
        "renew"
    } else if path.ends_with("/complete") {
        "complete"
    } else if path.ends_with("/fail") {
        "fail"
    } else if path.ends_with("/reconcile") {
        "reconcile"
    } else if path.ends_with("/guest-health") {
        "health"
    } else if path.contains("/apex-instruction-callbacks/") {
        "callback"
    } else if path.ends_with("/guest-token") {
        "create_token"
    } else if path.ends_with("/bootstrap") {
        "bootstrap"
    } else if path.ends_with("/observations") {
        "observe"
    } else if path.ends_with("/materialization") {
        "read_materialization"
    } else if path.ends_with("/provisioning") {
        "update_provisioning"
    } else if path.ends_with("/output") {
        "append_output"
    } else {
        match method {
            "GET" | "HEAD" => "read",
            "POST" => "create",
            "PUT" | "PATCH" => "update",
            "DELETE" => "delete",
            _ => "unknown",
        }
    }
}

fn requirement_code(requirement: PrincipalRequirement) -> &'static str {
    match requirement {
        PrincipalRequirement::TenantOrOperator => "tenant_or_operator",
        PrincipalRequirement::Operator => "operator",
        PrincipalRequirement::Worker => "worker",
        PrincipalRequirement::WorkerOrGuest => "worker_or_guest",
        PrincipalRequirement::Deny => "deny",
        PrincipalRequirement::NotExposed => "not_exposed",
    }
}

fn authorization_policy_digest() -> String {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, "policy_id", AUTHORIZATION_POLICY_ID);
    update_field(&mut hasher, "policy_version", AUTHORIZATION_POLICY_VERSION);
    for rule in AUTHORIZATION_POLICY_RULES {
        update_field(&mut hasher, "rule", rule);
    }
    let digest = hasher.finalize();
    format!("authz_policy_v1_{}", hex_digest(&digest))
}

fn decision_id(
    request_id: &str,
    method: &str,
    path: &str,
    tenant_id: &str,
    principal: Principal,
    policy: &RoutePolicy,
    policy_digest: &str,
) -> String {
    digest_id(
        "authz_decision_v1_",
        DigestMaterial {
            request_id: Some(request_id),
            method,
            path,
            tenant_id,
            principal,
            policy,
            policy_digest,
        },
    )
}

fn authorization_fingerprint(
    method: &str,
    path: &str,
    tenant_id: &str,
    principal: Principal,
    policy: &RoutePolicy,
    policy_digest: &str,
) -> String {
    digest_id(
        "authz_fingerprint_v1_",
        DigestMaterial {
            request_id: None,
            method,
            path,
            tenant_id,
            principal,
            policy,
            policy_digest,
        },
    )
}

fn receipt_id(decision_id: &str, policy_digest: &str) -> String {
    let mut hasher = Sha256::new();
    update_field(&mut hasher, "policy_digest", policy_digest);
    update_field(&mut hasher, "decision_id", decision_id);
    let digest = hasher.finalize();
    format!("authz_receipt_v2_{}", hex_digest(&digest))
}

struct DigestMaterial<'a> {
    request_id: Option<&'a str>,
    method: &'a str,
    path: &'a str,
    tenant_id: &'a str,
    principal: Principal,
    policy: &'a RoutePolicy,
    policy_digest: &'a str,
}

fn digest_id(prefix: &str, material: DigestMaterial<'_>) -> String {
    let DigestMaterial {
        request_id,
        method,
        path,
        tenant_id,
        principal,
        policy,
        policy_digest,
    } = material;
    let principal_class = principal_class(principal);
    let principal_binding = principal_binding(principal);
    let mut hasher = Sha256::new();
    update_field(&mut hasher, "policy_id", AUTHORIZATION_POLICY_ID);
    update_field(&mut hasher, "policy_version", AUTHORIZATION_POLICY_VERSION);
    update_field(&mut hasher, "policy_digest", policy_digest);
    update_field(&mut hasher, "resource_kind", policy.resource_kind);
    update_field(&mut hasher, "action", policy.action);
    update_field(
        &mut hasher,
        "requirement",
        requirement_code(policy.requirement),
    );
    if let Some(request_id) = request_id {
        update_field(&mut hasher, "request_id", request_id);
    }
    update_field(&mut hasher, "method", method);
    update_field(&mut hasher, "path", path);
    update_field(&mut hasher, "tenant_id", tenant_id);
    update_field(&mut hasher, "principal_class", principal_class);
    update_field(&mut hasher, "principal_binding", &principal_binding);

    let digest = hasher.finalize();
    format!("{prefix}{}", hex_digest(&digest))
}

fn hex_digest(digest: &[u8]) -> String {
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandboxwich_core::{SandboxId, WorkerId};

    #[test]
    fn decision_id_is_stable_and_bound_to_request_material() {
        let worker_id = WorkerId(Uuid::from_u128(1));
        let sandbox_id = SandboxId(Uuid::from_u128(2));
        let principal = Principal::Guest {
            worker_id,
            sandbox_id,
        };
        let first = AuthorizationContext::new(
            "request-1",
            Some("4bf92f3577b34da6a3ce929d0e0e4736"),
            "POST",
            "/v1/sandboxes/sandbox-1/stop",
            "tenant-private",
            principal,
        );
        let repeat = AuthorizationContext::new(
            "request-1",
            Some("4bf92f3577b34da6a3ce929d0e0e4736"),
            "POST",
            "/v1/sandboxes/sandbox-1/stop",
            "tenant-private",
            principal,
        );
        let changed_request = AuthorizationContext::new(
            "request-2",
            Some("4bf92f3577b34da6a3ce929d0e0e4736"),
            "POST",
            "/v1/sandboxes/sandbox-1/stop",
            "tenant-private",
            principal,
        );
        let changed_trace = AuthorizationContext::new(
            "request-1",
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "POST",
            "/v1/sandboxes/sandbox-1/stop",
            "tenant-private",
            principal,
        );

        assert_eq!(first, repeat);
        assert_ne!(first.decision_id, changed_request.decision_id);
        assert_eq!(first.decision_id, changed_trace.decision_id);
        assert_eq!(
            first.authorization_fingerprint,
            changed_request.authorization_fingerprint
        );
        assert_eq!(
            first.authorization_fingerprint,
            changed_trace.authorization_fingerprint
        );
        assert!(first.decision_id.starts_with("authz_decision_v1_"));
        assert_eq!(first.decision_id.len(), "authz_decision_v1_".len() + 64);
        assert!(
            first
                .authorization_fingerprint
                .starts_with("authz_fingerprint_v1_")
        );
        assert_eq!(
            first.authorization_fingerprint.len(),
            "authz_fingerprint_v1_".len() + 64
        );
        assert!(!first.decision_id.contains("tenant-private"));
        assert_eq!(first.principal_class, "guest");
        assert_eq!(first.policy_id, AUTHORIZATION_POLICY_ID);
        assert_eq!(first.policy_version, AUTHORIZATION_POLICY_VERSION);
    }

    #[test]
    fn principal_bindings_get_distinct_receipts_without_exposing_ids() {
        let worker = WorkerId(Uuid::from_u128(11));
        let sandbox = SandboxId(Uuid::from_u128(12));
        let tenant = AuthorizationContext::new(
            "request-1",
            None,
            "GET",
            "/v1/healthz",
            "tenant-private",
            Principal::Tenant,
        );
        let operator = AuthorizationContext::new(
            "request-1",
            None,
            "GET",
            "/v1/healthz",
            "tenant-private",
            Principal::Operator,
        );
        let worker_context = AuthorizationContext::new(
            "request-1",
            None,
            "GET",
            "/v1/healthz",
            "tenant-private",
            Principal::Worker(worker),
        );
        let guest = AuthorizationContext::new(
            "request-1",
            None,
            "GET",
            "/v1/healthz",
            "tenant-private",
            Principal::Guest {
                worker_id: worker,
                sandbox_id: sandbox,
            },
        );

        assert_ne!(tenant.decision_id, operator.decision_id);
        assert_ne!(operator.decision_id, worker_context.decision_id);
        assert_ne!(worker_context.decision_id, guest.decision_id);
        assert!(!guest.decision_id.contains(&worker.to_string()));
        assert!(!guest.decision_id.contains(&sandbox.to_string()));
    }

    #[test]
    fn invalid_request_ids_are_rejected() {
        assert!(!valid_request_id(""));
        assert!(!valid_request_id(" \t"));
        assert!(!valid_request_id("request\nwith-control"));
        assert!(!valid_request_id(&"x".repeat(257)));
        assert!(valid_request_id("request-1"));
    }
    #[test]
    fn route_policy_matrix_fails_closed_for_unknown_worker_paths() {
        let heartbeat = route_policy("POST", "/v1/workers/worker-1/heartbeat");
        let claim = route_policy("POST", "/v1/workers/worker-1/leases/claim");
        let registration = route_policy("POST", "/v1/workers/register");
        let operator = route_policy("GET", "/v1/operator/tenant-policies/default");
        let unknown_worker = route_policy("POST", "/v1/workers/worker-1/unknown");
        let unknown_route = route_policy("GET", "/v1/not-a-real-route");
        let identity_only = route_policy("POST", "/v1/maestro-workload-identities/validate");

        assert_eq!(heartbeat.requirement, PrincipalRequirement::Worker);
        assert_eq!(claim.requirement, PrincipalRequirement::WorkerOrGuest);
        assert_eq!(
            registration.requirement,
            PrincipalRequirement::TenantOrOperator
        );
        assert_eq!(operator.requirement, PrincipalRequirement::Operator);
        assert_eq!(unknown_worker.requirement, PrincipalRequirement::Deny);
        assert_eq!(unknown_route.requirement, PrincipalRequirement::Deny);
        assert_eq!(identity_only.requirement, PrincipalRequirement::NotExposed);
    }

    #[test]
    fn authorization_receipt_has_versioned_safe_durable_fields() {
        let context = AuthorizationContext::new(
            "request-1",
            None,
            "POST",
            "/v1/sandboxes/sandbox-private/stop",
            "tenant-private",
            Principal::Tenant,
        );
        let mut payload = serde_json::json!({});

        context.add_to_payload(&mut payload);

        assert_eq!(payload["_authorization"]["schema"], "authz_receipt_v2");
        assert_eq!(payload["_authorization"]["decision"], "allow");
        assert_eq!(payload["_authorization"]["action"], "stop");
        assert!(payload["_authorization"]["decisionId"].is_string());
        assert!(payload["_authorization"]["receiptId"].is_string());
        assert!(!payload.to_string().contains("tenant-private"));
        assert!(!payload.to_string().contains("sandbox-private"));
    }
}

#[cfg(test)]
mod conformance_tests {
    use super::*;
    use sandboxwich_core::WorkerId;
    use serde::Deserialize;

    #[test]
    fn explicit_lineage_is_exposed_without_raw_identifiers() {
        let context = AuthorizationContext::new_with_lineage(
            "lineage-1",
            "request-1",
            None,
            "GET",
            "/v1/sandboxes/sandbox-1",
            "tenant-private",
            Principal::Tenant,
        );
        let mut payload = serde_json::json!({});

        context.add_to_payload(&mut payload);

        assert_eq!(context.authorization_lineage_id, "lineage-1");
        assert_eq!(context.lineage_header().to_str().unwrap(), "lineage-1");
        assert_eq!(payload["_authorization"]["lineageId"], "lineage-1");
        assert!(!payload.to_string().contains("tenant-private"));
        assert!(!payload.to_string().contains("sandbox-1"));
    }

    #[test]
    fn shared_conformance_cases_fail_closed_for_sandboxwich() {
        #[derive(Debug, Deserialize)]
        struct Suite {
            schema: String,
            cases: Vec<Case>,
        }
        #[derive(Debug, Deserialize)]
        struct Case {
            id: String,
            engine: String,
            #[serde(default)]
            method: Option<String>,
            #[serde(default)]
            path: Option<String>,
            #[serde(default)]
            principal: Option<String>,
            expected_effect: String,
            expected_reason: String,
        }

        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/authorization/authz-conformance.v1.json");
        let suite: Suite = serde_json::from_str(
            &std::fs::read_to_string(fixture_path).expect("conformance fixture is readable"),
        )
        .expect("conformance fixture is valid JSON");
        assert_eq!(suite.schema, "authz_conformance_v1");

        for case in suite
            .cases
            .iter()
            .filter(|case| case.engine == "sandboxwich")
        {
            let principal = match case.principal.as_deref() {
                Some("tenant") => Principal::Tenant,
                Some("worker") => Principal::Worker(WorkerId(Uuid::from_u128(7))),
                Some("operator") => Principal::Operator,
                other => panic!("unsupported conformance principal {other:?}"),
            };
            let context = AuthorizationContext::new(
                "conformance-request",
                None,
                case.method.as_deref().unwrap_or("GET"),
                case.path.as_deref().expect("sandbox case path"),
                "tenant-private",
                principal,
            );
            let effect = if context.principal_allowed(principal) {
                "allow"
            } else {
                "deny"
            };
            assert_eq!(effect, case.expected_effect, "case {}", case.id);
            assert_eq!(
                context.decision_reason, case.expected_reason,
                "case {}",
                case.id
            );
        }
    }
}
pub(crate) static AUTHORIZATION_LINEAGE_ID_HEADER: HeaderName =
    HeaderName::from_static("x-authorization-lineage-id");
pub(crate) const AUTHORIZATION_ROUTE_MANIFEST: &[&str] = &[
    "/healthz",
    "/readyz",
    "/openapi.json",
    "/metrics",
    "/homes",
    "/homes/*",
    "/homes/*/sandboxes",
    "/sandboxes",
    "/sandboxes/*",
    "/sandboxes/*/observed-state",
    "/sandboxes/*/files",
    "/sandboxes/*/files/*",
    "/sandboxes/*/runtime-resources",
    "/sandboxes/*/stop",
    "/sandboxes/*/resident-processes/*",
    "/sandboxes/*/resident-processes/maestro-hosted-runner/connection-binding",
    "/sandboxes/*/resident-processes/maestro-hosted-runner/activations/validate",
    "/sandboxes/*/resident-processes/*/stop",
    "/sandboxes/*/resident-processes/*/events",
    "/sandboxes/*/resume",
    "/sandboxes/*/fork",
    "/sandboxes/*/snapshots",
    "/sandboxes/*/desktop",
    "/sandboxes/*/desktop-sessions",
    "/sandboxes/*/commands",
    "/sandboxes/*/prompt",
    "/sandboxes/*/events",
    "/desktop-sessions/*",
    "/desktop-sessions/*/status",
    "/desktop-sessions/*/access",
    "/secret-refs",
    "/secret-refs/*",
    "/snapshots/cleanup",
    "/snapshots/*",
    "/snapshots/*/fork",
    "/commands/*",
    "/commands/*/output",
    "/workers",
    "/capacity",
    "/jobs",
    "/jobs/*",
    "/divergence/reconcile",
    "/sandboxes/*/tool-call-ledger",
    "/sandboxes/*/divergence-findings",
    "/operations/*",
    "/operations/*/events",
    "/operations/*/cancel",
    "/sandboxes/*/guest-health",
    "/sandboxes/*/ssh-keys",
    "/sandboxes/*/ssh-access",
    "/ssh-keys/*/status",
    "/sandboxes/*/apex-task-instructions",
    "/resident-placement-attestations/redeem",
    "/resident-placement-attestations/validate",
    "/workers/register",
    "/workers/*/heartbeat",
    "/workers/*/drain",
    "/workers/*/runtime-resource-inventory",
    "/workers/*/runtime-resources/reconcile",
    "/workers/*/sandboxes/*/guest-token",
    "/workers/*/apex-instruction-callbacks/*",
    "/workers/*/leases/claim",
    "/resident-processes/*/bootstrap",
    "/resident-processes/*/observations",
    "/leases/*/renew",
    "/leases/*/materialization",
    "/leases/*/provisioning",
    "/leases/*/output",
    "/leases/*/complete",
    "/leases/*/fail",
    "/sandboxes/*/guest-token/refresh",
    "/operator/tenant-policies/*",
];
pub(crate) const AUTHORIZATION_NON_TENANT_ROUTE_MANIFEST: &[&str] =
    &["/maestro-workload-identities/validate"];

#[derive(Debug, Default)]
struct AuthorizationMetrics {
    decisions: AtomicU64,
    allows: AtomicU64,
    denials: AtomicU64,
    unknown_route_denials: AtomicU64,
    receipts: AtomicU64,
    latency_ns_sum: AtomicU64,
    latency_ns_max: AtomicU64,
}

static AUTHORIZATION_METRICS: OnceLock<AuthorizationMetrics> = OnceLock::new();

fn authorization_metrics() -> &'static AuthorizationMetrics {
    AUTHORIZATION_METRICS.get_or_init(AuthorizationMetrics::default)
}

pub(crate) fn record_decision(allowed: bool, unknown_route: bool, elapsed: Duration) {
    let metrics = authorization_metrics();
    metrics.decisions.fetch_add(1, Ordering::Relaxed);
    metrics.receipts.fetch_add(1, Ordering::Relaxed);
    if allowed {
        metrics.allows.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics.denials.fetch_add(1, Ordering::Relaxed);
        if unknown_route {
            metrics
                .unknown_route_denials
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    let elapsed_ns = elapsed.as_nanos().min(u64::MAX as u128) as u64;
    metrics
        .latency_ns_sum
        .fetch_add(elapsed_ns, Ordering::Relaxed);
    let mut observed = metrics.latency_ns_max.load(Ordering::Relaxed);
    while elapsed_ns > observed {
        match metrics.latency_ns_max.compare_exchange_weak(
            observed,
            elapsed_ns,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next) => observed = next,
        }
    }
}

pub(crate) fn append_authorization_metrics(body: &mut String) {
    let metrics = authorization_metrics();
    append_metric(
        body,
        "sandboxwich_authorization_decisions_total",
        "Authorization decisions evaluated.",
        "counter",
        metrics.decisions.load(Ordering::Relaxed),
    );
    append_metric(
        body,
        "sandboxwich_authorization_allows_total",
        "Authorization decisions that allowed the principal.",
        "counter",
        metrics.allows.load(Ordering::Relaxed),
    );
    append_metric(
        body,
        "sandboxwich_authorization_denials_total",
        "Authorization decisions that denied the principal.",
        "counter",
        metrics.denials.load(Ordering::Relaxed),
    );
    append_metric(
        body,
        "sandboxwich_authorization_unknown_route_denials_total",
        "Authorization denials caused by an unclassified route.",
        "counter",
        metrics.unknown_route_denials.load(Ordering::Relaxed),
    );
    append_metric(
        body,
        "sandboxwich_authorization_receipts_total",
        "Authorization receipts emitted.",
        "counter",
        metrics.receipts.load(Ordering::Relaxed),
    );
    append_metric(
        body,
        "sandboxwich_authorization_decision_latency_ns_sum",
        "Sum of authorization decision latency in nanoseconds.",
        "counter",
        metrics.latency_ns_sum.load(Ordering::Relaxed),
    );
    append_metric(
        body,
        "sandboxwich_authorization_decision_latency_ns_max",
        "Maximum authorization decision latency in nanoseconds.",
        "gauge",
        metrics.latency_ns_max.load(Ordering::Relaxed),
    );
}

fn append_metric(body: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    body.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n",
    ));
}
