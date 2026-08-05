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
use uuid::Uuid;

use crate::request_id::{REQUEST_ID_HEADER, RequestTrace};
use crate::state::Principal;

pub(crate) const AUTHORIZATION_POLICY_ID: &str = "sandboxwich-api-authz";
pub(crate) const AUTHORIZATION_POLICY_VERSION: &str = "v1";
pub(crate) static AUTHORIZATION_DECISION_ID_HEADER: HeaderName =
    HeaderName::from_static("x-authorization-decision-id");

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizationContext {
    pub(crate) request_id: String,
    pub(crate) decision_id: String,
    pub(crate) authorization_fingerprint: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) policy_id: &'static str,
    pub(crate) policy_version: &'static str,
    pub(crate) principal_class: &'static str,
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

        Self::new(
            &request_id,
            trace_id.as_deref(),
            request.method().as_str(),
            request.uri().path(),
            tenant_id,
            principal,
        )
    }

    fn new(
        request_id: &str,
        trace_id: Option<&str>,
        method: &str,
        path: &str,
        tenant_id: &str,
        principal: Principal,
    ) -> Self {
        Self {
            request_id: request_id.to_owned(),
            decision_id: decision_id(request_id, method, path, tenant_id, principal),
            authorization_fingerprint: authorization_fingerprint(
                method, path, tenant_id, principal,
            ),
            trace_id: trace_id.map(str::to_owned),
            policy_id: AUTHORIZATION_POLICY_ID,
            policy_version: AUTHORIZATION_POLICY_VERSION,
            principal_class: principal_class(principal),
        }
    }

    pub(crate) fn decision_header(&self) -> HeaderValue {
        HeaderValue::from_str(&self.decision_id)
            .expect("authorization decision id is a valid header value")
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

fn decision_id(
    request_id: &str,
    method: &str,
    path: &str,
    tenant_id: &str,
    principal: Principal,
) -> String {
    digest_id(
        "authz_decision_v1_",
        Some(request_id),
        method,
        path,
        tenant_id,
        principal,
    )
}

fn authorization_fingerprint(
    method: &str,
    path: &str,
    tenant_id: &str,
    principal: Principal,
) -> String {
    digest_id(
        "authz_fingerprint_v1_",
        None,
        method,
        path,
        tenant_id,
        principal,
    )
}

fn digest_id(
    prefix: &str,
    request_id: Option<&str>,
    method: &str,
    path: &str,
    tenant_id: &str,
    principal: Principal,
) -> String {
    let principal_class = principal_class(principal);
    let principal_binding = principal_binding(principal);
    let mut hasher = Sha256::new();
    update_field(&mut hasher, "policy_id", AUTHORIZATION_POLICY_ID);
    update_field(&mut hasher, "policy_version", AUTHORIZATION_POLICY_VERSION);
    if let Some(request_id) = request_id {
        update_field(&mut hasher, "request_id", request_id);
    }
    update_field(&mut hasher, "method", method);
    update_field(&mut hasher, "path", path);
    update_field(&mut hasher, "tenant_id", tenant_id);
    update_field(&mut hasher, "principal_class", principal_class);
    update_field(&mut hasher, "principal_binding", &principal_binding);

    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    format!("{prefix}{encoded}")
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
}
