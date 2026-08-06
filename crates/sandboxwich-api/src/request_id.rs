use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sandboxwich_core::ErrorEnvelope;
use std::time::Instant;
use tracing::Instrument;
use uuid::Uuid;

pub(crate) static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
pub(crate) static TRACEPARENT_HEADER: HeaderName = HeaderName::from_static("traceparent");
pub(crate) static TRACESTATE_HEADER: HeaderName = HeaderName::from_static("tracestate");

#[derive(Clone, Debug, Default)]
pub(crate) struct RequestTrace {
    pub(crate) request_id: String,
    pub(crate) traceparent: String,
    pub(crate) tracestate: String,
    pub(crate) trace_id: String,
}

impl RequestTrace {
    fn from_headers(request_id: &str, headers: &axum::http::HeaderMap) -> Self {
        let traceparent = headers
            .get(&TRACEPARENT_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(normalize_traceparent)
            .unwrap_or_default();
        let tracestate = if traceparent.is_empty() {
            String::new()
        } else {
            headers
                .get(&TRACESTATE_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| value.len() <= 512)
                .unwrap_or_default()
                .to_string()
        };
        let trace_id = traceparent
            .split('-')
            .nth(1)
            .unwrap_or_default()
            .to_string();
        Self {
            request_id: request_id.to_string(),
            traceparent,
            tracestate,
            trace_id,
        }
    }

    pub(crate) fn add_to_payload(&self, payload: &mut serde_json::Value) {
        if let serde_json::Value::Object(fields) = payload
            && !self.traceparent.is_empty()
        {
            fields.insert(
                "_traceparent".to_string(),
                serde_json::Value::String(self.traceparent.clone()),
            );
        }
    }
}

fn normalize_traceparent(value: &str) -> Option<String> {
    let value = value.trim();
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some()
        || version.len() != 2
        || version.eq_ignore_ascii_case("ff")
        || trace_id.len() != 32
        || span_id.len() != 16
        || flags.len() != 2
        || !trace_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !span_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !flags.bytes().all(|byte| byte.is_ascii_hexdigit())
        || trace_id.bytes().all(|byte| byte == b'0')
        || span_id.bytes().all(|byte| byte == b'0')
    {
        return None;
    }
    Some(value.to_string())
}

fn route_class(path: &str) -> &'static str {
    match path {
        path if path.contains("/sandboxes") => "sandbox",
        path if path.contains("/resident-processes") => "resident_process",
        path if path.contains("/workers") => "worker",
        path if path.contains("/jobs") => "job",
        path if path.contains("/operations") => "operation",
        path if path.contains("/snapshots") => "snapshot",
        path if path.contains("/leases") => "lease",
        _ => "other",
    }
}

pub(crate) async fn attach_request_id(mut request: Request, next: Next) -> Response {
    let request_id_header = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .filter(|value| value.to_str().is_ok_and(|value| !value.trim().is_empty()))
        .cloned()
        .unwrap_or_else(|| {
            HeaderValue::from_str(&Uuid::now_v7().to_string())
                .expect("generated request id is a valid header")
        });
    let request_id = request_id_header
        .to_str()
        .expect("validated request id is valid UTF-8")
        .to_string();
    let trace = RequestTrace::from_headers(&request_id, request.headers());
    let traceparent = (!trace.traceparent.is_empty()).then(|| trace.traceparent.clone());
    let tracestate = (!trace.tracestate.is_empty()).then(|| trace.tracestate.clone());
    let span = tracing::info_span!(
        "sandboxwich.http",
        method = %request.method(),
        route_class = route_class(request.uri().path()),
        request_id = %trace.request_id,
        trace_id = %trace.trace_id,
        w3c.traceparent = %trace.traceparent,
        w3c.tracestate = %trace.tracestate,
        authorization_decision_id = tracing::field::Empty,
        authorization_fingerprint = tracing::field::Empty,
        authorization_policy_id = tracing::field::Empty,
        authorization_policy_version = tracing::field::Empty,
        authorization_principal_class = tracing::field::Empty,
        authorization_trace_id = tracing::field::Empty,
        authorization_receipt_id = tracing::field::Empty,
        authorization_policy_digest = tracing::field::Empty,
        authorization_resource_kind = tracing::field::Empty,
        authorization_action = tracing::field::Empty,
        authorization_decision_reason = tracing::field::Empty,
        http_status_code = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    request.extensions_mut().insert(trace);
    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    span.record("http_status_code", response.status().as_u16());
    span.record("duration_ms", started.elapsed().as_millis() as u64);
    span.record(
        "outcome",
        if response.status().is_success() || response.status() == StatusCode::ACCEPTED {
            "success"
        } else {
            "error"
        },
    );
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER.clone(), request_id_header);
    if let Some(traceparent) = traceparent {
        response.headers_mut().insert(
            TRACEPARENT_HEADER.clone(),
            HeaderValue::from_str(&traceparent).expect("validated traceparent is a valid header"),
        );
    }
    if let Some(tracestate) = tracestate {
        response.headers_mut().insert(
            TRACESTATE_HEADER.clone(),
            HeaderValue::from_str(&tracestate).expect("validated tracestate is a valid header"),
        );
    }
    response
}

pub(crate) async fn normalize_framework_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if !response.status().is_client_error() && !response.status().is_server_error() {
        return response;
    }
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        return response;
    }
    let status = response.status();
    let code = match status {
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        status if status.is_client_error() => "invalid_request",
        _ => "internal",
    };
    let message = status.canonical_reason().unwrap_or("request failed");
    let (mut parts, _) = response.into_parts();
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let body = serde_json::to_vec(&ErrorEnvelope::new(code, message))
        .expect("error envelope is serializable");
    Response::from_parts(parts, Body::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_trace_preserves_valid_w3c_context_for_async_jobs() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            TRACEPARENT_HEADER.clone(),
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        headers.insert(
            TRACESTATE_HEADER.clone(),
            HeaderValue::from_static("vendor=value"),
        );

        let trace = RequestTrace::from_headers("req-1", &headers);
        let mut payload = json!({"sandboxId": "sandbox-1"});
        trace.add_to_payload(&mut payload);

        assert_eq!(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(payload["_traceparent"], trace.traceparent);
        assert!(payload.get("_tracestate").is_none());
    }

    #[test]
    fn request_trace_drops_invalid_w3c_context() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(TRACEPARENT_HEADER.clone(), HeaderValue::from_static("bad"));
        headers.insert(
            TRACESTATE_HEADER.clone(),
            HeaderValue::from_static("vendor=value"),
        );

        let trace = RequestTrace::from_headers("req-1", &headers);
        let mut payload = json!({"sandboxId": "sandbox-1"});
        trace.add_to_payload(&mut payload);

        assert!(trace.traceparent.is_empty());
        assert!(payload.get("_traceparent").is_none());
        assert!(payload.get("_tracestate").is_none());
    }
}
