use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sandboxwich_core::ErrorEnvelope;
use uuid::Uuid;

pub(crate) static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

pub(crate) async fn attach_request_id(request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .filter(|value| value.to_str().is_ok_and(|value| !value.trim().is_empty()))
        .cloned()
        .unwrap_or_else(|| {
            HeaderValue::from_str(&Uuid::now_v7().to_string()).expect("UUID is a valid header")
        });
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER.clone(), request_id);
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
