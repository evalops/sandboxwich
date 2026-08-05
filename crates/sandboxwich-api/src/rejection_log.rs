//! Logs every rejected mutation with the error code the caller was given.
//!
//! Before this module existed, a rejected mutation left no trace in the API's
//! own logs. Handler rejections (`ApiError` -> `ErrorEnvelope`) are returned to
//! the caller and dropped; axum's built-in `Json` rejection (422) never reaches
//! a handler at all. During the 2026-08-03 incident thousands of mutations were
//! refused -- a serde-mismatched body (422), the
//! `maestro-hosted-runner requires exact bounded workload identity bindings`
//! 400, name-allowlist 400s, state-transition 409s and
//! `resident_sidecar_worker_unsupported` 503s -- and the only way to find out
//! which was to hand-curl production.
//!
//! [`log_mutation_rejections`] closes that gap for `POST`/`PUT`/`PATCH`/
//! `DELETE`. Read rejections are deliberately left silent: several `GET` routes
//! 404 by design as a poll signal, most notably
//! `GET /sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/connection-binding`,
//! which returns 404 on every poll until placement completes.

use axum::body::{Body, HttpBody};
use axum::extract::{MatchedPath, Request};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

use crate::authz::AuthorizationContext;
use crate::state::TenantContext;

/// Largest rejection body buffered to read its `code`. Every rejection this
/// middleware reports is either a small `ErrorEnvelope` or a one-line framework
/// rejection string, so this only has to be big enough not to truncate those.
const MAX_INSPECTED_BODY_BYTES: usize = 8 * 1024;
/// Character cap on the logged free-text detail. Bounds one absurd serde error
/// (or a deeply nested `unknown field` list) to a fixed share of a log line.
const MAX_DETAIL_CHARS: usize = 200;
/// Character cap on the logged `code`. Real codes are short identifiers; this
/// only stops a non-conforming JSON body from writing an unbounded field.
const MAX_CODE_CHARS: usize = 64;

const UNMATCHED_ROUTE: &str = "<unmatched>";
const UNKNOWN_TENANT: &str = "<unknown>";
const UNKNOWN_CODE: &str = "<unknown>";
/// Code logged for a rejection produced by axum's `Json` extractor, which
/// rejects before the handler runs and so has no `ErrorEnvelope` of its own.
const JSON_REJECTION_CODE: &str = "json_rejection";
/// Code logged for any other non-JSON framework rejection (`Path`/`Query`
/// deserialization, body-limit, method-not-allowed, ...).
const FRAMEWORK_REJECTION_CODE: &str = "framework_rejection";

/// Body prefixes axum's `Json` extractor emits. Matched as a prefix because the
/// underlying serde error is appended after `": "` (see `__define_rejection!`
/// in axum-core).
const JSON_REJECTION_PREFIXES: &[&str] = &[
    "Failed to deserialize the JSON body into the target type",
    "Failed to parse the request body as JSON",
    "Expected request with `Content-Type: application/json`",
];

/// Whether a request method mutates state, and therefore whether its rejection
/// is worth a log line. `GET`/`HEAD`/`OPTIONS` are excluded on purpose: polling
/// callers drive read 4xx volume that carries no diagnostic value.
fn is_mutation(method: &axum::http::Method) -> bool {
    matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Logs every 4xx and 5xx answered on a mutation route at `WARN`.
///
/// Must be layered *inside* `auth_and_tenant` (so [`TenantContext`] is already
/// on the request) and *inside* `normalize_framework_errors` (so a framework
/// rejection is still carrying its original plain-text detail rather than the
/// generic envelope that middleware substitutes for the caller). Both hold for
/// the position it is installed at in `routes::app`.
pub(crate) async fn log_mutation_rejections(request: Request, next: Next) -> Response {
    if !is_mutation(request.method()) {
        return next.run(request).await;
    }

    let method = request.method().clone();
    // The route *template* (`/v1/sandboxes/{sandbox_id}/stop`), never the raw
    // URI: raw paths would put every id into the log message and defeat
    // grouping. `MatchedPath` is present here because `Router::layer` runs
    // after routing, including through `nest`.
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned());
    let tenant = request
        .extensions()
        .get::<TenantContext>()
        .map(|ctx| ctx.tenant_id.clone());
    let authorization_decision_id = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.decision_id.clone());
    let authorization_fingerprint = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.authorization_fingerprint.clone());
    let authorization_receipt_id = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.receipt_id.clone());
    let authorization_policy_digest = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.policy_digest.clone());
    let authorization_resource_kind = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.resource_kind);
    let authorization_action = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.action);
    let authorization_decision_reason = request
        .extensions()
        .get::<AuthorizationContext>()
        .map(|context| context.decision_reason);

    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let (response, rejection) = inspect_rejection(response).await;
    tracing::warn!(
        method = %method,
        route = route.as_deref().unwrap_or(UNMATCHED_ROUTE),
        status = status.as_u16(),
        code = rejection.code.as_deref().unwrap_or(UNKNOWN_CODE),
        detail = rejection.detail.as_deref().unwrap_or(""),
        tenant = tenant.as_deref().unwrap_or(UNKNOWN_TENANT),
        authorization_decision_id = authorization_decision_id.as_deref().unwrap_or("<none>"),
        authorization_fingerprint = authorization_fingerprint.as_deref().unwrap_or("<none>"),
        authorization_receipt_id = authorization_receipt_id.as_deref().unwrap_or("<none>"),
        authorization_policy_digest = authorization_policy_digest.as_deref().unwrap_or("<none>"),
        authorization_resource_kind = authorization_resource_kind.unwrap_or("<none>"),
        authorization_action = authorization_action.unwrap_or("<none>"),
        authorization_decision_reason = authorization_decision_reason.unwrap_or("<none>"),
        latency_ms,
        "mutation rejected"
    );
    response
}

/// What a rejection response body says about itself.
#[derive(Debug, Default, Eq, PartialEq)]
struct RejectionDetail {
    /// `ErrorEnvelope::code`, or a synthetic code for a framework rejection
    /// that has no envelope.
    code: Option<String>,
    /// Bounded, redacted free text: the envelope's message, or the framework
    /// rejection's own description (which for a `Json` rejection carries the
    /// serde error).
    detail: Option<String>,
}

/// Buffers a rejection body, reads what it can from it, and hands back a
/// response carrying the identical bytes.
async fn inspect_rejection(response: Response) -> (Response, RejectionDetail) {
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // Only a body whose exact length is already known and small is collected.
    // A streaming body reports no exact size hint and is passed through
    // untouched rather than buffered into memory; every rejection produced by
    // this crate or by axum is an in-memory `Bytes` body with an exact hint.
    if response
        .body()
        .size_hint()
        .exact()
        .is_none_or(|length| length > MAX_INSPECTED_BODY_BYTES as u64)
    {
        return (response, RejectionDetail::default());
    }

    let (parts, body) = response.into_parts();
    match axum::body::to_bytes(body, MAX_INSPECTED_BODY_BYTES).await {
        Ok(bytes) => {
            let rejection = classify_rejection_body(parts.status, content_type.as_deref(), &bytes);
            (Response::from_parts(parts, Body::from(bytes)), rejection)
        }
        Err(error) => {
            // Unreachable for the exact-length in-memory bodies selected
            // above; the body is already consumed at this point, so the
            // caller gets the same status with an empty body rather than a
            // hang. Logged so this never fails silently.
            tracing::warn!(%error, "failed to buffer a rejection body for logging");
            (
                Response::from_parts(parts, Body::empty()),
                RejectionDetail::default(),
            )
        }
    }
}

/// Reads the `code` and message out of a rejection body, defensively: an
/// unparseable or unexpected body yields `None` rather than an error.
fn classify_rejection_body(
    status: StatusCode,
    content_type: Option<&str>,
    body: &[u8],
) -> RejectionDetail {
    let is_json = content_type.is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return RejectionDetail::default();
        };
        return RejectionDetail {
            code: value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(|code| bound(sanitize_control_chars(code), MAX_CODE_CHARS)),
            detail: value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(|message| bound(redact_quoted(message), MAX_DETAIL_CHARS)),
        };
    }

    if body.is_empty() {
        return RejectionDetail::default();
    }
    let text = String::from_utf8_lossy(body);
    // A `Json` rejection is answered before the handler runs, so it has no
    // `ErrorEnvelope`. Identify it by the fixed prefixes axum uses and record
    // the serde error that follows -- that error names the offending field,
    // which is the whole diagnostic.
    let is_json_rejection = JSON_REJECTION_PREFIXES
        .iter()
        .any(|prefix| text.starts_with(prefix))
        || status == StatusCode::UNPROCESSABLE_ENTITY;
    RejectionDetail {
        code: Some(
            if is_json_rejection {
                JSON_REJECTION_CODE
            } else {
                FRAMEWORK_REJECTION_CODE
            }
            .to_owned(),
        ),
        detail: Some(bound(redact_quoted(&text), MAX_DETAIL_CHARS)),
    }
}

/// Replaces every double-quoted run with a fixed placeholder.
///
/// serde_json spells field names with backticks (``missing field `sandboxId` ``)
/// but echoes offending *values* in double quotes (`invalid type: string
/// "sk-live-...", expected u64`). Redacting only the double-quoted spans keeps
/// the entire diagnostic -- which field, what was expected, where -- without
/// copying request payload bytes into the log, which matters because request
/// bodies on these routes carry secret-bearing fields.
fn redact_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut inside_quotes = false;
    for character in raw.chars() {
        if character == '"' {
            if !inside_quotes {
                out.push_str("\"<redacted>\"");
            }
            inside_quotes = !inside_quotes;
            continue;
        }
        if !inside_quotes {
            out.push(normalize_char(character));
        }
    }
    out
}

fn sanitize_control_chars(raw: &str) -> String {
    raw.chars().map(normalize_char).collect()
}

/// Keeps a log line on one line and free of terminal control sequences.
fn normalize_char(character: char) -> char {
    if character.is_control() {
        ' '
    } else {
        character
    }
}

fn bound(mut value: String, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value;
    }
    value = value.chars().take(max_chars).collect();
    value.push_str("...");
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Principal;
    use axum::response::IntoResponse;
    use axum::routing::{get, post, put};
    use axum::{Extension, Json, Router, middleware};
    use sandboxwich_core::ErrorEnvelope;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        level: tracing::Level,
        message: String,
        fields: BTreeMap<String, String>,
    }

    impl CapturedEvent {
        fn field(&self, name: &str) -> &str {
            self.fields
                .get(name)
                .map(String::as_str)
                .unwrap_or_else(|| panic!("event is missing field {name}: {self:?}"))
        }
    }

    #[derive(Default)]
    struct FieldVisitor(BTreeMap<String, String>);

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_owned(), value.to_string());
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.insert(field.name().to_owned(), value.to_string());
        }
    }

    /// Collects every event emitted while it is the thread's default
    /// subscriber, so a test can assert on what was logged rather than on a
    /// proxy for it.
    #[derive(Clone, Default)]
    struct CaptureLayer(Arc<Mutex<Vec<CapturedEvent>>>);

    impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            let message = visitor.0.remove("message").unwrap_or_default();
            self.0
                .lock()
                .expect("capture mutex is never held across a panic")
                .push(CapturedEvent {
                    level: *event.metadata().level(),
                    message,
                    fields: visitor.0,
                });
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PutResidentProcessBody {
        #[allow(dead_code)]
        argv: Vec<String>,
    }

    async fn accepts_json_body(Json(_): Json<PutResidentProcessBody>) -> StatusCode {
        StatusCode::OK
    }

    async fn rejects_with_envelope() -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorEnvelope::new(
                "bad_request",
                "maestro-hosted-runner requires exact bounded workload identity bindings",
            )),
        )
            .into_response()
    }

    /// Mirrors `get_maestro_connection_binding`'s not-yet-placed answer: the
    /// normal poll signal, not a fault.
    async fn binding_not_ready() -> Response {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorEnvelope::new(
                "not_found",
                "Maestro hosted runner not found",
            )),
        )
            .into_response()
    }

    async fn accepts() -> StatusCode {
        StatusCode::OK
    }

    /// A miniature router carrying the real route templates, with the
    /// middleware layered exactly as `routes::app` layers it: inside the
    /// extension that supplies `TenantContext`, outside the handlers.
    fn test_router() -> Router {
        Router::new()
            .route(
                "/v1/sandboxes/{sandbox_id}/resident-processes/{name}",
                put(accepts_json_body),
            )
            .route(
                "/v1/sandboxes/{sandbox_id}/resident-processes/maestro-hosted-runner/connection-binding",
                get(binding_not_ready),
            )
            .route("/v1/sandboxes/{sandbox_id}/stop", post(rejects_with_envelope))
            .route("/v1/sandboxes/{sandbox_id}/fork", post(accepts))
            .layer(middleware::from_fn(log_mutation_rejections))
            .layer(Extension(TenantContext {
                tenant_id: "tenant-a".to_owned(),
                principal: Principal::Tenant,
            }))
    }

    async fn capture_request(request: Request) -> (Response, Vec<CapturedEvent>) {
        let layer = CaptureLayer::default();
        let events = layer.0.clone();
        let subscriber = tracing_subscriber::registry().with(layer);
        // `set_default` is thread-local, and `#[tokio::test]` drives this
        // future on the current thread, so the guard covers the whole request.
        let guard = tracing::subscriber::set_default(subscriber);
        let response = test_router()
            .oneshot(request)
            .await
            .expect("axum routers are infallible");
        drop(guard);
        let events = events.lock().expect("capture mutex").clone();
        (response, events)
    }

    fn mutation_rejections(events: &[CapturedEvent]) -> Vec<&CapturedEvent> {
        events
            .iter()
            .filter(|event| event.message == "mutation rejected")
            .collect()
    }

    fn json_request(method: &str, uri: &str, body: &str) -> Request {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("test request is well formed")
    }

    #[tokio::test]
    async fn json_body_rejection_is_logged_with_the_serde_error() {
        // The 422 that cost two hours on 2026-08-03: axum's `Json` extractor
        // rejects a serde-mismatched body before the handler runs, so nothing
        // downstream ever saw it.
        let (response, events) = capture_request(json_request(
            "PUT",
            "/v1/sandboxes/11111111-1111-1111-1111-111111111111/resident-processes/orb-executor",
            r#"{"argv": 7}"#,
        ))
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let logged = mutation_rejections(&events);
        assert_eq!(logged.len(), 1, "expected exactly one warning: {events:?}");
        let logged = logged[0];
        assert_eq!(logged.level, tracing::Level::WARN);
        assert_eq!(logged.field("code"), JSON_REJECTION_CODE);
        assert_eq!(logged.field("status"), "422");
        assert_eq!(logged.field("method"), "PUT");
        assert_eq!(
            logged.field("route"),
            "/v1/sandboxes/{sandbox_id}/resident-processes/{name}"
        );
        assert_eq!(logged.field("tenant"), "tenant-a");
        assert!(
            logged.field("latency_ms").parse::<u64>().is_ok(),
            "latency_ms must be numeric: {logged:?}"
        );
        // The serde error itself -- the field that failed and what was
        // expected -- is what makes this line actionable.
        let detail = logged.field("detail");
        assert!(
            detail.contains("Failed to deserialize the JSON body"),
            "detail must carry the rejection: {detail}"
        );
        assert!(
            detail.contains("invalid type: integer `7`"),
            "detail must carry the serde error: {detail}"
        );
    }

    #[tokio::test]
    async fn envelope_rejection_is_logged_with_its_code() {
        let (response, events) = capture_request(
            Request::builder()
                .method("POST")
                .uri("/v1/sandboxes/11111111-1111-1111-1111-111111111111/stop")
                .body(Body::empty())
                .expect("test request is well formed"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let logged = mutation_rejections(&events);
        assert_eq!(logged.len(), 1, "expected exactly one warning: {events:?}");
        let logged = logged[0];
        assert_eq!(logged.level, tracing::Level::WARN);
        assert_eq!(logged.field("code"), "bad_request");
        assert_eq!(logged.field("status"), "400");
        assert_eq!(logged.field("method"), "POST");
        assert_eq!(logged.field("route"), "/v1/sandboxes/{sandbox_id}/stop");
        assert_eq!(logged.field("tenant"), "tenant-a");
        assert!(
            logged
                .field("detail")
                .contains("exact bounded workload identity bindings"),
            "detail must carry the envelope message: {logged:?}"
        );

        // The caller still receives the identical body after the middleware
        // buffered it to read the code.
        let body = axum::body::to_bytes(response.into_body(), MAX_INSPECTED_BODY_BYTES)
            .await
            .expect("rejection body is buffered");
        let envelope: ErrorEnvelope =
            serde_json::from_slice(&body).expect("body survives inspection");
        assert_eq!(envelope.code, "bad_request");
        assert!(!envelope.ok);
    }

    #[tokio::test]
    async fn connection_binding_poll_404_is_not_logged() {
        // This route 404s on every poll until placement completes. Logging it
        // would bury the mutation rejections this middleware exists to surface.
        let (response, events) = capture_request(
            Request::builder()
                .method("GET")
                .uri(
                    "/v1/sandboxes/11111111-1111-1111-1111-111111111111/resident-processes/\
                     maestro-hosted-runner/connection-binding",
                )
                .body(Body::empty())
                .expect("test request is well formed"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            mutation_rejections(&events).is_empty(),
            "read-path 404s must stay unlogged: {events:?}"
        );
    }

    #[tokio::test]
    async fn accepted_mutations_are_not_logged() {
        let (response, events) = capture_request(
            Request::builder()
                .method("POST")
                .uri("/v1/sandboxes/11111111-1111-1111-1111-111111111111/fork")
                .body(Body::empty())
                .expect("test request is well formed"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            mutation_rejections(&events).is_empty(),
            "a 2xx must not log: {events:?}"
        );
    }

    #[test]
    fn json_envelope_code_and_message_are_read_defensively() {
        let body = serde_json::to_vec(&ErrorEnvelope::new(
            "resident_sidecar_worker_unsupported",
            "the resident sidecar requires its placed worker",
        ))
        .expect("envelope serializes");
        let rejection = classify_rejection_body(
            StatusCode::SERVICE_UNAVAILABLE,
            Some("application/json"),
            &body,
        );
        assert_eq!(
            rejection.code.as_deref(),
            Some("resident_sidecar_worker_unsupported")
        );

        // A JSON body that is not an `ErrorEnvelope` yields no code rather
        // than an error.
        let rejection = classify_rejection_body(
            StatusCode::BAD_REQUEST,
            Some("application/json"),
            br#"{"unexpected": true}"#,
        );
        assert_eq!(rejection, RejectionDetail::default());

        // Neither does a body that is not JSON at all despite the header.
        let rejection =
            classify_rejection_body(StatusCode::BAD_REQUEST, Some("application/json"), b"<html>");
        assert_eq!(rejection, RejectionDetail::default());

        // An empty non-JSON body carries nothing to report.
        let rejection = classify_rejection_body(StatusCode::CONFLICT, Some("text/plain"), b"");
        assert_eq!(rejection, RejectionDetail::default());
    }

    #[test]
    fn framework_rejections_are_separated_from_json_rejections() {
        let rejection = classify_rejection_body(
            StatusCode::BAD_REQUEST,
            Some("text/plain; charset=utf-8"),
            b"Failed to parse the request body as JSON: expected value at line 1 column 1",
        );
        assert_eq!(rejection.code.as_deref(), Some(JSON_REJECTION_CODE));

        let rejection = classify_rejection_body(
            StatusCode::METHOD_NOT_ALLOWED,
            Some("text/plain; charset=utf-8"),
            b"Method Not Allowed",
        );
        assert_eq!(rejection.code.as_deref(), Some(FRAMEWORK_REJECTION_CODE));
    }

    #[test]
    fn quoted_values_are_redacted_but_field_names_survive() {
        // serde_json echoes the offending value in double quotes; that value
        // can be a secret-bearing field from the request body.
        let redacted = redact_quoted(
            "Failed to deserialize the JSON body into the target type: \
             invalid type: string \"sbw_wtok_deadbeef\", expected u64 at line 1 column 40",
        );
        assert!(
            !redacted.contains("sbw_wtok_deadbeef"),
            "payload value leaked: {redacted}"
        );
        assert!(redacted.contains("\"<redacted>\""), "{redacted}");
        assert!(
            redacted.contains("expected u64 at line 1 column 40"),
            "{redacted}"
        );

        // Backtick-quoted field names are the diagnostic and must survive.
        let redacted = redact_quoted(
            "Failed to deserialize the JSON body into the target type: \
             missing field `sandboxId` at line 1 column 25",
        );
        assert!(redacted.contains("missing field `sandboxId`"), "{redacted}");

        // An unterminated quote still redacts its tail.
        let redacted = redact_quoted("invalid value: \"unterminated");
        assert_eq!(redacted, "invalid value: \"<redacted>\"");

        // Control characters can never break out onto their own log line.
        let redacted = redact_quoted("first\nsecond\r\tthird");
        assert_eq!(redacted, "first second  third");
    }

    #[test]
    fn logged_text_is_length_bounded() {
        let long = "x".repeat(MAX_DETAIL_CHARS * 4);
        let bounded = bound(long, MAX_DETAIL_CHARS);
        assert_eq!(bounded.chars().count(), MAX_DETAIL_CHARS + 3);
        assert!(bounded.ends_with("..."));

        // Multi-byte characters are counted, not sliced: truncating by byte
        // index would panic on a character boundary.
        let bounded = bound("é".repeat(MAX_DETAIL_CHARS * 2), MAX_DETAIL_CHARS);
        assert_eq!(bounded.chars().count(), MAX_DETAIL_CHARS + 3);

        let short = bound("short".to_owned(), MAX_DETAIL_CHARS);
        assert_eq!(short, "short");
    }

    #[test]
    fn only_state_changing_methods_are_logged() {
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(
                is_mutation(&axum::http::Method::from_bytes(method.as_bytes()).expect("method")),
                "{method} must be treated as a mutation"
            );
        }
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert!(
                !is_mutation(&axum::http::Method::from_bytes(method.as_bytes()).expect("method")),
                "{method} must stay unlogged"
            );
        }
    }
}
