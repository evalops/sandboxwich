use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sandboxwich_core::lifecycle_contract::LifecycleReasonCode;
use sandboxwich_core::*;
use sqlx::error::ErrorKind;

/// Decode the stable prefix emitted by the worker's `ProviderError` display.
/// The worker keeps the original Kubernetes detail after the colon; the API
/// stores that detail unchanged while recovering the already-established
/// provisioning taxonomy for resident-process status reads.
pub(crate) fn provider_error_fields(
    error: &str,
) -> (Option<ProvisioningErrorClass>, Option<String>) {
    let code = error
        .split_once(':')
        .map(|(code, _)| code.trim())
        .filter(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        });
    let class = provisioning_error_class_for_code(code);
    (class, code.map(str::to_string))
}

pub(crate) fn provisioning_error_class_for_code(
    code: Option<&str>,
) -> Option<ProvisioningErrorClass> {
    match code {
        Some("resource_quota") => Some(ProvisioningErrorClass::RetryableCapacity),
        Some(code) => LifecycleReasonCode::parse(code)
            .map(LifecycleReasonCode::default_provisioning_error_class),
        None => None,
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) details: Option<serde_json::Value>,
}

impl ApiError {
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
            details: None,
        }
    }

    /// 400 with a stable machine-readable `code` (not the generic
    /// `bad_request`). Use for cross-service contracts where consumers
    /// (runner-host) must classify the rejection without replaying the body.
    pub(crate) fn bad_request_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "authorization_denied",
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn conflict_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn conflict_code_with_details(
        code: &'static str,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    pub(crate) fn payload_too_large(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code,
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn too_many_requests(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code,
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
            details: None,
        }
    }

    pub(crate) fn not_implemented(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            code,
            message: message.into(),
            details: None,
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        // Classify the errors we can distinguish so clients don't see an opaque
        // 500 for conditions that are really "you conflicted with another writer"
        // (409) or "your request violates a data constraint" (400). Anything we
        // can't confidently classify still falls back to a 500, as before.
        if let sqlx::Error::Database(ref db_error) = error {
            if db_error.is_unique_violation() {
                tracing::warn!(%error, "database unique constraint violation");
                return Self::conflict("the request conflicts with an existing record");
            }
            if db_error.kind() == ErrorKind::CheckViolation {
                tracing::warn!(%error, "database check constraint violation");
                return Self::bad_request("the request violates a database constraint");
            }
        }
        tracing::error!(%error, "database error");
        Self::internal("database operation failed")
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "json persistence error");
        Self::internal("json persistence failed")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope::with_details(
                self.code,
                self.message,
                self.details,
            )),
        )
            .into_response()
    }
}
