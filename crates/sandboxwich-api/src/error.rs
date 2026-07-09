use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sandboxwich_core::*;
use sqlx::error::ErrorKind;

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
        }
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
        }
    }

    pub(crate) fn conflict_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            code: "unsupported",
            message: message.into(),
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
        }
    }

    pub(crate) fn not_implemented(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            code,
            message: message.into(),
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
            Json(ErrorEnvelope::new(self.code, self.message)),
        )
            .into_response()
    }
}
