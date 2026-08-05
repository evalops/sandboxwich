use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use sandboxwich_core::lifecycle_contract::LIFECYCLE_SUPPORTED_CONTRACTS_ENV;
use sandboxwich_core::lifecycle_contract::{LIFECYCLE_CONTRACT_HEADER, LIFECYCLE_CONTRACT_SHA256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

static LIFECYCLE_CONTRACT_HEADER_VALUE: OnceLock<HeaderValue> = OnceLock::new();

fn supported_contract_header(raw: Option<&str>) -> Result<HeaderValue, String> {
    let raw = raw.unwrap_or(LIFECYCLE_CONTRACT_SHA256);
    let digests = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if !digests.contains(LIFECYCLE_CONTRACT_SHA256) {
        return Err(format!(
            "{LIFECYCLE_SUPPORTED_CONTRACTS_ENV} must include the compiled lifecycle contract"
        ));
    }
    if digests.iter().any(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(format!(
            "{LIFECYCLE_SUPPORTED_CONTRACTS_ENV} must contain lowercase SHA-256 digests"
        ));
    }
    HeaderValue::from_str(&digests.into_iter().collect::<Vec<_>>().join(","))
        .map_err(|error| format!("invalid {LIFECYCLE_SUPPORTED_CONTRACTS_ENV}: {error}"))
}

pub(crate) fn configure_lifecycle_contract_header() -> anyhow::Result<()> {
    let raw = std::env::var(LIFECYCLE_SUPPORTED_CONTRACTS_ENV).ok();
    let value = supported_contract_header(raw.as_deref()).map_err(anyhow::Error::msg)?;
    LIFECYCLE_CONTRACT_HEADER_VALUE
        .set(value)
        .map_err(|_| anyhow::anyhow!("lifecycle contract header was configured twice"))
}

pub(crate) async fn attach_lifecycle_contract(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static(LIFECYCLE_CONTRACT_HEADER),
        LIFECYCLE_CONTRACT_HEADER_VALUE
            .get_or_init(|| HeaderValue::from_static(LIFECYCLE_CONTRACT_SHA256))
            .clone(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn every_response_identifies_the_compiled_lifecycle_contract() {
        let response = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(attach_lifecycle_contract))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response
                .headers()
                .get(LIFECYCLE_CONTRACT_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(LIFECYCLE_CONTRACT_SHA256)
        );
    }

    #[test]
    fn rollout_header_requires_current_but_can_advertise_previous_contracts() {
        let previous = "0".repeat(64);
        let value =
            supported_contract_header(Some(&format!("{previous},{LIFECYCLE_CONTRACT_SHA256}")))
                .unwrap();
        assert_eq!(
            value.to_str().unwrap(),
            format!("{previous},{LIFECYCLE_CONTRACT_SHA256}")
        );
        assert!(supported_contract_header(Some(&previous)).is_err());
    }
}
