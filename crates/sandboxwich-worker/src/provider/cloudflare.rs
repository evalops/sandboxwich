use super::*;
use sandboxwich_core::lifecycle_contract::LifecycleReasonCode;
use sandboxwich_core::{JobId, ProviderPreference};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

const MAX_BRIDGE_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_SSE_LINE_BYTES: usize = 64 * 1024;
const MAX_SSE_EVENT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_COMMAND_OUTPUT_BYTES: usize = 8 * 1024;
pub(crate) const CLOUDFLARE_REPLAY_LEDGER_CONFIGURED_ENV: &str =
    "SANDBOXWICH_CLOUDFLARE_REPLAY_LEDGER_CONFIGURED";

pub(crate) fn create_idempotency_key(sandbox_id: SandboxId) -> String {
    format!("sandboxwich-create-{sandbox_id}")
}

#[derive(Clone)]
pub struct CloudflareConfig {
    pub base_url: String,
    pub api_token: String,
    pub request_timeout: Duration,
    pub readiness_timeout: Duration,
    pub replay_ledger_configured: bool,
}

impl std::fmt::Debug for CloudflareConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudflareConfig")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("request_timeout", &self.request_timeout)
            .field("readiness_timeout", &self.readiness_timeout)
            .field("replay_ledger_configured", &self.replay_ledger_configured)
            .finish()
    }
}

impl CloudflareConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_map(|name| std::env::var(name).ok())
    }

    fn from_map(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let base_url = get("SANDBOXWICH_CLOUDFLARE_SANDBOX_URL")
            .context("SANDBOXWICH_CLOUDFLARE_SANDBOX_URL is required")?;
        let api_token = get("SANDBOXWICH_CLOUDFLARE_SANDBOX_TOKEN")
            .context("SANDBOXWICH_CLOUDFLARE_SANDBOX_TOKEN is required")?;
        anyhow::ensure!(
            !base_url.trim().is_empty(),
            "Cloudflare Bridge URL is empty"
        );
        anyhow::ensure!(
            !api_token.trim().is_empty(),
            "Cloudflare Bridge token is empty"
        );
        let replay_ledger_configured = match get(CLOUDFLARE_REPLAY_LEDGER_CONFIGURED_ENV)
            .as_deref()
            .map(str::trim)
        {
            None | Some("") | Some("false") => false,
            Some("true") => true,
            Some(_) => {
                anyhow::bail!("{CLOUDFLARE_REPLAY_LEDGER_CONFIGURED_ENV} must be true or false")
            }
        };
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token,
            request_timeout: Duration::from_secs(30),
            readiness_timeout: Duration::from_secs(60),
            replay_ledger_configured,
        })
    }
}

#[derive(Debug)]
struct CloudflareHttpError {
    status: u16,
    code: String,
}

impl std::fmt::Display for CloudflareHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cloudflare Bridge HTTP {} {}", self.status, self.code)
    }
}

impl std::error::Error for CloudflareHttpError {}

#[derive(Clone, Debug)]
struct BridgeSandbox {
    external_id: String,
    routing_scope: String,
}

#[derive(Clone, Debug)]
pub(crate) struct BridgeExecResult {
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

trait CloudflareBridge: Send + Sync {
    fn create(
        &self,
        sandbox_id: SandboxId,
        home_id: Option<HomeId>,
        spec: &SandboxProvisionSpec,
        create_key: &str,
    ) -> anyhow::Result<BridgeSandbox>;
    fn ready(&self, external_id: &str, routing_scope: &str) -> anyhow::Result<bool>;
    fn exec(
        &self,
        external_id: &str,
        routing_scope: &str,
        command_id: JobId,
        request: &AgentCommandRequest,
    ) -> anyhow::Result<BridgeExecResult>;
    fn delete(&self, external_id: &str, routing_scope: &str) -> anyhow::Result<()>;
    fn delete_recover(&self, external_id: &str, tenant_hint: &str) -> anyhow::Result<()>;
    fn health(&self) -> anyhow::Result<()>;
}

#[derive(Clone)]
struct HttpCloudflareBridge {
    config: CloudflareConfig,
    client: reqwest::Client,
    /// Owned runtime is only created when constructed *outside* an existing
    /// Tokio context (sync tests / non-async callers).
    ///
    /// When the worker runs under `#[tokio::main]`, we must not create a nested
    /// `Runtime`: dropping it from the outer async stack panics with
    /// "Cannot drop a runtime in a context where blocking is not allowed",
    /// which is exactly how production `sandboxwich-cloudflare-worker` crash-
    /// looped after capability registration started constructing a temporary
    /// Cloudflare provider during `run`.
    owned_runtime: Option<Arc<tokio::runtime::Runtime>>,
}

impl HttpCloudflareBridge {
    fn new(config: CloudflareConfig) -> anyhow::Result<Self> {
        let owned_runtime = match tokio::runtime::Handle::try_current() {
            Ok(_) => None,
            Err(_) => Some(Arc::new(
                tokio::runtime::Runtime::new()
                    .context("failed to create Cloudflare Bridge runtime")?,
            )),
        };
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .context("failed to build Cloudflare Bridge client")?;
        Ok(Self {
            config,
            client,
            owned_runtime,
        })
    }

    fn block_on<T>(
        &self,
        future: impl std::future::Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        if let Some(runtime) = &self.owned_runtime {
            return runtime.block_on(future);
        }
        // Already inside the worker's multi-thread runtime: drive the future on
        // the current handle. `block_in_place` keeps the outer runtime responsive
        // while the sync SandboxProvider trait blocks on bridge I/O.
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        routing_scope: &str,
    ) -> anyhow::Result<reqwest::RequestBuilder> {
        let (organization_id, workspace_id) = split_tenant_scope(routing_scope)
            .context("Cloudflare tenant scope must be exactly organization:workspace")?;
        Ok(self
            .client
            .request(method, api_endpoint(&self.config.base_url, path))
            .bearer_auth(&self.config.api_token)
            .header("x-organization-id", organization_id)
            .header("x-workspace-id", workspace_id))
    }

    fn routing_scope(spec: &SandboxProvisionSpec) -> anyhow::Result<String> {
        let scope = spec
            .provider_routing_scope
            .as_deref()
            .context("Cloudflare provider routing scope is required")?;
        split_tenant_scope(scope)
            .context("Cloudflare provider routing scope must be exactly organization:workspace")?;
        Ok(scope.to_string())
    }

    fn recovery_request(
        &self,
        method: reqwest::Method,
        path: &str,
        external_id: &str,
        tenant_hint: &str,
    ) -> anyhow::Result<reqwest::RequestBuilder> {
        anyhow::ensure!(
            !tenant_hint.trim().is_empty() && !tenant_hint.chars().any(char::is_whitespace),
            "Cloudflare recovery tenant hint is required"
        );
        Ok(self
            .client
            .request(method, api_endpoint(&self.config.base_url, path))
            .bearer_auth(&self.config.api_token)
            .header("x-sandboxwich-recover-identity", "stored")
            .header("x-sandboxwich-sandbox-id", external_id)
            .header("x-sandboxwich-recovery-tenant", tenant_hint))
    }

    async fn response_body(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
        let status = response.status();
        let bytes = bounded_response_bytes(&mut response).await?;
        if !status.is_success() {
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
            let code = value
                .get("code")
                .and_then(Value::as_str)
                .map(safe_bridge_code)
                .unwrap_or_else(|| "http_error".into());
            return Err(anyhow::Error::new(CloudflareHttpError {
                status: status.as_u16(),
                code,
            }));
        }
        Ok(bytes)
    }
}

pub(crate) async fn bounded_response_bytes(
    response: &mut reqwest::Response,
) -> anyhow::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BRIDGE_BODY_BYTES as u64)
    {
        anyhow::bail!("Cloudflare Bridge response exceeds bounded body limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Cloudflare Bridge response read failed")?
    {
        anyhow::ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_BRIDGE_BODY_BYTES,
            "Cloudflare Bridge response exceeds bounded body limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) fn safe_bridge_code(code: &str) -> String {
    if !code.is_empty()
        && code.len() <= 96
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        code.to_owned()
    } else {
        "http_error".into()
    }
}

impl CloudflareBridge for HttpCloudflareBridge {
    fn create(
        &self,
        sandbox_id: SandboxId,
        home_id: Option<HomeId>,
        spec: &SandboxProvisionSpec,
        create_key: &str,
    ) -> anyhow::Result<BridgeSandbox> {
        let scope = Self::routing_scope(spec)?;
        let body = json!({
            "sandboxId": sandbox_id,
            "homeId": home_id,
            "tenantId": scope,
            "memoryLimit": spec.memory_limit,
            "networkEgress": spec.network_egress,
        });
        let response = self.block_on(async {
            self.request(reqwest::Method::POST, "/sandbox", &scope)?
                .header("idempotency-key", create_key)
                .header("x-sandboxwich-sandbox-id", sandbox_id.to_string())
                .json(&body)
                .send()
                .await
                .context("Cloudflare Bridge request failed")
        })?;
        let bytes = self.block_on(Self::response_body(response))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context("Cloudflare create response is not JSON")?;
        let external_id = ["id", "sandboxId", "sandbox_id", "externalId"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
            .filter(|id| !id.is_empty())
            .context("Cloudflare create response is missing external sandbox id")?
            .to_string();
        Ok(BridgeSandbox {
            external_id,
            routing_scope: scope,
        })
    }

    fn ready(&self, external_id: &str, routing_scope: &str) -> anyhow::Result<bool> {
        let path = format!("/sandbox/{external_id}/running");
        let response = self.block_on(async {
            self.request(reqwest::Method::GET, &path, routing_scope)?
                .send()
                .await
                .context("Cloudflare Bridge request failed")
        })?;
        let bytes = self.block_on(Self::response_body(response))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context("Cloudflare readiness response is not JSON")?;
        Ok(value
            .get("running")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || value.get("ready").and_then(Value::as_bool).unwrap_or(false)
            || value
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| matches!(status, "running" | "ready")))
    }

    fn exec(
        &self,
        external_id: &str,
        routing_scope: &str,
        command_id: JobId,
        request: &AgentCommandRequest,
    ) -> anyhow::Result<BridgeExecResult> {
        let path = format!("/sandbox/{external_id}/exec");
        let mut response = self.block_on(async {
            self.request(reqwest::Method::POST, &path, routing_scope)?
                .header("x-sandboxwich-command-id", command_id.to_string())
                .header("idempotency-key", command_id.to_string())
                .json(request)
                .send()
                .await
                .context("Cloudflare Bridge request failed")
        })?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        if content_type.contains("text/event-stream") {
            return self.block_on(async {
                let mut parser = SseParser::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .context("Cloudflare Bridge SSE response read failed")?
                {
                    parser.push(&chunk)?;
                }
                parser.finish()
            });
        }
        let bytes = self.block_on(Self::response_body(response))?;
        parse_exec_response(&bytes, false)
    }

    fn delete(&self, external_id: &str, routing_scope: &str) -> anyhow::Result<()> {
        let path = format!("/sandbox/{external_id}");
        let response = self.block_on(async {
            self.request(reqwest::Method::DELETE, &path, routing_scope)?
                .send()
                .await
                .context("Cloudflare Bridge request failed")
        });
        match response {
            Ok(response) => match self.block_on(Self::response_body(response)) {
                Ok(_) => Ok(()),
                Err(error)
                    if error
                        .downcast_ref::<CloudflareHttpError>()
                        .is_some_and(|e| e.status == 404) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }

    fn delete_recover(&self, external_id: &str, tenant_hint: &str) -> anyhow::Result<()> {
        let path = format!("/sandbox/{external_id}");
        let response = self.block_on(async {
            self.recovery_request(reqwest::Method::DELETE, &path, external_id, tenant_hint)?
                .send()
                .await
                .context("Cloudflare Bridge recovery request failed")
        });
        match response {
            Ok(response) => match self.block_on(Self::response_body(response)) {
                Ok(_) => Ok(()),
                Err(error)
                    if error
                        .downcast_ref::<CloudflareHttpError>()
                        .is_some_and(|e| e.status == 404) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }

    fn health(&self) -> anyhow::Result<()> {
        let response = self.block_on(async {
            self.client
                .request(reqwest::Method::GET, health_endpoint(&self.config.base_url))
                .bearer_auth(&self.config.api_token)
                .send()
                .await
                .context("Cloudflare Bridge request failed")
        })?;
        self.block_on(Self::response_body(response)).map(|_| ())
    }
}

fn base_root(base_url: &str) -> &str {
    let trimmed = base_url.trim().trim_end_matches('/');
    trimmed.strip_suffix("/v1").unwrap_or(trimmed)
}

pub(crate) fn api_endpoint(base_url: &str, path: &str) -> String {
    format!("{}/v1{}", base_root(base_url), path)
}

pub(crate) fn health_endpoint(base_url: &str) -> String {
    format!("{}/health", base_root(base_url))
}

fn parse_exec_response(bytes: &[u8], sse: bool) -> anyhow::Result<BridgeExecResult> {
    if !sse {
        anyhow::ensure!(
            bytes.len() <= MAX_BRIDGE_BODY_BYTES,
            "Cloudflare exec response exceeds bounded body limit"
        );
        let value: serde_json::Value =
            serde_json::from_slice(bytes).context("Cloudflare exec response is not JSON")?;
        return Ok(BridgeExecResult {
            exit_code: value
                .get("exitCode")
                .or_else(|| value.get("exit_code"))
                .and_then(Value::as_i64)
                .map(|code| code as i32),
            stdout: capped_output(
                value
                    .get("stdout")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            stderr: capped_output(
                value
                    .get("stderr")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
        });
    }
    parse_sse_command_chunks(&[bytes]).map_err(|error| anyhow::anyhow!(error))
}

pub(crate) fn split_tenant_scope(scope: &str) -> Option<(&str, &str)> {
    let (organization, workspace) = scope.split_once(':')?;
    if organization.is_empty() || workspace.is_empty() || workspace.contains(':') {
        return None;
    }
    if organization.chars().any(char::is_whitespace) || workspace.chars().any(char::is_whitespace) {
        return None;
    }
    Some((organization, workspace))
}

fn capped_output(value: &str) -> String {
    let bytes = value.as_bytes();
    let end = bytes.len().min(MAX_COMMAND_OUTPUT_BYTES);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

struct SseParser {
    line: Vec<u8>,
    event: String,
    data: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
}

impl SseParser {
    fn new() -> Self {
        Self {
            line: Vec::new(),
            event: String::new(),
            data: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
        }
    }
    fn push(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        for byte in bytes {
            if *byte == b'\n' {
                self.process_line()?;
            } else {
                anyhow::ensure!(
                    self.line.len() < MAX_SSE_LINE_BYTES,
                    "Cloudflare exec SSE line exceeds bounded limit"
                );
                self.line.push(*byte);
            }
        }
        Ok(())
    }
    fn process_line(&mut self) -> anyhow::Result<()> {
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        if self.line.is_empty() {
            self.process_event()?;
            self.event.clear();
            self.data.clear();
        } else if let Ok(line) = std::str::from_utf8(&self.line) {
            if let Some(value) = line.strip_prefix("event:") {
                self.event = value.trim().to_owned();
            }
            if let Some(value) = line.strip_prefix("data:") {
                anyhow::ensure!(
                    self.data.len().saturating_add(value.trim().len()) <= MAX_SSE_EVENT_BYTES,
                    "Cloudflare exec SSE event exceeds bounded limit"
                );
                self.data.extend_from_slice(value.trim().as_bytes());
            }
        } else {
            anyhow::bail!("Cloudflare exec SSE was not UTF-8");
        }
        self.line.clear();
        Ok(())
    }
    fn process_event(&mut self) -> anyhow::Result<()> {
        match self.event.as_str() {
            "stdout" | "stderr" => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&self.data)
                    .context("Cloudflare exec SSE output invalid")?;
                let target = if self.event == "stdout" {
                    &mut self.stdout
                } else {
                    &mut self.stderr
                };
                let retained = MAX_COMMAND_OUTPUT_BYTES
                    .saturating_sub(target.len())
                    .min(decoded.len());
                target.extend_from_slice(&decoded[..retained]);
            }
            "exit" => {
                self.exit_code = serde_json::from_slice::<serde_json::Value>(&self.data)
                    .ok()
                    .and_then(|v| v.get("exit_code").and_then(Value::as_i64))
                    .map(|v| v as i32);
                anyhow::ensure!(self.exit_code.is_some(), "Cloudflare exec SSE exit invalid");
            }
            "error" => anyhow::bail!("Cloudflare exec failed"),
            _ => {}
        }
        Ok(())
    }
    fn finish(mut self) -> anyhow::Result<BridgeExecResult> {
        if !self.line.is_empty() {
            self.process_line()?;
        }
        if !self.event.is_empty() || !self.data.is_empty() {
            self.process_event()?;
        }
        anyhow::ensure!(self.exit_code.is_some(), "Cloudflare exec SSE omitted exit");
        Ok(BridgeExecResult {
            exit_code: self.exit_code,
            stdout: String::from_utf8_lossy(&self.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.stderr).into_owned(),
        })
    }
}

pub(crate) fn parse_sse_command_chunks(chunks: &[&[u8]]) -> anyhow::Result<BridgeExecResult> {
    let mut parser = SseParser::new();
    for chunk in chunks {
        parser.push(chunk)?;
    }
    parser.finish()
}

#[derive(Clone)]
pub struct CloudflareSandboxProvider {
    bridge: Arc<dyn CloudflareBridge>,
    readiness_timeout: Duration,
    replay_ledger_configured: bool,
}

impl CloudflareSandboxProvider {
    pub fn new(config: CloudflareConfig) -> anyhow::Result<Self> {
        let readiness_timeout = config.readiness_timeout;
        let replay_ledger_configured = config.replay_ledger_configured;
        Ok(Self {
            bridge: Arc::new(HttpCloudflareBridge::new(config)?),
            readiness_timeout,
            replay_ledger_configured,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            bridge: Arc::new(FakeBridge::default()),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_replay_ledger() -> Self {
        Self {
            bridge: Arc::new(FakeBridge::default()),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: true,
        }
    }

    fn provider_error(error: anyhow::Error) -> anyhow::Error {
        if let Some(http) = error.downcast_ref::<CloudflareHttpError>() {
            if http.code == "capacity_exceeded" || http.status == 429 {
                return anyhow::Error::new(ProviderError::classified(
                    ProvisioningErrorClass::RetryableCapacity,
                    LifecycleReasonCode::WorkspaceCapacityPending,
                    error,
                ));
            }
            let terminal = match http.status {
                401 | 403 => Some((
                    ProvisioningErrorClass::TerminalSecurity,
                    LifecycleReasonCode::KubernetesPolicyDenied,
                )),
                409 => Some((
                    ProvisioningErrorClass::TerminalContract,
                    LifecycleReasonCode::ResourceIdentityConflict,
                )),
                400 | 422 => Some((
                    ProvisioningErrorClass::TerminalContract,
                    LifecycleReasonCode::ResourceContractConflict,
                )),
                _ => None,
            };
            if let Some((error_class, reason_code)) = terminal {
                return anyhow::Error::new(ProviderError::classified(
                    error_class,
                    reason_code,
                    error,
                ));
            }
        }
        anyhow::Error::new(ProviderError::retryable(error))
    }

    fn provision_with_home(
        &self,
        sandbox_id: SandboxId,
        home_id: Option<HomeId>,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        anyhow::ensure!(
            spec.provider_preference == ProviderPreference::Cloudflare,
            "Cloudflare worker received a non-Cloudflare placement request"
        );
        let routing_scope = spec
            .provider_routing_scope
            .as_deref()
            .filter(|scope| split_tenant_scope(scope).is_some())
            .ok_or_else(|| {
                anyhow::Error::new(ProviderError::classified(
                    ProvisioningErrorClass::TerminalContract,
                    LifecycleReasonCode::ResourceContractConflict,
                    anyhow::anyhow!(
                        "Cloudflare provider routing scope must be exactly organization:workspace"
                    ),
                ))
            })?;
        debug_assert!(!routing_scope.is_empty());
        anyhow::ensure!(!cancelled.is_cancelled(), "Cloudflare provision cancelled");
        let create_key = create_idempotency_key(sandbox_id);
        let sandbox = self
            .bridge
            .create(sandbox_id, home_id, spec, &create_key)
            .map_err(|error| {
                if error.downcast_ref::<CloudflareHttpError>().is_some() {
                    Self::provider_error(error)
                } else {
                    anyhow::Error::new(ProviderError::retryable(anyhow::anyhow!(
                        "cloudflare_create_outcome_unknown"
                    )))
                }
            })?;
        if sandbox.external_id != sandbox_id.to_string() {
            self.bridge
                .delete(&sandbox.external_id, &sandbox.routing_scope)
                .map_err(Self::provider_error)?;
            anyhow::bail!(
                "Cloudflare Bridge external identity does not match the requested sandbox identity"
            );
        }
        let started = Instant::now();
        while started.elapsed() < self.readiness_timeout {
            anyhow::ensure!(!cancelled.is_cancelled(), "Cloudflare provision cancelled");
            match self
                .bridge
                .ready(&sandbox.external_id, &sandbox.routing_scope)
                .map_err(Self::provider_error)?
            {
                true => {
                    let resource = ProviderRuntimeResource {
                        sandbox_id,
                        snapshot_id: None,
                        provider: "cloudflare".to_string(),
                        resource_kind: RuntimeResourceKind::Pod,
                        purpose: RuntimeResourcePurpose::Runtime,
                        resource_name: sandbox.external_id.clone(),
                        namespace: sandbox.routing_scope.clone(),
                        status: RuntimeResourceStatus::Ready,
                        cluster: None,
                        storage_class: None,
                        snapshot_class: None,
                        storage_size: None,
                        runtime_image: None,
                        service_port: None,
                        target_port: None,
                        source_snapshot_id: None,
                        ready_at: Some(Utc::now()),
                        error: None,
                    };
                    let mut metadata = json!({
                        "externalId": sandbox.external_id,
                        "routingScope": sandbox.routing_scope,
                    });
                    if let Some(home_id) = home_id {
                        metadata["homeId"] = json!(home_id);
                    }
                    return Ok(ProviderSandboxHandle {
                        provider: "cloudflare".to_string(),
                        sandbox_id,
                        resources: vec![resource],
                        metadata,
                    });
                }
                false => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        Err(
            ProviderError::retryable(anyhow::anyhow!("Cloudflare sandbox readiness timed out"))
                .into(),
        )
    }
}

impl SandboxProvider for CloudflareSandboxProvider {
    fn provider_name(&self) -> &'static str {
        "cloudflare"
    }

    fn capability_report(&self) -> ProviderCapabilityReport {
        let mut capabilities = vec![WorkerCapability::ProvisionSandbox];
        if self.replay_ledger_configured {
            capabilities.push(WorkerCapability::RunCommand);
        }
        ProviderCapabilityReport {
            provider: "cloudflare".to_string(),
            capabilities,
            labels: BTreeMap::new(),
        }
    }

    fn health_report(&self) -> ProviderHealthReport {
        let result = self.bridge.health();
        ProviderHealthReport {
            provider: "cloudflare".to_string(),
            status: if result.is_ok() {
                ProviderHealthStatus::Healthy
            } else {
                ProviderHealthStatus::Degraded
            },
            checked_at: Utc::now(),
            labels: BTreeMap::new(),
            message: result.err().map(|error| error.to_string()),
        }
    }

    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        self.provision_with_home(sandbox_id, None, spec, cancelled)
    }

    fn provision_home_staged(
        &self,
        sandbox_id: SandboxId,
        home_id: HomeId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        anyhow::ensure!(
            spec.workspace_mode == WorkspaceMode::Persistent,
            "managed Cloudflare homes require persistent workspace mode"
        );
        let handle = self.provision_with_home(sandbox_id, Some(home_id), spec, cancelled)?;
        report(stage_update(ProvisioningStage::SandboxReady, None))?;
        Ok(handle)
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        self.exec_handoff_with_job_id(sandbox_id, JobId(sandbox_id.0), spec, request, cancelled)
    }

    fn exec_handoff_with_job_id(
        &self,
        _sandbox_id: SandboxId,
        job_id: JobId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        validate_agent_command_request(&request)?;
        anyhow::ensure!(!cancelled.is_cancelled(), "Cloudflare exec cancelled");
        anyhow::ensure!(
            self.replay_ledger_configured,
            "Cloudflare command execution requires a durable replay ledger"
        );
        let external_id = spec
            .provider_external_id
            .as_deref()
            .context("Cloudflare exec requires persisted external sandbox identity")?;
        let routing_scope = spec
            .provider_routing_scope
            .as_deref()
            .context("Cloudflare exec requires persisted routing scope")?;
        let started_at = Utc::now();
        let result = self
            .bridge
            .exec(external_id, routing_scope, job_id, &request)
            .map_err(Self::provider_error)?;
        Ok(AgentCommandResult {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            started_at,
            finished_at: Utc::now(),
        })
    }

    fn create_snapshot(
        &self,
        _sandbox_id: SandboxId,
        _snapshot_id: SnapshotId,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSnapshotHandle> {
        anyhow::bail!("Cloudflare provider does not support snapshots")
    }
    fn fork(
        &self,
        _parent_sandbox_id: SandboxId,
        _child_sandbox_id: SandboxId,
        _snapshot_id: SnapshotId,
        _spec: &SandboxProvisionSpec,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderForkHandle> {
        anyhow::bail!("Cloudflare provider does not support fork")
    }
    fn stop(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        // Provision rejects any Bridge identity that differs from this stable
        // control-plane ID. That makes the fallback safe after a create
        // response is lost before its runtime-resource row can be persisted.
        let stable_external_id = sandbox_id.to_string();
        let external_id = spec
            .provider_external_id
            .as_deref()
            .unwrap_or(&stable_external_id);
        let routing_scope = spec
            .provider_routing_scope
            .as_deref()
            .context("Cloudflare stop requires persisted routing scope or tenant hint")?;
        if split_tenant_scope(routing_scope).is_some() {
            self.bridge
                .delete(external_id, routing_scope)
                .map_err(Self::provider_error)
        } else {
            self.bridge
                .delete_recover(&stable_external_id, routing_scope)
                .map_err(Self::provider_error)
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct FakeBridge {
    calls: Mutex<Vec<String>>,
    create_external_id: Option<String>,
    delete_fails: bool,
}

#[cfg(test)]
impl CloudflareBridge for FakeBridge {
    fn create(
        &self,
        sandbox_id: SandboxId,
        _home_id: Option<HomeId>,
        spec: &SandboxProvisionSpec,
        _create_key: &str,
    ) -> anyhow::Result<BridgeSandbox> {
        self.calls.lock().unwrap().push("create".into());
        Ok(BridgeSandbox {
            external_id: self
                .create_external_id
                .clone()
                .unwrap_or_else(|| sandbox_id.to_string()),
            routing_scope: spec
                .provider_routing_scope
                .as_deref()
                .unwrap_or("missing")
                .to_string(),
        })
    }
    fn ready(&self, external_id: &str, _routing_scope: &str) -> anyhow::Result<bool> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("ready:{external_id}"));
        Ok(true)
    }
    fn exec(
        &self,
        external_id: &str,
        routing_scope: &str,
        _command_id: JobId,
        _request: &AgentCommandRequest,
    ) -> anyhow::Result<BridgeExecResult> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("exec:{external_id}:{routing_scope}"));
        Ok(BridgeExecResult {
            exit_code: Some(0),
            stdout: "ok".into(),
            stderr: String::new(),
        })
    }
    fn delete(&self, external_id: &str, routing_scope: &str) -> anyhow::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("delete:{external_id}:{routing_scope}"));
        if self.delete_fails {
            anyhow::bail!("bridge unavailable");
        }
        Ok(())
    }
    fn delete_recover(&self, external_id: &str, tenant_hint: &str) -> anyhow::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("delete-recover:{external_id}:{tenant_hint}"));
        if self.delete_fails {
            anyhow::bail!("bridge unavailable");
        }
        Ok(())
    }
    fn health(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_managed_home_is_attached_to_replacement_runtime() {
        let provider = CloudflareSandboxProvider::for_test_with_replay_ledger();
        let sandbox_id = SandboxId::new();
        let home_id = HomeId::new();
        let spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("org:workspace".into()),
            provider_routing_scope: Some("org:workspace".into()),
            workspace_mode: WorkspaceMode::Persistent,
            ..Default::default()
        };
        let mut stages = Vec::new();

        let handle = provider
            .provision_home_staged(
                sandbox_id,
                home_id,
                &spec,
                &CancelSignal::never_cancelled(),
                &mut |update| {
                    stages.push(update.stage);
                    Ok(())
                },
            )
            .expect("Cloudflare must attach a managed home to a replacement runtime");

        assert_eq!(handle.sandbox_id, sandbox_id);
        assert_eq!(handle.metadata["homeId"], home_id.to_string());
        assert_eq!(stages.last(), Some(&ProvisioningStage::SandboxReady));
    }

    #[test]
    fn cloudflare_create_uses_provider_routing_scope_not_control_plane_tenant() {
        let provider = CloudflareSandboxProvider::for_test_with_replay_ledger();
        let spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("evalops-platform".into()),
            provider_routing_scope: Some("org_1:workspace_1".into()),
            workspace_mode: WorkspaceMode::Persistent,
            ..Default::default()
        };

        let handle = provider
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .expect("authenticated control-plane tenant and provider routing scope are distinct");

        assert_eq!(handle.resources[0].namespace, "org_1:workspace_1");
    }

    #[test]
    fn cloudflare_missing_provider_routing_scope_is_terminal_contract_failure_before_create() {
        let provider = CloudflareSandboxProvider::for_test_with_replay_ledger();
        let spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("evalops-platform".into()),
            workspace_mode: WorkspaceMode::Persistent,
            ..Default::default()
        };

        let error = provider
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .expect_err("missing routing scope must fail before a bridge request");
        let provider_error = error.downcast_ref::<ProviderError>().unwrap();
        assert_eq!(
            provider_error.error_class(),
            ProvisioningErrorClass::TerminalContract
        );
        assert_eq!(provider_error.reason_code(), "resource_contract_conflict");
        assert!(error.to_string().contains("provider routing scope"));
    }

    #[test]
    fn cloudflare_command_capability_requires_durable_ledger_binding_marker() {
        let base = |name: &str| match name {
            "SANDBOXWICH_CLOUDFLARE_SANDBOX_URL" => Some("https://bridge.example".to_string()),
            "SANDBOXWICH_CLOUDFLARE_SANDBOX_TOKEN" => Some("secret".to_string()),
            _ => None,
        };
        let without_binding = CloudflareConfig::from_map(base).unwrap();
        assert!(!without_binding.replay_ledger_configured);
        assert!(
            !CloudflareSandboxProvider::new(without_binding)
                .unwrap()
                .capability_report()
                .capabilities
                .contains(&WorkerCapability::RunCommand)
        );

        let with_binding = CloudflareConfig::from_map(|name| match name {
            "SANDBOXWICH_CLOUDFLARE_SANDBOX_URL" => Some("https://bridge.example".to_string()),
            "SANDBOXWICH_CLOUDFLARE_SANDBOX_TOKEN" => Some("secret".to_string()),
            "SANDBOXWICH_CLOUDFLARE_REPLAY_LEDGER_CONFIGURED" => Some("true".to_string()),
            _ => None,
        })
        .unwrap();
        assert!(with_binding.replay_ledger_configured);
        assert!(
            CloudflareSandboxProvider::new(with_binding)
                .unwrap()
                .capability_report()
                .capabilities
                .contains(&WorkerCapability::RunCommand)
        );

        assert!(
            CloudflareConfig::from_map(|name| match name {
                "SANDBOXWICH_CLOUDFLARE_SANDBOX_URL" => Some("https://bridge.example".to_string()),
                "SANDBOXWICH_CLOUDFLARE_SANDBOX_TOKEN" => Some("secret".to_string()),
                "SANDBOXWICH_CLOUDFLARE_REPLAY_LEDGER_CONFIGURED" => Some("yes".to_string()),
                _ => None,
            })
            .is_err()
        );
    }

    #[test]
    fn cloudflare_http_bridge_keeps_runtime_alive_while_reading_response_body() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let sandbox_id = SandboxId::new();
        let response_body = format!(r#"{{"id":"{sandbox_id}"}}"#);
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let request_len = stream.read(&mut request).unwrap();
            request_tx
                .send(String::from_utf8_lossy(&request[..request_len]).into_owned())
                .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            )
            .unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            stream.write_all(response_body.as_bytes()).unwrap();
        });
        let bridge = HttpCloudflareBridge::new(CloudflareConfig {
            base_url: format!("http://{address}"),
            api_token: "secret".into(),
            request_timeout: Duration::from_secs(2),
            readiness_timeout: Duration::from_secs(2),
            replay_ledger_configured: true,
        })
        .unwrap();
        let spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("evalops-platform".into()),
            provider_routing_scope: Some("org:workspace".into()),
            ..Default::default()
        };

        let created = bridge
            .create(sandbox_id, None, &spec, "stable-create-key")
            .expect("response body must remain readable after response headers arrive");
        assert_eq!(created.external_id, sandbox_id.to_string());
        let request = request_rx.recv().unwrap().to_ascii_lowercase();
        assert!(request.contains("x-organization-id: org"));
        assert!(request.contains("x-workspace-id: workspace"));
        assert!(request.contains("\"tenantid\":\"org:workspace\""));
        assert!(!request.contains("\"tenantid\":\"evalops-platform\""));
        server.join().unwrap();
    }

    /// Regression for production crash-loop: constructing (and dropping) a
    /// Cloudflare provider from inside `#[tokio::main]` used to create a nested
    /// Runtime and panic on drop during capability registration.
    #[test]
    fn cloudflare_provider_construct_and_drop_inside_async_runtime_does_not_panic() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            // Mirrors registration_provider_capability_report: temporary
            // provider built on the async stack for a capability snapshot.
            let report = {
                let provider = CloudflareSandboxProvider::new(CloudflareConfig {
                    base_url: "https://bridge.example".into(),
                    api_token: "secret".into(),
                    request_timeout: Duration::from_secs(1),
                    readiness_timeout: Duration::from_secs(1),
                    replay_ledger_configured: true,
                })
                .expect("construct inside async context");
                let report = provider.capability_report();
                drop(provider);
                report
            };
            assert_eq!(report.provider, "cloudflare");
            assert!(
                report
                    .capabilities
                    .contains(&WorkerCapability::ProvisionSandbox),
                "capability report should list provision without panicking on drop"
            );
            assert!(
                report.capabilities.contains(&WorkerCapability::RunCommand),
                "ledger-configured provider must advertise run_command"
            );
        });
        // Dropping the outer test runtime after the nested work finishes must
        // also succeed (owned_runtime was None inside the async block).
        drop(runtime);
    }

    #[test]
    fn cloudflare_provision_exec_stop_uses_external_identity_and_tenant_scope() {
        let provider = CloudflareSandboxProvider::for_test_with_replay_ledger();
        let mut spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("org:workspace".into()),
            provider_routing_scope: Some("org:workspace".into()),
            ..Default::default()
        };
        let handle = provider
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .unwrap();
        let resource = &handle.resources[0];
        spec.provider_external_id = Some(resource.resource_name.clone());
        spec.provider_routing_scope = Some(resource.namespace.clone());
        let request = AgentCommandRequest {
            argv: vec!["true".into()],
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
            timeout_secs: None,
        };
        let result = provider
            .exec_handoff_with_job_id(
                SandboxId::new(),
                JobId::new(),
                &spec,
                request,
                &CancelSignal::never_cancelled(),
            )
            .unwrap();
        assert_eq!(result.stdout, "ok");
        provider
            .stop(
                SandboxId::new(),
                &SandboxTeardownSpec {
                    delete_gke_fqdn_policy: false,
                    provider_external_id: spec.provider_external_id,
                    provider_routing_scope: spec.provider_routing_scope,
                },
                &CancelSignal::never_cancelled(),
            )
            .unwrap();
    }

    #[test]
    fn cloudflare_capacity_exceeded_is_retryable_capacity() {
        let error =
            CloudflareSandboxProvider::provider_error(anyhow::Error::new(CloudflareHttpError {
                status: 503,
                code: "capacity_exceeded".into(),
            }));
        let provider_error = error.downcast_ref::<ProviderError>().unwrap();
        assert_eq!(
            provider_error.error_class(),
            ProvisioningErrorClass::RetryableCapacity
        );
        assert_eq!(provider_error.reason_code(), "workspace_capacity_pending");
    }

    #[test]
    fn cloudflare_contract_rejections_are_permanent() {
        for status in [400, 401, 403, 409] {
            let error = CloudflareSandboxProvider::provider_error(anyhow::Error::new(
                CloudflareHttpError {
                    status,
                    code: "recovery_contract_rejected".into(),
                },
            ));
            let provider_error = error.downcast_ref::<ProviderError>().unwrap();
            assert_eq!(provider_error.disposition(), RetryDisposition::Permanent);
        }
    }

    #[test]
    fn cloudflare_delete_is_idempotent_at_bridge_boundary() {
        let provider = CloudflareSandboxProvider::for_test();
        provider
            .stop(
                SandboxId::new(),
                &SandboxTeardownSpec {
                    delete_gke_fqdn_policy: false,
                    provider_external_id: Some("cf-external-1".into()),
                    provider_routing_scope: Some("org:workspace".into()),
                },
                &CancelSignal::never_cancelled(),
            )
            .unwrap();
    }

    #[test]
    fn cloudflare_stop_recovers_missing_persisted_identity_from_durable_scope() {
        let bridge = Arc::new(FakeBridge::default());
        let provider = CloudflareSandboxProvider {
            bridge: bridge.clone(),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: true,
        };
        let sandbox_id = SandboxId::new();

        provider
            .stop(
                sandbox_id,
                &SandboxTeardownSpec {
                    delete_gke_fqdn_policy: false,
                    provider_external_id: None,
                    provider_routing_scope: Some("org:workspace".into()),
                },
                &CancelSignal::never_cancelled(),
            )
            .expect("stable Cloudflare identity must remain teardown-capable after a lost create response");

        assert_eq!(
            bridge.calls.lock().unwrap().as_slice(),
            [format!("delete:{sandbox_id}:org:workspace")]
        );
    }

    #[test]
    fn cloudflare_stop_recovers_legacy_tenant_from_bridge_stored_identity() {
        let bridge = Arc::new(FakeBridge::default());
        let provider = CloudflareSandboxProvider {
            bridge: bridge.clone(),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: true,
        };
        let sandbox_id = SandboxId::new();

        provider
            .stop(
                sandbox_id,
                &SandboxTeardownSpec {
                    delete_gke_fqdn_policy: false,
                    provider_external_id: None,
                    provider_routing_scope: Some("evalops-platform".into()),
                },
                &CancelSignal::never_cancelled(),
            )
            .expect("legacy tenant hints must recover the stored bridge identity");

        assert_eq!(
            bridge.calls.lock().unwrap().as_slice(),
            [format!("delete-recover:{sandbox_id}:evalops-platform")]
        );
    }

    #[test]
    fn cloudflare_stop_keeps_bridge_failures_retryable_after_identity_recovery() {
        let provider = CloudflareSandboxProvider {
            bridge: Arc::new(FakeBridge {
                calls: Mutex::new(Vec::new()),
                create_external_id: None,
                delete_fails: true,
            }),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: true,
        };
        let error = provider
            .stop(
                SandboxId::new(),
                &SandboxTeardownSpec {
                    delete_gke_fqdn_policy: false,
                    provider_external_id: None,
                    provider_routing_scope: Some("evalops-platform".into()),
                },
                &CancelSignal::never_cancelled(),
            )
            .expect_err("transient bridge deletion failure must remain retryable");
        let provider_error = error
            .downcast_ref::<ProviderError>()
            .expect("bridge error must retain typed provider retry classification");
        assert_eq!(provider_error.disposition(), RetryDisposition::Retryable);
    }

    #[test]
    fn cloudflare_provision_rejects_bridge_identity_drift() {
        let bridge = Arc::new(FakeBridge {
            calls: Mutex::new(Vec::new()),
            create_external_id: Some("different-provider-id".into()),
            delete_fails: false,
        });
        let provider = CloudflareSandboxProvider {
            bridge: bridge.clone(),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: true,
        };
        let spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("org:workspace".into()),
            provider_routing_scope: Some("org:workspace".into()),
            ..Default::default()
        };

        let error = provider
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .expect_err("bridge identity drift would make deterministic teardown unsafe");
        assert!(error.to_string().contains("identity"));
        assert_eq!(
            bridge.calls.lock().unwrap().as_slice(),
            ["create", "delete:different-provider-id:org:workspace"]
        );
    }

    #[test]
    fn cloudflare_identity_drift_cleanup_failure_stays_retryable() {
        let provider = CloudflareSandboxProvider {
            bridge: Arc::new(FakeBridge {
                calls: Mutex::new(Vec::new()),
                create_external_id: Some("different-provider-id".into()),
                delete_fails: true,
            }),
            readiness_timeout: Duration::from_millis(100),
            replay_ledger_configured: true,
        };
        let spec = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("org:workspace".into()),
            provider_routing_scope: Some("org:workspace".into()),
            ..Default::default()
        };

        let error = provider
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .expect_err("failed cleanup must retry until the drifted sandbox is destroyed");
        let provider_error = error
            .downcast_ref::<ProviderError>()
            .expect("cleanup failure must retain typed provider retry classification");
        assert_eq!(provider_error.disposition(), RetryDisposition::Retryable);
    }

    #[test]
    fn cloudflare_requires_tenant_scope_and_reports_readiness() {
        let provider = CloudflareSandboxProvider::for_test();
        let missing_tenant = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            ..Default::default()
        };
        assert!(
            provider
                .provision(
                    SandboxId::new(),
                    &missing_tenant,
                    &CancelSignal::never_cancelled()
                )
                .is_err()
        );

        let scoped = SandboxProvisionSpec {
            provider_preference: ProviderPreference::Cloudflare,
            tenant_id: Some("org:workspace".into()),
            provider_routing_scope: Some("org:workspace".into()),
            ..Default::default()
        };
        let handle = provider
            .provision(SandboxId::new(), &scoped, &CancelSignal::never_cancelled())
            .unwrap();
        assert_eq!(handle.resources[0].status, RuntimeResourceStatus::Ready);
        assert_eq!(handle.resources[0].namespace, "org:workspace");
    }

    #[test]
    fn cloudflare_refuses_snapshot_operations() {
        let provider = CloudflareSandboxProvider::for_test();
        assert!(
            provider
                .create_snapshot(
                    SandboxId::new(),
                    SnapshotId::new(),
                    &CancelSignal::never_cancelled()
                )
                .is_err()
        );

        let resident_spec = IsolatedResidentProcessSpec {
            process_name: "resident".into(),
            sandbox_id: SandboxId::new(),
            process_id: ResidentProcessId::new(),
            generation: 0,
            lease_id: Uuid::new_v4(),
            argv: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            workspace_mode: WorkspaceMode::Ephemeral,
            workspace_claim_name: None,
            bootstrap: None,
        };
        let mut observe = |_observation| Ok(());
        assert!(
            provider
                .run_isolated_resident_process(
                    &resident_spec,
                    &CancelSignal::never_cancelled(),
                    &mut observe,
                )
                .is_err()
        );
    }
}
