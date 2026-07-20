use std::{
    collections::BTreeMap,
    net::IpAddr,
    process::Stdio,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use clap::ValueEnum;
use ipnet::IpNet;
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, DbVariant, ExecutionClass, HomeId,
    MAX_RESIDENT_PROCESS_BOOTSTRAP_BYTES, MAX_SANDBOX_FILE_BYTES, MaterializeFileDestination,
    MaterializeFileObservation, MemoryLimit, NetworkAllowRuleKind, NetworkEgress,
    ORB_SIDECAR_RESIDENT_PROCESS_UID, PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL,
    PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL_VALUE, ProviderCapabilityReport,
    ProviderForkHandle, ProviderHealthReport, ProviderHealthStatus, ProviderRuntimeResource,
    ProviderSandboxHandle, ProviderSnapshotHandle, ProvisioningErrorClass, ProvisioningStage,
    ProvisioningStageUpdateRequest, RESIDENT_PLACEMENT_ATTESTATION_FILE,
    RESIDENT_PROCESS_BOOTSTRAP_PREFIX, ResidentProcessId, RuntimeResourceInventoryResponse,
    RuntimeResourceKind, RuntimeResourcePurpose, RuntimeResourceStatus, SandboxId,
    SandboxProvisionSpec, SandboxRuntimeProfile, SnapshotId, WorkerCapability, WorkspaceMode,
    validate_agent_command_request,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::egress_gateway::EgressGatewayPolicy;

fn sha256_hex(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDisposition {
    Retryable,
    Permanent,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum IsolationProfile {
    #[default]
    Development,
    Gvisor,
    Kata,
}

impl IsolationProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Gvisor => "gvisor",
            Self::Kata => "kata",
        }
    }
}

#[derive(Debug)]
pub struct ProviderError {
    disposition: RetryDisposition,
    error_class: ProvisioningErrorClass,
    reason_code: &'static str,
    source: anyhow::Error,
}

impl ProviderError {
    pub fn retryable(source: impl Into<anyhow::Error>) -> Self {
        Self {
            disposition: RetryDisposition::Retryable,
            error_class: ProvisioningErrorClass::RetryableProvider,
            reason_code: "provider_transient",
            source: source.into(),
        }
    }

    pub fn classified(
        error_class: ProvisioningErrorClass,
        reason_code: &'static str,
        source: impl Into<anyhow::Error>,
    ) -> Self {
        let disposition = match error_class {
            ProvisioningErrorClass::RetryableProvider
            | ProvisioningErrorClass::RetryableCapacity => RetryDisposition::Retryable,
            ProvisioningErrorClass::TerminalContract | ProvisioningErrorClass::TerminalSecurity => {
                RetryDisposition::Permanent
            }
        };
        Self {
            disposition,
            error_class,
            reason_code,
            source: source.into(),
        }
    }

    pub fn disposition(&self) -> RetryDisposition {
        self.disposition
    }

    pub fn error_class(&self) -> ProvisioningErrorClass {
        self.error_class.clone()
    }

    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason_code(), self.source)
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

pub const KUBERNETES_MUTATION_ENV: &str = "SANDBOXWICH_K8S_ENABLE_MUTATION";
pub const DEFAULT_SANDBOX_GUEST_IMAGE: &str = "ghcr.io/evalops/sandboxwich-ubuntu-dev:latest";

/// Kubernetes defaults `imagePullPolicy` to `Always` for `:latest` (and for
/// untagged refs, which imply `:latest`) and to `IfNotPresent` otherwise. We
/// set it explicitly so pinned tags and kind-local images never attempt a
/// registry pull, while floating `:latest` tags still refresh.
///
/// Tag detection only looks at the last path segment so a registry host:port
/// (`localhost:5000/myimage`) is not mistaken for an image tag.
pub(crate) fn image_pull_policy_for(image: &str) -> &'static str {
    if image.contains("@sha256:") {
        return "IfNotPresent";
    }
    let name = image.rsplit('/').next().unwrap_or(image);
    match name.rsplit_once(':') {
        Some((_, tag)) if tag != "latest" && !tag.is_empty() => "IfNotPresent",
        _ => "Always",
    }
}

pub(crate) fn image_is_digest_pinned(image: &str) -> bool {
    image.split_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Default cap on the stdout/stderr captured from a single `kubectl` invocation
/// before it's stored in a `KubectlOutput` (and, from there, in job results and
/// provider metadata sent back to the control plane). Mirrors
/// `sandboxwich-agent`'s `DEFAULT_MAX_CAPTURED_OUTPUT_BYTES`: without a cap, a
/// chatty or misbehaving `kubectl` command could grow these unboundedly.
pub const DEFAULT_MAX_CAPTURED_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
/// Hard live-response limit for the fixed APEX instruction reader. The
/// instruction body is returned to its caller only and must never flow into
/// ordinary command/job output storage.
pub const APEX_TASK_INSTRUCTIONS_MAX_BYTES: usize = 1024 * 1024;
const APEX_TASK_INSTRUCTIONS_COMMAND: &str = "/opt/apex/bin/task-instructions";

/// Default bound applied to every `kubectl` invocation made by
/// [`KubernetesApplyProvider`] (see [`run_kubectl_command`]). Pod readiness
/// uses this bound with a five-second margin so `kubectl wait` reports its own
/// timeout before the process backstop fires. Configurable via
/// `with_kubectl_command_timeout`/`--kubectl-command-timeout-secs`/
/// `SANDBOXWICH_KUBECTL_COMMAND_TIMEOUT_SECS` for environments that need a
/// longer bound (e.g. slow-running commands executed via `kubectl exec`).
pub const DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS: u64 = 300;
/// Maximum time an isolated sidecar may remain without container-start
/// evidence. This is deliberately shorter than the resident lease lifetime so
/// an unschedulable or image-pull-blocked Pod releases its supervisor slot and
/// can be retried after fenced cleanup.
pub const DEFAULT_ISOLATED_RESIDENT_PROCESS_STARTUP_TIMEOUT_SECS: u64 = 120;
/// Initial and maximum delays for the bounded-backoff sidecar observer. The
/// backoff avoids a full Kubernetes Pod GET four times per second for every
/// steady-state sidecar while retaining prompt startup/terminal observations.
pub const DEFAULT_ISOLATED_RESIDENT_PROCESS_POLL_INTERVAL_MILLIS: u64 = 1_000;
pub const DEFAULT_ISOLATED_RESIDENT_PROCESS_MAX_POLL_INTERVAL_MILLIS: u64 = 5_000;

/// Default dedicated namespace sandbox workloads are provisioned into, kept
/// separate from the control-plane namespace (see GH-76). Not read directly
/// by this crate (the sandbox namespace stays opt-in via
/// `--sandbox-namespace`/`SANDBOXWICH_SANDBOX_NAMESPACE` to avoid changing
/// behavior for existing single-namespace deployments); this constant
/// documents the value the checked-in worker Deployment manifest sets
/// explicitly.
#[allow(dead_code)]
pub const DEFAULT_SANDBOX_NAMESPACE: &str = "sandboxwich-sandboxes";
/// Default namespace running the cluster DNS service.
pub const DEFAULT_DNS_NAMESPACE: &str = "kube-system";
/// Egress CIDRs excluded by default from `0.0.0.0/0` allow rules: link-local
/// (which covers cloud metadata endpoints) plus the k3s default cluster and
/// service CIDRs. Override with real values for non-k3s clusters (GH-66).
pub const DEFAULT_EGRESS_EXCLUDED_CIDRS: &[&str] =
    &["169.254.0.0/16", "10.42.0.0/16", "10.43.0.0/16"];
/// Default label used to identify control-plane pods allowed to reach a
/// sandbox's ssh/desktop/vnc ports (GH-67).
pub const DEFAULT_INGRESS_SELECTOR_KEY: &str = "app.kubernetes.io/part-of";
pub const DEFAULT_INGRESS_SELECTOR_VALUE: &str = "sandboxwich";
/// Kubernetes resource kinds (as a `kubectl get/delete` type list) that carry the
/// `sandboxwich.dev/sandbox-id` label and must be torn down when a sandbox is stopped.
pub const SANDBOX_TEARDOWN_RESOURCE_KINDS: &str =
    "pod,persistentvolumeclaim,service,networkpolicy,secret";
pub const SANDBOX_RECONCILIATION_RESOURCE_KINDS: &str =
    "pod,persistentvolumeclaim,service,secret,networkpolicy";
pub const GUEST_TOKEN_REDACTED: &str = "[redacted]";

/// Name prefix for the per-sandbox guest-token Secret (see
/// `guest_token_secret_name`). Also used by the Secret adoption contract to
/// recognize these Secrets and exempt their per-attempt-minted `api-token`
/// value (only) from byte equality.
pub const GUEST_TOKEN_SECRET_NAME_PREFIX: &str = "sandboxwich-guest-token-";
const GKE_FQDN_RESOURCE_KIND: &str = "fqdnnetworkpolicy.networking.gke.io";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SandboxTeardownSpec {
    pub(crate) delete_gke_fqdn_policy: bool,
}

/// Cheaply cloneable signal a job's background lease-renewal task (see
/// `handle_lease` in `main.rs`) uses to tell an in-flight `exec_handoff` call
/// that the lease is gone -- renewal failed after retries -- so the
/// long-running `kubectl exec` behind it should stop instead of running to
/// (possibly duplicated) completion against a lease this worker can no
/// longer prove is still its own.
#[derive(Clone, Debug, Default)]
pub struct CancelSignal(Arc<AtomicBool>);

impl CancelSignal {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// A signal that never fires; for callers (dry-run execution, smoke
    /// tests) with no lease-renewal loop backing them.
    pub fn never_cancelled() -> Self {
        Self::new()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct IsolatedResidentProcessBootstrap {
    pub content: Vec<u8>,
    pub target_file: String,
    pub mode: u32,
    pub placement_attestation: Option<Vec<u8>>,
}

impl std::fmt::Debug for IsolatedResidentProcessBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IsolatedResidentProcessBootstrap")
            .field(
                "content",
                &format_args!("<redacted:{} bytes>", self.content.len()),
            )
            .field("target_file", &self.target_file)
            .field("mode", &format_args!("{:#o}", self.mode))
            .field(
                "placement_attestation",
                &self
                    .placement_attestation
                    .as_ref()
                    .map(|value| format!("<redacted:{} bytes>", value.len())),
            )
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct IsolatedResidentProcessSpec {
    pub sandbox_id: SandboxId,
    pub process_id: ResidentProcessId,
    pub generation: u64,
    pub lease_id: Uuid,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub bootstrap: IsolatedResidentProcessBootstrap,
}

impl std::fmt::Debug for IsolatedResidentProcessSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IsolatedResidentProcessSpec")
            .field("sandbox_id", &self.sandbox_id)
            .field("process_id", &self.process_id)
            .field("generation", &self.generation)
            .field("lease_id", &self.lease_id)
            .field("argv", &self.argv)
            .field("cwd", &self.cwd)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("bootstrap", &self.bootstrap)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolatedResidentProcessState {
    Starting,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolatedResidentProcessObservation {
    pub state: IsolatedResidentProcessState,
    pub pod_name: String,
    pub pod_uid: Option<String>,
    pub ready: bool,
    pub exit_code: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IsolatedResidentProcessPodObservation {
    Pending {
        pod_name: String,
        pod_uid: Option<String>,
    },
    Started(IsolatedResidentProcessObservation),
}

fn isolated_resident_process_fence_suffix(spec: &IsolatedResidentProcessSpec) -> String {
    let process = spec.process_id.0.simple().to_string();
    let lease = spec.lease_id.simple().to_string();
    format!(
        "{}-g{}-{}",
        &process[..12],
        spec.generation,
        &lease[lease.len() - 12..]
    )
}

pub(crate) fn isolated_resident_process_pod_name(spec: &IsolatedResidentProcessSpec) -> String {
    format!("sw-sc-{}", isolated_resident_process_fence_suffix(spec))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolatedResidentProcessResult {
    pub final_observation: IsolatedResidentProcessObservation,
}

pub trait SandboxProvider {
    fn capability_report(&self) -> ProviderCapabilityReport;
    fn health_report(&self) -> ProviderHealthReport;
    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSandboxHandle>;
    fn provision_staged(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        let handle = self.provision(sandbox_id, spec, cancelled)?;
        report(stage_update(ProvisioningStage::SandboxReady, None))?;
        Ok(handle)
    }
    fn provision_home_staged(
        &self,
        sandbox_id: SandboxId,
        home_id: HomeId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        let _ = (sandbox_id, home_id, spec, cancelled, report);
        anyhow::bail!("provider does not support managed homes")
    }
    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult>;
    fn run_isolated_resident_process(
        &self,
        spec: &IsolatedResidentProcessSpec,
        cancelled: &CancelSignal,
        observe: &mut dyn FnMut(IsolatedResidentProcessObservation) -> anyhow::Result<()>,
    ) -> anyhow::Result<IsolatedResidentProcessResult> {
        let _ = (spec, cancelled, observe);
        anyhow::bail!("provider does not support isolated resident processes")
    }
    /// Reads the APEX task instruction stream from a live sandbox through one
    /// fixed executable. There is intentionally no request object: callers
    /// cannot supply argv, cwd, environment, or stdin.
    fn read_apex_task_instructions(
        &self,
        sandbox_id: SandboxId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<Vec<u8>> {
        let _ = (sandbox_id, cancelled);
        anyhow::bail!("provider does not support APEX task instruction reads")
    }
    fn materialize_file(
        &self,
        sandbox_id: SandboxId,
        destination: MaterializeFileDestination,
        expected_sha256: &str,
        content: &[u8],
        cancelled: &CancelSignal,
    ) -> anyhow::Result<MaterializeFileObservation> {
        let _ = (sandbox_id, destination, expected_sha256, content, cancelled);
        anyhow::bail!("provider does not support file materialization")
    }
    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSnapshotHandle>;
    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderForkHandle>;
    /// Tear down every resource associated with `sandbox_id`. Must be idempotent:
    /// calling it on an already-stopped (or never-provisioned) sandbox is not an error.
    fn stop(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()>;
    fn delete_home(&self, home_id: HomeId, cancelled: &CancelSignal) -> anyhow::Result<()> {
        let _ = (home_id, cancelled);
        anyhow::bail!("provider does not support managed home deletion")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesDryRunProvider {
    cluster: String,
    namespace: String,
    storage_class: Option<String>,
    snapshot_class: Option<String>,
    runtime_image: String,
    apex_trusted_supervisor_v1: bool,
    egress_gateway_image: Option<String>,
    workspace_storage: String,
    workspace_storage_override: bool,
    ssh_authorized_keys_secret: Option<String>,
    isolation_profile: IsolationProfile,
    runtime_class_name: Option<String>,
    isolation_backend: String,
    /// Dedicated namespace sandbox pods/services/PVCs/NetworkPolicies are
    /// rendered into. Falls back to `namespace` (the control-plane
    /// namespace) when unset, preserving pre-existing single-namespace
    /// deployments. See GH-76 for the namespace-separation rationale; full
    /// wiring (namespace manifest, cross-namespace secret sync, etc.) is
    /// tracked separately, this only controls where the provider renders
    /// sandbox resources.
    sandbox_namespace: Option<String>,
    /// Namespace running cluster DNS, used to scope the always-on DNS
    /// egress rule (GH-66).
    dns_namespace: String,
    /// Additional DNS endpoints that cannot be selected as ordinary pods,
    /// such as GKE NodeLocal DNSCache's link-local host-network address.
    /// Access is restricted to TCP/UDP port 53 and does not weaken the
    /// protected-CIDR carve-outs for any other traffic.
    dns_service_ips: Vec<IpAddr>,
    /// CIDRs carved out (via NetworkPolicy `except`) of every egress allow
    /// rule that overlaps them, so sandboxes can never reach the control
    /// plane / metadata endpoints regardless of egress mode -- not just
    /// `AllowAll`/`0.0.0.0/0`, but any allowlist CIDR that happens to
    /// contain one of these ranges too (GH-66). Seeded from
    /// `DEFAULT_EGRESS_EXCLUDED_CIDRS` and merged (not replaced) with any
    /// operator-supplied CIDRs via `with_egress_excluded_cidrs`, so the
    /// metadata carve-out can't be silently dropped by an override; use
    /// `with_egress_excluded_cidrs_replace` to opt out of that merge.
    egress_excluded_cidrs: Vec<String>,
    /// Narrow CIDRs that only provider-isolated sidecars may reach over
    /// TCP/443. These bypass the ordinary private-range carve-outs by design;
    /// startup validation rejects broad and hard-forbidden destinations.
    isolated_sidecar_https_cidrs: Vec<String>,
    /// Namespace containing pods allowed to reach a sandbox's ssh/desktop
    /// ports via the rendered ingress NetworkPolicy. Falls back to
    /// `namespace` (the control-plane namespace) when unset (GH-67).
    ingress_namespace: Option<String>,
    /// Pod selector labels identifying which pods in `ingress_namespace`
    /// may reach a sandbox's ssh/desktop ports (GH-67).
    ingress_pod_selector: BTreeMap<String, String>,
    /// Optional Secret name mounted read-only at
    /// `/run/sandboxwich/vnc/vnc-password` in the sandbox container (path
    /// exposed via `SANDBOXWICH_VNC_PASSWORD_FILE`), mirroring how
    /// `ssh_authorized_keys_secret` is mounted as a file rather than an env
    /// var (GH-67).
    vnc_password_secret: Option<String>,
    fqdn_egress_backend: Option<String>,
    guest_credentials: Option<GuestCredentials>,
}

#[derive(Clone, Eq, PartialEq)]
struct GuestCredentials {
    sandbox_id: SandboxId,
    worker_id: Uuid,
    api: String,
    token: String,
}

impl std::fmt::Debug for GuestCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestCredentials")
            .field("sandbox_id", &self.sandbox_id)
            .field("worker_id", &self.worker_id)
            .field("api", &self.api)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl KubernetesDryRunProvider {
    pub fn with_snapshot_class(
        cluster: impl Into<String>,
        namespace: impl Into<String>,
        storage_class: Option<String>,
        snapshot_class: Option<String>,
    ) -> Self {
        Self {
            cluster: cluster.into(),
            namespace: namespace.into(),
            storage_class,
            snapshot_class,
            runtime_image: DEFAULT_SANDBOX_GUEST_IMAGE.to_string(),
            apex_trusted_supervisor_v1: false,
            egress_gateway_image: None,
            workspace_storage: "2Gi".to_string(),
            workspace_storage_override: false,
            ssh_authorized_keys_secret: None,
            isolation_profile: IsolationProfile::Development,
            runtime_class_name: None,
            isolation_backend: "kubernetes".to_string(),
            sandbox_namespace: None,
            dns_namespace: DEFAULT_DNS_NAMESPACE.to_string(),
            dns_service_ips: Vec::new(),
            egress_excluded_cidrs: DEFAULT_EGRESS_EXCLUDED_CIDRS
                .iter()
                .map(|cidr| cidr.to_string())
                .collect(),
            isolated_sidecar_https_cidrs: Vec::new(),
            ingress_namespace: None,
            ingress_pod_selector: BTreeMap::from([(
                DEFAULT_INGRESS_SELECTOR_KEY.to_string(),
                DEFAULT_INGRESS_SELECTOR_VALUE.to_string(),
            )]),
            vnc_password_secret: None,
            fqdn_egress_backend: None,
            guest_credentials: None,
        }
    }

    pub fn with_runtime_image(mut self, image: Option<String>) -> Self {
        if let Some(image) = image {
            self.runtime_image = image;
        }
        self
    }

    pub fn with_apex_trusted_supervisor_v1(mut self, enabled: bool) -> Self {
        self.apex_trusted_supervisor_v1 = enabled;
        self
    }

    fn validate_runtime_profile(&self, spec: &SandboxProvisionSpec) -> anyhow::Result<()> {
        self.validate_network_policy_egress(&spec.network_egress)?;
        if spec.runtime_profile == SandboxRuntimeProfile::ApexTrustedSupervisorV1 {
            anyhow::ensure!(
                self.apex_trusted_supervisor_v1 && image_is_digest_pinned(&self.runtime_image),
                "apex_trusted_supervisor_v1 is not configured for this digest-pinned runtime"
            );
            anyhow::ensure!(
                spec.execution_class == ExecutionClass::SandboxedContainer,
                "apex_trusted_supervisor_v1 requires sandboxed_container execution_class"
            );
            anyhow::ensure!(
                self.isolation_profile == IsolationProfile::Gvisor
                    && self
                        .runtime_class_name
                        .as_deref()
                        .is_some_and(|name| !name.trim().is_empty()),
                "apex_trusted_supervisor_v1 requires the gvisor isolation profile and RuntimeClass"
            );
            anyhow::ensure!(
                !matches!(spec.network_egress, NetworkEgress::AllowAll),
                "apex_trusted_supervisor_v1 requires deny-by-default egress"
            );
        }
        if spec.execution_class == ExecutionClass::VirtualMachine {
            anyhow::ensure!(
                self.isolation_profile == IsolationProfile::Kata
                    && self
                        .runtime_class_name
                        .as_deref()
                        .is_some_and(|name| !name.trim().is_empty()),
                "virtual_machine execution_class requires the kata isolation profile and a RuntimeClass"
            );
        }
        Ok(())
    }

    pub fn with_egress_gateway_image(mut self, image: Option<String>) -> Self {
        self.egress_gateway_image = image.and_then(|image| {
            let image = image.trim();
            (!image.is_empty()).then(|| image.to_string())
        });
        self
    }

    pub fn with_workspace_storage(mut self, storage: Option<String>) -> Self {
        if let Some(storage) = storage {
            self.workspace_storage = storage;
            self.workspace_storage_override = true;
        }
        self
    }

    pub fn with_ssh_authorized_keys_secret(mut self, secret: Option<String>) -> Self {
        self.ssh_authorized_keys_secret = secret;
        self
    }

    pub fn with_isolation_profile(mut self, isolation_profile: IsolationProfile) -> Self {
        self.isolation_profile = isolation_profile;
        self
    }

    pub fn with_runtime_class_name(mut self, runtime_class_name: Option<String>) -> Self {
        self.runtime_class_name = runtime_class_name.and_then(|runtime_class_name| {
            let runtime_class_name = runtime_class_name.trim();
            if runtime_class_name.is_empty() {
                None
            } else {
                Some(runtime_class_name.to_string())
            }
        });
        if self.runtime_class_name.is_some() {
            self.isolation_backend = "runtime_class".to_string();
        }
        self
    }

    pub fn with_sandbox_namespace(mut self, sandbox_namespace: Option<String>) -> Self {
        self.sandbox_namespace = sandbox_namespace.and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        self
    }

    pub fn with_dns_namespace(mut self, dns_namespace: Option<String>) -> Self {
        if let Some(dns_namespace) = dns_namespace {
            let dns_namespace = dns_namespace.trim();
            if !dns_namespace.is_empty() {
                self.dns_namespace = dns_namespace.to_string();
            }
        }
        self
    }

    pub fn with_dns_service_ips(mut self, dns_service_ips: Vec<IpAddr>) -> Self {
        dns_service_ips.into_iter().for_each(|address| {
            if !self.dns_service_ips.contains(&address) {
                self.dns_service_ips.push(address);
            }
        });
        self.dns_service_ips.sort();
        self
    }

    pub fn with_cilium_fqdn_egress(mut self, enabled: bool) -> Self {
        if enabled {
            self.fqdn_egress_backend = Some("cilium".to_string());
        }
        self
    }

    fn teardown_resource_kinds_with_persisted_gke_fqdn(&self, persisted_gke_fqdn: bool) -> String {
        self.resource_kinds_with_optional_gke_fqdn(
            SANDBOX_TEARDOWN_RESOURCE_KINDS,
            persisted_gke_fqdn,
        )
    }

    fn reconciliation_resource_kinds(&self) -> String {
        self.resource_kinds_with_optional_gke_fqdn(SANDBOX_RECONCILIATION_RESOURCE_KINDS, false)
    }

    fn resource_kinds_with_optional_gke_fqdn(
        &self,
        base: &str,
        persisted_gke_fqdn: bool,
    ) -> String {
        if persisted_gke_fqdn {
            format!("{base},{GKE_FQDN_RESOURCE_KIND}")
        } else {
            base.to_string()
        }
    }

    /// Merges operator-supplied CIDRs into the excluded set (deduped
    /// against what's already there, including `DEFAULT_EGRESS_EXCLUDED_CIDRS`)
    /// rather than replacing it, so passing a custom list can only ever
    /// exclude *more* addresses than the default, never accidentally drop
    /// the `169.254.0.0/16` metadata carve-out. Use
    /// `with_egress_excluded_cidrs_replace` if you deliberately need to
    /// replace the set outright.
    pub fn with_egress_excluded_cidrs(mut self, cidrs: Vec<String>) -> Self {
        for cidr in Self::normalize_cidrs(cidrs) {
            if !self.egress_excluded_cidrs.contains(&cidr) {
                self.egress_excluded_cidrs.push(cidr);
            }
        }
        self
    }

    /// Escape hatch that replaces the excluded CIDR set outright instead of
    /// merging with `DEFAULT_EGRESS_EXCLUDED_CIDRS` (see
    /// `with_egress_excluded_cidrs`). Only use this if you are deliberately
    /// replacing the metadata/control-plane carve-out with an equivalent
    /// value for your environment -- e.g. a non-k3s cluster where the
    /// k3s-shaped defaults (`10.42.0.0/16`, `10.43.0.0/16`) are meaningless
    /// and you're supplying the real pod/service CIDRs instead. Passing an
    /// empty list is a no-op (kept for parity with the merge variant); to
    /// truly disable the carve-out, pass a value that can never match
    /// (there's no supported way to leave the metadata endpoint reachable
    /// by omission, that would have to be an explicit, obviously-named
    /// escape hatch of its own, which nothing currently requests).
    pub fn with_egress_excluded_cidrs_replace(mut self, cidrs: Vec<String>) -> Self {
        let cidrs = Self::normalize_cidrs(cidrs);
        if !cidrs.is_empty() {
            self.egress_excluded_cidrs = cidrs;
        }
        self
    }

    fn normalize_cidrs(cidrs: Vec<String>) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        cidrs
            .into_iter()
            .map(|cidr| cidr.trim().to_string())
            .filter(|cidr| !cidr.is_empty() && seen.insert(cidr.clone()))
            .collect()
    }

    pub fn with_isolated_sidecar_https_cidrs(mut self, cidrs: Vec<String>) -> anyhow::Result<Self> {
        let mut normalized = std::collections::BTreeSet::new();
        for value in cidrs {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let network = IpNet::from_str(value)
                .with_context(|| format!("invalid isolated sidecar HTTPS CIDR {value}"))?;
            let minimum_prefix = if network.addr().is_ipv4() { 24 } else { 64 };
            anyhow::ensure!(
                network.prefix_len() >= minimum_prefix,
                "isolated sidecar HTTPS CIDR {network} is broader than /{minimum_prefix}"
            );
            let address = network.network();
            let hard_forbidden = match address {
                IpAddr::V4(address) => {
                    address.is_unspecified()
                        || address.is_loopback()
                        || address.is_link_local()
                        || address.is_multicast()
                        || address.is_broadcast()
                }
                IpAddr::V6(address) => {
                    address.is_unspecified()
                        || address.is_loopback()
                        || address.is_unicast_link_local()
                        || address.is_multicast()
                        || address.to_ipv4_mapped().is_some()
                }
            };
            anyhow::ensure!(
                !hard_forbidden,
                "isolated sidecar HTTPS CIDR {network} targets a hard-forbidden destination"
            );
            normalized.insert(network.to_string());
        }
        self.isolated_sidecar_https_cidrs = normalized.into_iter().collect();
        Ok(self)
    }

    pub fn with_ingress_namespace(mut self, ingress_namespace: Option<String>) -> Self {
        self.ingress_namespace = ingress_namespace.and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        self
    }

    pub fn with_ingress_pod_selector(mut self, selector: Vec<(String, String)>) -> Self {
        if !selector.is_empty() {
            self.ingress_pod_selector = selector.into_iter().collect();
        }
        self
    }

    pub fn with_vnc_password_secret(mut self, secret: Option<String>) -> Self {
        self.vnc_password_secret = secret.and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        });
        self
    }

    pub fn with_guest_credentials(
        mut self,
        sandbox_id: SandboxId,
        worker_id: Uuid,
        api: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        let api = api.into().trim_end_matches('/').to_string();
        let token = token.into();
        self.guest_credentials =
            (!api.is_empty() && !token.trim().is_empty()).then_some(GuestCredentials {
                sandbox_id,
                worker_id,
                api,
                token,
            });
        self
    }

    pub(crate) fn effective_sandbox_namespace(&self) -> &str {
        self.sandbox_namespace
            .as_deref()
            .unwrap_or(self.namespace.as_str())
    }

    fn effective_ingress_namespace(&self) -> &str {
        self.ingress_namespace
            .as_deref()
            .unwrap_or(self.namespace.as_str())
    }

    fn labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::from([
            ("cluster".to_string(), self.cluster.clone()),
            (
                "namespace".to_string(),
                self.effective_sandbox_namespace().to_string(),
            ),
            (
                "control_plane_namespace".to_string(),
                self.namespace.clone(),
            ),
            ("provider_mode".to_string(), "dry_run".to_string()),
        ]);
        if let Some(storage_class) = &self.storage_class {
            labels.insert("storage_class".to_string(), storage_class.clone());
        }
        if let Some(snapshot_class) = &self.snapshot_class {
            labels.insert("snapshot_class".to_string(), snapshot_class.clone());
        }
        labels.insert("runtime_image".to_string(), self.runtime_image.clone());
        if self.apex_trusted_supervisor_v1 {
            labels.insert(
                "runtime_profile".to_string(),
                SandboxRuntimeProfile::ApexTrustedSupervisorV1
                    .as_db_str()
                    .to_string(),
            );
        }
        labels.insert(
            "workspace_storage".to_string(),
            self.workspace_storage.clone(),
        );
        labels.insert(
            "isolation_profile".to_string(),
            self.isolation_profile.as_str().to_string(),
        );
        if let Some(secret) = &self.ssh_authorized_keys_secret {
            labels.insert("ssh_authorized_keys_secret".to_string(), secret.clone());
        }
        if let Some(runtime_class_name) = &self.runtime_class_name {
            labels.insert("runtime_class_name".to_string(), runtime_class_name.clone());
        }
        labels.insert(
            "isolation_backend".to_string(),
            self.isolation_backend.clone(),
        );
        labels
    }

    fn metadata(
        &self,
        sandbox_id: SandboxId,
        operation: &'static str,
        spec: &SandboxProvisionSpec,
    ) -> anyhow::Result<serde_json::Value> {
        self.validate_runtime_profile(spec)?;
        let network_policy = self.network_policy_manifest(sandbox_id, &spec.network_egress)?;
        let egress_gateway_pod =
            self.egress_gateway_pod_manifest(sandbox_id, &spec.network_egress)?;
        let egress_gateway_service =
            self.egress_gateway_service_manifest(sandbox_id, &spec.network_egress);
        let egress_gateway_network_policy =
            self.egress_gateway_network_policy_manifest(sandbox_id, &spec.network_egress)?;
        let pvc = (spec.workspace_mode == WorkspaceMode::Persistent).then(|| {
            self.pvc_manifest(
                format!("sandboxwich-pvc-{sandbox_id}"),
                Some(sandbox_id),
                &spec.memory_limit,
            )
        });
        Ok(json!({
            "provider": "kubernetes",
            "mode": "dry_run",
            "operation": operation,
            "cluster": self.cluster,
            "namespace": self.effective_sandbox_namespace(),
            "controlPlaneNamespace": self.namespace,
            "sandboxId": sandbox_id,
            "podName": format!("sandboxwich-{}", sandbox_id),
            "storageClass": self.storage_class,
            "snapshotClass": self.snapshot_class,
            "workspaceStorage": self.effective_workspace_storage_for_spec(spec),
            "workspaceMode": spec.workspace_mode,
            "runtime": self.runtime_metadata(),
            "resources": self.resource_metadata(&spec.memory_limit),
            "networkEgress": spec.network_egress,
            "isolation": self.isolation_metadata(),
            "manifests": {
                "pod": self.pod_manifest(sandbox_id, spec),
                "pvc": pvc,
                "sshService": self.ssh_service_manifest(sandbox_id),
                "desktopService": self.desktop_service_manifest(sandbox_id),
                "networkPolicy": network_policy,
                "egressGatewayPod": egress_gateway_pod,
                "egressGatewayService": egress_gateway_service,
                "egressGatewayNetworkPolicy": egress_gateway_network_policy,
                "guestTokenSecret": self.guest_token_secret_manifest_redacted(sandbox_id),
            }
        }))
    }

    fn runtime_metadata(&self) -> serde_json::Value {
        json!({
            "image": self.runtime_image,
            "workspaceMount": "/workspace",
            "sshPort": 2222,
            "desktopPort": 6080,
            "sshAuthorizedKeysSecret": self.ssh_authorized_keys_secret,
            "sshAuthorizedKeysSecretKey": "authorized_keys"
        })
    }

    fn resource_metadata(&self, memory_limit: &MemoryLimit) -> serde_json::Value {
        json!({
            "memoryLimit": memory_limit,
            "cpu": memory_limit.cpu_limit(),
            "workspaceStorage": self.effective_workspace_storage(memory_limit)
        })
    }

    fn isolation_metadata(&self) -> serde_json::Value {
        json!({
            "backend": self.isolation_backend,
            "profile": self.isolation_profile.as_str(),
            "runtimeClassName": self.runtime_class_name
        })
    }

    fn validate_network_policy_egress(&self, network_egress: &NetworkEgress) -> anyhow::Result<()> {
        if let NetworkEgress::Allowlist { rules } = network_egress
            && let Some(rule) = rules
                .iter()
                .find(|rule| rule.kind == NetworkAllowRuleKind::Host)
        {
            if self.fqdn_egress_backend.as_deref() == Some("cilium") {
                return Ok(());
            }
            if let Some(image) = &self.egress_gateway_image {
                if image_is_digest_pinned(image) {
                    return Ok(());
                }
                bail!(
                    "egress_gateway_image_unpinned: host allow rule {} requires a digest-pinned gateway image",
                    rule.value
                );
            }
            bail!(
                "egress_gateway_image_required: host allow rule {} requires SANDBOXWICH_EGRESS_GATEWAY_IMAGE",
                rule.value
            );
        }
        Ok(())
    }

    fn host_rules<'a>(&self, network_egress: &'a NetworkEgress) -> impl Iterator<Item = &'a str> {
        network_egress
            .rules()
            .iter()
            .filter(|rule| rule.kind == NetworkAllowRuleKind::Host)
            .map(|rule| rule.value.as_str())
    }

    fn uses_egress_gateway(&self, network_egress: &NetworkEgress) -> bool {
        self.fqdn_egress_backend.as_deref() != Some("cilium")
            && self.host_rules(network_egress).next().is_some()
    }

    fn egress_gateway_policy(
        &self,
        network_egress: &NetworkEgress,
    ) -> anyhow::Result<Option<EgressGatewayPolicy>> {
        if !self.uses_egress_gateway(network_egress) {
            return Ok(None);
        }
        let denied_cidrs = self
            .egress_excluded_cidrs
            .iter()
            .map(|cidr| IpNet::from_str(cidr))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(EgressGatewayPolicy::new(
            self.host_rules(network_egress)
                .map(ToString::to_string)
                .collect(),
            vec![80, 443],
            denied_cidrs,
        )?))
    }

    fn effective_workspace_storage(&self, memory_limit: &MemoryLimit) -> String {
        if self.workspace_storage_override {
            self.workspace_storage.clone()
        } else {
            memory_limit.disk_limit().to_string()
        }
    }

    fn effective_workspace_storage_for_spec(&self, spec: &SandboxProvisionSpec) -> String {
        if spec.workspace_mode == WorkspaceMode::Ephemeral {
            // emptyDir usage counts against the container's aggregate
            // ephemeral-storage limit. Never advertise or render a workspace
            // ceiling above the limit that Kubernetes actually enforces.
            Self::ephemeral_storage_limit(&spec.memory_limit).to_string()
        } else {
            self.effective_workspace_storage(&spec.memory_limit)
        }
    }

    fn object_metadata(&self, name: String, sandbox_id: Option<SandboxId>) -> serde_json::Value {
        let mut labels = serde_json::Map::from_iter([
            (
                "app.kubernetes.io/name".to_string(),
                json!("sandboxwich-sandbox"),
            ),
            (
                "app.kubernetes.io/managed-by".to_string(),
                json!("sandboxwich"),
            ),
        ]);
        if let Some(sandbox_id) = sandbox_id {
            labels.insert("sandboxwich.dev/sandbox-id".to_string(), json!(sandbox_id));
        }
        json!({
            "name": name,
            "namespace": self.effective_sandbox_namespace(),
            "labels": labels
        })
    }

    /// Ephemeral (root filesystem) storage limit for the sandbox container.
    /// This is separate from the PVC-backed `/workspace` mount and bounds
    /// how much a sandbox can write to `/tmp`, `/home`, and other
    /// node-local paths, preventing a single sandbox from filling node
    /// disk (GH-75).
    fn ephemeral_storage_limit(memory_limit: &MemoryLimit) -> &'static str {
        match memory_limit {
            MemoryLimit::OneG => "1Gi",
            MemoryLimit::FourG => "2Gi",
            MemoryLimit::SixteenG => "4Gi",
            MemoryLimit::SixtyFourG => "8Gi",
        }
    }

    fn pod_manifest(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
    ) -> serde_json::Value {
        let mut volume_mounts = vec![json!({
            "name": "workspace",
            "mountPath": "/workspace"
        })];
        let workspace_volume = match &spec.workspace_mode {
            WorkspaceMode::Ephemeral => json!({
                "name": "workspace",
                "emptyDir": { "sizeLimit": self.effective_workspace_storage_for_spec(spec) }
            }),
            WorkspaceMode::GenericEphemeral => json!({
                "name": "workspace",
                "ephemeral": {
                    "volumeClaimTemplate": {
                        "metadata": { "labels": { "sandboxwich.dev/sandbox-id": sandbox_id } },
                        "spec": {
                            "accessModes": ["ReadWriteOnce"],
                            "storageClassName": self.storage_class,
                            "resources": { "requests": {
                                "storage": self.effective_workspace_storage(&spec.memory_limit)
                            }}
                        }
                    }
                }
            }),
            WorkspaceMode::Persistent => json!({
                "name": "workspace",
                "persistentVolumeClaim": { "claimName": format!("sandboxwich-pvc-{sandbox_id}") }
            }),
        };
        let mut volumes = vec![workspace_volume];
        let mut env = vec![
            json!({
                "name": "SANDBOXWICH_WORKSPACE",
                "value": "/workspace"
            }),
            json!({
                "name": "SANDBOXWICH_SSH_PORT",
                "value": "2222"
            }),
        ];
        if self
            .guest_credentials
            .as_ref()
            .is_some_and(|credentials| credentials.sandbox_id == sandbox_id)
        {
            volume_mounts.push(json!({
                "name": "sandboxwich-guest-token",
                "mountPath": "/run/sandboxwich/guest",
                "readOnly": true
            }));
            volumes.push(json!({
                "name": "sandboxwich-guest-token",
                "secret": {
                    "secretName": self.guest_token_secret_name(sandbox_id),
                    "items": [{"key": "api-token", "path": "api-token"}]
                }
            }));
            env.extend([
                json!({
                    "name": "SANDBOXWICH_API",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": self.guest_token_secret_name(sandbox_id),
                            "key": "api-url"
                        }
                    }
                }),
                json!({
                    "name": "SANDBOXWICH_GUEST_TOKEN_FILE",
                    "value": "/run/sandboxwich/guest/api-token"
                }),
                json!({
                    "name": "SANDBOXWICH_SANDBOX_ID",
                    "value": sandbox_id.to_string()
                }),
                json!({
                    "name": "SANDBOXWICH_WORKER_ID",
                    "value": self.guest_credentials.as_ref().unwrap().worker_id.to_string()
                }),
            ]);
        }

        if self.uses_egress_gateway(&spec.network_egress) {
            let proxy = format!("http://sandboxwich-egress-gateway-{sandbox_id}:8080");
            for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                env.push(json!({"name": name, "value": proxy}));
            }
            for name in ["NO_PROXY", "no_proxy"] {
                env.push(json!({
                    "name": name,
                    "value": "localhost,127.0.0.1,::1"
                }));
            }
        }

        if let Some(secret_name) = &self.ssh_authorized_keys_secret {
            volume_mounts.push(json!({
                "name": "ssh-authorized-keys",
                "mountPath": "/run/sandboxwich/ssh",
                "readOnly": true
            }));
            volumes.push(json!({
                "name": "ssh-authorized-keys",
                "secret": {
                    "secretName": secret_name,
                    "items": [{
                        "key": "authorized_keys",
                        "path": "authorized_keys"
                    }]
                }
            }));
            env.push(json!({
                "name": "SANDBOXWICH_AUTHORIZED_KEYS_FILE",
                "value": "/run/sandboxwich/ssh/authorized_keys"
            }));
        }

        if let Some(secret_name) = &self.vnc_password_secret {
            // Mounted as a read-only file rather than a `secretKeyRef` env
            // var, mirroring the SSH authorized-keys handling above:
            // container env vars are visible to anything that can read
            // this pod's spec/status via the Kubernetes API (e.g.
            // `kubectl describe pod`, or any ServiceAccount with `get pods`
            // in this namespace), not just the process itself, whereas a
            // mounted file is only readable by whoever can exec into the
            // container or read the volume directly.
            volume_mounts.push(json!({
                "name": "vnc-password",
                "mountPath": "/run/sandboxwich/vnc",
                "readOnly": true
            }));
            volumes.push(json!({
                "name": "vnc-password",
                "secret": {
                    "secretName": secret_name,
                    "items": [{
                        "key": "vnc-password",
                        "path": "vnc-password"
                    }]
                }
            }));
            env.push(json!({
                "name": "SANDBOXWICH_VNC_PASSWORD_FILE",
                "value": "/run/sandboxwich/vnc/vnc-password"
            }));
        }

        let ephemeral_storage = Self::ephemeral_storage_limit(&spec.memory_limit);
        let apex_supervisor =
            spec.runtime_profile == SandboxRuntimeProfile::ApexTrustedSupervisorV1;
        let pod_security_context = if apex_supervisor {
            json!({
                "runAsNonRoot": false,
                "runAsUser": 0,
                "runAsGroup": 0,
                "fsGroup": 10001,
                "seccompProfile": { "type": "RuntimeDefault" }
            })
        } else {
            json!({
                "runAsNonRoot": true,
                "runAsUser": 10001,
                "runAsGroup": 10001,
                "fsGroup": 10001,
                "seccompProfile": { "type": "RuntimeDefault" }
            })
        };
        let container_security_context = if apex_supervisor {
            json!({
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": false,
                "runAsNonRoot": false,
                "runAsUser": 0,
                "runAsGroup": 0,
                "capabilities": {
                    "drop": ["ALL"],
                    "add": ["CHOWN", "SETGID", "SETUID", "KILL", "DAC_READ_SEARCH"]
                },
                "seccompProfile": { "type": "RuntimeDefault" }
            })
        } else {
            json!({
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": false,
                "runAsNonRoot": true,
                "capabilities": { "drop": ["ALL"] },
                "seccompProfile": { "type": "RuntimeDefault" }
            })
        };
        let mut pod_spec = Map::from_iter([
            ("automountServiceAccountToken".to_string(), json!(false)),
            ("securityContext".to_string(), pod_security_context),
            (
                "containers".to_string(),
                json!([{
                    "name": "sandbox",
                    "image": self.runtime_image,
                    // Mutable tags (`:latest`) must re-pull; pin/tags used by
                    // kind and local loads must not force registry access.
                    "imagePullPolicy": image_pull_policy_for(&self.runtime_image),
                    "ports": [
                        {"name": "ssh", "containerPort": 2222},
                        {"name": "desktop", "containerPort": 6080}
                    ],
                    "env": env,
                    "resources": {
                        "requests": {
                            "cpu": spec.memory_limit.cpu_limit(),
                            "memory": spec.memory_limit.memory_quantity(),
                            "ephemeral-storage": ephemeral_storage
                        },
                        "limits": {
                            "cpu": spec.memory_limit.cpu_limit(),
                            "memory": spec.memory_limit.memory_quantity(),
                            "ephemeral-storage": ephemeral_storage
                        }
                    },
                    "securityContext": container_security_context,
                    "volumeMounts": volume_mounts
                }]),
            ),
            ("volumes".to_string(), json!(volumes)),
        ]);
        if let Some(runtime_class_name) = &self.runtime_class_name {
            pod_spec.insert("runtimeClassName".to_string(), json!(runtime_class_name));
        }

        let mut manifest = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": self.object_metadata(format!("sandboxwich-{sandbox_id}"), Some(sandbox_id)),
            "spec": pod_spec
        });
        manifest["metadata"]["labels"]["sandboxwich.dev/component"] = json!("runtime");
        manifest
    }

    fn pod_manifest_with_home(
        &self,
        sandbox_id: SandboxId,
        home_id: HomeId,
        spec: &SandboxProvisionSpec,
    ) -> serde_json::Value {
        let mut manifest = self.pod_manifest(sandbox_id, spec);
        manifest["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] =
            json!(format!("sandboxwich-home-{home_id}"));
        manifest
    }

    fn guest_token_secret_name(&self, sandbox_id: SandboxId) -> String {
        format!("{GUEST_TOKEN_SECRET_NAME_PREFIX}{sandbox_id}")
    }

    fn guest_token_secret_manifest(&self, sandbox_id: SandboxId) -> Option<serde_json::Value> {
        let credentials = self
            .guest_credentials
            .as_ref()
            .filter(|credentials| credentials.sandbox_id == sandbox_id)?;
        Some(self.render_guest_token_secret(sandbox_id, &credentials.api, &credentials.token))
    }

    fn guest_token_secret_manifest_redacted(
        &self,
        sandbox_id: SandboxId,
    ) -> Option<serde_json::Value> {
        let credentials = self
            .guest_credentials
            .as_ref()
            .filter(|credentials| credentials.sandbox_id == sandbox_id)?;
        Some(self.render_guest_token_secret(sandbox_id, &credentials.api, GUEST_TOKEN_REDACTED))
    }

    fn render_guest_token_secret(
        &self,
        sandbox_id: SandboxId,
        api: &str,
        token: &str,
    ) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "Opaque",
            "metadata": self.object_metadata(self.guest_token_secret_name(sandbox_id), Some(sandbox_id)),
            "stringData": {
                "api-url": api,
                "api-token": token
            }
        })
    }

    fn pvc_manifest(
        &self,
        name: String,
        sandbox_id: Option<SandboxId>,
        memory_limit: &MemoryLimit,
    ) -> serde_json::Value {
        let mut spec = Map::from_iter([
            ("accessModes".to_string(), json!(["ReadWriteOnce"])),
            (
                "resources".to_string(),
                json!({
                    "requests": {
                        "storage": self.effective_workspace_storage(memory_limit)
                    }
                }),
            ),
        ]);
        if let Some(storage_class) = &self.storage_class {
            spec.insert("storageClassName".to_string(), json!(storage_class));
        }

        json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": self.object_metadata(name, sandbox_id),
            "spec": spec
        })
    }

    fn home_pvc_manifest(&self, home_id: HomeId, memory_limit: &MemoryLimit) -> serde_json::Value {
        let mut manifest =
            self.pvc_manifest(format!("sandboxwich-home-{home_id}"), None, memory_limit);
        manifest["metadata"]["labels"]["sandboxwich.dev/home-id"] = json!(home_id);
        manifest
    }

    /// Builds an `ipBlock` for `cidr`, carving the configured
    /// `egress_excluded_cidrs` (control-plane / cloud metadata / cluster
    /// service ranges) out via `except` wherever they actually overlap
    /// `cidr` -- not just for the wide-open `0.0.0.0/0` case (GH-66,
    /// GH-<this fix>). A narrower allowlist entry like `10.0.0.0/8` fully
    /// contains the default excluded ranges (`10.42.0.0/16`,
    /// `10.43.0.0/16`) and, if it happened to include `169.254.0.0/16`,
    /// would otherwise expose the cloud metadata endpoint
    /// (`169.254.169.254`) to every sandbox -- a direct path to credential
    /// theft. CIDR blocks are power-of-two aligned, so two CIDRs can only
    /// ever be identical, nested (one strictly contains the other), or
    /// disjoint; there is no partial-overlap case to handle. Returns an
    /// error if an excluded CIDR fully contains (or equals) `cidr`, since
    /// Kubernetes NetworkPolicy requires every `except` entry to be a
    /// strict subset of `cidr` and there would be nothing left to allow.
    fn ip_block(&self, cidr: &str) -> anyhow::Result<serde_json::Value> {
        let except = self.excepted_cidrs_for(cidr)?;
        if except.is_empty() {
            Ok(json!({ "cidr": cidr }))
        } else {
            Ok(json!({
                "cidr": cidr,
                "except": except
            }))
        }
    }

    /// Computes which of the configured `egress_excluded_cidrs` must be
    /// rendered as `except` entries for the allow rule `cidr`, per the
    /// containment rules described on `ip_block`.
    fn excepted_cidrs_for(&self, cidr: &str) -> anyhow::Result<Vec<String>> {
        if self.egress_excluded_cidrs.is_empty() {
            return Ok(Vec::new());
        }
        let allowed =
            IpNet::from_str(cidr).with_context(|| format!("invalid egress allow CIDR {cidr}"))?;
        let mut except = Vec::new();
        for excluded_str in &self.egress_excluded_cidrs {
            let excluded = IpNet::from_str(excluded_str)
                .with_context(|| format!("invalid egress excluded CIDR {excluded_str}"))?;
            if excluded.contains(&allowed) {
                bail!(
                    "egress allow rule {cidr} is entirely covered by excluded control-plane/metadata CIDR {excluded_str}; refusing to render a NetworkPolicy that would either expose it or leave nothing allowed"
                );
            }
            if allowed.contains(&excluded) {
                except.push(excluded_str.clone());
            }
        }
        Ok(except)
    }

    /// Egress rule always appended so sandboxes can resolve DNS even under
    /// a restrictive allowlist (GH-66). Scoped to the cluster DNS
    /// namespace/pods rather than left open.
    fn dns_egress_rules(&self) -> Vec<serde_json::Value> {
        let mut rules = vec![json!({
            "to": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": self.dns_namespace
                    }
                },
                "podSelector": {
                    "matchLabels": {
                        "k8s-app": "kube-dns"
                    }
                }
            }],
            "ports": [
                {"protocol": "UDP", "port": 53},
                {"protocol": "TCP", "port": 53}
            ]
        })];
        rules.extend(self.dns_service_ips.iter().map(|address| {
            let cidr = match address {
                IpAddr::V4(address) => format!("{address}/32"),
                IpAddr::V6(address) => format!("{address}/128"),
            };
            json!({
                "to": [{"ipBlock": {"cidr": cidr}}],
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53}
                ]
            })
        }));
        rules
    }

    fn api_egress_rule(&self) -> serde_json::Value {
        json!({
            "to": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": self.effective_ingress_namespace()
                    }
                },
                "podSelector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": "sandboxwich-api"
                    }
                }
            }],
            "ports": [{"protocol": "TCP", "port": 3217}]
        })
    }

    /// Ingress rule restricting the sandbox's ssh/desktop/vnc ports to
    /// control-plane pods only, closing the unauthenticated cross-tenant
    /// path where any pod on the cluster network (including other
    /// tenants' sandboxes) could otherwise reach them directly (GH-67).
    fn ingress_rule(&self) -> serde_json::Value {
        json!({
            "from": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": self.effective_ingress_namespace()
                    }
                },
                "podSelector": {
                    "matchLabels": self.ingress_pod_selector
                }
            }],
            "ports": [
                {"protocol": "TCP", "port": 2222},
                {"protocol": "TCP", "port": 6080},
                {"protocol": "TCP", "port": 5900}
            ]
        })
    }

    fn network_policy_manifest(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
    ) -> anyhow::Result<serde_json::Value> {
        self.validate_network_policy_egress(network_egress)?;
        if self.fqdn_egress_backend.as_deref() == Some("cilium")
            && network_egress
                .rules()
                .iter()
                .any(|rule| rule.kind == NetworkAllowRuleKind::Host)
        {
            return Ok(self.cilium_fqdn_policy_manifest(sandbox_id, network_egress));
        }
        let mut egress = match network_egress {
            NetworkEgress::DenyAll => Vec::new(),
            NetworkEgress::AllowAll => {
                vec![json!({ "to": [{ "ipBlock": self.ip_block("0.0.0.0/0")? }] })]
            }
            NetworkEgress::Allowlist { rules } => {
                let mut egress: Vec<serde_json::Value> = rules
                    .iter()
                    .filter(|rule| rule.kind == NetworkAllowRuleKind::Cidr)
                    .map(|rule| -> anyhow::Result<serde_json::Value> {
                        Ok(json!({
                            "to": [{ "ipBlock": self.ip_block(&rule.value)? }]
                        }))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                if self.uses_egress_gateway(network_egress) {
                    egress.push(json!({
                        "to": [{
                            "podSelector": {"matchLabels": {
                                "sandboxwich.dev/sandbox-id": sandbox_id,
                                "sandboxwich.dev/component": "egress-gateway"
                            }}
                        }],
                        "ports": [{"protocol": "TCP", "port": 8080}]
                    }));
                }
                egress
            }
        };
        // Control-plane DNS and the authenticated API channel are invariant
        // system dependencies, not tenant-selected workload egress.
        egress.extend(self.dns_egress_rules());
        egress.push(self.api_egress_rule());

        Ok(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": self.object_metadata(format!("sandboxwich-egress-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "sandboxwich.dev/sandbox-id": sandbox_id,
                        "sandboxwich.dev/component": "runtime"
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [self.ingress_rule()],
                "egress": egress
            }
        }))
    }

    fn cilium_fqdn_policy_manifest(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
    ) -> serde_json::Value {
        let rules = network_egress.rules();
        let hosts: Vec<_> = rules
            .iter()
            .filter(|rule| rule.kind == NetworkAllowRuleKind::Host)
            .map(|rule| {
                if rule.value.starts_with("*.") {
                    json!({"matchPattern": rule.value})
                } else {
                    json!({"matchName": rule.value})
                }
            })
            .collect();
        let cidrs: Vec<_> = rules
            .iter()
            .filter(|rule| rule.kind == NetworkAllowRuleKind::Cidr)
            .map(|rule| {
                let block = self.ip_block(&rule.value)?;
                Ok(json!({
                    "cidr": block["cidr"],
                    "exceptCIDRs": block.get("except").cloned().unwrap_or_else(|| json!([]))
                }))
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .expect("CIDRs were validated before provider dispatch");
        let mut ingress_labels = serde_json::Map::from_iter([(
            "k8s:io.kubernetes.pod.namespace".to_string(),
            json!(self.effective_ingress_namespace()),
        )]);
        for (key, value) in &self.ingress_pod_selector {
            ingress_labels.insert(format!("k8s:{key}"), json!(value));
        }
        let denied_cidrs: Vec<_> = self
            .egress_excluded_cidrs
            .iter()
            .map(|cidr| json!({"cidr": cidr}))
            .collect();
        let mut egress = vec![json!({"toFQDNs": hosts})];
        if !cidrs.is_empty() {
            egress.push(json!({"toCIDRSet": cidrs}));
        }
        egress.push(json!({
            "toEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": self.dns_namespace, "k8s:k8s-app": "kube-dns"}}],
            "toPorts": [{"ports": [{"port": "53", "protocol": "ANY"}]}]
        }));
        egress.push(json!({
            "toEndpoints": [{"matchLabels": {
                "k8s:io.kubernetes.pod.namespace": self.effective_ingress_namespace(),
                "k8s:app.kubernetes.io/name": "sandboxwich-api"
            }}],
            "toPorts": [{"ports": [{"port": "3217", "protocol": "TCP"}]}]
        }));
        egress.extend(self.dns_service_ips.iter().map(|address| {
            let cidr = match address {
                IpAddr::V4(address) => format!("{address}/32"),
                IpAddr::V6(address) => format!("{address}/128"),
            };
            json!({
                "toCIDRSet": [{"cidr": cidr}],
                "toPorts": [{"ports": [{"port": "53", "protocol": "ANY"}]}]
            })
        }));
        json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": self.object_metadata(format!("sandboxwich-egress-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "endpointSelector": {"matchLabels": {"sandboxwich.dev/sandbox-id": sandbox_id}},
                "ingress": [{
                    "fromEndpoints": [{"matchLabels": ingress_labels}],
                    "toPorts": [{"ports": [
                        {"port": "2222", "protocol": "TCP"}, {"port": "6080", "protocol": "TCP"}, {"port": "5900", "protocol": "TCP"}
                    ]}]
                }],
                "egress": egress,
                "egressDeny": [{"toCIDRSet": denied_cidrs}]
            }
        })
    }

    fn egress_gateway_pod_manifest(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let Some(policy) = self.egress_gateway_policy(network_egress)? else {
            return Ok(None);
        };
        let image = self
            .egress_gateway_image
            .as_deref()
            .context("egress_gateway_image_required")?;
        let mut manifest = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": self.object_metadata(
                format!("sandboxwich-egress-gateway-{sandbox_id}"),
                Some(sandbox_id),
            ),
            "spec": {
                "automountServiceAccountToken": false,
                "securityContext": {
                    "runAsNonRoot": true,
                    "runAsUser": 10001,
                    "runAsGroup": 10001,
                    "seccompProfile": {"type": "RuntimeDefault"}
                },
                "containers": [{
                    "name": "gateway",
                    "image": image,
                    "imagePullPolicy": image_pull_policy_for(image),
                    "args": ["egress-gateway"],
                    "ports": [{"name": "proxy", "containerPort": 8080}],
                    "readinessProbe": {
                        "exec": {"command": [
                            "/usr/local/bin/sandboxwich",
                            "egress-gateway-health"
                        ]},
                        "periodSeconds": 2,
                        "timeoutSeconds": 1,
                        "failureThreshold": 5
                    },
                    "livenessProbe": {
                        "exec": {"command": [
                            "/usr/local/bin/sandboxwich",
                            "egress-gateway-health"
                        ]},
                        "periodSeconds": 10,
                        "timeoutSeconds": 1,
                        "failureThreshold": 3
                    },
                    "env": [{
                        "name": "SANDBOXWICH_EGRESS_GATEWAY_POLICY",
                        "value": serde_json::to_string(&policy)?
                    }],
                    "resources": {
                        "requests": {"cpu": "25m", "memory": "32Mi", "ephemeral-storage": "32Mi"},
                        "limits": {"cpu": "250m", "memory": "128Mi", "ephemeral-storage": "128Mi"}
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": true,
                        "runAsNonRoot": true,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"}
                    }
                }]
            }
        });
        manifest["metadata"]["labels"]["sandboxwich.dev/component"] = json!("egress-gateway");
        manifest["metadata"]["annotations"] = json!({
            "sandboxwich.dev/egress-policy-id": policy.policy_id
        });
        Ok(Some(manifest))
    }

    fn egress_gateway_service_manifest(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
    ) -> Option<serde_json::Value> {
        self.uses_egress_gateway(network_egress).then(|| {
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": self.object_metadata(
                    format!("sandboxwich-egress-gateway-{sandbox_id}"),
                    Some(sandbox_id),
                ),
                "spec": {
                    "type": "ClusterIP",
                    "selector": {
                        "sandboxwich.dev/sandbox-id": sandbox_id,
                        "sandboxwich.dev/component": "egress-gateway"
                    },
                    "ports": [{"name": "proxy", "port": 8080, "targetPort": "proxy"}]
                }
            })
        })
    }

    fn egress_gateway_network_policy_manifest(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let Some(policy) = self.egress_gateway_policy(network_egress)? else {
            return Ok(None);
        };
        let denied_v4 = policy
            .denied_cidrs
            .iter()
            .filter(|cidr| cidr.addr().is_ipv4())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let denied_v6 = policy
            .denied_cidrs
            .iter()
            .filter(|cidr| match cidr {
                IpNet::V6(cidr) => cidr.network().to_ipv4_mapped().is_none(),
                IpNet::V4(_) => false,
            })
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut egress = self.dns_egress_rules();
        egress.extend([
            json!({
                "to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": denied_v4}}],
                "ports": [
                    {"protocol": "TCP", "port": 80},
                    {"protocol": "TCP", "port": 443}
                ]
            }),
            json!({
                "to": [{"ipBlock": {"cidr": "::/0", "except": denied_v6}}],
                "ports": [
                    {"protocol": "TCP", "port": 80},
                    {"protocol": "TCP", "port": 443}
                ]
            }),
        ]);
        Ok(Some(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": self.object_metadata(
                format!("sandboxwich-egress-gateway-{sandbox_id}"),
                Some(sandbox_id),
            ),
            "spec": {
                "podSelector": {"matchLabels": {
                    "sandboxwich.dev/sandbox-id": sandbox_id,
                    "sandboxwich.dev/component": "egress-gateway"
                }},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {
                        "sandboxwich.dev/sandbox-id": sandbox_id,
                        "sandboxwich.dev/component": "runtime"
                    }}}],
                    "ports": [{"protocol": "TCP", "port": 8080}]
                }],
                "egress": egress
            }
        })))
    }

    fn ssh_service_manifest(&self, sandbox_id: SandboxId) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": self.object_metadata(format!("sandboxwich-ssh-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "type": "ClusterIP",
                "selector": {
                    "sandboxwich.dev/sandbox-id": sandbox_id,
                    "sandboxwich.dev/component": "runtime"
                },
                "ports": [{
                    "name": "ssh",
                    "port": 22,
                    "targetPort": "ssh"
                }]
            }
        })
    }

    fn fork_pvc_manifest(
        &self,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        memory_limit: &MemoryLimit,
    ) -> serde_json::Value {
        let mut spec = Map::from_iter([
            ("accessModes".to_string(), json!(["ReadWriteOnce"])),
            (
                "resources".to_string(),
                json!({
                    "requests": {
                        "storage": self.effective_workspace_storage(memory_limit)
                    }
                }),
            ),
            (
                "dataSource".to_string(),
                json!({
                    "name": format!("sandboxwich-snapshot-{snapshot_id}"),
                    "kind": "VolumeSnapshot",
                    "apiGroup": "snapshot.storage.k8s.io"
                }),
            ),
        ]);
        if let Some(storage_class) = &self.storage_class {
            spec.insert("storageClassName".to_string(), json!(storage_class));
        }

        json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": self.object_metadata(format!("sandboxwich-pvc-{child_sandbox_id}"), Some(child_sandbox_id)),
            "spec": spec
        })
    }

    fn desktop_service_manifest(&self, sandbox_id: SandboxId) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": self.object_metadata(format!("sandboxwich-desktop-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "type": "ClusterIP",
                "selector": {
                    "sandboxwich.dev/sandbox-id": sandbox_id,
                    "sandboxwich.dev/component": "runtime"
                },
                "ports": [{
                    "name": "desktop",
                    "port": 6080,
                    "targetPort": "desktop"
                }]
            }
        })
    }

    fn volume_snapshot_manifest(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> serde_json::Value {
        let mut spec = Map::from_iter([(
            "source".to_string(),
            json!({
                "persistentVolumeClaimName": format!("sandboxwich-pvc-{sandbox_id}")
            }),
        )]);
        if let Some(snapshot_class) = &self.snapshot_class {
            spec.insert("volumeSnapshotClassName".to_string(), json!(snapshot_class));
        }

        json!({
            "apiVersion": "snapshot.storage.k8s.io/v1",
            "kind": "VolumeSnapshot",
            "metadata": self.object_metadata(format!("sandboxwich-snapshot-{snapshot_id}"), Some(sandbox_id)),
            "spec": spec
        })
    }

    fn sandbox_resources(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        status: RuntimeResourceStatus,
    ) -> Vec<ProviderRuntimeResource> {
        let mut resources = Vec::new();
        if spec.workspace_mode == WorkspaceMode::Persistent {
            resources.push(self.workspace_pvc_resource(
                sandbox_id,
                &spec.memory_limit,
                status.clone(),
                None,
            ));
        }
        resources.extend([
            self.runtime_pod_resource(sandbox_id, status.clone()),
            self.ssh_service_resource(sandbox_id, status.clone()),
            self.desktop_service_resource(sandbox_id, status.clone()),
            self.network_policy_resource(sandbox_id, status.clone()),
        ]);
        resources.extend(self.egress_gateway_resources(
            sandbox_id,
            &spec.network_egress,
            status.clone(),
        ));
        resources
    }

    fn provision_home_handle(
        &self,
        sandbox_id: SandboxId,
        home_id: HomeId,
        spec: &SandboxProvisionSpec,
        status: RuntimeResourceStatus,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        let mut handle = ProviderSandboxHandle {
            provider: "kubernetes".to_string(),
            sandbox_id,
            resources: self.sandbox_resources(sandbox_id, spec, status),
            metadata: self.metadata(sandbox_id, "provision", spec)?,
        };
        handle.resources.retain(|resource| {
            resource.resource_kind != RuntimeResourceKind::PersistentVolumeClaim
        });
        handle.metadata["homeId"] = json!(home_id);
        handle.metadata["manifests"]["pvc"] = self.home_pvc_manifest(home_id, &spec.memory_limit);
        handle.metadata["manifests"]["pod"] =
            self.pod_manifest_with_home(sandbox_id, home_id, spec);
        Ok(handle)
    }

    fn fork_resources(
        &self,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        status: RuntimeResourceStatus,
    ) -> Vec<ProviderRuntimeResource> {
        let mut resources = vec![
            self.workspace_pvc_resource(
                child_sandbox_id,
                &spec.memory_limit,
                status.clone(),
                Some(snapshot_id),
            ),
            self.runtime_pod_resource(child_sandbox_id, status.clone()),
            self.ssh_service_resource(child_sandbox_id, status.clone()),
            self.desktop_service_resource(child_sandbox_id, status.clone()),
            self.network_policy_resource(child_sandbox_id, status.clone()),
        ];
        resources.extend(self.egress_gateway_resources(
            child_sandbox_id,
            &spec.network_egress,
            status.clone(),
        ));
        resources
    }

    fn snapshot_resources(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        status: RuntimeResourceStatus,
    ) -> Vec<ProviderRuntimeResource> {
        let mut resource = self.base_resource(
            sandbox_id,
            Some(snapshot_id),
            RuntimeResourceKind::VolumeSnapshot,
            RuntimeResourcePurpose::Snapshot,
            format!("sandboxwich-snapshot-{snapshot_id}"),
            status,
        );
        resource.snapshot_class = self.snapshot_class.clone();
        vec![resource]
    }

    fn workspace_pvc_resource(
        &self,
        sandbox_id: SandboxId,
        memory_limit: &MemoryLimit,
        status: RuntimeResourceStatus,
        source_snapshot_id: Option<SnapshotId>,
    ) -> ProviderRuntimeResource {
        let mut resource = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::PersistentVolumeClaim,
            RuntimeResourcePurpose::Workspace,
            format!("sandboxwich-pvc-{sandbox_id}"),
            status,
        );
        resource.storage_class = self.storage_class.clone();
        resource.storage_size = Some(self.effective_workspace_storage(memory_limit));
        resource.source_snapshot_id = source_snapshot_id;
        resource
    }

    fn runtime_pod_resource(
        &self,
        sandbox_id: SandboxId,
        status: RuntimeResourceStatus,
    ) -> ProviderRuntimeResource {
        let mut resource = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Pod,
            RuntimeResourcePurpose::Runtime,
            format!("sandboxwich-{sandbox_id}"),
            status,
        );
        resource.runtime_image = Some(self.runtime_image.clone());
        resource
    }

    fn ssh_service_resource(
        &self,
        sandbox_id: SandboxId,
        status: RuntimeResourceStatus,
    ) -> ProviderRuntimeResource {
        let mut resource = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Service,
            RuntimeResourcePurpose::Ssh,
            format!("sandboxwich-ssh-{sandbox_id}"),
            status,
        );
        resource.service_port = Some(22);
        resource.target_port = Some("ssh".to_string());
        resource
    }

    fn network_policy_resource(
        &self,
        sandbox_id: SandboxId,
        status: RuntimeResourceStatus,
    ) -> ProviderRuntimeResource {
        self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::NetworkPolicy,
            RuntimeResourcePurpose::Network,
            format!("sandboxwich-egress-{sandbox_id}"),
            status,
        )
    }

    fn egress_gateway_resources(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
        status: RuntimeResourceStatus,
    ) -> Vec<ProviderRuntimeResource> {
        if !self.uses_egress_gateway(network_egress) {
            return Vec::new();
        }
        let name = format!("sandboxwich-egress-gateway-{sandbox_id}");
        let mut pod = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Pod,
            RuntimeResourcePurpose::Network,
            name.clone(),
            status.clone(),
        );
        pod.runtime_image = self.egress_gateway_image.clone();
        let mut service = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Service,
            RuntimeResourcePurpose::Network,
            name.clone(),
            status.clone(),
        );
        service.service_port = Some(8080);
        service.target_port = Some("proxy".to_string());
        let policy = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::NetworkPolicy,
            RuntimeResourcePurpose::Network,
            name,
            status,
        );
        vec![pod, service, policy]
    }

    fn desktop_service_resource(
        &self,
        sandbox_id: SandboxId,
        status: RuntimeResourceStatus,
    ) -> ProviderRuntimeResource {
        let mut resource = self.base_resource(
            sandbox_id,
            None,
            RuntimeResourceKind::Service,
            RuntimeResourcePurpose::Desktop,
            format!("sandboxwich-desktop-{sandbox_id}"),
            status,
        );
        resource.service_port = Some(6080);
        resource.target_port = Some("desktop".to_string());
        resource
    }

    fn base_resource(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: Option<SnapshotId>,
        resource_kind: RuntimeResourceKind,
        purpose: RuntimeResourcePurpose,
        resource_name: String,
        status: RuntimeResourceStatus,
    ) -> ProviderRuntimeResource {
        ProviderRuntimeResource {
            sandbox_id,
            snapshot_id,
            provider: "kubernetes".to_string(),
            resource_kind,
            purpose,
            resource_name,
            namespace: self.effective_sandbox_namespace().to_string(),
            status,
            cluster: Some(self.cluster.clone()),
            storage_class: None,
            snapshot_class: None,
            storage_size: None,
            runtime_image: None,
            service_port: None,
            target_port: None,
            source_snapshot_id: None,
            ready_at: None,
            error: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KubernetesApplyPlan {
    pub provider: String,
    pub mode: String,
    pub operation: String,
    pub cluster: String,
    pub namespace: String,
    pub kubectl: String,
    pub exec_handoff: AgentCommandResult,
    pub apply_args: Vec<String>,
    pub cleanup_args: Vec<String>,
    pub apply_manifests: Vec<Value>,
    pub cleanup_manifests: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KubernetesApplyOutcome {
    pub ok: bool,
    pub applied: bool,
    pub cleaned_up: bool,
    pub plan: KubernetesApplyPlan,
    pub apply_status: String,
    pub apply_stdout: String,
    pub apply_stderr: String,
    pub cleanup_status: String,
    pub cleanup_stdout: String,
    pub cleanup_stderr: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesApplyProvider {
    dry_run: KubernetesDryRunProvider,
    kubectl: String,
    kubectl_context: Option<String>,
    confirm_apply: bool,
    mutation_enabled: bool,
    kubectl_command_timeout: Duration,
    max_captured_output_bytes: u64,
    isolated_resident_process_image: Option<String>,
    isolated_resident_process_startup_timeout: Duration,
    isolated_resident_process_poll_interval: Duration,
    isolated_resident_process_max_poll_interval: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KubernetesResourceIdentity {
    resource_kind: RuntimeResourceKind,
    namespace: String,
    name: String,
    uid: String,
    observed_generation: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedKubernetesResource {
    sandbox_id: SandboxId,
    resource_kind: RuntimeResourceKind,
    namespace: String,
    name: String,
    uid: String,
    expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedKubernetesResource {
    sandbox_id: Option<SandboxId>,
    resource_kind: RuntimeResourceKind,
    namespace: String,
    name: String,
    uid: String,
    resident_lease_id: Option<Uuid>,
    created_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReconciliationInventory {
    sandbox_ids: std::collections::HashSet<SandboxId>,
    resources: Vec<ExpectedKubernetesResource>,
    active_resident_lease_ids: std::collections::HashSet<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationClassification {
    Expected,
    Missing,
    Orphaned,
    Expired,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReconciliationDecision {
    classification: ReconciliationClassification,
    resource: Option<ObservedKubernetesResource>,
    delete_allowed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationLimits {
    pub max_scanned: usize,
    pub max_deleted: usize,
    pub max_elapsed: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationOutcome {
    pub(crate) decisions: Vec<ReconciliationDecision>,
    pub(crate) deleted: usize,
    pub(crate) apply: bool,
}

fn classify_reconciliation(
    inventory: &ReconciliationInventory,
    observed: &[ObservedKubernetesResource],
    expired_sandboxes: &std::collections::HashMap<SandboxId, chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> Vec<ReconciliationDecision> {
    let mut decisions = observed
        .iter()
        .map(|resource| {
            let coordinate_match = inventory.resources.iter().find(|expected| {
                Some(expected.sandbox_id) == resource.sandbox_id
                    && expected.resource_kind == resource.resource_kind
                    && expected.namespace == resource.namespace
                    && expected.name == resource.name
            });
            let classification = match resource.sandbox_id {
                None => ReconciliationClassification::Indeterminate,
                Some(_)
                    if resource.resident_lease_id.is_some_and(|lease_id| {
                        inventory.active_resident_lease_ids.contains(&lease_id)
                    }) =>
                {
                    ReconciliationClassification::Expected
                }
                Some(_) if resource.resident_lease_id.is_some() => resource
                    .created_at
                    .filter(|created_at| {
                        now.signed_duration_since(*created_at) >= chrono::Duration::minutes(5)
                    })
                    .map_or(ReconciliationClassification::Indeterminate, |_| {
                        ReconciliationClassification::Orphaned
                    }),
                Some(_)
                    if coordinate_match.is_some_and(|expected| expected.uid != resource.uid) =>
                {
                    ReconciliationClassification::Indeterminate
                }
                Some(sandbox_id)
                    if expired_sandboxes
                        .get(&sandbox_id)
                        .is_some_and(|expires_at| *expires_at <= now) =>
                {
                    ReconciliationClassification::Expired
                }
                Some(_) if coordinate_match.is_some() => ReconciliationClassification::Expected,
                Some(sandbox_id) if inventory.sandbox_ids.contains(&sandbox_id) => {
                    ReconciliationClassification::Indeterminate
                }
                Some(_) => ReconciliationClassification::Orphaned,
            };
            ReconciliationDecision {
                delete_allowed: matches!(
                    classification,
                    ReconciliationClassification::Orphaned | ReconciliationClassification::Expired
                ),
                classification,
                resource: Some(resource.clone()),
            }
        })
        .collect::<Vec<_>>();

    for expected in &inventory.resources {
        if !observed.iter().any(|resource| {
            resource.sandbox_id == Some(expected.sandbox_id)
                && resource.resource_kind == expected.resource_kind
                && resource.namespace == expected.namespace
                && resource.name == expected.name
                && resource.uid == expected.uid
        }) {
            decisions.push(ReconciliationDecision {
                classification: ReconciliationClassification::Missing,
                resource: None,
                delete_allowed: false,
            });
        }
    }
    decisions
}

fn plan_orphan_reconciliation(
    inventory: anyhow::Result<ReconciliationInventory>,
    observed: &[ObservedKubernetesResource],
    expired_sandboxes: &std::collections::HashMap<SandboxId, chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> Vec<ReconciliationDecision> {
    match inventory {
        Ok(inventory) => classify_reconciliation(&inventory, observed, expired_sandboxes, now),
        Err(_) => observed
            .iter()
            .cloned()
            .map(|resource| ReconciliationDecision {
                classification: ReconciliationClassification::Indeterminate,
                resource: Some(resource),
                delete_allowed: false,
            })
            .collect(),
    }
}

fn kubernetes_delete_path(resource: &ObservedKubernetesResource) -> anyhow::Result<String> {
    let plural = match resource.resource_kind {
        RuntimeResourceKind::Pod => "pods",
        RuntimeResourceKind::PersistentVolumeClaim => "persistentvolumeclaims",
        RuntimeResourceKind::Service => "services",
        RuntimeResourceKind::Secret => "secrets",
        RuntimeResourceKind::NetworkPolicy => {
            if resource.name.starts_with("sandboxwich-fqdn-egress-") {
                return Ok(format!(
                    "/apis/networking.gke.io/v1alpha1/namespaces/{}/fqdnnetworkpolicies/{}",
                    resource.namespace, resource.name
                ));
            }
            return Ok(format!(
                "/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies/{}",
                resource.namespace, resource.name
            ));
        }
        RuntimeResourceKind::VolumeSnapshot => {
            bail!("volume snapshots are outside orphan reconciliation scope")
        }
    };
    Ok(format!(
        "/api/v1/namespaces/{}/{plural}/{}",
        resource.namespace, resource.name
    ))
}

fn kubernetes_delete_options(resource: &ObservedKubernetesResource) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": { "uid": resource.uid },
        "propagationPolicy": "Background"
    })
}

fn runtime_resource_kind_for_kubernetes_kind(kind: &str) -> anyhow::Result<RuntimeResourceKind> {
    match kind {
        "PersistentVolumeClaim" => Ok(RuntimeResourceKind::PersistentVolumeClaim),
        "NetworkPolicy" | "FQDNNetworkPolicy" => Ok(RuntimeResourceKind::NetworkPolicy),
        "Secret" => Ok(RuntimeResourceKind::Secret),
        "Pod" => Ok(RuntimeResourceKind::Pod),
        "Service" => Ok(RuntimeResourceKind::Service),
        other => bail!("unsupported staged Kubernetes resource kind {other}"),
    }
}

fn adoption_contract(resource: &Value) -> anyhow::Result<Value> {
    let kind = resource["kind"]
        .as_str()
        .context("Kubernetes resource kind is required")?;
    let contract = match kind {
        "PersistentVolumeClaim" => json!({
            "storageClassName": resource["spec"]["storageClassName"],
            "accessModes": resource["spec"]["accessModes"],
            "volumeMode": resource["spec"]["volumeMode"],
            "dataSource": resource["spec"]["dataSource"],
        }),
        "NetworkPolicy" => {
            let mut spec = resource["spec"].clone();
            let fields = spec
                .as_object_mut()
                .context("NetworkPolicy spec must be an object")?;
            // The API server omits empty slices when serializing an object
            // back to JSON. For a policy that includes `Egress` in
            // policyTypes, an absent `egress` field and `egress: []` both
            // mean deny all; canonicalize that representation before the
            // security-sensitive comparison.
            fields.entry("ingress").or_insert_with(|| json!([]));
            fields.entry("egress").or_insert_with(|| json!([]));
            spec
        }
        "FQDNNetworkPolicy" => resource["spec"].clone(),
        "Pod" => {
            let mut containers = resource["spec"]["containers"].clone();
            if let Some(containers) = containers.as_array_mut() {
                for container in containers {
                    let Some(env) = container["env"].as_array_mut() else {
                        continue;
                    };
                    let has_guest_token = env
                        .iter()
                        .any(|entry| entry["name"] == "SANDBOXWICH_GUEST_TOKEN_FILE");
                    if has_guest_token {
                        // A lost-response replay may be leased by a replacement
                        // worker. Preserve the running pod's original guest-token
                        // binding instead of treating the replacement worker id
                        // as immutable pod drift. The id is routing metadata, not
                        // authority; the mounted guest token remains the scoped
                        // credential and every other env field must still match.
                        for entry in env
                            .iter_mut()
                            .filter(|entry| entry["name"] == "SANDBOXWICH_WORKER_ID")
                        {
                            entry["value"] = json!("<placement-worker>");
                        }
                    }
                }
            }
            json!({
                "runtimeClassName": resource["spec"]["runtimeClassName"],
                "automountServiceAccountToken": resource["spec"]["automountServiceAccountToken"],
                "hostNetwork": resource["spec"]["hostNetwork"].as_bool().unwrap_or(false),
                "hostPID": resource["spec"]["hostPID"].as_bool().unwrap_or(false),
                "hostIPC": resource["spec"]["hostIPC"].as_bool().unwrap_or(false),
                "securityContext": resource["spec"]["securityContext"],
                "containers": containers,
                "volumes": resource["spec"]["volumes"],
            })
        }
        "Service" => json!({
            "type": resource["spec"]["type"],
            "selector": resource["spec"]["selector"],
            "ports": resource["spec"]["ports"],
        }),
        "Secret" => {
            let mut data = resource["data"].as_object().cloned().unwrap_or_default();
            if let Some(string_data) = resource["stringData"].as_object() {
                for (key, value) in string_data {
                    let value = value
                        .as_str()
                        .context("Secret stringData values must be strings")?;
                    data.insert(
                        key.clone(),
                        json!(general_purpose::STANDARD.encode(value.as_bytes())),
                    );
                }
            }
            // The guest-token Secret's `api-token` is minted fresh for every
            // provisioning attempt, so a replayed provision (lost-response
            // recovery) can never byte-match the token the live Secret
            // holds. Its adoption contract is presence, not equality: the
            // existing token is the one the running pod already mounted and
            // it stays valid on its own expiry/revocation schedule. Every
            // other key -- notably `api-url` -- still must match exactly,
            // because adopting a Secret that points the guest agent at a
            // different control plane is precisely what this check refuses.
            if resource["metadata"]["name"]
                .as_str()
                .is_some_and(|name| name.starts_with(GUEST_TOKEN_SECRET_NAME_PREFIX))
                && let Some(token) = data.get_mut("api-token")
            {
                *token = json!("<present>");
            }
            json!({
                "type": resource["type"],
                "immutable": resource["immutable"],
                "data": data,
            })
        }
        other => bail!("unsupported adoption contract for Kubernetes kind {other}"),
    };
    Ok(contract)
}

fn semantic_contract_matches(desired: &Value, observed: &Value) -> bool {
    match desired {
        Value::Null => true,
        Value::Object(desired_fields) => desired_fields.iter().all(|(key, desired_value)| {
            desired_value.is_null()
                || observed.get(key).is_some_and(|observed_value| {
                    semantic_contract_matches(desired_value, observed_value)
                })
        }),
        Value::Array(desired_items) => observed.as_array().is_some_and(|observed_items| {
            desired_items.len() == observed_items.len()
                && desired_items
                    .iter()
                    .zip(observed_items)
                    .all(|(desired_item, observed_item)| {
                        semantic_contract_matches(desired_item, observed_item)
                    })
        }),
        _ => desired == observed,
    }
}

fn validate_adoption_contract(desired: &Value, observed: &Value) -> anyhow::Result<()> {
    let kind = desired["kind"]
        .as_str()
        .context("desired Kubernetes resource kind is required")?;
    if observed["kind"] != desired["kind"]
        || observed["metadata"]["name"] != desired["metadata"]["name"]
        || observed["metadata"]["namespace"] != desired["metadata"]["namespace"]
        || !semantic_contract_matches(&adoption_contract(desired)?, &adoption_contract(observed)?)
    {
        let error_class = match kind {
            "Pod" | "NetworkPolicy" | "Secret" => ProvisioningErrorClass::TerminalSecurity,
            _ => ProvisioningErrorClass::TerminalContract,
        };
        return Err(anyhow::Error::new(ProviderError::classified(
            error_class,
            "resource_contract_conflict",
            anyhow::anyhow!("existing Kubernetes {kind} does not match the desired contract"),
        )));
    }
    Ok(())
}

fn classified_kubectl_failure(context: &str, stderr: &str) -> ProviderError {
    let message = format!("{context}: {stderr}");
    let normalized = stderr.to_ascii_lowercase();
    if normalized.contains("unbound immediate persistentvolumeclaims")
        || normalized.contains("insufficient cpu")
        || normalized.contains("insufficient memory")
        || normalized.contains("unschedulable")
    {
        return ProviderError::classified(
            ProvisioningErrorClass::RetryableCapacity,
            "workspace_capacity_pending",
            anyhow::anyhow!(message),
        );
    }
    if normalized.contains("admission")
        || normalized.contains("forbidden")
        || normalized.contains("denied")
        || normalized.contains("unauthorized")
    {
        return ProviderError::classified(
            ProvisioningErrorClass::TerminalSecurity,
            "kubernetes_policy_denied",
            anyhow::anyhow!(message),
        );
    }
    if normalized.contains("invalid")
        || normalized.contains("immutable")
        || normalized.contains("required value")
    {
        return ProviderError::classified(
            ProvisioningErrorClass::TerminalContract,
            "kubernetes_contract_invalid",
            anyhow::anyhow!(message),
        );
    }
    ProviderError::classified(
        ProvisioningErrorClass::RetryableProvider,
        "kubernetes_provider_transient",
        anyhow::anyhow!(message),
    )
}

fn stage_update(
    stage: ProvisioningStage,
    identity: Option<KubernetesResourceIdentity>,
) -> ProvisioningStageUpdateRequest {
    ProvisioningStageUpdateRequest {
        stage,
        resource_kind: identity.as_ref().map(|value| value.resource_kind.clone()),
        resource_namespace: identity.as_ref().map(|value| value.namespace.clone()),
        resource_name: identity.as_ref().map(|value| value.name.clone()),
        resource_uid: identity.as_ref().map(|value| value.uid.clone()),
        observed_generation: identity.and_then(|value| value.observed_generation),
        attempt_count: 1,
        last_error_class: None,
        last_error_code: None,
        last_error: None,
    }
}

impl KubernetesApplyProvider {
    pub fn new(dry_run: KubernetesDryRunProvider, kubectl: impl Into<String>) -> Self {
        let kubectl_context = Some(dry_run.cluster.clone());
        Self {
            dry_run,
            kubectl: kubectl.into(),
            kubectl_context,
            confirm_apply: false,
            mutation_enabled: false,
            kubectl_command_timeout: Duration::from_secs(DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS),
            max_captured_output_bytes: DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
            isolated_resident_process_image: None,
            isolated_resident_process_startup_timeout: Duration::from_secs(
                DEFAULT_ISOLATED_RESIDENT_PROCESS_STARTUP_TIMEOUT_SECS,
            ),
            isolated_resident_process_poll_interval: Duration::from_millis(
                DEFAULT_ISOLATED_RESIDENT_PROCESS_POLL_INTERVAL_MILLIS,
            ),
            isolated_resident_process_max_poll_interval: Duration::from_millis(
                DEFAULT_ISOLATED_RESIDENT_PROCESS_MAX_POLL_INTERVAL_MILLIS,
            ),
        }
    }

    pub fn with_guest_credentials(
        mut self,
        sandbox_id: SandboxId,
        worker_id: Uuid,
        api: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        self.dry_run = self
            .dry_run
            .with_guest_credentials(sandbox_id, worker_id, api, token);
        self
    }

    pub fn with_kubectl_context(mut self, context: Option<String>) -> Self {
        self.kubectl_context = context.and_then(|context| {
            let context = context.trim();
            if context.is_empty() || context == "in-cluster" {
                None
            } else {
                Some(context.to_string())
            }
        });
        self
    }

    pub fn with_mutation_gate(mut self, confirm_apply: bool, mutation_enabled: bool) -> Self {
        self.confirm_apply = confirm_apply;
        self.mutation_enabled = mutation_enabled;
        self
    }

    /// Overrides the bound applied to every `kubectl` invocation this provider
    /// makes (see [`DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS`]). A hung `kubectl`
    /// process (e.g. talking to an unreachable API server) is killed once this
    /// elapses instead of wedging the worker's job-execution thread forever.
    pub fn with_kubectl_command_timeout(mut self, timeout: Duration) -> Self {
        self.kubectl_command_timeout = timeout;
        self
    }

    fn pod_ready_timeout_arg(&self) -> String {
        let seconds = self
            .kubectl_command_timeout
            .as_secs()
            .saturating_sub(5)
            .max(1);
        format!("--timeout={seconds}s")
    }

    /// Caps the stdout/stderr captured from every `kubectl` invocation this
    /// provider makes. See `DEFAULT_MAX_CAPTURED_OUTPUT_BYTES`.
    pub fn with_max_captured_output_bytes(mut self, max_captured_output_bytes: u64) -> Self {
        self.max_captured_output_bytes = max_captured_output_bytes;
        self
    }

    pub fn with_isolated_resident_process_image(mut self, image: Option<String>) -> Self {
        self.isolated_resident_process_image = image.and_then(|image| {
            let image = image.trim();
            (!image.is_empty()).then(|| image.to_string())
        });
        self
    }

    pub fn with_isolated_resident_process_startup_timeout(mut self, timeout: Duration) -> Self {
        self.isolated_resident_process_startup_timeout = timeout.max(Duration::from_millis(1));
        self
    }

    pub fn with_isolated_resident_process_poll_intervals(
        mut self,
        initial: Duration,
        maximum: Duration,
    ) -> Self {
        self.isolated_resident_process_poll_interval = initial.max(Duration::from_millis(1));
        self.isolated_resident_process_max_poll_interval =
            maximum.max(self.isolated_resident_process_poll_interval);
        self
    }

    pub fn isolated_resident_process_image(&self) -> Option<&str> {
        self.isolated_resident_process_image.as_deref()
    }

    fn isolated_resident_process_configured(&self) -> bool {
        self.isolated_resident_process_image
            .as_deref()
            .is_some_and(image_is_digest_pinned)
            && self
                .dry_run
                .runtime_class_name
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty())
    }

    pub fn provision_staged<F>(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: F,
    ) -> anyhow::Result<ProviderSandboxHandle>
    where
        F: FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    {
        self.provision_staged_with_home(sandbox_id, None, spec, cancelled, report)
    }

    fn provision_staged_with_home<F>(
        &self,
        sandbox_id: SandboxId,
        home_id: Option<HomeId>,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        mut report: F,
    ) -> anyhow::Result<ProviderSandboxHandle>
    where
        F: FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    {
        self.dry_run
            .validate_network_policy_egress(&spec.network_egress)?;
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        report(stage_update(ProvisioningStage::WorkspacePlanned, None))?;

        if spec.workspace_mode == WorkspaceMode::Persistent {
            let workspace = home_id.map_or_else(
                || {
                    self.dry_run.pvc_manifest(
                        format!("sandboxwich-pvc-{sandbox_id}"),
                        Some(sandbox_id),
                        &spec.memory_limit,
                    )
                },
                |home_id| self.dry_run.home_pvc_manifest(home_id, &spec.memory_limit),
            );
            let workspace_identity = match home_id {
                Some(home_id) => {
                    self.apply_or_adopt_home_manifest(&workspace, home_id, cancelled)?
                }
                None => self.apply_or_adopt_manifest(&workspace, sandbox_id, cancelled)?,
            };
            report(stage_update(
                ProvisioningStage::WorkspaceReady,
                Some(workspace_identity),
            ))?;
        } else {
            report(stage_update(ProvisioningStage::WorkspaceReady, None))?;
        }

        if let Some(gateway_policy) = self
            .dry_run
            .egress_gateway_network_policy_manifest(sandbox_id, &spec.network_egress)?
        {
            let policy_identity =
                self.apply_or_adopt_manifest(&gateway_policy, sandbox_id, cancelled)?;
            report(stage_update(
                ProvisioningStage::NetworkPolicyReady,
                Some(policy_identity),
            ))?;
            let gateway_service = self
                .dry_run
                .egress_gateway_service_manifest(sandbox_id, &spec.network_egress)
                .context("gateway service missing for host policy")?;
            self.apply_or_adopt_manifest(&gateway_service, sandbox_id, cancelled)?;
            let gateway_pod = self
                .dry_run
                .egress_gateway_pod_manifest(sandbox_id, &spec.network_egress)?
                .context("gateway pod missing for host policy")?;
            self.apply_or_adopt_manifest(&gateway_pod, sandbox_id, cancelled)?;
            let gateway_name = format!("sandboxwich-egress-gateway-{sandbox_id}");
            let wait = self.wait_for_named_pod_ready(&gateway_name, cancelled)?;
            if !wait.success {
                return Err(anyhow::Error::new(classified_kubectl_failure(
                    "egress gateway pod did not become ready",
                    &wait.stderr,
                )));
            }
        }

        let network_policy = self
            .dry_run
            .network_policy_manifest(sandbox_id, &spec.network_egress)?;
        let network_identity =
            self.apply_or_adopt_manifest(&network_policy, sandbox_id, cancelled)?;
        report(stage_update(
            ProvisioningStage::NetworkPolicyReady,
            Some(network_identity),
        ))?;
        // The pod manifest below mounts the guest-token Secret whenever guest
        // credentials exist for this sandbox, so the Secret must be applied
        // before the pod or the kubelet mount fails until the pod times out.
        // The unstaged `provision` path gets this ordering from
        // `provision_manifests`; this staged path must apply it explicitly.
        if let Some(secret) = self.dry_run.guest_token_secret_manifest(sandbox_id) {
            let secret_identity = self.apply_or_adopt_manifest(&secret, sandbox_id, cancelled)?;
            report(stage_update(
                ProvisioningStage::CredentialsReady,
                Some(secret_identity),
            ))?;
        } else {
            report(stage_update(ProvisioningStage::CredentialsReady, None))?;
        }

        let pod = home_id.map_or_else(
            || self.dry_run.pod_manifest(sandbox_id, spec),
            |home_id| {
                self.dry_run
                    .pod_manifest_with_home(sandbox_id, home_id, spec)
            },
        );
        let pod_identity = self.apply_or_adopt_manifest(&pod, sandbox_id, cancelled)?;
        let wait = self.wait_for_pod_ready(sandbox_id, cancelled)?;
        if !wait.success {
            return Err(anyhow::Error::new(classified_kubectl_failure(
                "sandbox pod did not become ready",
                &wait.stderr,
            )));
        }
        report(stage_update(
            ProvisioningStage::PodReady,
            Some(pod_identity),
        ))?;

        let ssh_service = self.dry_run.ssh_service_manifest(sandbox_id);
        let ssh_service_identity =
            self.apply_or_adopt_manifest(&ssh_service, sandbox_id, cancelled)?;
        report(stage_update(
            ProvisioningStage::ServiceReady,
            Some(ssh_service_identity),
        ))?;
        let desktop_service = self.dry_run.desktop_service_manifest(sandbox_id);
        let service_identity =
            self.apply_or_adopt_manifest(&desktop_service, sandbox_id, cancelled)?;
        report(stage_update(
            ProvisioningStage::ServiceReady,
            Some(service_identity),
        ))?;
        report(stage_update(ProvisioningStage::SandboxReady, None))?;

        let mut handle = match home_id {
            Some(home_id) => self.dry_run.provision_home_handle(
                sandbox_id,
                home_id,
                spec,
                RuntimeResourceStatus::Ready,
            )?,
            None => self.dry_run.provision(sandbox_id, spec, cancelled)?,
        };
        mark_resources(
            &mut handle.resources,
            RuntimeResourceStatus::Ready,
            Some(Utc::now()),
        );
        if let Some(metadata) = handle.metadata.as_object_mut() {
            metadata.insert("mode".to_string(), json!("apply"));
            metadata.insert("provisioningMode".to_string(), json!("staged"));
        }
        Ok(handle)
    }

    fn discover_reconciliation_resources(
        &self,
        max_scanned: usize,
        max_elapsed: Duration,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<Vec<ObservedKubernetesResource>> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "get".to_string(),
            self.dry_run.reconciliation_resource_kinds(),
            "--selector".to_string(),
            "sandboxwich.dev/sandbox-id".to_string(),
            "--output".to_string(),
            "json".to_string(),
        ]);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "discover sandbox resources for reconciliation",
            self.kubectl_command_timeout.min(max_elapsed),
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !output.success {
            return Err(anyhow::Error::new(classified_kubectl_failure(
                "sandbox resource discovery failed",
                &output.stderr,
            )));
        }
        let list: Value = serde_json::from_str(&output.stdout)
            .context("kubectl reconciliation inventory was not valid JSON")?;
        let items = list["items"]
            .as_array()
            .context("kubectl reconciliation inventory omitted items")?;
        if items.len() > max_scanned {
            bail!("Kubernetes inventory exceeded max_scanned={max_scanned}");
        }
        items
            .iter()
            .map(|item| {
                let kind = item["kind"]
                    .as_str()
                    .context("observed Kubernetes resource omitted kind")?;
                let label = item["metadata"]["labels"]["sandboxwich.dev/sandbox-id"].as_str();
                Ok(ObservedKubernetesResource {
                    sandbox_id: label
                        .and_then(|value| Uuid::parse_str(value).ok())
                        .map(SandboxId),
                    resource_kind: runtime_resource_kind_for_kubernetes_kind(kind)?,
                    namespace: item["metadata"]["namespace"]
                        .as_str()
                        .context("observed Kubernetes resource omitted namespace")?
                        .to_string(),
                    name: item["metadata"]["name"]
                        .as_str()
                        .context("observed Kubernetes resource omitted name")?
                        .to_string(),
                    uid: item["metadata"]["uid"]
                        .as_str()
                        .context("observed Kubernetes resource omitted uid")?
                        .to_string(),
                    resident_lease_id: item["metadata"]["labels"]["sandboxwich.dev/lease-id"]
                        .as_str()
                        .and_then(|value| Uuid::parse_str(value).ok()),
                    created_at: item["metadata"]["creationTimestamp"]
                        .as_str()
                        .map(|value| {
                            chrono::DateTime::parse_from_rfc3339(value)
                                .map(|value| value.with_timezone(&Utc))
                                .context(
                                    "observed Kubernetes resource has invalid creationTimestamp",
                                )
                        })
                        .transpose()?,
                })
            })
            .collect()
    }

    fn delete_reconciled_resource(
        &self,
        resource: &ObservedKubernetesResource,
        timeout: Duration,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        if self.kubectl_context.is_some() {
            bail!("UID-fenced orphan deletion is supported only with in-cluster credentials");
        }
        if cancelled.is_cancelled() {
            bail!("orphan reconciliation was cancelled before delete");
        }
        let path = kubernetes_delete_path(resource)?;
        let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .context("read in-cluster service account token")?;
        let certificate = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
            .context("read in-cluster Kubernetes CA")?;
        let certificate = reqwest::Certificate::from_pem(&certificate)
            .context("parse in-cluster Kubernetes CA")?;
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .context("KUBERNETES_SERVICE_HOST is not set")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
            .context("KUBERNETES_SERVICE_PORT is not set")?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let url = format!("https://{host}:{port}{path}");
        let timeout = self.kubectl_command_timeout.min(timeout);
        let request = async move {
            let client = reqwest::Client::builder()
                .add_root_certificate(certificate)
                .timeout(timeout)
                .build()?;
            client
                .delete(url)
                .bearer_auth(token.trim())
                .json(&kubernetes_delete_options(resource))
                .send()
                .await
                .map_err(anyhow::Error::new)
        };
        let response = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(request)?,
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build runtime for Kubernetes UID-fenced delete")?
                .block_on(request)?,
        };
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            bail!(
                "Kubernetes UID-fenced delete failed with {}",
                response.status()
            );
        }
        Ok(())
    }

    pub fn reconcile_orphans(
        &self,
        inventory: anyhow::Result<RuntimeResourceInventoryResponse>,
        limits: ReconciliationLimits,
        apply: bool,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ReconciliationOutcome> {
        let started = std::time::Instant::now();
        let observed = match self.discover_reconciliation_resources(
            limits.max_scanned,
            limits.max_elapsed,
            cancelled,
        ) {
            Ok(resources) => resources,
            Err(_error) => {
                let decisions = inventory
                    .ok()
                    .map(|inventory| inventory.resources)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|_| ReconciliationDecision {
                        classification: ReconciliationClassification::Indeterminate,
                        resource: None,
                        delete_allowed: false,
                    })
                    .collect();
                return Ok(ReconciliationOutcome {
                    decisions,
                    deleted: 0,
                    apply,
                });
            }
        };
        let inventory = inventory.and_then(|response| {
            if response.provider != "kubernetes"
                || response.namespace != self.dry_run.effective_sandbox_namespace()
                || response.cluster.as_deref() != Some(self.dry_run.cluster.as_str())
                || !response.complete
                || response.next_cursor.is_some()
            {
                bail!("runtime resource inventory scope did not match this worker");
            }
            Ok(ReconciliationInventory {
                sandbox_ids: response.sandbox_ids.into_iter().collect(),
                active_resident_lease_ids: response.active_resident_lease_ids.into_iter().collect(),
                resources: response
                    .resources
                    .into_iter()
                    .map(|resource| ExpectedKubernetesResource {
                        sandbox_id: resource.sandbox_id,
                        resource_kind: resource.resource_kind,
                        namespace: resource.namespace,
                        name: resource.name,
                        uid: resource.uid,
                        expires_at: resource.cleanup_deadline,
                    })
                    .collect(),
            })
        });
        let expired = inventory
            .as_ref()
            .ok()
            .map(|inventory| {
                inventory
                    .resources
                    .iter()
                    .filter_map(|resource| resource.expires_at.map(|at| (resource.sandbox_id, at)))
                    .collect()
            })
            .unwrap_or_default();
        let mut decisions = plan_orphan_reconciliation(inventory, &observed, &expired, Utc::now());
        decisions.truncate(limits.max_scanned);
        let mut deleted = 0;
        if apply {
            for decision in &decisions {
                if deleted >= limits.max_deleted || started.elapsed() >= limits.max_elapsed {
                    break;
                }
                if decision.delete_allowed
                    && let Some(resource) = decision.resource.as_ref()
                {
                    let remaining = limits.max_elapsed.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        break;
                    }
                    self.delete_reconciled_resource(resource, remaining, cancelled)?;
                    deleted += 1;
                }
            }
        }
        Ok(ReconciliationOutcome {
            decisions,
            deleted,
            apply,
        })
    }

    fn apply_or_adopt_manifest(
        &self,
        manifest: &Value,
        sandbox_id: SandboxId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<KubernetesResourceIdentity> {
        self.apply_or_adopt_manifest_with_identity(
            manifest,
            "sandboxwich.dev/sandbox-id",
            &sandbox_id.to_string(),
            "sandbox",
            cancelled,
        )
    }

    fn apply_or_adopt_home_manifest(
        &self,
        manifest: &Value,
        home_id: HomeId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<KubernetesResourceIdentity> {
        self.apply_or_adopt_manifest_with_identity(
            manifest,
            "sandboxwich.dev/home-id",
            &home_id.to_string(),
            "home",
            cancelled,
        )
    }

    fn apply_or_adopt_manifest_with_identity(
        &self,
        manifest: &Value,
        identity_label: &str,
        identity_value: &str,
        identity_name: &str,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<KubernetesResourceIdentity> {
        let kind = manifest["kind"]
            .as_str()
            .context("Kubernetes manifest kind is required")?;
        let resource_kind = runtime_resource_kind_for_kubernetes_kind(kind)?;

        if let Some(identity) = self.read_resource_identity(
            manifest,
            identity_label,
            identity_value,
            identity_name,
            resource_kind.clone(),
            cancelled,
        )? {
            return Ok(identity);
        }

        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            std::slice::from_ref(manifest),
            "apply staged sandbox resource",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !apply.success {
            return Err(anyhow::Error::new(classified_kubectl_failure(
                "kubectl apply staged sandbox resource failed",
                &apply.stderr,
            )));
        }
        self.read_resource_identity(
            manifest,
            identity_label,
            identity_value,
            identity_name,
            resource_kind,
            cancelled,
        )?
        .ok_or_else(|| {
            anyhow::Error::new(ProviderError::classified(
                ProvisioningErrorClass::RetryableProvider,
                "resource_observation_missing",
                anyhow::anyhow!("staged Kubernetes resource was not observable after apply"),
            ))
        })
    }

    fn read_resource_identity(
        &self,
        desired: &Value,
        identity_label: &str,
        identity_value: &str,
        identity_name: &str,
        resource_kind: RuntimeResourceKind,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<Option<KubernetesResourceIdentity>> {
        let kind = desired["kind"]
            .as_str()
            .context("Kubernetes manifest kind is required")?;
        let name = desired["metadata"]["name"]
            .as_str()
            .context("Kubernetes manifest metadata.name is required")?;
        let namespace = desired["metadata"]["namespace"]
            .as_str()
            .context("Kubernetes manifest metadata.namespace is required")?;
        let mut args = self.kubectl_base_args();
        args.extend([
            "get".to_string(),
            kind.to_string(),
            name.to_string(),
            "--ignore-not-found".to_string(),
            "-o".to_string(),
            "json".to_string(),
        ]);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "read staged sandbox resource",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !output.success {
            return Err(anyhow::Error::new(classified_kubectl_failure(
                "kubectl get staged sandbox resource failed",
                &output.stderr,
            )));
        }
        if output.stdout.trim().is_empty() {
            return Ok(None);
        }
        let observed: Value = serde_json::from_str(&output.stdout).map_err(|error| {
            anyhow::Error::new(ProviderError::classified(
                ProvisioningErrorClass::RetryableProvider,
                "resource_observation_invalid",
                anyhow::Error::new(error).context("kubectl returned invalid resource JSON"),
            ))
        })?;
        if observed["metadata"]["labels"][identity_label] != json!(identity_value) {
            return Err(anyhow::Error::new(ProviderError::classified(
                ProvisioningErrorClass::TerminalContract,
                "resource_identity_conflict",
                anyhow::anyhow!(
                    "existing Kubernetes resource has a conflicting {identity_name} identity"
                ),
            )));
        }
        validate_adoption_contract(desired, &observed)?;
        let uid = observed["metadata"]["uid"].as_str().ok_or_else(|| {
            anyhow::Error::new(ProviderError::classified(
                ProvisioningErrorClass::RetryableProvider,
                "resource_identity_missing",
                anyhow::anyhow!("observed Kubernetes resource UID is required"),
            ))
        })?;
        Ok(Some(KubernetesResourceIdentity {
            resource_kind,
            namespace: namespace.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
            observed_generation: observed["metadata"]["generation"].as_i64(),
        }))
    }

    /// Renders the smoke-test plan printed by `provider-apply-plan` and
    /// applied/cleaned by `provider-apply-smoke`.
    ///
    /// Deliberately does NOT include the per-sandbox worker-token Secret
    /// (GH-101): the plan is serialized to stdout/logs as data, so the raw
    /// token must never appear in it, and the smoke CLI paths never
    /// configure worker credentials in the first place (the pod manifest's
    /// Secret *reference* by name is harmless -- if credentials were ever
    /// configured here, the smoke pod would simply stall on the missing
    /// Secret rather than leak anything).
    pub fn smoke_plan(
        &self,
        sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> KubernetesApplyPlan {
        let spec = SandboxProvisionSpec::default();
        let provision_pvc = self.dry_run.pvc_manifest(
            format!("sandboxwich-pvc-{sandbox_id}"),
            Some(sandbox_id),
            &spec.memory_limit,
        );
        let provision_pod = self.dry_run.pod_manifest(sandbox_id, &spec);
        let provision_network_policy = self
            .dry_run
            .network_policy_manifest(sandbox_id, &spec.network_egress)
            .expect("default network egress should render");
        let provision_ssh_service = self.dry_run.ssh_service_manifest(sandbox_id);
        let provision_service = self.dry_run.desktop_service_manifest(sandbox_id);
        let snapshot = self
            .dry_run
            .volume_snapshot_manifest(sandbox_id, snapshot_id);
        let fork_pvc =
            self.dry_run
                .fork_pvc_manifest(child_sandbox_id, snapshot_id, &spec.memory_limit);
        let fork_pod = self.dry_run.pod_manifest(child_sandbox_id, &spec);
        let fork_network_policy = self
            .dry_run
            .network_policy_manifest(child_sandbox_id, &spec.network_egress)
            .expect("default network egress should render");
        let fork_ssh_service = self.dry_run.ssh_service_manifest(child_sandbox_id);
        let fork_service = self.dry_run.desktop_service_manifest(child_sandbox_id);
        let exec_handoff = self
            .dry_run
            .exec_handoff(
                sandbox_id,
                &spec,
                AgentCommandRequest {
                    argv: vec!["echo".to_string(), "sandboxwich".to_string()],
                    cwd: None,
                    env: BTreeMap::new(),
                    stdin: None,
                    timeout_secs: None,
                },
                &CancelSignal::never_cancelled(),
            )
            .expect("dry-run exec handoff should not fail");
        let apply_manifests = vec![
            provision_pvc.clone(),
            provision_pod.clone(),
            provision_network_policy.clone(),
            provision_ssh_service.clone(),
            provision_service.clone(),
            snapshot.clone(),
            fork_pvc.clone(),
            fork_pod.clone(),
            fork_network_policy.clone(),
            fork_ssh_service.clone(),
            fork_service.clone(),
        ];
        let cleanup_manifests = vec![
            fork_service,
            fork_ssh_service,
            fork_network_policy,
            fork_pod,
            fork_pvc,
            snapshot,
            provision_service,
            provision_ssh_service,
            provision_network_policy,
            provision_pod,
            provision_pvc,
        ];

        KubernetesApplyPlan {
            provider: "kubernetes".to_string(),
            mode: "apply".to_string(),
            operation: "smoke".to_string(),
            cluster: self.dry_run.cluster.clone(),
            namespace: self.dry_run.effective_sandbox_namespace().to_string(),
            kubectl: self.kubectl.clone(),
            exec_handoff,
            apply_args: self.kubectl_args("apply"),
            cleanup_args: self.kubectl_delete_args(),
            apply_manifests,
            cleanup_manifests,
        }
    }

    pub fn validate_apply_gate(confirm_apply: bool, mutation_enabled: bool) -> anyhow::Result<()> {
        if !confirm_apply || !mutation_enabled {
            bail!(
                "refusing to mutate Kubernetes resources; pass --confirm-apply and set {KUBERNETES_MUTATION_ENV}=1"
            );
        }
        Ok(())
    }

    pub fn mutation_enabled_from_env() -> bool {
        std::env::var(KUBERNETES_MUTATION_ENV)
            .map(|value| value == "1")
            .unwrap_or(false)
    }

    pub fn apply_smoke(
        &self,
        plan: KubernetesApplyPlan,
        confirm_apply: bool,
        mutation_enabled: bool,
        cleanup: bool,
    ) -> anyhow::Result<KubernetesApplyOutcome> {
        Self::validate_apply_gate(confirm_apply, mutation_enabled)?;

        // `apply_smoke` is a standalone, manually-invoked diagnostic (`provider-smoke`),
        // not part of the lease-renewal-driven work loop, so there is no `CancelSignal`
        // to thread through here.
        let apply = run_kubectl_documents(
            &plan.kubectl,
            &plan.apply_args,
            &plan.apply_manifests,
            "apply smoke manifests",
            self.kubectl_command_timeout,
            None,
            self.max_captured_output_bytes,
        )?;
        let mut cleanup_status = String::new();
        let mut cleanup_stdout = String::new();
        let mut cleanup_stderr = String::new();
        let mut cleaned_up = false;

        if cleanup {
            let cleanup_output = run_kubectl_documents(
                &plan.kubectl,
                &plan.cleanup_args,
                &plan.cleanup_manifests,
                "cleanup smoke manifests",
                self.kubectl_command_timeout,
                None,
                self.max_captured_output_bytes,
            )?;
            cleanup_status = cleanup_output.status;
            cleanup_stdout = cleanup_output.stdout;
            cleanup_stderr = cleanup_output.stderr;
            cleaned_up = cleanup_output.success;
        }

        if !apply.success {
            let cleanup_suffix = if cleanup && !cleaned_up {
                format!("; cleanup also failed with {cleanup_status}: {cleanup_stderr}")
            } else {
                String::new()
            };
            bail!(
                "kubectl apply smoke manifests failed with {}: {}{}",
                apply.status,
                apply.stderr,
                cleanup_suffix
            );
        }

        if cleanup && !cleaned_up {
            bail!("kubectl cleanup smoke manifests failed with {cleanup_status}: {cleanup_stderr}");
        }

        Ok(KubernetesApplyOutcome {
            ok: true,
            applied: true,
            cleaned_up,
            plan,
            apply_status: apply.status,
            apply_stdout: apply.stdout,
            apply_stderr: apply.stderr,
            cleanup_status,
            cleanup_stdout,
            cleanup_stderr,
        })
    }

    fn kubectl_args(&self, verb: &str) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        args.extend([verb.to_string(), "-f".to_string(), "-".to_string()]);
        args
    }

    fn kubectl_delete_args(&self) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "delete".to_string(),
            "--ignore-not-found=true".to_string(),
            "-f".to_string(),
            "-".to_string(),
        ]);
        args
    }

    fn kubectl_base_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(context) = &self.kubectl_context {
            args.extend(["--context".to_string(), context.clone()]);
        }
        args.extend([
            "-n".to_string(),
            self.dry_run.effective_sandbox_namespace().to_string(),
        ]);
        args
    }

    fn pod_name(&self, sandbox_id: SandboxId) -> String {
        format!("sandboxwich-{sandbox_id}")
    }

    fn provision_manifests(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
    ) -> anyhow::Result<Vec<Value>> {
        self.dry_run.validate_runtime_profile(spec)?;
        let mut manifests = Vec::new();
        if spec.workspace_mode == WorkspaceMode::Persistent {
            manifests.push(self.dry_run.pvc_manifest(
                format!("sandboxwich-pvc-{sandbox_id}"),
                Some(sandbox_id),
                &spec.memory_limit,
            ));
        }
        manifests.extend(self.dry_run.guest_token_secret_manifest(sandbox_id));
        if let Some(gateway) = self
            .dry_run
            .egress_gateway_pod_manifest(sandbox_id, &spec.network_egress)?
        {
            manifests.push(gateway);
        }
        if let Some(service) = self
            .dry_run
            .egress_gateway_service_manifest(sandbox_id, &spec.network_egress)
        {
            manifests.push(service);
        }
        if let Some(policy) = self
            .dry_run
            .egress_gateway_network_policy_manifest(sandbox_id, &spec.network_egress)?
        {
            manifests.push(policy);
        }
        manifests.push(
            self.dry_run
                .network_policy_manifest(sandbox_id, &spec.network_egress)?,
        );
        manifests.push(self.dry_run.pod_manifest(sandbox_id, spec));
        manifests.push(self.dry_run.ssh_service_manifest(sandbox_id));
        manifests.push(self.dry_run.desktop_service_manifest(sandbox_id));
        Ok(manifests)
    }

    fn fork_manifests(
        &self,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
    ) -> anyhow::Result<Vec<Value>> {
        self.dry_run.validate_runtime_profile(spec)?;
        let mut manifests =
            vec![
                self.dry_run
                    .fork_pvc_manifest(child_sandbox_id, snapshot_id, &spec.memory_limit),
            ];
        manifests.extend(self.dry_run.guest_token_secret_manifest(child_sandbox_id));
        if let Some(gateway) = self
            .dry_run
            .egress_gateway_pod_manifest(child_sandbox_id, &spec.network_egress)?
        {
            manifests.push(gateway);
        }
        if let Some(service) = self
            .dry_run
            .egress_gateway_service_manifest(child_sandbox_id, &spec.network_egress)
        {
            manifests.push(service);
        }
        if let Some(policy) = self
            .dry_run
            .egress_gateway_network_policy_manifest(child_sandbox_id, &spec.network_egress)?
        {
            manifests.push(policy);
        }
        manifests.push(
            self.dry_run
                .network_policy_manifest(child_sandbox_id, &spec.network_egress)?,
        );
        manifests.push(self.dry_run.pod_manifest(child_sandbox_id, spec));
        manifests.push(self.dry_run.ssh_service_manifest(child_sandbox_id));
        manifests.push(self.dry_run.desktop_service_manifest(child_sandbox_id));
        Ok(manifests)
    }

    /// Waits for the sandbox pod to become ready within the configured kubectl
    /// command bound. `cancelled` is polled
    /// throughout: if the caller's lease renewal is lost while this is in flight, the
    /// wait is aborted instead of letting a mutating provision/fork run to completion
    /// against a lease this worker can no longer prove is still its own (see
    /// `run_kubectl_command_async`'s doc comment).
    fn wait_for_pod_ready(
        &self,
        sandbox_id: SandboxId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<KubectlOutput> {
        self.wait_for_named_pod_ready(&self.pod_name(sandbox_id), cancelled)
    }

    fn wait_for_named_pod_ready(
        &self,
        pod_name: &str,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<KubectlOutput> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "wait".to_string(),
            "--for=condition=Ready".to_string(),
            format!("pod/{pod_name}"),
            self.pod_ready_timeout_arg(),
        ]);
        run_kubectl_command(
            &self.kubectl,
            &args,
            "wait for sandbox pod readiness",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )
    }

    fn wait_for_gateway_ready_if_needed(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<Option<KubectlOutput>> {
        if !self.dry_run.uses_egress_gateway(network_egress) {
            return Ok(None);
        }
        let name = format!("sandboxwich-egress-gateway-{sandbox_id}");
        let wait = self.wait_for_named_pod_ready(&name, cancelled)?;
        if !wait.success {
            bail!(
                "egress gateway pod did not become ready with {}: {}",
                wait.status,
                wait.stderr
            );
        }
        Ok(Some(wait))
    }

    /// Returns true if the sandbox's pod already exists in the cluster. Used so that
    /// `exec_handoff` only provisions when necessary instead of re-applying the full
    /// manifest set (and its immutable Pod fields) before every command.
    fn pod_exists(&self, sandbox_id: SandboxId, cancelled: &CancelSignal) -> anyhow::Result<bool> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "get".to_string(),
            "pod".to_string(),
            self.pod_name(sandbox_id),
            "--ignore-not-found".to_string(),
            "-o".to_string(),
            "name".to_string(),
        ]);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "check sandbox pod existence",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !output.success {
            bail!(
                "kubectl get pod failed with {}: {}",
                output.status,
                output.stderr
            );
        }
        Ok(!output.stdout.trim().is_empty())
    }

    /// Renders the `kubectl delete` argument list that tears down every resource
    /// labeled with this sandbox's id. Split out from `stop` so it can be exercised
    /// in unit tests without invoking a real `kubectl` binary.
    fn teardown_args(&self, sandbox_id: SandboxId) -> Vec<String> {
        self.teardown_args_with_spec(sandbox_id, &SandboxTeardownSpec::default())
    }

    fn teardown_args_with_spec(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
    ) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "delete".to_string(),
            self.dry_run
                .teardown_resource_kinds_with_persisted_gke_fqdn(spec.delete_gke_fqdn_policy),
            "-l".to_string(),
            format!("sandboxwich.dev/sandbox-id={sandbox_id}"),
            "--ignore-not-found=true".to_string(),
        ]);
        args
    }

    /// Best-effort teardown of every resource labeled with `sandbox_id`, used to
    /// roll back a partially-applied `provision`/`fork` after a later step (the
    /// apply itself, or the readiness wait) fails. Without this, a failed
    /// provision/fork leaked its PVC/Pod/Service/NetworkPolicy forever, since the
    /// caller only ever saw the original error and never got a handle to clean
    /// up.
    ///
    /// Deliberately swallows its own failures (beyond logging to stderr): a
    /// rollback that itself fails must never mask or replace the original
    /// provisioning error that triggered it, since that original error is what
    /// the caller (and its retry/alerting logic) needs to see. `--ignore-not-found`
    /// on the underlying `kubectl delete` also makes this safe to call even when
    /// nothing was actually applied yet (e.g. `provision`'s own `kubectl apply`
    /// failed to spawn at all).
    ///
    /// Deliberately does *not* take a `CancelSignal`: unlike the apply/wait steps
    /// this cleans up after, a `kubectl delete` with `--ignore-not-found` is
    /// idempotent and only ever removes resources labeled with this exact
    /// `sandbox_id`, so it carries none of the "might duplicate a mutating side
    /// effect" risk cancellation exists to prevent. Honoring cancellation here
    /// would instead race the delete against its own spawn (a cancelled signal is
    /// typically already true by the time rollback runs, so the `tokio::select!`
    /// in `run_kubectl_command_async` would very likely kill the process before it
    /// could delete anything) and turn a best-effort cleanup into a guaranteed
    /// leak.
    fn rollback_applied_resources(&self, sandbox_id: SandboxId, context: &'static str) {
        let args = self.teardown_args(sandbox_id);
        match run_kubectl_command(
            &self.kubectl,
            &args,
            "rollback applied resources after failed provision/fork",
            self.kubectl_command_timeout,
            None,
            self.max_captured_output_bytes,
        ) {
            Ok(output) if output.success => {
                eprintln!(
                    "sandboxwich-worker: rolled back resources for sandbox {sandbox_id} after \
                     failed {context}"
                );
            }
            Ok(output) => {
                eprintln!(
                    "warning: rollback of sandbox {sandbox_id} resources after failed {context} \
                     itself failed with {}: {} (resources may be leaked; original error is not \
                     masked by this)",
                    output.status, output.stderr
                );
            }
            Err(error) => {
                eprintln!(
                    "warning: rollback of sandbox {sandbox_id} resources after failed {context} \
                     could not run kubectl: {error:#} (resources may be leaked; original error is \
                     not masked by this)"
                );
            }
        }
    }

    /// Renders the `kubectl exec` argument list for `request`. Env var
    /// *values* are never placed on this argv: any process on the guest
    /// (or on the worker host itself, via its own `ps`/argv) can read
    /// another process's `/proc/*/cmdline`, so passing secrets as
    /// positional `KEY=VALUE` args to `env` -- as this used to do -- leaks
    /// them to anything with process-listing access. When `request.env`
    /// is non-empty, this instead wires up `kubectl exec -i` plus a small
    /// `bash -c` wrapper that reads a counted prefix of NUL-delimited
    /// `KEY=VALUE` pairs from stdin and `export`s them before `exec`ing the
    /// real command with any remaining bytes still available on stdin; the
    /// caller must pipe `exec_stdin_payload(request)` to that invocation's
    /// stdin. NUL is a safe delimiter because POSIX environment variable
    /// values can never contain an embedded NUL byte, unlike newlines.
    fn exec_args(&self, sandbox_id: SandboxId, request: &AgentCommandRequest) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        let needs_env = !request.env.is_empty();
        if needs_env || request.stdin.is_some() {
            args.push("-i".to_string());
        }
        args.extend([
            "exec".to_string(),
            self.pod_name(sandbox_id),
            "--".to_string(),
        ]);

        if needs_env {
            args.extend([
                "bash".to_string(),
                "-c".to_string(),
                EXEC_ENV_WRAPPER_SCRIPT.to_string(),
                "sandboxwich-exec".to_string(),
                request.env.len().to_string(),
            ]);
            if let Some(cwd) = &request.cwd {
                args.push("1".to_string());
                args.push(cwd.clone());
            } else {
                args.push("0".to_string());
            }
            args.extend(request.argv.clone());
            return args;
        }

        if let Some(cwd) = &request.cwd {
            args.extend([
                "sh".to_string(),
                "-lc".to_string(),
                "cd \"$1\" && shift && exec \"$@\"".to_string(),
                "sandboxwich-cwd".to_string(),
                cwd.clone(),
            ]);
            args.extend(request.argv.clone());
            return args;
        }

        args.extend(request.argv.clone());
        args
    }

    fn apex_task_instructions_args(&self, sandbox_id: SandboxId) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "exec".to_string(),
            self.pod_name(sandbox_id),
            "--".to_string(),
            APEX_TASK_INSTRUCTIONS_COMMAND.to_string(),
        ]);
        args
    }

    /// Builds the counted NUL-delimited `KEY=VALUE` prefix followed by the
    /// exact command stdin bytes. Returns `None` when neither input exists,
    /// so callers preserve the previous non-interactive behavior.
    fn exec_stdin_payload(request: &AgentCommandRequest) -> Option<Vec<u8>> {
        if request.env.is_empty() {
            return request.stdin.clone();
        }
        let mut payload = Vec::new();
        for (key, value) in &request.env {
            payload.extend_from_slice(key.as_bytes());
            payload.push(b'=');
            payload.extend_from_slice(value.as_bytes());
            payload.push(0);
        }
        if let Some(stdin) = &request.stdin {
            payload.extend_from_slice(stdin);
        }
        Some(payload)
    }

    fn isolated_resident_process_secret_name(&self, spec: &IsolatedResidentProcessSpec) -> String {
        format!("sw-scb-{}", isolated_resident_process_fence_suffix(spec))
    }

    fn isolated_resident_process_network_policy_name(
        &self,
        spec: &IsolatedResidentProcessSpec,
    ) -> String {
        format!("sw-scnp-{}", isolated_resident_process_fence_suffix(spec))
    }

    fn validate_isolated_resident_process_spec(
        &self,
        spec: &IsolatedResidentProcessSpec,
    ) -> anyhow::Result<()> {
        let image = self
            .isolated_resident_process_image()
            .context("isolated resident-process sidecar image is not configured")?;
        anyhow::ensure!(
            image_is_digest_pinned(image),
            "isolated resident-process sidecar image must be digest-pinned"
        );
        anyhow::ensure!(
            self.dry_run
                .runtime_class_name
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty()),
            "isolated resident-process sidecar requires a RuntimeClass"
        );
        anyhow::ensure!(
            !spec.argv.is_empty()
                && spec
                    .argv
                    .iter()
                    .all(|argument| !argument.as_bytes().contains(&0)),
            "isolated resident-process argv is invalid"
        );
        if let Some(cwd) = &spec.cwd {
            anyhow::ensure!(
                std::path::Path::new(cwd).is_absolute() && !cwd.as_bytes().contains(&0),
                "isolated resident-process cwd must be an absolute path"
            );
        }
        anyhow::ensure!(
            spec.env.iter().all(|(key, value)| {
                !key.is_empty()
                    && !key.contains('=')
                    && !key.as_bytes().contains(&0)
                    && !value.as_bytes().contains(&0)
            }),
            "isolated resident-process environment is invalid"
        );
        anyhow::ensure!(
            !spec.bootstrap.content.is_empty()
                && spec.bootstrap.content.len() <= MAX_RESIDENT_PROCESS_BOOTSTRAP_BYTES,
            "isolated resident-process bootstrap must be between 1 byte and 64 KiB"
        );
        anyhow::ensure!(
            (0o400..=0o700).contains(&spec.bootstrap.mode),
            "isolated resident-process bootstrap mode must be between 0400 and 0700"
        );
        let prefix = std::path::Path::new(RESIDENT_PROCESS_BOOTSTRAP_PREFIX);
        let target = std::path::Path::new(&spec.bootstrap.target_file);
        let relative = target
            .strip_prefix(prefix)
            .context("isolated resident-process bootstrap path is outside the allowed root")?;
        anyhow::ensure!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|component| { matches!(component, std::path::Component::Normal(_)) }),
            "isolated resident-process bootstrap target is invalid"
        );
        if let Some(attestation) = &spec.bootstrap.placement_attestation {
            anyhow::ensure!(
                !attestation.is_empty()
                    && attestation.len() <= MAX_RESIDENT_PROCESS_BOOTSTRAP_BYTES,
                "isolated resident-process placement attestation must be between 1 byte and 64 KiB"
            );
            anyhow::ensure!(
                spec.bootstrap.target_file != RESIDENT_PLACEMENT_ATTESTATION_FILE,
                "isolated resident-process bootstrap target collides with the placement attestation path"
            );
        }
        Ok(())
    }

    fn isolated_resident_process_labels(&self, spec: &IsolatedResidentProcessSpec) -> Value {
        json!({
            "app.kubernetes.io/name": "orb-sidecar",
            "app.kubernetes.io/component": "isolated-resident-process",
            "sandboxwich.dev/sandbox-id": spec.sandbox_id.to_string(),
            "sandboxwich.dev/resident-process-id": spec.process_id.to_string(),
            "sandboxwich.dev/generation": spec.generation.to_string(),
            "sandboxwich.dev/lease-id": spec.lease_id.to_string(),
        })
    }

    fn isolated_resident_process_manifests(
        &self,
        spec: &IsolatedResidentProcessSpec,
    ) -> anyhow::Result<Vec<Value>> {
        self.validate_isolated_resident_process_spec(spec)?;
        let pod_name = isolated_resident_process_pod_name(spec);
        let secret_name = self.isolated_resident_process_secret_name(spec);
        let network_policy_name = self.isolated_resident_process_network_policy_name(spec);
        let labels = self.isolated_resident_process_labels(spec);
        let relative_target = std::path::Path::new(&spec.bootstrap.target_file)
            .strip_prefix(RESIDENT_PROCESS_BOOTSTRAP_PREFIX)
            .expect("validated bootstrap target")
            .to_string_lossy()
            .into_owned();
        let mut secret_data = Map::from_iter([(
            "bootstrap".to_string(),
            json!(general_purpose::STANDARD.encode(&spec.bootstrap.content)),
        )]);
        let mut secret_items = vec![json!({
            "key": "bootstrap",
            "path": relative_target,
            "mode": spec.bootstrap.mode,
        })];
        if let Some(attestation) = &spec.bootstrap.placement_attestation {
            secret_data.insert(
                "placement-attestation".to_string(),
                json!(general_purpose::STANDARD.encode(attestation)),
            );
            let attestation_path = std::path::Path::new(RESIDENT_PLACEMENT_ATTESTATION_FILE)
                .strip_prefix(RESIDENT_PROCESS_BOOTSTRAP_PREFIX)
                .expect("placement attestation path is under the bootstrap root")
                .to_string_lossy()
                .into_owned();
            secret_items.push(json!({
                "key": "placement-attestation",
                "path": attestation_path,
                "mode": 0o400,
            }));
        }
        let secret = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": secret_name,
                "namespace": self.dry_run.effective_sandbox_namespace(),
                "labels": labels,
            },
            "type": "Opaque",
            "immutable": true,
            "data": secret_data,
        });
        let mut network_egress = self.dry_run.dns_egress_rules();
        network_egress.extend(
            self.dry_run
                .isolated_sidecar_https_cidrs
                .iter()
                .map(|cidr| {
                    json!({
                        "to": [{ "ipBlock": { "cidr": cidr } }],
                        "ports": [{ "protocol": "TCP", "port": 443 }],
                    })
                }),
        );
        network_egress.push(json!({
            "to": [{ "ipBlock": self.dry_run.ip_block("0.0.0.0/0")? }],
            "ports": [{ "protocol": "TCP", "port": 443 }],
        }));
        let network_policy = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": network_policy_name,
                "namespace": self.dry_run.effective_sandbox_namespace(),
                "labels": labels,
            },
            "spec": {
                "podSelector": { "matchLabels": labels },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": network_egress,
            },
        });
        let env = spec
            .env
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect::<Vec<_>>();
        let mut container = json!({
            "name": "orb-sidecar",
            "image": self
                .isolated_resident_process_image()
                .expect("validated sidecar image"),
            "imagePullPolicy": "IfNotPresent",
            "command": spec.argv,
            "env": env,
            "securityContext": {
                "allowPrivilegeEscalation": false,
                "readOnlyRootFilesystem": true,
                "runAsNonRoot": true,
                "runAsUser": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                "runAsGroup": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                "capabilities": { "drop": ["ALL"] },
                "seccompProfile": { "type": "RuntimeDefault" },
            },
            "resources": {
                "requests": { "cpu": "50m", "memory": "64Mi" },
                "limits": { "cpu": "500m", "memory": "256Mi" },
            },
            "volumeMounts": [
                {
                    "name": "bootstrap",
                    "mountPath": RESIDENT_PROCESS_BOOTSTRAP_PREFIX,
                },
                {
                    "name": "tmp",
                    "mountPath": "/tmp",
                },
            ],
        });
        if let Some(cwd) = &spec.cwd {
            container
                .as_object_mut()
                .expect("container is an object")
                .insert("workingDir".to_string(), json!(cwd));
        }
        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": self.dry_run.effective_sandbox_namespace(),
                "labels": labels,
            },
            "spec": {
                "runtimeClassName": self.dry_run.runtime_class_name,
                "automountServiceAccountToken": false,
                "enableServiceLinks": false,
                "hostNetwork": false,
                "hostPID": false,
                "hostIPC": false,
                "restartPolicy": "Never",
                "terminationGracePeriodSeconds": 30,
                "securityContext": {
                    "runAsNonRoot": true,
                    "runAsUser": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                    "runAsGroup": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                    "fsGroup": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                    "seccompProfile": { "type": "RuntimeDefault" },
                },
                "initContainers": [{
                    "name": "bootstrap-handoff",
                    "image": self
                        .isolated_resident_process_image()
                        .expect("validated sidecar image"),
                    "imagePullPolicy": "IfNotPresent",
                    "command": [
                        "/bin/sh",
                        "-c",
                        "set -eu; cp -R /source/. /run/sandboxwich/bootstrap/; chmod -R go-rwx /run/sandboxwich/bootstrap",
                    ],
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": true,
                        "runAsNonRoot": true,
                        "runAsUser": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                        "runAsGroup": ORB_SIDECAR_RESIDENT_PROCESS_UID,
                        "capabilities": { "drop": ["ALL"] },
                        "seccompProfile": { "type": "RuntimeDefault" },
                    },
                    "resources": {
                        "requests": { "cpu": "10m", "memory": "16Mi" },
                        "limits": { "cpu": "100m", "memory": "32Mi" },
                    },
                    "volumeMounts": [
                        {
                            "name": "bootstrap-source",
                            "mountPath": "/source",
                            "readOnly": true,
                        },
                        {
                            "name": "bootstrap",
                            "mountPath": RESIDENT_PROCESS_BOOTSTRAP_PREFIX,
                        },
                    ],
                }],
                "containers": [container],
                "volumes": [
                    {
                        "name": "bootstrap-source",
                        "secret": {
                            "secretName": secret_name,
                            "defaultMode": spec.bootstrap.mode,
                            "items": secret_items,
                        },
                    },
                    {
                        "name": "bootstrap",
                        "emptyDir": {
                            "medium": "Memory",
                            "sizeLimit": "1Mi",
                        },
                    },
                    {
                        "name": "tmp",
                        "emptyDir": {
                            "sizeLimit": "64Mi",
                        },
                    },
                ],
            },
        });
        Ok(vec![secret, network_policy, pod])
    }

    fn isolated_resident_process_cleanup_manifests(
        &self,
        spec: &IsolatedResidentProcessSpec,
    ) -> Vec<Value> {
        vec![
            json!({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": self.isolated_resident_process_network_policy_name(spec),
                    "namespace": self.dry_run.effective_sandbox_namespace(),
                },
            }),
            json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": isolated_resident_process_pod_name(spec),
                    "namespace": self.dry_run.effective_sandbox_namespace(),
                },
            }),
            json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": self.isolated_resident_process_secret_name(spec),
                    "namespace": self.dry_run.effective_sandbox_namespace(),
                },
            }),
        ]
    }

    fn observe_isolated_resident_process(
        &self,
        spec: &IsolatedResidentProcessSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<IsolatedResidentProcessPodObservation> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "get".to_string(),
            "pod".to_string(),
            isolated_resident_process_pod_name(spec),
            "-o".to_string(),
            "json".to_string(),
        ]);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "observe isolated resident-process pod",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        anyhow::ensure!(
            output.success,
            "kubectl get isolated resident-process pod failed with {}: {}",
            output.status,
            output.stderr
        );
        let pod: Value = serde_json::from_str(&output.stdout)
            .context("isolated resident-process pod observation was invalid JSON")?;
        let pod_uid = pod["metadata"]["uid"].as_str().map(str::to_string);
        let status = &pod["status"]["containerStatuses"][0];
        let ready = status["ready"].as_bool().unwrap_or(false);
        let exit_code = status["state"]["terminated"]["exitCode"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok());
        let phase = pod["status"]["phase"].as_str().unwrap_or("Pending");
        let pod_name = isolated_resident_process_pod_name(spec);
        let container_started =
            status["state"]["running"].is_object() || status["state"]["terminated"].is_object();
        if !container_started && !matches!(phase, "Succeeded" | "Failed") {
            return Ok(IsolatedResidentProcessPodObservation::Pending { pod_name, pod_uid });
        }
        let state = if exit_code.is_some() || matches!(phase, "Succeeded" | "Failed") {
            if exit_code == Some(0) || (exit_code.is_none() && phase == "Succeeded") {
                IsolatedResidentProcessState::Succeeded
            } else {
                IsolatedResidentProcessState::Failed
            }
        } else if phase == "Running" && ready {
            IsolatedResidentProcessState::Running
        } else {
            IsolatedResidentProcessState::Starting
        };
        Ok(IsolatedResidentProcessPodObservation::Started(
            IsolatedResidentProcessObservation {
                state,
                pod_name,
                pod_uid,
                ready,
                exit_code,
            },
        ))
    }
}

/// Guest-side wrapper invoked via `bash -c` by `exec_args` when the request
/// carries env vars. Argument order (after the `bash -c` command string
/// itself, `$0` is `sandboxwich-exec`): `$1` is the env-pair count, the next
/// argument is `"1"`/`"0"` for has-cwd, then the cwd when present, and the
/// remaining args are the real command. Reading exactly the counted
/// NUL-delimited env prefix leaves all remaining stdin bytes for that command.
const EXEC_ENV_WRAPPER_SCRIPT: &str = concat!(
    "env_count=\"$1\"; shift; ",
    "while [ \"$env_count\" -gt 0 ]; do ",
    "IFS= read -r -d '' kv || exit 1; ",
    "case \"$kv\" in *=*) export \"${kv%%=*}\"=\"${kv#*=}\" ;; esac; ",
    "env_count=$((env_count - 1)); ",
    "done; ",
    "has_cwd=\"$1\"; shift; ",
    "if [ \"$has_cwd\" = \"1\" ]; then cd \"$1\" || exit 1; shift; fi; ",
    "exec \"$@\""
);

#[derive(Debug)]
struct KubectlOutput {
    success: bool,
    code: Option<i32>,
    status: String,
    stdout: String,
    stderr: String,
}

/// Decodes `bytes` as (possibly lossy) UTF-8, capping the result at
/// `max_bytes`. When truncated, appends a marker noting how many bytes were
/// cut so a truncated capture is never mistaken for the complete output.
fn cap_output_bytes(bytes: &[u8], max_bytes: u64) -> String {
    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    if bytes.len() <= max_bytes {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let omitted = bytes.len() - max_bytes;
    let mut text = String::from_utf8_lossy(&bytes[..max_bytes]).into_owned();
    text.push_str(&format!("\n[truncated {omitted} bytes]\n"));
    text
}

/// Applies/deletes `manifests` via `kubectl -f -`, piping the rendered documents to
/// stdin. Routes through [`run_kubectl_command_with_stdin`] (bounded by `timeout`,
/// killed+reaped on timeout or cancellation, transport failures wrapped as
/// [`ProviderError::retryable`]) rather than blocking synchronously: previously this
/// used `std::process::Command::wait_with_output()` directly, which -- unlike every
/// other kubectl invocation in this module -- had no bound at all, so a wedged API
/// server hung the calling job-execution thread (and, with it, the sandbox slot the
/// lease keeps renewing) forever, and any failure surfaced as a plain `anyhow::Error`
/// that `classify_retry` treats as permanent even though a hung/unreachable API
/// server is exactly the kind of transient infrastructure failure that should be
/// retried.
fn run_kubectl_documents(
    kubectl: &str,
    args: &[String],
    manifests: &[Value],
    context: &'static str,
    timeout: Duration,
    cancelled: Option<&CancelSignal>,
    max_output_bytes: u64,
) -> anyhow::Result<KubectlOutput> {
    let payload = render_manifest_documents(manifests)?.into_bytes();
    run_kubectl_command_with_stdin(
        kubectl,
        args,
        Some(&payload),
        context,
        timeout,
        cancelled,
        max_output_bytes,
    )
}

/// How often a kubectl invocation polls a `CancelSignal` for cancellation
/// while waiting on the child.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(500);

fn sleep_with_cancellation(duration: Duration, cancelled: &CancelSignal) -> anyhow::Result<()> {
    let deadline = Instant::now() + duration;
    loop {
        anyhow::ensure!(
            !cancelled.is_cancelled(),
            "isolated resident-process execution cancelled after lease loss"
        );
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

/// Runs a `kubectl` invocation with a bounded wait, killing the child and
/// returning a "timed out" error if it hasn't exited within `timeout`.
///
/// Previously this used `std::process::Command::output()`, which blocks the
/// calling thread until `kubectl` exits with no bound at all: a `kubectl`
/// stuck talking to an unreachable/misbehaving API server (or `kubectl exec`
/// into a wedged pod) hung the worker's job-execution thread forever. This is
/// called from a synchronous `SandboxProvider` method that itself always runs
/// either inside `tokio::task::spawn_blocking` (see `handle_lease`) or
/// directly within `#[tokio::main]`'s task, so a Tokio runtime `Handle` is
/// normally available to drive the bounded async wait below; callers with no
/// ambient runtime at all (synchronous unit tests) get a throwaway
/// current-thread runtime instead.
fn run_kubectl_command(
    kubectl: &str,
    args: &[String],
    context: &'static str,
    timeout: Duration,
    cancelled: Option<&CancelSignal>,
    max_output_bytes: u64,
) -> anyhow::Result<KubectlOutput> {
    run_kubectl_command_with_stdin(
        kubectl,
        args,
        None,
        context,
        timeout,
        cancelled,
        max_output_bytes,
    )
}

/// Like `run_kubectl_command`, but when `stdin_payload` is `Some`, pipes it
/// to the child's stdin and closes it (sending EOF) before waiting for
/// output. Used by `exec_handoff` to hand env var values to the guest's
/// `bash -c` wrapper over stdin instead of argv (see `exec_args`).
fn run_kubectl_command_with_stdin(
    kubectl: &str,
    args: &[String],
    stdin_payload: Option<&[u8]>,
    context: &'static str,
    timeout: Duration,
    cancelled: Option<&CancelSignal>,
    max_output_bytes: u64,
) -> anyhow::Result<KubectlOutput> {
    let command = run_kubectl_command_async(
        kubectl,
        args,
        stdin_payload,
        context,
        timeout,
        cancelled,
        max_output_bytes,
    );
    let result = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(command),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build a runtime to drive a kubectl invocation")?
            .block_on(command),
    };
    result.map_err(|error| anyhow::Error::new(ProviderError::retryable(error)))
}

fn run_fixed_apex_task_instructions(
    kubectl: &str,
    args: &[String],
    timeout: Duration,
    cancelled: &CancelSignal,
) -> anyhow::Result<Vec<u8>> {
    let command = run_fixed_apex_task_instructions_async(kubectl, args, timeout, cancelled);
    let result = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(command),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build runtime for APEX instruction read")?
            .block_on(command),
    };
    result.map_err(|error| anyhow::Error::new(ProviderError::retryable(error)))
}

async fn drain_bounded<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    retained_limit: usize,
) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(retained);
        }
        let remaining = retained_limit.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
    }
}

async fn run_fixed_apex_task_instructions_async(
    kubectl: &str,
    args: &[String],
    timeout: Duration,
    cancelled: &CancelSignal,
) -> anyhow::Result<Vec<u8>> {
    let mut child = tokio::process::Command::new(kubectl)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn fixed APEX task instruction reader")?;
    let stdout = child
        .stdout
        .take()
        .context("failed to capture APEX stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("failed to capture APEX stderr")?;
    let mut stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout
            .take((APEX_TASK_INSTRUCTIONS_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        Ok::<_, std::io::Error>(bytes)
    });
    // Drain stderr so the child cannot deadlock, but retain only a small
    // diagnostic prefix. The bytes are deliberately never included in an
    // error, log, event, or persisted result.
    let stderr_task = tokio::spawn(drain_bounded(stderr, 4096));

    enum First {
        Status(std::io::Result<std::process::ExitStatus>),
        Stdout(Result<std::io::Result<Vec<u8>>, tokio::task::JoinError>),
        Cancelled,
        TimedOut,
    }
    let first = tokio::select! {
        status = child.wait() => First::Status(status),
        stdout = &mut stdout_task => First::Stdout(stdout),
        () = async {
            loop {
                if cancelled.is_cancelled() { return; }
                tokio::time::sleep(CANCEL_POLL_INTERVAL).await;
            }
        } => First::Cancelled,
        () = tokio::time::sleep(timeout) => First::TimedOut,
    };

    let (status, output) = match first {
        First::Status(status) => {
            let status = status.context("failed waiting for fixed APEX instruction reader")?;
            let output = stdout_task
                .await
                .context("APEX stdout reader task failed")?
                .context("failed reading APEX stdout")?;
            (status, output)
        }
        First::Stdout(output) => {
            let output = output
                .context("APEX stdout reader task failed")?
                .context("failed reading APEX stdout")?;
            if output.len() > APEX_TASK_INSTRUCTIONS_MAX_BYTES {
                let _ = child.start_kill();
                let _ = child.wait().await;
                stderr_task.abort();
                anyhow::bail!("apex_task_instructions_too_large");
            }
            let status = tokio::time::timeout(timeout, child.wait())
                .await
                .context("fixed APEX instruction reader timed out")?
                .context("failed waiting for fixed APEX instruction reader")?;
            (status, output)
        }
        First::Cancelled => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            anyhow::bail!("fixed APEX instruction read cancelled after lease loss");
        }
        First::TimedOut => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            anyhow::bail!("fixed APEX instruction read timed out");
        }
    };
    let _ = stderr_task.await;
    anyhow::ensure!(
        output.len() <= APEX_TASK_INSTRUCTIONS_MAX_BYTES,
        "apex_task_instructions_too_large"
    );
    anyhow::ensure!(status.success(), "fixed APEX instruction reader failed");
    Ok(output)
}

async fn run_kubectl_command_async(
    kubectl: &str,
    args: &[String],
    stdin_payload: Option<&[u8]>,
    context: &'static str,
    timeout: Duration,
    cancelled: Option<&CancelSignal>,
    max_output_bytes: u64,
) -> anyhow::Result<KubectlOutput> {
    let mut command = tokio::process::Command::new(kubectl);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_payload.is_some() {
        command.stdin(Stdio::piped());
    }
    // ETXTBSY: exec can transiently fail while another thread's fork holds a
    // still-open write descriptor for the executable (rust-lang/cargo#7670).
    // In production `kubectl` is never being rewritten, so retrying is free;
    // in tests the fake kubectl scripts are written moments before use and
    // concurrent test threads make this race real.
    const ETXTBSY: i32 = 26;
    let mut spawn_attempts: u64 = 0;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(error) if error.raw_os_error() == Some(ETXTBSY) && spawn_attempts < 4 => {
                spawn_attempts += 1;
                tokio::time::sleep(Duration::from_millis(10 * spawn_attempts)).await;
            }
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context(format!("failed to spawn kubectl for {context}")));
            }
        }
    };
    let stdin_pipe = match stdin_payload {
        Some(_) => Some(child.stdin.take().context("failed to open kubectl stdin")?),
        None => None,
    };
    let mut stdout_pipe = child
        .stdout
        .take()
        .context("failed to capture kubectl stdout")?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .context("failed to capture kubectl stderr")?;

    // Feed stdin (dropping the pipe afterwards sends EOF) and drain
    // stdout/stderr concurrently with waiting on the child: kubectl can
    // write more than a single pipe buffer's worth of output, and waiting for
    // exit before ever reading the pipes risks a classic deadlock (kubectl
    // blocks writing to a full pipe while we block waiting for it to exit).
    // The same reasoning applies to writing the stdin payload.
    let drive = async {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let feed_stdin = async {
            if let (Some(mut stdin), Some(payload)) = (stdin_pipe, stdin_payload) {
                stdin.write_all(payload).await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let (status, feed_result, stdout_result, stderr_result) = tokio::join!(
            child.wait(),
            feed_stdin,
            stdout_pipe.read_to_end(&mut stdout),
            stderr_pipe.read_to_end(&mut stderr),
        );
        let status = status?;
        stdout_result?;
        stderr_result?;
        if status.success() {
            feed_result?;
        }
        Ok::<_, std::io::Error>((status, stdout, stderr))
    };

    // If the caller's lease renewal is lost while this kubectl invocation is
    // in flight (e.g. a `kubectl exec` running a long command), cancelling
    // here means the process gets killed promptly instead of running to
    // (possibly duplicated) completion against a lease this worker can no
    // longer prove is still its own. Callers with no lease-renewal loop
    // behind them (e.g. `wait_for_pod_ready`, `stop`) pass `None`, which
    // never fires.
    let wait_for_cancellation = async {
        match cancelled {
            Some(cancelled) => loop {
                if cancelled.is_cancelled() {
                    return;
                }
                tokio::time::sleep(CANCEL_POLL_INTERVAL).await;
            },
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        result = tokio::time::timeout(timeout, drive) => {
            match result {
                Ok(result) => {
                    let (status, stdout, stderr) =
                        result.with_context(|| format!("failed to run kubectl for {context}"))?;
                    Ok(KubectlOutput {
                        success: status.success(),
                        code: status.code(),
                        status: status.to_string(),
                        stdout: cap_output_bytes(&stdout, max_output_bytes),
                        stderr: cap_output_bytes(&stderr, max_output_bytes),
                    })
                }
                Err(_elapsed) => {
                    // `drive` (and the mutable borrow of `child` it held via
                    // `child.wait()`) was dropped when the timeout fired, so
                    // `child` is free to use again here.
                    if let Err(kill_error) = child.start_kill() {
                        eprintln!(
                            "warning: failed to kill timed-out kubectl process ({context}): {kill_error}"
                        );
                    }
                    // Reap the process so it doesn't linger as a zombie.
                    let _ = child.wait().await;
                    bail!(
                        "kubectl {context} timed out after {timeout:?} and was killed; this is \
                         treated as a transient infrastructure failure and retried like other \
                         timeouts"
                    );
                }
            }
        }
        () = wait_for_cancellation => {
            if let Err(kill_error) = child.start_kill() {
                eprintln!(
                    "warning: failed to kill cancelled kubectl process ({context}): {kill_error}"
                );
            }
            let _ = child.wait().await;
            bail!(
                "kubectl {context} was cancelled because lease renewal was lost; the job is \
                 being abandoned so it isn't run twice"
            );
        }
    }
}

fn render_manifest_documents(manifests: &[Value]) -> anyhow::Result<String> {
    let mut documents = String::new();
    for (index, manifest) in manifests.iter().enumerate() {
        if index > 0 {
            documents.push_str("\n---\n");
        }
        documents.push_str(
            &serde_json::to_string_pretty(manifest)
                .context("failed to serialize Kubernetes manifest")?,
        );
    }
    documents.push('\n');
    Ok(documents)
}

fn mark_resources(
    resources: &mut [ProviderRuntimeResource],
    status: RuntimeResourceStatus,
    ready_at: Option<chrono::DateTime<Utc>>,
) {
    for resource in resources {
        resource.status = status.clone();
        resource.ready_at = ready_at;
    }
}

impl SandboxProvider for KubernetesDryRunProvider {
    fn capability_report(&self) -> ProviderCapabilityReport {
        let mut capabilities = vec![
            WorkerCapability::K8sPod,
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::RunCommand,
            WorkerCapability::Snapshot,
            WorkerCapability::DesktopStream,
        ];
        if self.apex_trusted_supervisor_v1
            && image_is_digest_pinned(&self.runtime_image)
            && self.isolation_profile == IsolationProfile::Gvisor
            && self
                .runtime_class_name
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty())
        {
            capabilities.push(WorkerCapability::ApexTrustedSupervisorV1);
            capabilities.push(WorkerCapability::ApexTaskInstructions);
        }
        if self.runtime_class_name.is_some() {
            match self.isolation_profile {
                IsolationProfile::Development => {}
                IsolationProfile::Gvisor => {
                    capabilities.push(WorkerCapability::SandboxedContainer);
                }
                IsolationProfile::Kata => {
                    capabilities.push(WorkerCapability::VirtualMachine);
                }
            }
        }
        if self.fqdn_egress_backend.as_deref() == Some("cilium")
            || self
                .egress_gateway_image
                .as_deref()
                .is_some_and(image_is_digest_pinned)
        {
            capabilities.push(WorkerCapability::FqdnEgress);
        }
        ProviderCapabilityReport {
            provider: "kubernetes".to_string(),
            capabilities,
            labels: self.labels(),
        }
    }

    fn health_report(&self) -> ProviderHealthReport {
        ProviderHealthReport {
            provider: "kubernetes".to_string(),
            status: ProviderHealthStatus::Healthy,
            checked_at: Utc::now(),
            labels: self.labels(),
            message: Some(
                "dry-run provider ready; no Kubernetes API mutations enabled".to_string(),
            ),
        }
    }

    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        self.validate_network_policy_egress(&spec.network_egress)?;
        Ok(ProviderSandboxHandle {
            provider: "kubernetes".to_string(),
            sandbox_id,
            resources: self.sandbox_resources(sandbox_id, spec, RuntimeResourceStatus::Planned),
            metadata: self.metadata(sandbox_id, "provision", spec)?,
        })
    }

    fn provision_home_staged(
        &self,
        sandbox_id: SandboxId,
        home_id: HomeId,
        spec: &SandboxProvisionSpec,
        _cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        report(stage_update(ProvisioningStage::WorkspacePlanned, None))?;
        report(stage_update(ProvisioningStage::WorkspaceReady, None))?;
        report(stage_update(ProvisioningStage::SandboxReady, None))?;
        self.provision_home_handle(sandbox_id, home_id, spec, RuntimeResourceStatus::Planned)
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        validate_agent_command_request(&request)?;
        let started_at = Utc::now();
        let finished_at = Utc::now();
        Ok(AgentCommandResult {
            exit_code: Some(0),
            stdout: serde_json::to_string(&json!({
                "provider": "kubernetes",
                "mode": "dry_run",
                "operation": "exec",
                "sandboxId": sandbox_id,
                "memoryLimit": spec.memory_limit,
                "networkEgress": spec.network_egress,
                "argv": request.argv,
                "cwd": request.cwd,
                "envKeys": request.env.keys().collect::<Vec<_>>()
            }))
            .unwrap_or_else(|_| "{}".to_string()),
            stderr: String::new(),
            started_at,
            finished_at,
        })
    }

    fn run_isolated_resident_process(
        &self,
        _spec: &IsolatedResidentProcessSpec,
        _cancelled: &CancelSignal,
        _observe: &mut dyn FnMut(IsolatedResidentProcessObservation) -> anyhow::Result<()>,
    ) -> anyhow::Result<IsolatedResidentProcessResult> {
        anyhow::bail!("isolated resident-process execution is unavailable in dry-run mode")
    }

    fn materialize_file(
        &self,
        sandbox_id: SandboxId,
        destination: MaterializeFileDestination,
        expected_sha256: &str,
        content: &[u8],
        cancelled: &CancelSignal,
    ) -> anyhow::Result<MaterializeFileObservation> {
        let _ = (sandbox_id, destination, expected_sha256, content, cancelled);
        anyhow::bail!("materialization attestation is unavailable in dry-run mode")
    }

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSnapshotHandle> {
        Ok(ProviderSnapshotHandle {
            provider: "kubernetes".to_string(),
            snapshot_id,
            resources: self.snapshot_resources(
                sandbox_id,
                snapshot_id,
                RuntimeResourceStatus::Planned,
            ),
            metadata: json!({
                "provider": "kubernetes",
                "mode": "dry_run",
                "operation": "snapshot",
                "cluster": self.cluster,
                "namespace": self.effective_sandbox_namespace(),
                "controlPlaneNamespace": self.namespace,
                "sandboxId": sandbox_id,
                "snapshotId": snapshot_id,
                "volumeSnapshotName": format!("sandboxwich-snapshot-{}", snapshot_id),
                "storageClass": self.storage_class,
                "snapshotClass": self.snapshot_class,
                "manifests": {
                    "volumeSnapshot": self.volume_snapshot_manifest(sandbox_id, snapshot_id)
                }
            }),
        })
    }

    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderForkHandle> {
        self.validate_runtime_profile(spec)?;
        self.validate_network_policy_egress(&spec.network_egress)?;
        let network_policy =
            self.network_policy_manifest(child_sandbox_id, &spec.network_egress)?;
        Ok(ProviderForkHandle {
            provider: "kubernetes".to_string(),
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            resources: self.fork_resources(
                child_sandbox_id,
                snapshot_id,
                spec,
                RuntimeResourceStatus::Planned,
            ),
            metadata: json!({
                "provider": "kubernetes",
                "mode": "dry_run",
                "operation": "fork",
                "cluster": self.cluster,
                "namespace": self.effective_sandbox_namespace(),
                "controlPlaneNamespace": self.namespace,
                "parentSandboxId": parent_sandbox_id,
                "childSandboxId": child_sandbox_id,
                "snapshotId": snapshot_id,
                "pvcCloneName": format!("sandboxwich-pvc-{}", child_sandbox_id),
                "storageClass": self.storage_class,
                "snapshotClass": self.snapshot_class,
                "runtime": self.runtime_metadata(),
                "resources": self.resource_metadata(&spec.memory_limit),
                "networkEgress": spec.network_egress,
                "isolation": self.isolation_metadata(),
                "manifests": {
                    "pvc": self.fork_pvc_manifest(child_sandbox_id, snapshot_id, &spec.memory_limit),
                    "pod": self.pod_manifest(child_sandbox_id, spec),
                    "sshService": self.ssh_service_manifest(child_sandbox_id),
                    "desktopService": self.desktop_service_manifest(child_sandbox_id),
                    "networkPolicy": network_policy,
                    "guestTokenSecret": self.guest_token_secret_manifest_redacted(child_sandbox_id),
                }
            }),
        })
    }

    fn stop(
        &self,
        _sandbox_id: SandboxId,
        _spec: &SandboxTeardownSpec,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        // Dry-run provider never applies anything to a cluster, so there is nothing
        // to tear down; treat it as a successful (planned) no-op.
        Ok(())
    }

    fn delete_home(&self, _home_id: HomeId, _cancelled: &CancelSignal) -> anyhow::Result<()> {
        Ok(())
    }
}

impl SandboxProvider for KubernetesApplyProvider {
    fn capability_report(&self) -> ProviderCapabilityReport {
        let mut report = self.dry_run.capability_report();
        report.capabilities.push(WorkerCapability::MaterializeFile);
        if self.isolated_resident_process_configured() {
            report.labels.insert(
                PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL.to_string(),
                PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL_VALUE.to_string(),
            );
        }
        report
            .labels
            .insert("provider_mode".to_string(), "apply".to_string());
        report.labels.insert(
            "kubectl_context".to_string(),
            self.kubectl_context
                .clone()
                .unwrap_or_else(|| "in-cluster".to_string()),
        );
        report
    }

    fn health_report(&self) -> ProviderHealthReport {
        let mut labels = self.capability_report().labels;
        labels.insert(
            "mutation_enabled".to_string(),
            self.mutation_enabled.to_string(),
        );
        ProviderHealthReport {
            provider: "kubernetes".to_string(),
            status: if self.confirm_apply && self.mutation_enabled {
                ProviderHealthStatus::Healthy
            } else {
                ProviderHealthStatus::Degraded
            },
            checked_at: Utc::now(),
            labels,
            message: Some(format!(
                "apply provider ready; mutations require --confirm-apply and {KUBERNETES_MUTATION_ENV}=1"
            )),
        }
    }

    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        self.dry_run
            .validate_network_policy_egress(&spec.network_egress)?;
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let manifests = self.provision_manifests(sandbox_id, spec)?;
        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            &manifests,
            "apply sandbox manifests",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !apply.success {
            // kubectl apply of a multi-document manifest set is not atomic: some
            // objects may have been created before the command as a whole failed.
            // Best-effort tear those down rather than leaking them (GH rollback fix).
            self.rollback_applied_resources(sandbox_id, "provision (kubectl apply)");
            bail!(
                "kubectl apply sandbox manifests failed with {}: {}",
                apply.status,
                apply.stderr
            );
        }
        if let Err(error) =
            self.wait_for_gateway_ready_if_needed(sandbox_id, &spec.network_egress, cancelled)
        {
            self.rollback_applied_resources(sandbox_id, "provision (wait for gateway ready)");
            return Err(error);
        }
        let wait = match self.wait_for_pod_ready(sandbox_id, cancelled) {
            Ok(wait) => wait,
            Err(error) => {
                self.rollback_applied_resources(sandbox_id, "provision (wait for pod ready)");
                return Err(error);
            }
        };
        if !wait.success {
            self.rollback_applied_resources(sandbox_id, "provision (wait for pod ready)");
            bail!(
                "sandbox pod did not become ready with {}: {}",
                wait.status,
                wait.stderr
            );
        }

        let mut handle = self.dry_run.provision(sandbox_id, spec, cancelled)?;
        mark_resources(
            &mut handle.resources,
            RuntimeResourceStatus::Ready,
            Some(Utc::now()),
        );
        if let Some(metadata) = handle.metadata.as_object_mut() {
            metadata.insert("mode".to_string(), json!("apply"));
            metadata.insert("applyStatus".to_string(), json!(apply.status));
            metadata.insert("applyStdout".to_string(), json!(apply.stdout));
            metadata.insert("waitStatus".to_string(), json!(wait.status));
            metadata.insert("waitStdout".to_string(), json!(wait.stdout));
        }
        Ok(handle)
    }

    fn provision_home_staged(
        &self,
        sandbox_id: SandboxId,
        home_id: HomeId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        self.provision_staged_with_home(sandbox_id, Some(home_id), spec, cancelled, |update| {
            report(update)
        })
    }

    fn provision_staged(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<ProviderSandboxHandle> {
        KubernetesApplyProvider::provision_staged(self, sandbox_id, spec, cancelled, report)
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        validate_agent_command_request(&request)?;
        // Only provision when the pod is actually missing. Re-applying the full
        // manifest set (and re-waiting up to 120s) before every command is both slow
        // and unsafe: Pod `resources` are immutable, so an exec whose spec drifts from
        // the original provisioning would otherwise hard-fail every subsequent command.
        if !self.pod_exists(sandbox_id, cancelled)? {
            self.provision(sandbox_id, spec, cancelled)?;
        }
        let started_at = Utc::now();
        // A per-command `timeout_secs` (see `AgentCommandRequest`) takes
        // precedence over this provider's default bound, so a job's
        // requested timeout is honored the same way whether it executes via
        // `kubectl exec` here or directly in-guest via `sandboxwich-agent`.
        let timeout = request
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.kubectl_command_timeout);
        let stdin_payload = Self::exec_stdin_payload(&request);
        let output = run_kubectl_command_with_stdin(
            &self.kubectl,
            &self.exec_args(sandbox_id, &request),
            stdin_payload.as_deref(),
            "execute sandbox command",
            timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        let finished_at = Utc::now();
        Ok(AgentCommandResult {
            exit_code: output.code.or(Some(if output.success { 0 } else { 1 })),
            stdout: output.stdout,
            stderr: output.stderr,
            started_at,
            finished_at,
        })
    }

    fn run_isolated_resident_process(
        &self,
        spec: &IsolatedResidentProcessSpec,
        cancelled: &CancelSignal,
        observe: &mut dyn FnMut(IsolatedResidentProcessObservation) -> anyhow::Result<()>,
    ) -> anyhow::Result<IsolatedResidentProcessResult> {
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let manifests = self.isolated_resident_process_manifests(spec)?;
        let cleanup_manifests = self.isolated_resident_process_cleanup_manifests(spec);
        let run_result = (|| {
            let apply = run_kubectl_documents(
                &self.kubectl,
                &self.kubectl_args("apply"),
                &manifests,
                "apply isolated resident-process manifests",
                self.kubectl_command_timeout,
                Some(cancelled),
                self.max_captured_output_bytes,
            )?;
            anyhow::ensure!(
                apply.success,
                "kubectl apply isolated resident-process manifests failed with {}",
                apply.status
            );

            let started_at = Instant::now();
            let mut previous = None;
            let mut poll_interval = self.isolated_resident_process_poll_interval;
            loop {
                anyhow::ensure!(
                    !cancelled.is_cancelled(),
                    "isolated resident-process execution cancelled after lease loss"
                );
                let pod_observation = self.observe_isolated_resident_process(spec, cancelled)?;
                let changed = match pod_observation {
                    IsolatedResidentProcessPodObservation::Pending { pod_name, pod_uid } => {
                        if started_at.elapsed() >= self.isolated_resident_process_startup_timeout {
                            let observation = IsolatedResidentProcessObservation {
                                state: IsolatedResidentProcessState::Failed,
                                pod_name,
                                pod_uid,
                                ready: false,
                                exit_code: None,
                            };
                            observe(observation)?;
                            return Err(anyhow::Error::new(ProviderError::retryable(
                                anyhow::anyhow!(
                                    "isolated resident-process sidecar exceeded its startup deadline"
                                ),
                            )));
                        }
                        false
                    }
                    IsolatedResidentProcessPodObservation::Started(observation) => {
                        let changed = previous.as_ref() != Some(&observation);
                        if changed {
                            observe(observation.clone())?;
                            previous = Some(observation.clone());
                        }
                        if matches!(
                            observation.state,
                            IsolatedResidentProcessState::Succeeded
                                | IsolatedResidentProcessState::Failed
                        ) {
                            return Ok(IsolatedResidentProcessResult {
                                final_observation: observation,
                            });
                        }
                        changed
                    }
                };
                if changed {
                    poll_interval = self.isolated_resident_process_poll_interval;
                } else {
                    poll_interval = poll_interval
                        .saturating_mul(2)
                        .min(self.isolated_resident_process_max_poll_interval);
                }
                let sleep_duration = if previous.is_none() {
                    poll_interval.min(
                        self.isolated_resident_process_startup_timeout
                            .saturating_sub(started_at.elapsed()),
                    )
                } else {
                    poll_interval
                };
                sleep_with_cancellation(sleep_duration, cancelled)?;
            }
        })();

        // Cleanup manifests contain names only. In particular, the raw/base64
        // bootstrap bytes are never replayed through cleanup, persisted in a
        // provider handle, or included in diagnostics.
        let cleanup = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_delete_args(),
            &cleanup_manifests,
            "cleanup isolated resident-process manifests",
            self.kubectl_command_timeout,
            None,
            self.max_captured_output_bytes,
        );
        match (run_result, cleanup) {
            (Ok(result), Ok(output)) if output.success => Ok(result),
            (Ok(_), Ok(output)) => anyhow::bail!(
                "kubectl cleanup isolated resident-process manifests failed with {}: {}",
                output.status,
                output.stderr
            ),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Ok(output)) => {
                if !output.success {
                    eprintln!(
                        "warning: isolated resident-process cleanup failed with {}: {}",
                        output.status, output.stderr
                    );
                }
                Err(error)
            }
            (Err(error), Err(cleanup_error)) => {
                eprintln!(
                    "warning: isolated resident-process cleanup could not run: {cleanup_error:#}"
                );
                Err(error)
            }
        }
    }

    fn read_apex_task_instructions(
        &self,
        sandbox_id: SandboxId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<Vec<u8>> {
        // A live read is valid only against a provider-owned pod that already
        // exists. Never provision/re-apply as a side effect of this endpoint.
        anyhow::ensure!(
            self.pod_exists(sandbox_id, cancelled)?,
            "sandbox provider apply proof is unavailable"
        );
        run_fixed_apex_task_instructions(
            &self.kubectl,
            &self.apex_task_instructions_args(sandbox_id),
            self.kubectl_command_timeout,
            cancelled,
        )
    }

    fn materialize_file(
        &self,
        sandbox_id: SandboxId,
        destination: MaterializeFileDestination,
        expected_sha256: &str,
        content: &[u8],
        cancelled: &CancelSignal,
    ) -> anyhow::Result<MaterializeFileObservation> {
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        anyhow::ensure!(
            content.len() as u64 <= MAX_SANDBOX_FILE_BYTES,
            "materialization exceeds 64 MiB"
        );
        anyhow::ensure!(
            sha256_hex(content) == expected_sha256,
            "materialization digest mismatch"
        );
        anyhow::ensure!(
            self.pod_exists(sandbox_id, cancelled)?,
            "sandbox pod is unavailable"
        );
        let request = AgentCommandRequest {
            argv: vec![
                "/opt/apex/bin/import-file".to_string(),
                "--destination".to_string(),
                destination.guest_path().to_string(),
                "--sha256".to_string(),
                expected_sha256.to_string(),
            ],
            cwd: None,
            env: Default::default(),
            // An empty marker causes `exec_args` to add `-i`; the content
            // itself is passed once, as a borrowed slice, below.
            stdin: Some(Vec::new()),
            timeout_secs: Some(300),
        };
        let output = run_kubectl_command_with_stdin(
            &self.kubectl,
            &self.exec_args(sandbox_id, &request),
            Some(content),
            "materialize sandbox file",
            Duration::from_secs(300),
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        anyhow::ensure!(output.success, "sandbox file materialization failed");
        let observation_request = AgentCommandRequest {
            argv: vec![
                "/usr/bin/sha256sum".to_string(),
                destination.guest_path().to_string(),
            ],
            cwd: None,
            env: Default::default(),
            stdin: None,
            timeout_secs: Some(30),
        };
        let observation = run_kubectl_command_with_stdin(
            &self.kubectl,
            &self.exec_args(sandbox_id, &observation_request),
            None,
            "observe materialized sandbox file",
            Duration::from_secs(30),
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        anyhow::ensure!(
            observation.success,
            "sandbox file materialization observation failed"
        );
        let mut fields = observation.stdout.split_ascii_whitespace();
        let destination_sha256 = fields
            .next()
            .context("materialization observation digest is missing")?;
        let observed_path = fields
            .next()
            .context("materialization observation destination is missing")?;
        anyhow::ensure!(
            fields.next().is_none()
                && destination_sha256.len() == 64
                && destination_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                && observed_path == destination.guest_path(),
            "materialization observation is invalid"
        );
        anyhow::ensure!(
            destination_sha256 == expected_sha256,
            "materialized destination digest mismatch"
        );
        Ok(MaterializeFileObservation {
            destination_sha256: destination_sha256.to_string(),
            size_bytes: content.len() as u64,
        })
    }

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderSnapshotHandle> {
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let snapshot = self
            .dry_run
            .volume_snapshot_manifest(sandbox_id, snapshot_id);
        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            std::slice::from_ref(&snapshot),
            "apply snapshot manifest",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !apply.success {
            bail!(
                "kubectl apply snapshot manifest failed with {}: {}",
                apply.status,
                apply.stderr
            );
        }
        let mut handle = self
            .dry_run
            .create_snapshot(sandbox_id, snapshot_id, cancelled)?;
        mark_resources(
            &mut handle.resources,
            RuntimeResourceStatus::Applied,
            Some(Utc::now()),
        );
        if let Some(metadata) = handle.metadata.as_object_mut() {
            metadata.insert("mode".to_string(), json!("apply"));
            metadata.insert("applyStatus".to_string(), json!(apply.status));
            metadata.insert("applyStdout".to_string(), json!(apply.stdout));
        }
        Ok(handle)
    }

    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<ProviderForkHandle> {
        self.dry_run
            .validate_network_policy_egress(&spec.network_egress)?;
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let manifests = self.fork_manifests(child_sandbox_id, snapshot_id, spec)?;
        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            &manifests,
            "apply fork manifests",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !apply.success {
            // Same non-atomicity concern as provision(): some of the fork's
            // manifests may already have been created before the apply as a
            // whole failed. Roll back everything labeled with the child sandbox
            // id rather than leaking it.
            self.rollback_applied_resources(child_sandbox_id, "fork (kubectl apply)");
            bail!(
                "kubectl apply fork manifests failed with {}: {}",
                apply.status,
                apply.stderr
            );
        }
        if let Err(error) =
            self.wait_for_gateway_ready_if_needed(child_sandbox_id, &spec.network_egress, cancelled)
        {
            self.rollback_applied_resources(child_sandbox_id, "fork (wait for gateway ready)");
            return Err(error);
        }
        let wait = match self.wait_for_pod_ready(child_sandbox_id, cancelled) {
            Ok(wait) => wait,
            Err(error) => {
                self.rollback_applied_resources(child_sandbox_id, "fork (wait for pod ready)");
                return Err(error);
            }
        };
        if !wait.success {
            self.rollback_applied_resources(child_sandbox_id, "fork (wait for pod ready)");
            bail!(
                "forked sandbox pod did not become ready with {}: {}",
                wait.status,
                wait.stderr
            );
        }
        let mut handle = self.dry_run.fork(
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            spec,
            cancelled,
        )?;
        mark_resources(
            &mut handle.resources,
            RuntimeResourceStatus::Ready,
            Some(Utc::now()),
        );
        if let Some(metadata) = handle.metadata.as_object_mut() {
            metadata.insert("mode".to_string(), json!("apply"));
            metadata.insert("applyStatus".to_string(), json!(apply.status));
            metadata.insert("applyStdout".to_string(), json!(apply.stdout));
            metadata.insert("waitStatus".to_string(), json!(wait.status));
            metadata.insert("waitStdout".to_string(), json!(wait.stdout));
        }
        Ok(handle)
    }

    fn stop(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let args = self.teardown_args_with_spec(sandbox_id, spec);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "delete sandbox resources",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !output.success {
            bail!(
                "kubectl delete sandbox resources failed with {}: {}",
                output.status,
                output.stderr
            );
        }
        Ok(())
    }

    fn delete_home(&self, home_id: HomeId, cancelled: &CancelSignal) -> anyhow::Result<()> {
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let mut args = self.kubectl_base_args();
        args.extend([
            "delete".to_string(),
            "persistentvolumeclaim".to_string(),
            format!("sandboxwich-home-{home_id}"),
            "--ignore-not-found=true".to_string(),
        ]);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "delete managed home",
            self.kubectl_command_timeout,
            Some(cancelled),
            self.max_captured_output_bytes,
        )?;
        if !output.success {
            bail!(
                "kubectl delete managed home failed with {}: {}",
                output.status,
                output.stderr
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
