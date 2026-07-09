use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use chrono::Utc;
use ipnet::IpNet;
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, MemoryLimit, NetworkAllowRuleKind, NetworkEgress,
    ProviderCapabilityReport, ProviderForkHandle, ProviderHealthReport, ProviderHealthStatus,
    ProviderRuntimeResource, ProviderSandboxHandle, ProviderSnapshotHandle, RuntimeResourceKind,
    RuntimeResourcePurpose, RuntimeResourceStatus, SandboxId, SandboxProvisionSpec, SnapshotId,
    WorkerCapability,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const KUBERNETES_MUTATION_ENV: &str = "SANDBOXWICH_K8S_ENABLE_MUTATION";
pub const DEFAULT_SANDBOX_GUEST_IMAGE: &str = "ghcr.io/evalops/sandboxwich-ubuntu-dev:latest";
/// Default cap on the stdout/stderr captured from a single `kubectl` invocation
/// before it's stored in a `KubectlOutput` (and, from there, in job results and
/// provider metadata sent back to the control plane). Mirrors
/// `sandboxwich-agent`'s `DEFAULT_MAX_CAPTURED_OUTPUT_BYTES`: without a cap, a
/// chatty or misbehaving `kubectl` command could grow these unboundedly.
pub const DEFAULT_MAX_CAPTURED_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;

/// Default bound applied to every `kubectl` invocation made by
/// [`KubernetesApplyProvider`] (see [`run_kubectl_command`]). Deliberately
/// longer than `wait_for_pod_ready`'s own `--timeout=120s` flag so this is a
/// backstop against a wedged `kubectl`/API server (a process that hangs
/// rather than erroring out after its own internal timeout), not something
/// that routinely races that flag. Configurable via
/// `with_kubectl_command_timeout`/`--kubectl-command-timeout-secs`/
/// `SANDBOXWICH_KUBECTL_COMMAND_TIMEOUT_SECS` for environments that need a
/// longer bound (e.g. slow-running commands executed via `kubectl exec`).
pub const DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS: u64 = 300;

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
/// Includes `secret` (GH-101) so the per-sandbox worker-token Secret (see
/// `worker_token_secret_manifest`) is cleaned up alongside the pod that mounts
/// it, without needing separate lifecycle tracking; this is safe because the
/// delete is always scoped to this specific sandbox's label, never a bare
/// `kubectl delete secret --all`.
pub const SANDBOX_TEARDOWN_RESOURCE_KINDS: &str =
    "pod,persistentvolumeclaim,service,networkpolicy,secret";
/// Placeholder substituted for the raw worker-scoped token in every
/// serialized/persisted/printed rendering of the per-sandbox worker-token
/// Secret (provider handle metadata, which the API persists into the
/// sandboxes table's `provider_metadata` column and returns to tenant
/// clients). The raw token exists only in the manifest set piped to
/// `kubectl apply` stdin (GH-101).
pub const WORKER_TOKEN_REDACTED: &str = "[redacted]";

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

pub trait SandboxProvider {
    fn capability_report(&self) -> ProviderCapabilityReport;
    fn health_report(&self) -> ProviderHealthReport;
    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
    ) -> anyhow::Result<ProviderSandboxHandle>;
    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult>;
    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> anyhow::Result<ProviderSnapshotHandle>;
    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
    ) -> anyhow::Result<ProviderForkHandle>;
    /// Tear down every resource associated with `sandbox_id`. Must be idempotent:
    /// calling it on an already-stopped (or never-provisioned) sandbox is not an error.
    fn stop(&self, sandbox_id: SandboxId) -> anyhow::Result<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesDryRunProvider {
    cluster: String,
    namespace: String,
    storage_class: Option<String>,
    snapshot_class: Option<String>,
    runtime_image: String,
    workspace_storage: String,
    workspace_storage_override: bool,
    ssh_authorized_keys_secret: Option<String>,
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
    /// `(worker_id, worker_token)` for the worker-scoped API token (GH-64)
    /// this provider injects into every sandbox it provisions, so the guest
    /// agent running inside the pod can authenticate to guest-facing routes
    /// as itself rather than with a tenant-wide token (GH-101). Unlike
    /// `ssh_authorized_keys_secret`/`vnc_password_secret`, which reference
    /// operator-managed secrets that already exist in the cluster, this
    /// provider synthesizes and applies the Secret itself (see
    /// `worker_token_secret_manifest`), because the token is minted fresh at
    /// worker registration and cannot be pre-provisioned. `None` when no
    /// worker credentials are configured (e.g. dry-run smoke commands with
    /// no registered worker), in which case no token is wired into the pod
    /// at all -- matching pre-GH-101 behavior rather than injecting a
    /// tenant-wide token as a fallback.
    worker_credentials: Option<(String, String)>,
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
            workspace_storage: "2Gi".to_string(),
            workspace_storage_override: false,
            ssh_authorized_keys_secret: None,
            runtime_class_name: None,
            isolation_backend: "kubernetes".to_string(),
            sandbox_namespace: None,
            dns_namespace: DEFAULT_DNS_NAMESPACE.to_string(),
            egress_excluded_cidrs: DEFAULT_EGRESS_EXCLUDED_CIDRS
                .iter()
                .map(|cidr| cidr.to_string())
                .collect(),
            ingress_namespace: None,
            ingress_pod_selector: BTreeMap::from([(
                DEFAULT_INGRESS_SELECTOR_KEY.to_string(),
                DEFAULT_INGRESS_SELECTOR_VALUE.to_string(),
            )]),
            vnc_password_secret: None,
            worker_credentials: None,
        }
    }

    pub fn with_runtime_image(mut self, image: Option<String>) -> Self {
        if let Some(image) = image {
            self.runtime_image = image;
        }
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

    /// Configures the worker-scoped API token (GH-64) delivered into every
    /// sandbox this provider provisions (GH-101). `worker_token` is
    /// typically the credential minted by `POST /workers/register` and
    /// resolved to `(tenant_id, worker_id)` by the API's guest-facing
    /// routes; `worker_id` is the same id the token resolves to, delivered
    /// alongside it so the guest agent can address itself in
    /// `/workers/{id}/leases/claim` without needing to be told separately.
    /// A `None`/empty `worker_token` clears any previously configured
    /// credentials rather than wiring in a worker id with no token.
    pub fn with_worker_credentials(
        mut self,
        worker_id: impl Into<String>,
        worker_token: Option<String>,
    ) -> Self {
        let worker_id = worker_id.into();
        self.worker_credentials = worker_token.and_then(|token| {
            let token = token.trim();
            if token.is_empty() {
                None
            } else {
                Some((worker_id, token.to_string()))
            }
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
        labels.insert(
            "workspace_storage".to_string(),
            self.workspace_storage.clone(),
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
        let network_policy = self.network_policy_manifest(sandbox_id, &spec.network_egress)?;
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
            "workspaceStorage": self.effective_workspace_storage(&spec.memory_limit),
            "runtime": self.runtime_metadata(),
            "resources": self.resource_metadata(&spec.memory_limit),
            "networkEgress": spec.network_egress,
            "isolation": self.isolation_metadata(),
            "manifests": {
                "pod": self.pod_manifest(sandbox_id, spec),
                "pvc": self.pvc_manifest(format!("sandboxwich-pvc-{sandbox_id}"), Some(sandbox_id), &spec.memory_limit),
                "sshService": self.ssh_service_manifest(sandbox_id),
                "desktopService": self.desktop_service_manifest(sandbox_id),
                "networkPolicy": network_policy,
                // Redacted: this metadata is persisted by the API into the
                // sandboxes table and returned to tenant clients, so the
                // raw token must never appear here (GH-101).
                "workerTokenSecret": self.worker_token_secret_manifest_redacted(sandbox_id)
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
            "runtimeClassName": self.runtime_class_name
        })
    }

    fn validate_network_policy_egress(network_egress: &NetworkEgress) -> anyhow::Result<()> {
        if let NetworkEgress::Allowlist { rules } = network_egress
            && let Some(rule) = rules
                .iter()
                .find(|rule| rule.kind == NetworkAllowRuleKind::Host)
        {
            bail!(
                "standard Kubernetes NetworkPolicy cannot enforce host allow rule {}; use cidr allow rules or a provider with FQDN egress support",
                rule.value
            );
        }
        Ok(())
    }

    fn effective_workspace_storage(&self, memory_limit: &MemoryLimit) -> String {
        if self.workspace_storage_override {
            self.workspace_storage.clone()
        } else {
            memory_limit.disk_limit().to_string()
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
        let mut volumes = vec![json!({
            "name": "workspace",
            "persistentVolumeClaim": {
                "claimName": format!("sandboxwich-pvc-{sandbox_id}")
            }
        })];
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

        if let Some((worker_id, _token)) = &self.worker_credentials {
            // GH-101: the worker-scoped token (GH-64) is mounted as a
            // read-only file rather than a plain env var or `secretKeyRef`,
            // for the same reason as the VNC password above -- it must not
            // show up in `kubectl get pod -o yaml`/`kubectl describe pod` or
            // anything else that can read this pod's spec through the
            // Kubernetes API, only to a process that can exec into the
            // container or read the volume directly. `SANDBOXWICH_WORKER_ID`
            // is not a credential (it identifies the worker, not the
            // secret), so it travels as a plain env var like
            // `SANDBOXWICH_WORKSPACE`/`SANDBOXWICH_SSH_PORT` above.
            volume_mounts.push(json!({
                "name": "worker-token",
                "mountPath": "/run/sandboxwich/token",
                "readOnly": true
            }));
            volumes.push(json!({
                "name": "worker-token",
                "secret": {
                    "secretName": self.worker_token_secret_name(sandbox_id),
                    "items": [{
                        "key": "api-token",
                        "path": "api-token"
                    }]
                }
            }));
            env.push(json!({
                "name": "SANDBOXWICH_API_TOKEN_FILE",
                "value": "/run/sandboxwich/token/api-token"
            }));
            env.push(json!({
                "name": "SANDBOXWICH_WORKER_ID",
                "value": worker_id
            }));
        }

        let ephemeral_storage = Self::ephemeral_storage_limit(&spec.memory_limit);
        let mut pod_spec = Map::from_iter([
            ("automountServiceAccountToken".to_string(), json!(false)),
            (
                "securityContext".to_string(),
                json!({
                    "runAsNonRoot": true,
                    "runAsUser": 10001,
                    "runAsGroup": 10001,
                    "fsGroup": 10001,
                    "seccompProfile": {
                        "type": "RuntimeDefault"
                    }
                }),
            ),
            (
                "containers".to_string(),
                json!([{
                    "name": "sandbox",
                    "image": self.runtime_image,
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
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": false,
                        "runAsNonRoot": true,
                        "capabilities": {
                            "drop": ["ALL"]
                        },
                        "seccompProfile": {
                            "type": "RuntimeDefault"
                        }
                    },
                    "volumeMounts": volume_mounts
                }]),
            ),
            ("volumes".to_string(), json!(volumes)),
        ]);
        if let Some(runtime_class_name) = &self.runtime_class_name {
            pod_spec.insert("runtimeClassName".to_string(), json!(runtime_class_name));
        }

        json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": self.object_metadata(format!("sandboxwich-{sandbox_id}"), Some(sandbox_id)),
            "spec": pod_spec
        })
    }

    /// Name of the per-sandbox Secret carrying this worker's scoped API
    /// token (see `worker_token_secret_manifest`). Scoped to `sandbox_id`
    /// (not shared across every sandbox this worker provisions) so it is
    /// torn down by the same label-selected `kubectl delete` that already
    /// cleans up a sandbox's pod/PVC/services/network policy (see
    /// `SANDBOX_TEARDOWN_RESOURCE_KINDS`), without needing separate
    /// lifecycle tracking.
    fn worker_token_secret_name(&self, sandbox_id: SandboxId) -> String {
        format!("sandboxwich-worker-token-{sandbox_id}")
    }

    /// Renders the Secret carrying this worker's scoped API token (GH-64)
    /// for `sandbox_id`, or `None` when no worker credentials are
    /// configured. Unlike `ssh_authorized_keys_secret`/`vnc_password_secret`
    /// -- which reference operator-managed secrets assumed to already exist
    /// in the cluster -- this provider must synthesize and apply this
    /// Secret itself, since the token is minted fresh at worker
    /// registration (GH-64) and cannot be pre-provisioned by an operator
    /// ahead of time (GH-101).
    ///
    /// SECURITY: this manifest carries the RAW token and must only ever be
    /// piped to `kubectl apply` stdin (see `provision_manifests`/
    /// `fork_manifests`). Anything that serializes a manifest as *data* --
    /// provider handle metadata (persisted verbatim into the control-plane
    /// database's `provider_metadata` column and returned to tenant clients
    /// on sandbox reads), smoke-plan output, logs -- must use
    /// [`Self::worker_token_secret_manifest_redacted`] instead, or the
    /// token ends up stored/served in plaintext: the exact exposure class
    /// GH-64/GH-99 were closing.
    fn worker_token_secret_manifest(&self, sandbox_id: SandboxId) -> Option<serde_json::Value> {
        let (_, token) = self.worker_credentials.as_ref()?;
        Some(self.render_worker_token_secret(sandbox_id, token))
    }

    /// Like [`Self::worker_token_secret_manifest`], but with the token value
    /// replaced by [`WORKER_TOKEN_REDACTED`]. This is the only variant that
    /// may appear in provider handle metadata (`"manifests"` blocks in
    /// provision/fork metadata) or any other serialized/persisted/printed
    /// output: handle metadata leaves the worker as data -- the API stores
    /// it in the sandboxes table and returns it to tenant clients -- so the
    /// raw token must never travel through it. The secret's name/kind/labels
    /// are preserved so operators can still see *which* Secret a sandbox
    /// uses without seeing its contents.
    fn worker_token_secret_manifest_redacted(
        &self,
        sandbox_id: SandboxId,
    ) -> Option<serde_json::Value> {
        self.worker_credentials.as_ref()?;
        Some(self.render_worker_token_secret(sandbox_id, WORKER_TOKEN_REDACTED))
    }

    fn render_worker_token_secret(&self, sandbox_id: SandboxId, token: &str) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "Opaque",
            "metadata": self.object_metadata(
                self.worker_token_secret_name(sandbox_id),
                Some(sandbox_id)
            ),
            "stringData": {
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
    fn dns_egress_rule(&self) -> serde_json::Value {
        json!({
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
        Self::validate_network_policy_egress(network_egress)?;
        let egress = match network_egress {
            NetworkEgress::DenyAll => Vec::new(),
            NetworkEgress::AllowAll => vec![
                json!({ "to": [{ "ipBlock": self.ip_block("0.0.0.0/0")? }] }),
                self.dns_egress_rule(),
            ],
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
                egress.push(self.dns_egress_rule());
                egress
            }
        };

        Ok(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": self.object_metadata(format!("sandboxwich-egress-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "sandboxwich.dev/sandbox-id": sandbox_id
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [self.ingress_rule()],
                "egress": egress
            }
        }))
    }

    fn ssh_service_manifest(&self, sandbox_id: SandboxId) -> serde_json::Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": self.object_metadata(format!("sandboxwich-ssh-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "type": "ClusterIP",
                "selector": {
                    "sandboxwich.dev/sandbox-id": sandbox_id
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
                    "sandboxwich.dev/sandbox-id": sandbox_id
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
        vec![
            self.workspace_pvc_resource(sandbox_id, &spec.memory_limit, status.clone(), None),
            self.runtime_pod_resource(sandbox_id, status.clone()),
            self.ssh_service_resource(sandbox_id, status.clone()),
            self.desktop_service_resource(sandbox_id, status.clone()),
            self.network_policy_resource(sandbox_id, status),
        ]
    }

    fn fork_resources(
        &self,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        status: RuntimeResourceStatus,
    ) -> Vec<ProviderRuntimeResource> {
        vec![
            self.workspace_pvc_resource(
                child_sandbox_id,
                &spec.memory_limit,
                status.clone(),
                Some(snapshot_id),
            ),
            self.runtime_pod_resource(child_sandbox_id, status.clone()),
            self.ssh_service_resource(child_sandbox_id, status.clone()),
            self.desktop_service_resource(child_sandbox_id, status.clone()),
            self.network_policy_resource(child_sandbox_id, status),
        ]
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
        }
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

    /// Caps the stdout/stderr captured from every `kubectl` invocation this
    /// provider makes. See `DEFAULT_MAX_CAPTURED_OUTPUT_BYTES`.
    pub fn with_max_captured_output_bytes(mut self, max_captured_output_bytes: u64) -> Self {
        self.max_captured_output_bytes = max_captured_output_bytes;
        self
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

        let apply = run_kubectl_documents(
            &plan.kubectl,
            &plan.apply_args,
            &plan.apply_manifests,
            "apply smoke manifests",
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
        let mut manifests = vec![self.dry_run.pvc_manifest(
            format!("sandboxwich-pvc-{sandbox_id}"),
            Some(sandbox_id),
            &spec.memory_limit,
        )];
        // Applied ahead of the pod that mounts it (GH-101): kubectl apply of a
        // multi-document manifest set is not strictly atomic/ordered, but a
        // pod referencing a not-yet-applied Secret only stalls in
        // `ContainerCreating` until the Secret shows up (well within
        // `wait_for_pod_ready`'s timeout) rather than failing outright, so
        // this ordering is a courtesy, not a correctness requirement.
        manifests.extend(self.dry_run.worker_token_secret_manifest(sandbox_id));
        manifests.push(self.dry_run.pod_manifest(sandbox_id, spec));
        manifests.push(
            self.dry_run
                .network_policy_manifest(sandbox_id, &spec.network_egress)?,
        );
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
        let mut manifests =
            vec![
                self.dry_run
                    .fork_pvc_manifest(child_sandbox_id, snapshot_id, &spec.memory_limit),
            ];
        // GH-101: same courtesy ordering as `provision_manifests` -- the
        // child sandbox gets its own worker-token Secret, scoped to its own
        // `child_sandbox_id`, since it's a distinct pod with its own
        // teardown lifecycle.
        manifests.extend(self.dry_run.worker_token_secret_manifest(child_sandbox_id));
        manifests.push(self.dry_run.pod_manifest(child_sandbox_id, spec));
        manifests.push(
            self.dry_run
                .network_policy_manifest(child_sandbox_id, &spec.network_egress)?,
        );
        manifests.push(self.dry_run.ssh_service_manifest(child_sandbox_id));
        manifests.push(self.dry_run.desktop_service_manifest(child_sandbox_id));
        Ok(manifests)
    }

    fn wait_for_pod_ready(&self, sandbox_id: SandboxId) -> anyhow::Result<KubectlOutput> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "wait".to_string(),
            "--for=condition=Ready".to_string(),
            format!("pod/{}", self.pod_name(sandbox_id)),
            "--timeout=120s".to_string(),
        ]);
        run_kubectl_command(
            &self.kubectl,
            &args,
            "wait for sandbox pod readiness",
            self.kubectl_command_timeout,
            None,
            self.max_captured_output_bytes,
        )
    }

    /// Returns true if the sandbox's pod already exists in the cluster. Used so that
    /// `exec_handoff` only provisions when necessary instead of re-applying the full
    /// manifest set (and its immutable Pod fields) before every command.
    fn pod_exists(&self, sandbox_id: SandboxId) -> anyhow::Result<bool> {
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
            None,
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
        let mut args = self.kubectl_base_args();
        args.extend([
            "delete".to_string(),
            SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string(),
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
    /// `bash -c` wrapper that reads NUL-delimited `KEY=VALUE` pairs from
    /// stdin and `export`s them before `exec`ing the real command; the
    /// caller must pipe `exec_stdin_payload(request)` to that invocation's
    /// stdin. NUL is a safe delimiter because POSIX environment variable
    /// values can never contain an embedded NUL byte, unlike newlines.
    fn exec_args(&self, sandbox_id: SandboxId, request: &AgentCommandRequest) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        let needs_env = !request.env.is_empty();
        if needs_env {
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

    /// Builds the NUL-delimited `KEY=VALUE` payload that must be piped to
    /// the stdin of the `kubectl exec` invocation built by `exec_args` when
    /// `request.env` is non-empty. Returns `None` when there's nothing to
    /// send, so callers know not to bother opening a piped stdin at all.
    fn exec_stdin_payload(request: &AgentCommandRequest) -> Option<Vec<u8>> {
        if request.env.is_empty() {
            return None;
        }
        let mut payload = Vec::new();
        for (key, value) in &request.env {
            payload.extend_from_slice(key.as_bytes());
            payload.push(b'=');
            payload.extend_from_slice(value.as_bytes());
            payload.push(0);
        }
        Some(payload)
    }
}

/// Guest-side wrapper invoked via `bash -c` by `exec_args` when the request
/// carries env vars. Argument order (after the `bash -c` command string
/// itself, `$0` is `sandboxwich-exec`): `$1` is `"1"`/`"0"` for
/// has-cwd, `$2` is the cwd (only present when `$1 == "1"`), and the
/// remaining args are the real command to run. Env `KEY=VALUE` pairs are
/// read from stdin, NUL-delimited, before anything else runs.
const EXEC_ENV_WRAPPER_SCRIPT: &str = concat!(
    "while IFS= read -r -d '' kv; do ",
    "case \"$kv\" in *=*) export \"${kv%%=*}\"=\"${kv#*=}\" ;; esac; ",
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

fn run_kubectl_documents(
    kubectl: &str,
    args: &[String],
    manifests: &[Value],
    context: &'static str,
    max_output_bytes: u64,
) -> anyhow::Result<KubectlOutput> {
    let mut child = Command::new(kubectl)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn kubectl for {context}"))?;

    let mut stdin = child.stdin.take().context("failed to open kubectl stdin")?;
    stdin
        .write_all(render_manifest_documents(manifests)?.as_bytes())
        .context("failed to write manifests to kubectl stdin")?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for kubectl {context}"))?;
    let stdout = cap_output_bytes(&output.stdout, max_output_bytes);
    let stderr = cap_output_bytes(&output.stderr, max_output_bytes);

    Ok(KubectlOutput {
        success: output.status.success(),
        code: output.status.code(),
        status: output.status.to_string(),
        stdout,
        stderr,
    })
}

/// How often a kubectl invocation polls a `CancelSignal` for cancellation
/// while waiting on the child.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(500);

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
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(command),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build a runtime to drive a kubectl invocation")?
            .block_on(command),
    }
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
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn kubectl for {context}"))?;
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
        tokio::try_join!(
            child.wait(),
            feed_stdin,
            stdout_pipe.read_to_end(&mut stdout),
            stderr_pipe.read_to_end(&mut stderr),
        )
        .map(|(status, (), _, _)| (status, stdout, stderr))
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
            WorkerCapability::AgentPrompt,
            WorkerCapability::Snapshot,
            WorkerCapability::DesktopStream,
        ];
        if self.runtime_class_name.is_some() {
            capabilities.push(WorkerCapability::GvisorSandbox);
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
    ) -> anyhow::Result<ProviderSandboxHandle> {
        Self::validate_network_policy_egress(&spec.network_egress)?;
        Ok(ProviderSandboxHandle {
            provider: "kubernetes".to_string(),
            sandbox_id,
            resources: self.sandbox_resources(sandbox_id, spec, RuntimeResourceStatus::Planned),
            metadata: self.metadata(sandbox_id, "provision", spec)?,
        })
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
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

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
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
    ) -> anyhow::Result<ProviderForkHandle> {
        Self::validate_network_policy_egress(&spec.network_egress)?;
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
                    // Redacted: fork handle metadata is persisted/served by
                    // the API exactly like provision metadata (GH-101).
                    "workerTokenSecret": self.worker_token_secret_manifest_redacted(child_sandbox_id)
                }
            }),
        })
    }

    fn stop(&self, _sandbox_id: SandboxId) -> anyhow::Result<()> {
        // Dry-run provider never applies anything to a cluster, so there is nothing
        // to tear down; treat it as a successful (planned) no-op.
        Ok(())
    }
}

impl SandboxProvider for KubernetesApplyProvider {
    fn capability_report(&self) -> ProviderCapabilityReport {
        let mut report = self.dry_run.capability_report();
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
    ) -> anyhow::Result<ProviderSandboxHandle> {
        KubernetesDryRunProvider::validate_network_policy_egress(&spec.network_egress)?;
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let manifests = self.provision_manifests(sandbox_id, spec)?;
        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            &manifests,
            "apply sandbox manifests",
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
        let wait = match self.wait_for_pod_ready(sandbox_id) {
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

        let mut handle = self.dry_run.provision(sandbox_id, spec)?;
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

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        // Only provision when the pod is actually missing. Re-applying the full
        // manifest set (and re-waiting up to 120s) before every command is both slow
        // and unsafe: Pod `resources` are immutable, so an exec whose spec drifts from
        // the original provisioning would otherwise hard-fail every subsequent command.
        if !self.pod_exists(sandbox_id)? {
            self.provision(sandbox_id, spec)?;
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

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
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
            self.max_captured_output_bytes,
        )?;
        if !apply.success {
            bail!(
                "kubectl apply snapshot manifest failed with {}: {}",
                apply.status,
                apply.stderr
            );
        }
        let mut handle = self.dry_run.create_snapshot(sandbox_id, snapshot_id)?;
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
    ) -> anyhow::Result<ProviderForkHandle> {
        KubernetesDryRunProvider::validate_network_policy_egress(&spec.network_egress)?;
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let manifests = self.fork_manifests(child_sandbox_id, snapshot_id, spec)?;
        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            &manifests,
            "apply fork manifests",
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
        let wait = match self.wait_for_pod_ready(child_sandbox_id) {
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
        let mut handle =
            self.dry_run
                .fork(parent_sandbox_id, child_sandbox_id, snapshot_id, spec)?;
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

    fn stop(&self, sandbox_id: SandboxId) -> anyhow::Result<()> {
        Self::validate_apply_gate(self.confirm_apply, self.mutation_enabled)?;
        let args = self.teardown_args(sandbox_id);
        let output = run_kubectl_command(
            &self.kubectl,
            &args,
            "delete sandbox resources",
            self.kubectl_command_timeout,
            None,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_kubectl_command_async_succeeds_within_timeout() {
        let output = run_kubectl_command_async(
            "sh",
            &["-c".to_string(), "echo hi && exit 0".to_string()],
            None,
            "test fast command",
            Duration::from_secs(5),
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
        )
        .await
        .expect("fast command should succeed well within the timeout");
        assert!(output.success);
        assert_eq!(output.stdout.trim(), "hi");
    }

    #[tokio::test]
    async fn run_kubectl_command_async_kills_the_child_and_errors_on_timeout() {
        // Regression test for item 3(b): before this fix, `run_kubectl_command`
        // used `std::process::Command::output()` with no bound at all, so a
        // wedged `kubectl` (e.g. `kubectl exec` into an unresponsive pod, or
        // `kubectl` stuck talking to an unreachable API server) hung the
        // worker's job-execution thread forever. A command that would run far
        // longer than the configured timeout must be killed and reported as a
        // distinct timeout failure well before it would naturally exit.
        let started = std::time::Instant::now();
        let error = run_kubectl_command_async(
            "sh",
            &["-c".to_string(), "sleep 30".to_string()],
            None,
            "test slow command",
            Duration::from_millis(200),
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
        )
        .await
        .expect_err("a command that outlives the timeout must be treated as a failure");
        let elapsed = started.elapsed();

        assert!(
            error.to_string().contains("timed out"),
            "error should be distinctly reported as a timeout, got: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the timed-out child should have been killed almost immediately instead of \
             the caller waiting anywhere near its full 30s sleep; elapsed = {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn run_kubectl_command_async_is_cancelled_when_lease_renewal_is_lost() {
        // Regression test for item 4(b): before this fix, `handle_lease`'s
        // renewal task just logged and looped when renewal failed, while the
        // job kept executing regardless -- it could be re-queued and picked
        // up by another worker while this one was still running `kubectl
        // exec` for it. A lost-renewal signal must cancel the in-flight
        // kubectl invocation promptly instead of letting it run to
        // completion.
        let cancelled = CancelSignal::new();
        let flip_cancelled = cancelled.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flip_cancelled.cancel();
        });

        let started = std::time::Instant::now();
        let error = run_kubectl_command_async(
            "sh",
            &["-c".to_string(), "sleep 30".to_string()],
            None,
            "test slow command",
            Duration::from_secs(60), // Long enough that the timeout branch can't win the race.
            Some(&cancelled),
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
        )
        .await
        .expect_err("a cancelled kubectl invocation must be treated as a failure");
        let elapsed = started.elapsed();

        assert!(
            error.to_string().contains("cancelled"),
            "error should be distinctly reported as a cancellation, got: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the cancelled child should have been killed almost immediately instead of \
             the caller waiting anywhere near its full 30s sleep or 60s timeout; \
             elapsed = {elapsed:?}"
        );
    }

    #[test]
    fn kubernetes_dry_run_reports_k8s_capabilities_and_health() {
        let provider = KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
            None,
        );

        let capabilities = provider.capability_report();
        assert_eq!(capabilities.provider, "kubernetes");
        assert!(
            capabilities
                .capabilities
                .contains(&WorkerCapability::K8sPod)
        );
        assert!(
            capabilities
                .capabilities
                .contains(&WorkerCapability::Snapshot)
        );
        assert!(
            capabilities
                .capabilities
                .contains(&WorkerCapability::AgentPrompt)
        );
        assert_eq!(
            capabilities.labels.get("storage_class").map(String::as_str),
            Some("local-path")
        );

        let health = provider.health_report();
        assert_eq!(health.status, ProviderHealthStatus::Healthy);
        assert_eq!(health.provider, "kubernetes");
    }

    #[test]
    fn kubernetes_dry_run_covers_provider_smoke_path_without_cluster_mutation() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let sandbox_id = SandboxId::new();
        let child_sandbox_id = SandboxId::new();
        let snapshot_id = SnapshotId::new();
        let spec = SandboxProvisionSpec::default();

        let provisioned = provider
            .provision(sandbox_id, &spec)
            .expect("dry-run provision should succeed");
        assert_eq!(provisioned.metadata["mode"], "dry_run");
        assert_eq!(provisioned.metadata["operation"], "provision");
        assert_eq!(
            provisioned.metadata["runtime"]["image"],
            DEFAULT_SANDBOX_GUEST_IMAGE
        );
        assert_eq!(provisioned.metadata["manifests"]["pod"]["kind"], "Pod");
        assert_eq!(
            provisioned.metadata["manifests"]["pod"]["spec"]["containers"][0]["image"],
            DEFAULT_SANDBOX_GUEST_IMAGE
        );
        assert_eq!(
            provisioned.metadata["manifests"]["pod"]["spec"]["securityContext"]["runAsNonRoot"],
            true
        );
        assert_eq!(
            provisioned.metadata["manifests"]["networkPolicy"]["kind"],
            "NetworkPolicy"
        );
        assert_eq!(
            provisioned.metadata["manifests"]["sshService"]["kind"],
            "Service"
        );
        assert_eq!(
            provisioned.metadata["manifests"]["desktopService"]["kind"],
            "Service"
        );

        let exec = provider
            .exec_handoff(
                sandbox_id,
                &spec,
                AgentCommandRequest {
                    argv: vec!["echo".to_string(), "hello".to_string()],
                    cwd: None,
                    env: BTreeMap::new(),
                    timeout_secs: None,
                },
                &CancelSignal::never_cancelled(),
            )
            .expect("dry-run exec should succeed");
        assert_eq!(exec.exit_code, Some(0));
        assert!(exec.stdout.contains("\"operation\":\"exec\""));

        let snapshot = provider
            .create_snapshot(sandbox_id, snapshot_id)
            .expect("dry-run snapshot should succeed");
        assert_eq!(snapshot.metadata["operation"], "snapshot");
        assert_eq!(
            snapshot.metadata["manifests"]["volumeSnapshot"]["kind"],
            "VolumeSnapshot"
        );

        let fork = provider
            .fork(sandbox_id, child_sandbox_id, snapshot_id, &spec)
            .expect("dry-run fork should succeed");
        assert_eq!(fork.metadata["operation"], "fork");
        assert_eq!(fork.provider, "kubernetes");
        assert_eq!(
            fork.metadata["manifests"]["pvc"]["kind"],
            "PersistentVolumeClaim"
        );
        assert_eq!(
            fork.metadata["manifests"]["pvc"]["spec"]["dataSource"]["kind"],
            "VolumeSnapshot"
        );
        assert_eq!(fork.metadata["manifests"]["sshService"]["kind"], "Service");
    }

    #[test]
    fn kubernetes_dry_run_uses_configured_runtime_image() {
        let runtime_image = "ghcr.io/evalops/sandboxwich-ubuntu-dev:sha-test".to_string();
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_runtime_image(Some(runtime_image.clone()));

        let capabilities = provider.capability_report();
        assert_eq!(
            capabilities.labels.get("runtime_image").map(String::as_str),
            Some(runtime_image.as_str())
        );

        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        assert_eq!(
            provisioned.metadata["runtime"]["image"],
            runtime_image.as_str()
        );
        assert_eq!(
            provisioned.metadata["manifests"]["pod"]["spec"]["containers"][0]["image"],
            runtime_image.as_str()
        );
    }

    #[test]
    fn kubernetes_dry_run_uses_configured_workspace_storage() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_workspace_storage(Some("2Gi".to_string()));

        let capabilities = provider.capability_report();
        assert_eq!(
            capabilities
                .labels
                .get("workspace_storage")
                .map(String::as_str),
            Some("2Gi")
        );

        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        assert_eq!(
            provisioned.metadata["manifests"]["pvc"]["spec"]["resources"]["requests"]["storage"],
            "2Gi"
        );
    }

    #[test]
    fn configured_workspace_storage_overrides_non_default_tier_disk_size() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_workspace_storage(Some("20Gi".to_string()));
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::FourG,
            network_egress: NetworkEgress::DenyAll,
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        assert_eq!(
            provisioned.metadata["manifests"]["pvc"]["spec"]["resources"]["requests"]["storage"],
            "20Gi"
        );
    }

    #[test]
    fn kubernetes_dry_run_renders_resource_network_and_runtime_class_controls() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_runtime_class_name(Some("gvisor".to_string()));
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::FourG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "10.0.0.0/8".to_string(),
                }],
            },
        };
        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let pod = &provisioned.metadata["manifests"]["pod"];
        let network_policy = &provisioned.metadata["manifests"]["networkPolicy"];

        assert_eq!(pod["spec"]["runtimeClassName"], "gvisor");
        assert_eq!(
            pod["spec"]["containers"][0]["resources"]["limits"]["memory"],
            "4Gi"
        );
        assert_eq!(
            pod["spec"]["containers"][0]["resources"]["limits"]["cpu"],
            "1"
        );
        assert_eq!(
            provisioned.metadata["manifests"]["pvc"]["spec"]["resources"]["requests"]["storage"],
            "8Gi"
        );
        assert_eq!(
            network_policy["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"],
            "10.0.0.0/8"
        );
        assert_eq!(
            pod["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"][0],
            "ALL"
        );
        assert!(
            provider
                .capability_report()
                .capabilities
                .contains(&WorkerCapability::GvisorSandbox)
        );
    }

    #[test]
    fn kubernetes_dry_run_rejects_host_allow_rules_for_standard_network_policy() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Host,
                    value: "api.example.com".to_string(),
                }],
            },
        };

        let error = provider
            .provision(SandboxId::new(), &spec)
            .expect_err("host allow rules should not silently render deny-all");
        assert!(error.to_string().contains("cannot enforce host allow rule"));
    }

    #[test]
    fn kubernetes_pod_mounts_authorized_keys_secret_by_reference() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_ssh_authorized_keys_secret(Some("sandboxwich-authorized-keys".to_string()));
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let pod = &provisioned.metadata["manifests"]["pod"];

        assert_eq!(
            provisioned.metadata["runtime"]["sshAuthorizedKeysSecret"],
            "sandboxwich-authorized-keys"
        );
        assert!(
            pod["spec"]["containers"][0]["volumeMounts"]
                .as_array()
                .expect("volume mounts should be an array")
                .iter()
                .any(|mount| mount["name"] == "ssh-authorized-keys"
                    && mount["mountPath"] == "/run/sandboxwich/ssh"
                    && mount["readOnly"] == true)
        );
        assert!(
            pod["spec"]["volumes"]
                .as_array()
                .expect("volumes should be an array")
                .iter()
                .any(|volume| volume["name"] == "ssh-authorized-keys"
                    && volume["secret"]["secretName"] == "sandboxwich-authorized-keys"
                    && volume["secret"]["items"][0]["key"] == "authorized_keys")
        );
        assert!(
            !serde_json::to_string(pod)
                .expect("pod manifest should serialize")
                .contains("ssh-rsa")
        );
    }

    #[test]
    fn kubernetes_apply_plan_covers_smoke_and_cleanup_without_mutation() {
        let provider = KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
            Some("local-path-snapshot".to_string()),
        );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());

        assert_eq!(plan.mode, "apply");
        assert_eq!(plan.operation, "smoke");
        assert_eq!(
            plan.apply_args,
            vec![
                "--context",
                "k3s-ci",
                "-n",
                "sandboxwich-ci",
                "apply",
                "-f",
                "-"
            ]
        );
        assert_eq!(
            plan.cleanup_args,
            vec![
                "--context",
                "k3s-ci",
                "-n",
                "sandboxwich-ci",
                "delete",
                "--ignore-not-found=true",
                "-f",
                "-"
            ]
        );
        assert!(plan.apply_manifests.iter().any(|manifest| {
            manifest["kind"] == "VolumeSnapshot"
                && manifest["spec"]["volumeSnapshotClassName"] == "local-path-snapshot"
        }));
        assert!(plan.apply_manifests.iter().any(|manifest| {
            manifest["kind"] == "PersistentVolumeClaim"
                && manifest["spec"]["dataSource"]["kind"] == "VolumeSnapshot"
        }));
        assert!(
            plan.apply_manifests
                .iter()
                .any(|manifest| manifest["kind"] == "Service"
                    && manifest["spec"]["ports"][0]["name"] == "ssh")
        );
        assert_eq!(plan.cleanup_manifests.len(), plan.apply_manifests.len());
        assert!(
            !plan
                .apply_manifests
                .iter()
                .any(|manifest| manifest["kind"] == "Secret")
        );
    }

    #[test]
    fn kubernetes_apply_provider_can_use_in_cluster_service_account() {
        let provider = KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
            None,
        );
        let apply = KubernetesApplyProvider::new(provider, "kubectl")
            .with_kubectl_context(Some("in-cluster".to_string()))
            .with_mutation_gate(true, true);
        let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());

        assert!(!plan.apply_args.iter().any(|arg| arg == "--context"));
        assert_eq!(&plan.apply_args[..2], ["-n", "sandboxwich-ci"]);

        let sandbox_id = SandboxId::new();
        let request = AgentCommandRequest {
            argv: vec!["printf".to_string(), "ok".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            timeout_secs: None,
        };
        let exec_args = apply.exec_args(sandbox_id, &request);

        assert!(!exec_args.iter().any(|arg| arg == "--context"));
        assert_eq!(&exec_args[..2], ["-n", "sandboxwich-ci"]);
        assert!(exec_args.contains(&format!("sandboxwich-{sandbox_id}")));
        assert_eq!(
            &exec_args[exec_args.len() - 2..],
            ["printf".to_string(), "ok".to_string()]
        );
    }

    #[test]
    fn exec_args_never_render_env_values_on_argv() {
        let provider = KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
            None,
        );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let sandbox_id = SandboxId::new();
        let mut env = BTreeMap::new();
        env.insert(
            "SUPER_SECRET_TOKEN".to_string(),
            "sk-do-not-leak-this-value".to_string(),
        );
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        let request = AgentCommandRequest {
            argv: vec!["printf".to_string(), "ok".to_string()],
            cwd: None,
            env,
            timeout_secs: None,
        };

        let exec_args = apply.exec_args(sandbox_id, &request);

        // The secret value (and even the innocuous one) must never appear
        // anywhere on argv, whether as a whole arg or embedded in one --
        // /proc/*/cmdline and any local `ps` visibility would otherwise
        // leak it to every other process on the guest, plus the worker
        // host's own process table.
        assert!(
            !exec_args
                .iter()
                .any(|arg| arg.contains("sk-do-not-leak-this-value")),
            "secret value leaked onto kubectl exec argv: {exec_args:?}"
        );
        assert!(
            !exec_args
                .iter()
                .any(|arg| arg.contains("SUPER_SECRET_TOKEN")),
            "env var name leaked onto kubectl exec argv: {exec_args:?}"
        );
        assert!(
            !exec_args.iter().any(|arg| arg == "env"),
            "must not shell out to `env KEY=VALUE ...` positional args anymore"
        );

        // `-i` must be set so kubectl actually connects the payload stdin.
        assert!(exec_args.contains(&"-i".to_string()));
        assert!(exec_args.contains(&"bash".to_string()));
        // The real command must still be intact at the tail of argv.
        assert_eq!(
            &exec_args[exec_args.len() - 2..],
            ["printf".to_string(), "ok".to_string()]
        );
    }

    #[test]
    fn exec_args_without_env_do_not_request_stdin_or_a_wrapper() {
        let provider = KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
            None,
        );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let request = AgentCommandRequest {
            argv: vec!["printf".to_string(), "ok".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            timeout_secs: None,
        };

        let exec_args = apply.exec_args(SandboxId::new(), &request);

        assert!(!exec_args.contains(&"-i".to_string()));
        assert!(!exec_args.contains(&"bash".to_string()));
        assert!(KubernetesApplyProvider::exec_stdin_payload(&request).is_none());
    }

    #[test]
    fn exec_args_carry_cwd_through_the_env_wrapper_when_both_are_set() {
        let provider = KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
            None,
        );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let mut env = BTreeMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        let request = AgentCommandRequest {
            argv: vec!["pwd".to_string()],
            cwd: Some("/workspace/project".to_string()),
            env,
            timeout_secs: None,
        };

        let exec_args = apply.exec_args(SandboxId::new(), &request);

        assert!(exec_args.contains(&"-i".to_string()));
        assert!(exec_args.iter().any(|arg| arg == "/workspace/project"));
        assert_eq!(exec_args[exec_args.len() - 1], "pwd");
        assert!(!exec_args.iter().any(|arg| arg.contains("FOO=bar")));
    }

    #[test]
    fn exec_stdin_payload_nul_delimits_key_value_pairs() {
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "1".to_string());
        env.insert("B".to_string(), "two".to_string());
        let request = AgentCommandRequest {
            argv: vec!["true".to_string()],
            cwd: None,
            env,
            timeout_secs: None,
        };

        let payload = KubernetesApplyProvider::exec_stdin_payload(&request)
            .expect("non-empty env should produce a stdin payload");
        let text = String::from_utf8(payload).expect("payload should be valid utf-8");
        let entries: Vec<&str> = text.split('\0').filter(|s| !s.is_empty()).collect();

        assert!(entries.contains(&"A=1"));
        assert!(entries.contains(&"B=two"));
    }

    #[test]
    fn kubernetes_apply_gate_requires_explicit_double_opt_in() {
        let missing_flag = KubernetesApplyProvider::validate_apply_gate(false, true)
            .expect_err("missing --confirm-apply should fail");
        assert!(missing_flag.to_string().contains("--confirm-apply"));

        let missing_env = KubernetesApplyProvider::validate_apply_gate(true, false)
            .expect_err("missing mutation env should fail");
        assert!(missing_env.to_string().contains(KUBERNETES_MUTATION_ENV));

        KubernetesApplyProvider::validate_apply_gate(true, true)
            .expect("double opt-in should pass validation");
    }

    #[test]
    fn allow_all_egress_carves_out_control_plane_and_dns_ranges() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::AllowAll,
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let policy = &provisioned.metadata["manifests"]["networkPolicy"];

        assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));

        let egress = policy["spec"]["egress"]
            .as_array()
            .expect("egress should be an array");
        let open_rule = &egress[0]["to"][0]["ipBlock"];
        assert_eq!(open_rule["cidr"], "0.0.0.0/0");
        let except = open_rule["except"]
            .as_array()
            .expect("0.0.0.0/0 rule should carve out control-plane/link-local ranges");
        let except: Vec<&str> = except.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(except.contains(&"169.254.0.0/16"));
        assert!(except.contains(&"10.42.0.0/16"));
        assert!(except.contains(&"10.43.0.0/16"));

        let dns_rule = egress
            .iter()
            .find(|rule| rule["ports"][0]["port"] == 53)
            .expect("a DNS egress rule should always be present");
        assert_eq!(
            dns_rule["to"][0]["podSelector"]["matchLabels"]["k8s-app"],
            "kube-dns"
        );
        assert_eq!(
            dns_rule["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "kube-system"
        );
        let ports: Vec<(String, i64)> = dns_rule["ports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["protocol"].as_str().unwrap().to_string(),
                    p["port"].as_i64().unwrap(),
                )
            })
            .collect();
        assert!(ports.contains(&("UDP".to_string(), 53)));
        assert!(ports.contains(&("TCP".to_string(), 53)));
    }

    #[test]
    fn allowlist_egress_carves_out_control_plane_ranges_contained_within_allowed_cidr() {
        // GH-<egress carve-out fix>: `10.0.0.0/8` fully contains the default
        // k3s pod/service ranges (`10.42.0.0/16`, `10.43.0.0/16`), so an
        // allowlist entry that broad must carve them out via `except` just
        // like `0.0.0.0/0` does -- an allowlist CIDR is not exempt from the
        // carve-out just because it isn't exactly `0.0.0.0/0`.
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "10.0.0.0/8".to_string(),
                }],
            },
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
            .as_array()
            .expect("egress should be an array");

        assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "10.0.0.0/8");
        let except: Vec<&str> = egress[0]["to"][0]["ipBlock"]["except"]
            .as_array()
            .expect("10.0.0.0/8 fully contains the k3s pod/service ranges and must carve them out")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(except.contains(&"10.42.0.0/16"));
        assert!(except.contains(&"10.43.0.0/16"));
        // 169.254.0.0/16 doesn't overlap 10.0.0.0/8 at all, so it must not
        // appear as an (invalid, non-subset) except entry.
        assert!(!except.contains(&"169.254.0.0/16"));

        assert!(
            egress.iter().any(|rule| rule["ports"][0]["port"] == 53),
            "allowlist egress must still include a DNS rule so name resolution keeps working"
        );
    }

    #[test]
    fn allowlist_egress_leaves_disjoint_narrow_cidrs_untouched() {
        // A CIDR that shares no addresses with any excluded range gets no
        // `except` at all -- the carve-out logic must not add irrelevant
        // exceptions.
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "192.168.1.0/24".to_string(),
                }],
            },
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
            .as_array()
            .expect("egress should be an array");

        assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "192.168.1.0/24");
        assert!(egress[0]["to"][0]["ipBlock"]["except"].is_null());
    }

    #[test]
    fn allowlist_egress_rejects_cidr_fully_covered_by_an_excluded_range() {
        // If the allowed CIDR is entirely inside (or equal to) an excluded
        // range, there is nothing left to allow once the carve-out is
        // applied -- k8s NetworkPolicy also requires `except` entries to be
        // a strict subset of `cidr`, so `except == cidr` isn't just
        // pointless, it's invalid. Reject rather than silently exposing the
        // excluded range or producing a broken manifest.
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "169.254.169.0/24".to_string(),
                }],
            },
        };

        let err = provider
            .provision(SandboxId::new(), &spec)
            .expect_err("allowlisting a range fully covered by an excluded CIDR must be rejected");
        assert!(err.to_string().contains("169.254.0.0/16"));
    }

    #[test]
    fn allowlist_egress_rejects_cidr_exactly_equal_to_an_excluded_range() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "10.42.0.0/16".to_string(),
                }],
            },
        };

        provider
            .provision(SandboxId::new(), &spec)
            .expect_err("allowlisting a CIDR identical to an excluded range must be rejected");
    }

    #[test]
    fn allowlist_egress_carves_out_control_plane_ranges_when_wide_open_cidr_is_allowed() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "0.0.0.0/0".to_string(),
                }],
            },
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
            .as_array()
            .expect("egress should be an array");

        assert!(
            !egress[0]["to"][0]["ipBlock"]["except"]
                .as_array()
                .expect("0.0.0.0/0 allowlist entry should carve out control-plane ranges")
                .is_empty()
        );
    }

    #[test]
    fn ipv6_allowlist_cidr_containing_an_ipv6_excluded_range_carves_it_out() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_egress_excluded_cidrs(vec!["fd00:ec2::254/128".to_string()]);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "fd00::/8".to_string(),
                }],
            },
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
            .as_array()
            .expect("egress should be an array");

        assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "fd00::/8");
        let except: Vec<&str> = egress[0]["to"][0]["ipBlock"]["except"]
            .as_array()
            .expect("ipv6 allowlist entry should carve out the overlapping ipv6 excluded range")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(except.contains(&"fd00:ec2::254/128"));
        // The default (ipv4) excluded CIDRs never overlap an ipv6 allow
        // rule, so they must not show up either.
        assert!(!except.contains(&"169.254.0.0/16"));
    }

    #[test]
    fn ipv6_allow_rule_is_unaffected_by_default_ipv4_excluded_cidrs() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::Allowlist {
                rules: vec![sandboxwich_core::NetworkAllowRule {
                    kind: NetworkAllowRuleKind::Cidr,
                    value: "2001:db8::/32".to_string(),
                }],
            },
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
            .as_array()
            .expect("egress should be an array");

        assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "2001:db8::/32");
        assert!(egress[0]["to"][0]["ipBlock"]["except"].is_null());
    }

    #[test]
    fn operator_supplied_egress_excluded_cidrs_merge_with_defaults() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_egress_excluded_cidrs(vec!["172.16.0.0/12".to_string()]);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::AllowAll,
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let except: Vec<&str> = provisioned.metadata["manifests"]["networkPolicy"]["spec"]
            ["egress"][0]["to"][0]["ipBlock"]["except"]
            .as_array()
            .expect("except should be an array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();

        // The operator-supplied CIDR is merged in...
        assert!(except.contains(&"172.16.0.0/12"));
        // ...alongside every default, including the metadata carve-out --
        // an override can never silently drop it.
        assert!(except.contains(&"169.254.0.0/16"));
        assert!(except.contains(&"10.42.0.0/16"));
        assert!(except.contains(&"10.43.0.0/16"));
    }

    #[test]
    fn with_egress_excluded_cidrs_replace_drops_the_defaults() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_egress_excluded_cidrs_replace(vec!["172.16.0.0/12".to_string()]);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::AllowAll,
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let except: Vec<&str> = provisioned.metadata["manifests"]["networkPolicy"]["spec"]
            ["egress"][0]["to"][0]["ipBlock"]["except"]
            .as_array()
            .expect("except should be an array")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();

        assert_eq!(except, vec!["172.16.0.0/12"]);
    }

    #[test]
    fn deny_all_egress_still_renders_no_egress_rules() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::DenyAll,
        };

        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        assert_eq!(
            provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"],
            json!([])
        );
    }

    #[test]
    fn network_policy_renders_ingress_rule_restricted_to_control_plane_pods() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let policy = &provisioned.metadata["manifests"]["networkPolicy"];

        assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));
        let ingress = policy["spec"]["ingress"]
            .as_array()
            .expect("ingress should be an array");
        assert_eq!(ingress.len(), 1);
        let from = &ingress[0]["from"][0];
        assert_eq!(
            from["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "sandboxwich-ci"
        );
        assert_eq!(
            from["podSelector"]["matchLabels"]["app.kubernetes.io/part-of"],
            "sandboxwich"
        );
        let ports: Vec<i64> = ingress[0]["ports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["port"].as_i64().unwrap())
            .collect();
        assert_eq!(ports, vec![2222, 6080, 5900]);
    }

    #[test]
    fn ingress_namespace_and_selector_are_configurable() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_ingress_namespace(Some("sandboxwich-ingress".to_string()))
                .with_ingress_pod_selector(vec![(
                    "app".to_string(),
                    "sandboxwich-proxy".to_string(),
                )]);
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let from =
            &provisioned.metadata["manifests"]["networkPolicy"]["spec"]["ingress"][0]["from"][0];

        assert_eq!(
            from["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "sandboxwich-ingress"
        );
        assert_eq!(
            from["podSelector"]["matchLabels"]["app"],
            "sandboxwich-proxy"
        );
    }

    #[test]
    fn pod_disables_service_account_token_automount_and_sets_ephemeral_storage_limits() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let spec = SandboxProvisionSpec {
            memory_limit: MemoryLimit::FourG,
            network_egress: NetworkEgress::DenyAll,
        };
        let provisioned = provider
            .provision(SandboxId::new(), &spec)
            .expect("dry-run provision should succeed");
        let pod = &provisioned.metadata["manifests"]["pod"];

        assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
        assert_eq!(
            pod["spec"]["containers"][0]["resources"]["requests"]["ephemeral-storage"],
            "2Gi"
        );
        assert_eq!(
            pod["spec"]["containers"][0]["resources"]["limits"]["ephemeral-storage"],
            "2Gi"
        );
    }

    #[test]
    fn vnc_password_secret_is_mounted_as_a_read_only_file_not_an_env_var() {
        // The VNC password must be mounted as a file (mirroring the SSH
        // authorized-keys handling) rather than injected via
        // `secretKeyRef`: pod env vars are visible to anything that can
        // read this pod's spec through the Kubernetes API, not just the
        // process itself.
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_vnc_password_secret(Some("sandboxwich-vnc-password".to_string()));
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let pod = &provisioned.metadata["manifests"]["pod"];
        let env = pod["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env should be an array");

        assert!(
            !env.iter()
                .any(|entry| entry["name"] == "SANDBOXWICH_VNC_PASSWORD"),
            "the raw VNC password must never be injected as a plain env var"
        );
        assert!(env.iter().any(|entry| {
            entry["name"] == "SANDBOXWICH_VNC_PASSWORD_FILE"
                && entry["value"] == "/run/sandboxwich/vnc/vnc-password"
        }));

        let volume_mounts = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should be an array");
        assert!(volume_mounts.iter().any(|mount| {
            mount["name"] == "vnc-password"
                && mount["mountPath"] == "/run/sandboxwich/vnc"
                && mount["readOnly"] == true
        }));

        let volumes = pod["spec"]["volumes"]
            .as_array()
            .expect("volumes should be an array");
        assert!(volumes.iter().any(|volume| {
            volume["name"] == "vnc-password"
                && volume["secret"]["secretName"] == "sandboxwich-vnc-password"
                && volume["secret"]["items"][0]["key"] == "vnc-password"
                && volume["secret"]["items"][0]["path"] == "vnc-password"
        }));
    }

    #[test]
    fn worker_token_is_mounted_as_a_read_only_secret_file_not_an_env_var() {
        // GH-101: mirrors `vnc_password_secret_is_mounted_as_a_read_only_file_not_an_env_var`.
        // The worker-scoped token (GH-64) must never appear as a plain pod
        // env var or on any argv -- only a mounted file, readable solely by
        // whoever can exec into the container or read the volume directly.
        let sandbox_id = SandboxId::new();
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials(
                    "8f14e45f-ceea-467e-adc5-96718431224b",
                    Some("sbw_wtok_supersecret".to_string()),
                );
        let provisioned = provider
            .provision(sandbox_id, &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let pod = &provisioned.metadata["manifests"]["pod"];
        let env = pod["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env should be an array");

        assert!(
            !env.iter()
                .any(|entry| entry["name"] == "SANDBOXWICH_API_TOKEN"),
            "the raw worker token must never be injected as a plain env var"
        );
        assert!(env.iter().any(|entry| {
            entry["name"] == "SANDBOXWICH_API_TOKEN_FILE"
                && entry["value"] == "/run/sandboxwich/token/api-token"
        }));
        assert!(env.iter().any(|entry| {
            entry["name"] == "SANDBOXWICH_WORKER_ID"
                && entry["value"] == "8f14e45f-ceea-467e-adc5-96718431224b"
        }));

        let volume_mounts = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should be an array");
        assert!(volume_mounts.iter().any(|mount| {
            mount["name"] == "worker-token"
                && mount["mountPath"] == "/run/sandboxwich/token"
                && mount["readOnly"] == true
        }));

        let expected_secret_name = format!("sandboxwich-worker-token-{sandbox_id}");
        let volumes = pod["spec"]["volumes"]
            .as_array()
            .expect("volumes should be an array");
        assert!(volumes.iter().any(|volume| {
            volume["name"] == "worker-token"
                && volume["secret"]["secretName"] == expected_secret_name
                && volume["secret"]["items"][0]["key"] == "api-token"
                && volume["secret"]["items"][0]["path"] == "api-token"
        }));

        assert!(
            !serde_json::to_string(pod)
                .expect("pod manifest should serialize")
                .contains("sbw_wtok_supersecret"),
            "the raw token must not appear anywhere in the pod manifest itself"
        );
    }

    #[test]
    fn provision_metadata_redacts_the_worker_token_but_keeps_the_secret_identity() {
        // GH-101 leak regression: provider handle metadata is persisted
        // verbatim by the API into the sandboxes table's `provider_metadata`
        // column and returned to tenant clients on sandbox reads, so the raw
        // token must never appear anywhere in it -- only in the manifest set
        // actually piped to `kubectl apply` stdin. The Secret's identity
        // (kind/name/labels) stays visible so operators can tell which
        // Secret a sandbox uses without seeing its contents.
        let sandbox_id = SandboxId::new();
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials(
                    "8f14e45f-ceea-467e-adc5-96718431224b",
                    Some("sbw_wtok_supersecret".to_string()),
                );
        let provisioned = provider
            .provision(sandbox_id, &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let secret = &provisioned.metadata["manifests"]["workerTokenSecret"];

        assert_eq!(secret["kind"], "Secret");
        assert_eq!(secret["apiVersion"], "v1");
        assert_eq!(secret["type"], "Opaque");
        assert_eq!(secret["stringData"]["api-token"], WORKER_TOKEN_REDACTED);
        assert_eq!(
            secret["metadata"]["name"],
            format!("sandboxwich-worker-token-{sandbox_id}")
        );
        assert_eq!(
            secret["metadata"]["labels"]["sandboxwich.dev/sandbox-id"],
            sandbox_id.to_string()
        );

        assert!(
            !serde_json::to_string(&provisioned.metadata)
                .expect("provision metadata should serialize")
                .contains("sbw_wtok_supersecret"),
            "the raw worker token must not appear anywhere in provision handle metadata"
        );
    }

    #[test]
    fn no_worker_token_wiring_when_credentials_are_not_configured() {
        // Absence of `with_worker_credentials` must not fall back to
        // injecting any token at all (e.g. a tenant-wide one) -- it should
        // behave exactly as it did before GH-101.
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");
        let pod = &provisioned.metadata["manifests"]["pod"];
        let env = pod["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env should be an array");

        assert!(
            !env.iter()
                .any(|entry| entry["name"] == "SANDBOXWICH_API_TOKEN_FILE")
        );
        assert!(
            !env.iter()
                .any(|entry| entry["name"] == "SANDBOXWICH_WORKER_ID")
        );
        assert!(
            !pod["spec"]["volumes"]
                .as_array()
                .expect("volumes should be an array")
                .iter()
                .any(|volume| volume["name"] == "worker-token")
        );
        assert!(provisioned.metadata["manifests"]["workerTokenSecret"].is_null());
    }

    #[test]
    fn with_worker_credentials_clears_configured_token_when_given_none_or_blank() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials("worker-a", Some("sbw_wtok_a".to_string()))
                .with_worker_credentials("worker-a", Some("   ".to_string()));
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");

        assert!(provisioned.metadata["manifests"]["workerTokenSecret"].is_null());
    }

    #[test]
    fn fork_child_pod_gets_its_own_worker_token_secret_scoped_to_the_child_sandbox() {
        let parent_sandbox_id = SandboxId::new();
        let child_sandbox_id = SandboxId::new();
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials(
                    "8f14e45f-ceea-467e-adc5-96718431224b",
                    Some("sbw_wtok_supersecret".to_string()),
                );
        let forked = provider
            .fork(
                parent_sandbox_id,
                child_sandbox_id,
                SnapshotId::new(),
                &SandboxProvisionSpec::default(),
            )
            .expect("dry-run fork should succeed");

        let secret = &forked.metadata["manifests"]["workerTokenSecret"];
        assert_eq!(
            secret["metadata"]["name"],
            format!("sandboxwich-worker-token-{child_sandbox_id}")
        );
        // Fork handle metadata is persisted/served by the API exactly like
        // provision metadata, so it carries the redacted rendering only.
        assert_eq!(secret["stringData"]["api-token"], WORKER_TOKEN_REDACTED);
        assert!(
            !serde_json::to_string(&forked.metadata)
                .expect("fork metadata should serialize")
                .contains("sbw_wtok_supersecret"),
            "the raw worker token must not appear anywhere in fork handle metadata"
        );

        let pod = &forked.metadata["manifests"]["pod"];
        assert!(
            pod["spec"]["volumes"]
                .as_array()
                .expect("volumes should be an array")
                .iter()
                .any(|volume| volume["name"] == "worker-token"
                    && volume["secret"]["secretName"]
                        == format!("sandboxwich-worker-token-{child_sandbox_id}"))
        );
    }

    #[test]
    fn apply_provision_manifests_apply_the_worker_token_secret_before_the_pod_that_mounts_it() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials(
                    "8f14e45f-ceea-467e-adc5-96718431224b",
                    Some("sbw_wtok_supersecret".to_string()),
                );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let sandbox_id = SandboxId::new();

        let manifests = apply
            .provision_manifests(sandbox_id, &SandboxProvisionSpec::default())
            .expect("manifests should render");

        let secret_index = manifests
            .iter()
            .position(|manifest| manifest["kind"] == "Secret")
            .expect("a Secret manifest should be included when worker credentials are configured");
        let pod_index = manifests
            .iter()
            .position(|manifest| manifest["kind"] == "Pod")
            .expect("a Pod manifest should always be included");
        assert!(
            secret_index < pod_index,
            "the Secret should be applied before the Pod that mounts it"
        );
        assert_eq!(
            manifests[secret_index]["stringData"]["api-token"],
            "sbw_wtok_supersecret"
        );
    }

    #[test]
    fn apply_fork_manifests_include_a_worker_token_secret_for_the_child_sandbox() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials(
                    "8f14e45f-ceea-467e-adc5-96718431224b",
                    Some("sbw_wtok_supersecret".to_string()),
                );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let child_sandbox_id = SandboxId::new();

        let manifests = apply
            .fork_manifests(
                child_sandbox_id,
                SnapshotId::new(),
                &SandboxProvisionSpec::default(),
            )
            .expect("manifests should render");

        assert!(manifests.iter().any(|manifest| {
            manifest["kind"] == "Secret"
                && manifest["metadata"]["name"]
                    == format!("sandboxwich-worker-token-{child_sandbox_id}")
        }));
    }

    #[test]
    fn smoke_plan_never_contains_the_raw_worker_token() {
        // The smoke plan is serialized wholesale to stdout/logs by
        // `provider-apply-plan`/`provider-apply-smoke`, so even a provider
        // configured with worker credentials must not leak the raw token
        // through it (the plan deliberately omits the worker-token Secret;
        // pod manifests reference it by name only).
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_worker_credentials(
                    "8f14e45f-ceea-467e-adc5-96718431224b",
                    Some("sbw_wtok_supersecret".to_string()),
                );
        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());

        let serialized = serde_json::to_string(&plan).expect("smoke plan should serialize");
        assert!(
            !serialized.contains("sbw_wtok_supersecret"),
            "the raw worker token must not appear anywhere in the serialized smoke plan"
        );
        assert!(
            !plan
                .apply_manifests
                .iter()
                .any(|manifest| manifest["kind"] == "Secret"),
            "the smoke plan must not include the worker-token Secret manifest at all"
        );
    }

    #[test]
    fn teardown_resource_kinds_include_secret_so_worker_token_secrets_are_cleaned_up() {
        assert!(
            SANDBOX_TEARDOWN_RESOURCE_KINDS
                .split(',')
                .any(|kind| kind == "secret"),
            "the per-sandbox worker-token Secret must be torn down alongside the pod that \
             mounts it, or it will be leaked on every sandbox stop"
        );
    }

    #[test]
    fn sandbox_namespace_override_places_all_sandbox_resources_in_dedicated_namespace() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich", None, None)
                .with_sandbox_namespace(Some("sandboxwich-sandboxes".to_string()));
        let provisioned = provider
            .provision(SandboxId::new(), &SandboxProvisionSpec::default())
            .expect("dry-run provision should succeed");

        assert_eq!(provisioned.metadata["namespace"], "sandboxwich-sandboxes");
        assert_eq!(provisioned.metadata["controlPlaneNamespace"], "sandboxwich");
        assert_eq!(
            provisioned.metadata["manifests"]["pod"]["metadata"]["namespace"],
            "sandboxwich-sandboxes"
        );
        assert_eq!(
            provisioned.metadata["manifests"]["networkPolicy"]["metadata"]["namespace"],
            "sandboxwich-sandboxes"
        );
        assert!(
            provisioned
                .resources
                .iter()
                .all(|resource| resource.namespace == "sandboxwich-sandboxes")
        );

        let apply = KubernetesApplyProvider::new(provider, "kubectl");
        let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());
        assert!(
            plan.apply_args
                .contains(&"sandboxwich-sandboxes".to_string())
        );
        assert!(!plan.apply_args.contains(&"sandboxwich".to_string()));
    }

    #[test]
    fn teardown_args_delete_every_labeled_resource_kind_scoped_to_namespace() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let apply = KubernetesApplyProvider::new(provider, "kubectl")
            .with_kubectl_context(Some("k3s-ci".to_string()))
            .with_mutation_gate(true, true);
        let sandbox_id = SandboxId::new();

        let args = apply.teardown_args(sandbox_id);

        assert_eq!(
            args,
            vec![
                "--context".to_string(),
                "k3s-ci".to_string(),
                "-n".to_string(),
                "sandboxwich-ci".to_string(),
                "delete".to_string(),
                SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string(),
                "-l".to_string(),
                format!("sandboxwich.dev/sandbox-id={sandbox_id}"),
                "--ignore-not-found=true".to_string(),
            ]
        );
    }

    #[test]
    fn teardown_args_omit_context_flag_for_in_cluster_service_account() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let apply = KubernetesApplyProvider::new(provider, "kubectl")
            .with_kubectl_context(Some("in-cluster".to_string()))
            .with_mutation_gate(true, true);

        let args = apply.teardown_args(SandboxId::new());

        assert!(!args.iter().any(|arg| arg == "--context"));
        assert_eq!(args[0], "-n");
        assert!(args.contains(&SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string()));
    }

    #[test]
    fn stop_refuses_to_mutate_without_confirm_apply_gate() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let apply = KubernetesApplyProvider::new(provider, "kubectl");

        let error = apply
            .stop(SandboxId::new())
            .expect_err("stop without the mutation gate should fail closed");
        assert!(error.to_string().contains("--confirm-apply"));
    }

    #[test]
    fn dry_run_stop_is_a_successful_no_op() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);

        provider
            .stop(SandboxId::new())
            .expect("dry-run stop should never fail");
    }

    #[test]
    fn cap_output_bytes_passes_through_short_output_unchanged() {
        let text = "hello world";
        assert_eq!(cap_output_bytes(text.as_bytes(), 1024), text);
        // A cap exactly equal to the byte length is still "no truncation".
        assert_eq!(cap_output_bytes(text.as_bytes(), text.len() as u64), text);
    }

    #[test]
    fn cap_output_bytes_truncates_and_marks_omitted_byte_count() {
        let text = "0123456789";
        let capped = cap_output_bytes(text.as_bytes(), 4);

        assert!(capped.starts_with("0123"));
        assert!(
            capped.contains("[truncated 6 bytes]"),
            "expected a marker noting the 6 omitted bytes, got: {capped:?}"
        );
    }

    /// Writes an executable fake `kubectl` script to a fresh temp directory,
    /// returning `(script_path, log_path)`. The script:
    /// - appends every invocation's space-joined argv as one line to `log_path`
    ///   (bracketed with leading/trailing spaces so tests can match whole
    ///   tokens like " delete " without false positives on substrings), and
    /// - drains stdin for the "apply" verb, mirroring how
    ///   `run_kubectl_documents` actually pipes manifests in via stdin so the
    ///   real caller's `write_all` doesn't block on a full pipe;
    /// - exits non-zero if `fail_verb` is present in argv, and zero otherwise.
    ///
    /// This lets rollback behavior be exercised end-to-end (provision/fork
    /// calling through to a real rollback `kubectl delete`) without requiring
    /// a real cluster or kubectl binary.
    fn write_fake_kubectl(
        fail_verb: Option<&'static str>,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("sandboxwich-fake-kubectl-{}", SandboxId::new()));
        std::fs::create_dir_all(&dir).expect("create fake kubectl temp dir");
        let log_path = dir.join("log.txt");
        let fail_check = match fail_verb {
            Some(verb) => format!("case \" $* \" in *\" {verb} \"*) exit 1 ;; esac\n"),
            None => String::new(),
        };
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             case \" $* \" in\n\
             \x20\x20*\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
             esac\n\
             {fail_check}exit 0\n",
            log = log_path.display(),
        );
        let script_path = dir.join("kubectl");
        std::fs::write(&script_path, script).expect("write fake kubectl script");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path)
                .expect("stat fake kubectl script")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl script");
        }
        (script_path, log_path)
    }

    fn apply_provider_with_fake_kubectl(kubectl: &std::path::Path) -> KubernetesApplyProvider {
        let dry_run =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
            .with_kubectl_context(Some("in-cluster".to_string()))
            .with_mutation_gate(true, true)
    }

    #[test]
    fn provision_rolls_back_applied_resources_when_pod_never_becomes_ready() {
        let (kubectl, log_path) = write_fake_kubectl(Some("wait"));
        let provider = apply_provider_with_fake_kubectl(&kubectl);
        let sandbox_id = SandboxId::new();

        let error = provider
            .provision(sandbox_id, &SandboxProvisionSpec::default())
            .expect_err("a pod that never becomes ready should fail provision");
        assert!(error.to_string().contains("did not become ready"));

        let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
        assert!(
            log.contains(" apply "),
            "expected an apply invocation, got: {log}"
        );
        assert!(
            log.contains(" wait "),
            "expected a wait invocation, got: {log}"
        );
        assert!(
            log.contains(" delete "),
            "expected a rollback delete invocation after the failed wait, got: {log}"
        );
        assert!(
            log.contains(&format!("sandboxwich.dev/sandbox-id={sandbox_id}")),
            "rollback delete should be scoped to the sandbox that failed to provision, got: {log}"
        );

        let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
    }

    #[test]
    fn provision_rolls_back_applied_resources_when_apply_itself_fails() {
        // kubectl apply -f - with multiple documents is not atomic: some objects
        // can already exist by the time the command as a whole reports failure.
        let (kubectl, log_path) = write_fake_kubectl(Some("apply"));
        let provider = apply_provider_with_fake_kubectl(&kubectl);
        let sandbox_id = SandboxId::new();

        let error = provider
            .provision(sandbox_id, &SandboxProvisionSpec::default())
            .expect_err("a failing kubectl apply should fail provision");
        assert!(error.to_string().contains("kubectl apply"));

        let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
        assert!(
            log.contains(" delete "),
            "expected a rollback delete invocation after the failed apply, got: {log}"
        );
        assert!(log.contains(&format!("sandboxwich.dev/sandbox-id={sandbox_id}")));

        let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
    }

    #[test]
    fn fork_rolls_back_applied_resources_when_child_pod_never_becomes_ready() {
        let (kubectl, log_path) = write_fake_kubectl(Some("wait"));
        let provider = apply_provider_with_fake_kubectl(&kubectl);
        let parent_sandbox_id = SandboxId::new();
        let child_sandbox_id = SandboxId::new();
        let snapshot_id = SnapshotId::new();

        let error = provider
            .fork(
                parent_sandbox_id,
                child_sandbox_id,
                snapshot_id,
                &SandboxProvisionSpec::default(),
            )
            .expect_err("a forked pod that never becomes ready should fail fork");
        assert!(error.to_string().contains("did not become ready"));

        let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
        assert!(
            log.contains(" delete "),
            "expected a rollback delete invocation for the fork, got: {log}"
        );
        assert!(
            log.contains(&format!("sandboxwich.dev/sandbox-id={child_sandbox_id}")),
            "rollback should be scoped to the child sandbox id (the one that was actually \
             applied for the fork), got: {log}"
        );
        assert!(
            !log.contains(&format!("sandboxwich.dev/sandbox-id={parent_sandbox_id}")),
            "rollback must not touch the parent sandbox's resources, got: {log}"
        );

        let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
    }

    #[test]
    fn successful_provision_does_not_trigger_any_rollback_delete() {
        let (kubectl, log_path) = write_fake_kubectl(None);
        let provider = apply_provider_with_fake_kubectl(&kubectl);
        let sandbox_id = SandboxId::new();

        provider
            .provision(sandbox_id, &SandboxProvisionSpec::default())
            .expect("apply and wait both succeeding should provision successfully");

        let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
        assert!(log.contains(" apply "));
        assert!(log.contains(" wait "));
        assert!(
            !log.contains(" delete "),
            "a successful provision must not roll anything back, got: {log}"
        );

        let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
    }

    /// Like `write_fake_kubectl`, but the "wait" verb also writes `stdout_bytes`
    /// bytes of `x` to stdout before exiting 0. Used to exercise the byte cap
    /// end-to-end through `provision`'s real kubectl-invocation plumbing rather
    /// than just unit-testing `cap_output_bytes` in isolation.
    fn write_fake_kubectl_with_wait_stdout(
        stdout_bytes: usize,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("sandboxwich-fake-kubectl-{}", SandboxId::new()));
        std::fs::create_dir_all(&dir).expect("create fake kubectl temp dir");
        let log_path = dir.join("log.txt");
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             case \" $* \" in\n\
             \x20\x20*\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
             esac\n\
             case \" $* \" in\n\
             \x20\x20*\" wait \"*) head -c {stdout_bytes} /dev/zero | tr '\\0' 'x' ;;\n\
             esac\n\
             exit 0\n",
            log = log_path.display(),
        );
        let script_path = dir.join("kubectl");
        std::fs::write(&script_path, script).expect("write fake kubectl script");
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path)
                .expect("stat fake kubectl script")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl script");
        }
        (script_path, log_path)
    }

    #[test]
    fn kubectl_output_is_capped_at_the_configured_byte_limit() {
        let (kubectl, _log_path) = write_fake_kubectl_with_wait_stdout(1024);
        let dry_run =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
        let provider =
            KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
                .with_kubectl_context(Some("in-cluster".to_string()))
                .with_mutation_gate(true, true)
                .with_max_captured_output_bytes(16);
        let sandbox_id = SandboxId::new();

        let handle = provider
            .provision(sandbox_id, &SandboxProvisionSpec::default())
            .expect("provision against the fake kubectl should succeed");

        let wait_stdout = handle.metadata["waitStdout"]
            .as_str()
            .expect("waitStdout should be a string");
        // 1024 bytes of "x" produced by the fake kubectl must be capped well
        // below that, with a marker noting how much was cut.
        assert!(
            wait_stdout.len() < 1024,
            "expected captured waitStdout to be capped, got {} bytes",
            wait_stdout.len()
        );
        assert!(
            wait_stdout.contains("[truncated 1008 bytes]"),
            "expected a truncation marker for the omitted bytes, got: {wait_stdout:?}"
        );

        let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
    }
}
