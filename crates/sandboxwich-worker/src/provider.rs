use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, bail};
use chrono::Utc;
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, MemoryLimit, NetworkAllowRuleKind, NetworkEgress,
    ProviderCapabilityReport, ProviderForkHandle, ProviderHealthReport, ProviderHealthStatus,
    ProviderRuntimeResource, ProviderSandboxHandle, ProviderSnapshotHandle, RuntimeResourceKind,
    RuntimeResourcePurpose, RuntimeResourceStatus, SandboxId, SandboxProvisionSpec, SnapshotId,
    WorkerCapability,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

pub const KUBERNETES_MUTATION_ENV: &str = "SANDBOXWICH_K8S_ENABLE_MUTATION";
pub const DEFAULT_SANDBOX_GUEST_IMAGE: &str = "ghcr.io/evalops/sandboxwich-ubuntu-dev:latest";

/// Kubernetes resource kinds (as a `kubectl get/delete` type list) that carry the
/// `sandboxwich.dev/sandbox-id` label and must be torn down when a sandbox is stopped.
pub const SANDBOX_TEARDOWN_RESOURCE_KINDS: &str = "pod,persistentvolumeclaim,service,networkpolicy";

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

    fn labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::from([
            ("cluster".to_string(), self.cluster.clone()),
            ("namespace".to_string(), self.namespace.clone()),
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
            "namespace": self.namespace,
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
                "networkPolicy": network_policy
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
        if let NetworkEgress::Allowlist { rules } = network_egress {
            if let Some(rule) = rules
                .iter()
                .find(|rule| rule.kind == NetworkAllowRuleKind::Host)
            {
                bail!(
                    "standard Kubernetes NetworkPolicy cannot enforce host allow rule {}; use cidr allow rules or a provider with FQDN egress support",
                    rule.value
                );
            }
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
            "namespace": self.namespace,
            "labels": labels
        })
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

        let mut pod_spec = Map::from_iter([
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
                            "memory": spec.memory_limit.memory_quantity()
                        },
                        "limits": {
                            "cpu": spec.memory_limit.cpu_limit(),
                            "memory": spec.memory_limit.memory_quantity()
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

    fn network_policy_manifest(
        &self,
        sandbox_id: SandboxId,
        network_egress: &NetworkEgress,
    ) -> anyhow::Result<serde_json::Value> {
        Self::validate_network_policy_egress(network_egress)?;
        let egress = match network_egress {
            NetworkEgress::DenyAll => Vec::new(),
            NetworkEgress::AllowAll => vec![json!({})],
            NetworkEgress::Allowlist { rules } => rules
                .iter()
                .filter(|rule| rule.kind == NetworkAllowRuleKind::Cidr)
                .map(|rule| {
                    json!({
                        "to": [{
                            "ipBlock": {
                                "cidr": rule.value
                            }
                        }]
                    })
                })
                .collect(),
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
                "policyTypes": ["Egress"],
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
            namespace: self.namespace.clone(),
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
                },
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
            namespace: self.dry_run.namespace.clone(),
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
        args.extend(["-n".to_string(), self.dry_run.namespace.clone()]);
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
        Ok(vec![
            self.dry_run.pvc_manifest(
                format!("sandboxwich-pvc-{sandbox_id}"),
                Some(sandbox_id),
                &spec.memory_limit,
            ),
            self.dry_run.pod_manifest(sandbox_id, spec),
            self.dry_run
                .network_policy_manifest(sandbox_id, &spec.network_egress)?,
            self.dry_run.ssh_service_manifest(sandbox_id),
            self.dry_run.desktop_service_manifest(sandbox_id),
        ])
    }

    fn wait_for_pod_ready(&self, sandbox_id: SandboxId) -> anyhow::Result<KubectlOutput> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "wait".to_string(),
            "--for=condition=Ready".to_string(),
            format!("pod/{}", self.pod_name(sandbox_id)),
            "--timeout=120s".to_string(),
        ]);
        run_kubectl_command(&self.kubectl, &args, "wait for sandbox pod readiness")
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
        let output = run_kubectl_command(&self.kubectl, &args, "check sandbox pod existence")?;
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

    fn exec_args(&self, sandbox_id: SandboxId, request: &AgentCommandRequest) -> Vec<String> {
        let mut args = self.kubectl_base_args();
        args.extend([
            "exec".to_string(),
            self.pod_name(sandbox_id),
            "--".to_string(),
        ]);

        if request.cwd.is_some() || !request.env.is_empty() {
            if !request.env.is_empty() {
                args.push("env".to_string());
                for (key, value) in &request.env {
                    args.push(format!("{key}={value}"));
                }
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
        }

        args.extend(request.argv.clone());
        args
    }
}

struct KubectlOutput {
    success: bool,
    code: Option<i32>,
    status: String,
    stdout: String,
    stderr: String,
}

fn run_kubectl_documents(
    kubectl: &str,
    args: &[String],
    manifests: &[Value],
    context: &'static str,
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
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    Ok(KubectlOutput {
        success: output.status.success(),
        code: output.status.code(),
        status: output.status.to_string(),
        stdout,
        stderr,
    })
}

fn run_kubectl_command(
    kubectl: &str,
    args: &[String],
    context: &'static str,
) -> anyhow::Result<KubectlOutput> {
    let output = Command::new(kubectl)
        .args(args)
        .output()
        .with_context(|| format!("failed to run kubectl for {context}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    Ok(KubectlOutput {
        success: output.status.success(),
        code: output.status.code(),
        status: output.status.to_string(),
        stdout,
        stderr,
    })
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
                "namespace": self.namespace,
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
                "namespace": self.namespace,
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
                    "networkPolicy": network_policy
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
        )?;
        if !apply.success {
            bail!(
                "kubectl apply sandbox manifests failed with {}: {}",
                apply.status,
                apply.stderr
            );
        }
        let wait = self.wait_for_pod_ready(sandbox_id)?;
        if !wait.success {
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
    ) -> anyhow::Result<AgentCommandResult> {
        // Only provision when the pod is actually missing. Re-applying the full
        // manifest set (and re-waiting up to 120s) before every command is both slow
        // and unsafe: Pod `resources` are immutable, so an exec whose spec drifts from
        // the original provisioning would otherwise hard-fail every subsequent command.
        if !self.pod_exists(sandbox_id)? {
            self.provision(sandbox_id, spec)?;
        }
        let started_at = Utc::now();
        let output = run_kubectl_command(
            &self.kubectl,
            &self.exec_args(sandbox_id, &request),
            "execute sandbox command",
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
        let network_policy = self
            .dry_run
            .network_policy_manifest(child_sandbox_id, &spec.network_egress)?;
        let manifests = vec![
            self.dry_run
                .fork_pvc_manifest(child_sandbox_id, snapshot_id, &spec.memory_limit),
            self.dry_run.pod_manifest(child_sandbox_id, spec),
            network_policy,
            self.dry_run.ssh_service_manifest(child_sandbox_id),
            self.dry_run.desktop_service_manifest(child_sandbox_id),
        ];
        let apply = run_kubectl_documents(
            &self.kubectl,
            &self.kubectl_args("apply"),
            &manifests,
            "apply fork manifests",
        )?;
        if !apply.success {
            bail!(
                "kubectl apply fork manifests failed with {}: {}",
                apply.status,
                apply.stderr
            );
        }
        let wait = self.wait_for_pod_ready(child_sandbox_id)?;
        if !wait.success {
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
        let output = run_kubectl_command(&self.kubectl, &args, "delete sandbox resources")?;
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
                },
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
}
