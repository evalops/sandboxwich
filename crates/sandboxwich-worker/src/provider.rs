use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, bail};
use chrono::Utc;
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, ProviderCapabilityReport, ProviderForkHandle,
    ProviderHealthReport, ProviderHealthStatus, ProviderSandboxHandle, ProviderSnapshotHandle,
    SandboxId, SnapshotId, WorkerCapability,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

pub const KUBERNETES_MUTATION_ENV: &str = "SANDBOXWICH_K8S_ENABLE_MUTATION";
pub const DEFAULT_SANDBOX_GUEST_IMAGE: &str = "ghcr.io/evalops/sandboxwich-ubuntu-dev:latest";

pub trait SandboxProvider {
    fn capability_report(&self) -> ProviderCapabilityReport;
    fn health_report(&self) -> ProviderHealthReport;
    fn provision(&self, sandbox_id: SandboxId) -> ProviderSandboxHandle;
    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        request: AgentCommandRequest,
    ) -> AgentCommandResult;
    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> ProviderSnapshotHandle;
    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> ProviderForkHandle;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesDryRunProvider {
    cluster: String,
    namespace: String,
    storage_class: Option<String>,
    snapshot_class: Option<String>,
    runtime_image: String,
    ssh_authorized_keys_secret: Option<String>,
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
            ssh_authorized_keys_secret: None,
        }
    }

    pub fn with_runtime_image(mut self, image: Option<String>) -> Self {
        if let Some(image) = image {
            self.runtime_image = image;
        }
        self
    }

    pub fn with_ssh_authorized_keys_secret(mut self, secret: Option<String>) -> Self {
        self.ssh_authorized_keys_secret = secret;
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
        if let Some(secret) = &self.ssh_authorized_keys_secret {
            labels.insert("ssh_authorized_keys_secret".to_string(), secret.clone());
        }
        labels
    }

    fn metadata(&self, sandbox_id: SandboxId, operation: &'static str) -> serde_json::Value {
        json!({
            "provider": "kubernetes",
            "mode": "dry_run",
            "operation": operation,
            "cluster": self.cluster,
            "namespace": self.namespace,
            "sandboxId": sandbox_id,
            "podName": format!("sandboxwich-{}", sandbox_id),
            "storageClass": self.storage_class,
            "snapshotClass": self.snapshot_class,
            "runtime": self.runtime_metadata(),
            "manifests": {
                "pod": self.pod_manifest(sandbox_id),
                "pvc": self.pvc_manifest(format!("sandboxwich-pvc-{sandbox_id}")),
                "sshService": self.ssh_service_manifest(sandbox_id),
                "desktopService": self.desktop_service_manifest(sandbox_id)
            }
        })
    }

    fn runtime_metadata(&self) -> serde_json::Value {
        json!({
            "image": self.runtime_image,
            "workspaceMount": "/workspace",
            "sshPort": 22,
            "desktopPort": 6080,
            "sshAuthorizedKeysSecret": self.ssh_authorized_keys_secret,
            "sshAuthorizedKeysSecretKey": "authorized_keys"
        })
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

    fn pod_manifest(&self, sandbox_id: SandboxId) -> serde_json::Value {
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
        let mut env = vec![json!({
            "name": "SANDBOXWICH_WORKSPACE",
            "value": "/workspace"
        })];

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

        json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": self.object_metadata(format!("sandboxwich-{sandbox_id}"), Some(sandbox_id)),
            "spec": {
                "containers": [{
                    "name": "sandbox",
                    "image": self.runtime_image,
                    "ports": [
                        {"name": "ssh", "containerPort": 22},
                        {"name": "desktop", "containerPort": 6080}
                    ],
                    "env": env,
                    "volumeMounts": volume_mounts
                }],
                "volumes": volumes
            }
        })
    }

    fn pvc_manifest(&self, name: String) -> serde_json::Value {
        let mut spec = Map::from_iter([
            ("accessModes".to_string(), json!(["ReadWriteOnce"])),
            (
                "resources".to_string(),
                json!({
                    "requests": {
                        "storage": "40Gi"
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
            "metadata": self.object_metadata(name, None),
            "spec": spec
        })
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
    ) -> serde_json::Value {
        let mut spec = Map::from_iter([
            ("accessModes".to_string(), json!(["ReadWriteOnce"])),
            (
                "resources".to_string(),
                json!({
                    "requests": {
                        "storage": "40Gi"
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
}

impl KubernetesApplyProvider {
    pub fn new(dry_run: KubernetesDryRunProvider, kubectl: impl Into<String>) -> Self {
        Self {
            dry_run,
            kubectl: kubectl.into(),
        }
    }

    pub fn smoke_plan(
        &self,
        sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> KubernetesApplyPlan {
        let provision_pvc = self
            .dry_run
            .pvc_manifest(format!("sandboxwich-pvc-{sandbox_id}"));
        let provision_pod = self.dry_run.pod_manifest(sandbox_id);
        let provision_ssh_service = self.dry_run.ssh_service_manifest(sandbox_id);
        let provision_service = self.dry_run.desktop_service_manifest(sandbox_id);
        let snapshot = self
            .dry_run
            .volume_snapshot_manifest(sandbox_id, snapshot_id);
        let fork_pvc = self
            .dry_run
            .fork_pvc_manifest(child_sandbox_id, snapshot_id);
        let fork_pod = self.dry_run.pod_manifest(child_sandbox_id);
        let fork_ssh_service = self.dry_run.ssh_service_manifest(child_sandbox_id);
        let fork_service = self.dry_run.desktop_service_manifest(child_sandbox_id);
        let exec_handoff = self.dry_run.exec_handoff(
            sandbox_id,
            AgentCommandRequest {
                argv: vec!["echo".to_string(), "sandboxwich".to_string()],
                cwd: None,
                env: BTreeMap::new(),
            },
        );
        let apply_manifests = vec![
            provision_pvc.clone(),
            provision_pod.clone(),
            provision_ssh_service.clone(),
            provision_service.clone(),
            snapshot.clone(),
            fork_pvc.clone(),
            fork_pod.clone(),
            fork_ssh_service.clone(),
            fork_service.clone(),
        ];
        let cleanup_manifests = vec![
            fork_service,
            fork_ssh_service,
            fork_pod,
            fork_pvc,
            snapshot,
            provision_service,
            provision_ssh_service,
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
        vec![
            "--context".to_string(),
            self.dry_run.cluster.clone(),
            "-n".to_string(),
            self.dry_run.namespace.clone(),
            verb.to_string(),
            "-f".to_string(),
            "-".to_string(),
        ]
    }

    fn kubectl_delete_args(&self) -> Vec<String> {
        vec![
            "--context".to_string(),
            self.dry_run.cluster.clone(),
            "-n".to_string(),
            self.dry_run.namespace.clone(),
            "delete".to_string(),
            "--ignore-not-found=true".to_string(),
            "-f".to_string(),
            "-".to_string(),
        ]
    }
}

struct KubectlOutput {
    success: bool,
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

impl SandboxProvider for KubernetesDryRunProvider {
    fn capability_report(&self) -> ProviderCapabilityReport {
        ProviderCapabilityReport {
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::K8sPod,
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
                WorkerCapability::AgentPrompt,
                WorkerCapability::Snapshot,
                WorkerCapability::DesktopStream,
            ],
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

    fn provision(&self, sandbox_id: SandboxId) -> ProviderSandboxHandle {
        ProviderSandboxHandle {
            provider: "kubernetes".to_string(),
            sandbox_id,
            metadata: self.metadata(sandbox_id, "provision"),
        }
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        request: AgentCommandRequest,
    ) -> AgentCommandResult {
        let started_at = Utc::now();
        let finished_at = Utc::now();
        AgentCommandResult {
            exit_code: Some(0),
            stdout: serde_json::to_string(&json!({
                "provider": "kubernetes",
                "mode": "dry_run",
                "operation": "exec",
                "sandboxId": sandbox_id,
                "argv": request.argv,
                "cwd": request.cwd,
                "envKeys": request.env.keys().collect::<Vec<_>>()
            }))
            .unwrap_or_else(|_| "{}".to_string()),
            stderr: String::new(),
            started_at,
            finished_at,
        }
    }

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> ProviderSnapshotHandle {
        ProviderSnapshotHandle {
            provider: "kubernetes".to_string(),
            snapshot_id,
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
        }
    }

    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
    ) -> ProviderForkHandle {
        ProviderForkHandle {
            provider: "kubernetes".to_string(),
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
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
                "manifests": {
                    "pvc": self.fork_pvc_manifest(child_sandbox_id, snapshot_id),
                    "pod": self.pod_manifest(child_sandbox_id),
                    "sshService": self.ssh_service_manifest(child_sandbox_id),
                    "desktopService": self.desktop_service_manifest(child_sandbox_id)
                }
            }),
        }
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

        let provisioned = provider.provision(sandbox_id);
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
            provisioned.metadata["manifests"]["sshService"]["kind"],
            "Service"
        );
        assert_eq!(
            provisioned.metadata["manifests"]["desktopService"]["kind"],
            "Service"
        );

        let exec = provider.exec_handoff(
            sandbox_id,
            AgentCommandRequest {
                argv: vec!["echo".to_string(), "hello".to_string()],
                cwd: None,
                env: BTreeMap::new(),
            },
        );
        assert_eq!(exec.exit_code, Some(0));
        assert!(exec.stdout.contains("\"operation\":\"exec\""));

        let snapshot = provider.create_snapshot(sandbox_id, snapshot_id);
        assert_eq!(snapshot.metadata["operation"], "snapshot");
        assert_eq!(
            snapshot.metadata["manifests"]["volumeSnapshot"]["kind"],
            "VolumeSnapshot"
        );

        let fork = provider.fork(sandbox_id, child_sandbox_id, snapshot_id);
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

        let provisioned = provider.provision(SandboxId::new());
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
    fn kubernetes_pod_mounts_authorized_keys_secret_by_reference() {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_ssh_authorized_keys_secret(Some("sandboxwich-authorized-keys".to_string()));
        let provisioned = provider.provision(SandboxId::new());
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
}
