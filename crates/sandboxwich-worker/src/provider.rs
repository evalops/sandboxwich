use std::collections::BTreeMap;

use chrono::Utc;
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, ProviderCapabilityReport, ProviderForkHandle,
    ProviderHealthReport, ProviderHealthStatus, ProviderSandboxHandle, ProviderSnapshotHandle,
    SandboxId, SnapshotId, WorkerCapability,
};
use serde_json::json;

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
}

impl KubernetesDryRunProvider {
    pub fn new(
        cluster: impl Into<String>,
        namespace: impl Into<String>,
        storage_class: Option<String>,
    ) -> Self {
        Self {
            cluster: cluster.into(),
            namespace: namespace.into(),
            storage_class,
        }
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
            "storageClass": self.storage_class
        })
    }
}

impl SandboxProvider for KubernetesDryRunProvider {
    fn capability_report(&self) -> ProviderCapabilityReport {
        ProviderCapabilityReport {
            provider: "kubernetes".to_string(),
            capabilities: vec![
                WorkerCapability::K8sPod,
                WorkerCapability::ProvisionSandbox,
                WorkerCapability::RunCommand,
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
                "storageClass": self.storage_class
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
                "storageClass": self.storage_class
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_dry_run_reports_k8s_capabilities_and_health() {
        let provider = KubernetesDryRunProvider::new(
            "k3s-ci",
            "sandboxwich-ci",
            Some("local-path".to_string()),
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
        let provider = KubernetesDryRunProvider::new("k3s-ci", "sandboxwich-ci", None);
        let sandbox_id = SandboxId::new();
        let child_sandbox_id = SandboxId::new();
        let snapshot_id = SnapshotId::new();

        let provisioned = provider.provision(sandbox_id);
        assert_eq!(provisioned.metadata["mode"], "dry_run");
        assert_eq!(provisioned.metadata["operation"], "provision");

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

        let fork = provider.fork(sandbox_id, child_sandbox_id, snapshot_id);
        assert_eq!(fork.metadata["operation"], "fork");
        assert_eq!(fork.provider, "kubernetes");
    }
}
