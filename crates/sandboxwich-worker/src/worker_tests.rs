use super::*;
use crate::provider::SandboxTeardownSpec;
use base64::engine::general_purpose;
use chrono::Utc;
use sandboxwich_core::lifecycle_contract::LifecycleReasonCode;
use sandboxwich_core::{
    ExecutionClass, Job, JobId, JobStatus, MAX_COMMAND_STDIN_BYTES, RuntimeResourceKind,
    RuntimeResourcePurpose, SandboxId, SnapshotId,
};
use sha2::Digest;

fn provider() -> KubernetesDryRunProvider {
    KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        Some("local-path-snapshot".to_string()),
    )
}

#[test]
fn cloudflare_registration_omits_run_command_without_the_durable_ledger() {
    let requested = vec![
        WorkerCapability::ProvisionSandbox,
        WorkerCapability::RunCommand,
        WorkerCapability::Snapshot,
    ];
    let report = CloudflareSandboxProvider::for_test().capability_report();

    assert_eq!(
        capabilities_for_worker_provider(&requested, "cloudflare", Some(&report)),
        vec![WorkerCapability::ProvisionSandbox]
    );
}

#[test]
fn cloudflare_registration_includes_run_command_with_the_durable_ledger() {
    let requested = vec![
        WorkerCapability::ProvisionSandbox,
        WorkerCapability::RunCommand,
        WorkerCapability::Snapshot,
    ];
    let report = CloudflareSandboxProvider::for_test_with_replay_ledger().capability_report();

    assert_eq!(
        capabilities_for_worker_provider(&requested, "cloudflare", Some(&report)),
        vec![
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::RunCommand,
        ]
    );
}

#[test]
fn runtime_provider_forwards_managed_home_lifecycle() {
    let provider = RuntimeProvider::DryRun(provider());
    let sandbox_id = SandboxId::new();
    let home_id = HomeId::new();
    let mut stages = Vec::new();

    let handle = provider
        .provision_home_staged(
            sandbox_id,
            home_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            &mut |update| {
                stages.push(update.stage);
                Ok(())
            },
        )
        .expect("runtime provider delegates managed-home provisioning");

    assert_eq!(handle.sandbox_id, sandbox_id);
    assert!(!stages.is_empty());
    provider
        .delete_home(home_id, &CancelSignal::never_cancelled())
        .expect("runtime provider delegates managed-home deletion");
}

struct AttestingMaterializationProvider {
    inner: KubernetesDryRunProvider,
}

impl SandboxProvider for AttestingMaterializationProvider {
    fn capability_report(&self) -> sandboxwich_core::ProviderCapabilityReport {
        self.inner.capability_report()
    }

    fn health_report(&self) -> sandboxwich_core::ProviderHealthReport {
        self.inner.health_report()
    }

    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        self.inner.provision(sandbox_id, spec, cancelled)
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        self.inner
            .exec_handoff(sandbox_id, spec, request, cancelled)
    }

    fn materialize_file(
        &self,
        _sandbox_id: SandboxId,
        _destination: sandboxwich_core::MaterializeFileDestination,
        expected_sha256: &str,
        content: &[u8],
        _compiler_cache_identity: Option<&[u8]>,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::MaterializeFileObservation> {
        let destination_sha256 = format!("{:x}", sha2::Sha256::digest(content));
        anyhow::ensure!(destination_sha256 == expected_sha256, "digest mismatch");
        Ok(sandboxwich_core::MaterializeFileObservation {
            destination_sha256,
            size_bytes: content.len() as u64,
        })
    }

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSnapshotHandle> {
        self.inner
            .create_snapshot(sandbox_id, snapshot_id, cancelled)
    }

    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderForkHandle> {
        self.inner.fork(
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            spec,
            cancelled,
        )
    }

    fn stop(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        self.inner.stop(sandbox_id, spec, cancelled)
    }
}

fn attesting_materialization_provider() -> AttestingMaterializationProvider {
    AttestingMaterializationProvider { inner: provider() }
}

struct ResidentTestProvider {
    inner: KubernetesDryRunProvider,
    calls: std::sync::atomic::AtomicUsize,
    fail_with_error: bool,
    capacity_failures_remaining: std::sync::atomic::AtomicUsize,
}

impl ResidentTestProvider {
    fn terminal_failure() -> Self {
        Self {
            inner: provider(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            fail_with_error: false,
            capacity_failures_remaining: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn cancelled_error() -> Self {
        Self {
            inner: provider(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            fail_with_error: true,
            capacity_failures_remaining: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn capacity_then_terminal(failures: usize) -> Self {
        Self {
            inner: provider(),
            calls: std::sync::atomic::AtomicUsize::new(0),
            fail_with_error: false,
            capacity_failures_remaining: std::sync::atomic::AtomicUsize::new(failures),
        }
    }
}

impl SandboxProvider for ResidentTestProvider {
    fn capability_report(&self) -> sandboxwich_core::ProviderCapabilityReport {
        self.inner.capability_report()
    }

    fn health_report(&self) -> sandboxwich_core::ProviderHealthReport {
        self.inner.health_report()
    }

    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        self.inner.provision(sandbox_id, spec, cancelled)
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        self.inner
            .exec_handoff(sandbox_id, spec, request, cancelled)
    }

    fn run_isolated_resident_process(
        &self,
        spec: &IsolatedResidentProcessSpec,
        _cancelled: &CancelSignal,
        observe: &mut dyn FnMut(IsolatedResidentProcessObservation) -> anyhow::Result<()>,
    ) -> anyhow::Result<provider::IsolatedResidentProcessResult> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self
            .capacity_failures_remaining
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(anyhow::Error::new(ProviderError::classified(
                sandboxwich_core::ProvisioningErrorClass::RetryableCapacity,
                LifecycleReasonCode::WorkspaceCapacityPending,
                anyhow::anyhow!("injected ResourceQuota pressure"),
            )));
        }
        if self.fail_with_error {
            anyhow::bail!("injected cancellation")
        }
        let observation = IsolatedResidentProcessObservation {
            state: IsolatedResidentProcessState::Failed,
            pod_name: format!("sandboxwich-sidecar-{}", spec.process_id),
            pod_uid: Some("test-pod-uid".to_string()),
            ready: false,
            exit_code: Some(1),
        };
        observe(observation.clone())?;
        Ok(provider::IsolatedResidentProcessResult {
            final_observation: observation,
        })
    }

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSnapshotHandle> {
        self.inner
            .create_snapshot(sandbox_id, snapshot_id, cancelled)
    }

    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderForkHandle> {
        self.inner.fork(
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            spec,
            cancelled,
        )
    }

    fn stop(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        self.inner.stop(sandbox_id, spec, cancelled)
    }
}

fn resident_job(restart_policy: ResidentProcessRestartPolicy) -> Job {
    let sandbox_id = SandboxId::new();
    job(
        JobKind::RunResidentProcess,
        json!({
            "sandboxId": sandbox_id,
            "residentProcessId": ResidentProcessId::new(),
            "name": ORB_SIDECAR_RESIDENT_PROCESS_NAME,
            "generation": 1,
            "argv": ["/usr/local/bin/orb-sidecar"],
            "cwd": null,
            "env": {},
            "restartPolicy": restart_policy,
            "bootstrapSha256": "a".repeat(64),
        }),
        WorkerCapability::ProvisionSandbox,
    )
}

fn resident_bootstrap() -> ResidentProcessBootstrapReadResponse {
    ResidentProcessBootstrapReadResponse {
        ok: true,
        content: b"secret".to_vec(),
        sha256: "a".repeat(64),
        target_file: "/run/sandboxwich/bootstrap/token".to_string(),
        mode: 0o400,
        placement_attestation: None,
        sterile_activation: None,
    }
}

fn job(kind: JobKind, payload: serde_json::Value, capability: WorkerCapability) -> Job {
    let now = Utc::now();
    Job {
        id: JobId::new(),
        tenant_id: "default".to_string(),
        kind,
        status: JobStatus::Leased,
        payload,
        required_capability: capability,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        priority: 0,
        attempts: 1,
        max_attempts: 3,
        scheduled_at: now,
        created_at: now,
        updated_at: now,
        last_error: None,
    }
}

fn completed_result(outcome: WorkerJobOutcome) -> WorkerJobResult {
    match outcome {
        WorkerJobOutcome::Complete(value) => value,
        WorkerJobOutcome::ApexTaskInstructions { .. } => {
            panic!("expected durable completion, got ephemeral instruction outcome")
        }
        WorkerJobOutcome::Fail { error, .. } => panic!("expected completion, got {error}"),
    }
}

#[test]
fn dispatches_provision_job_to_provider_manifest() {
    let sandbox_id = SandboxId::new();
    let outcome = execute_job(
        &job(
            JobKind::ProvisionSandbox,
            json!({ "sandboxId": sandbox_id }),
            WorkerCapability::ProvisionSandbox,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect("provision job should execute");
    let WorkerJobResult::ProvisionSandbox { handle } = completed_result(outcome) else {
        panic!("expected provision result");
    };

    assert_eq!(handle.sandbox_id, sandbox_id);
    assert!(handle.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Pod
            && resource.purpose == RuntimeResourcePurpose::Runtime
    }));
    assert!(handle.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Service
            && resource.purpose == RuntimeResourcePurpose::Ssh
    }));
}

#[test]
fn dispatches_provision_stage_reports_before_returning_the_handle() {
    let sandbox_id = SandboxId::new();
    let mut stages = Vec::new();
    let outcome = execute_job_with_reporter(
        &job(
            JobKind::ProvisionSandbox,
            json!({ "sandboxId": sandbox_id }),
            WorkerCapability::ProvisionSandbox,
        ),
        None,
        &provider(),
        &CancelSignal::never_cancelled(),
        &mut |report| {
            stages.push(report.stage);
            Ok(())
        },
    )
    .expect("provision with reporter succeeds");

    assert!(matches!(outcome, WorkerJobOutcome::Complete(_)));
    assert_eq!(
        stages,
        vec![sandboxwich_core::ProvisioningStage::SandboxReady]
    );
}

#[test]
fn provisioning_report_targets_the_lease_and_uses_its_attempt() {
    let lease_id = sandboxwich_core::LeaseId::new();
    let (method, url, request) = provisioning_stage_request(
        "https://sandboxwich.example/v1/",
        lease_id,
        4,
        ProvisioningStageUpdateRequest {
            stage: sandboxwich_core::ProvisioningStage::PodReady,
            resource_kind: Some(RuntimeResourceKind::Pod),
            resource_namespace: Some("sandboxwich-sandboxes".to_string()),
            resource_name: Some("sandboxwich-test".to_string()),
            resource_uid: Some("uid-test".to_string()),
            observed_generation: Some(1),
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        },
    );

    assert_eq!(method, reqwest::Method::PUT);
    assert_eq!(
        url,
        format!("https://sandboxwich.example/v1/leases/{lease_id}/provisioning")
    );
    assert_eq!(request.attempt_count, 4);
}

#[test]
fn provider_errors_expose_typed_retry_class_and_reason_code() {
    let error = ProviderError::classified(
        sandboxwich_core::ProvisioningErrorClass::RetryableCapacity,
        LifecycleReasonCode::WorkspaceCapacityPending,
        anyhow::anyhow!("unbound immediate PersistentVolumeClaims"),
    );

    assert_eq!(
        error.error_class(),
        sandboxwich_core::ProvisioningErrorClass::RetryableCapacity
    );
    assert_eq!(error.reason_code(), "workspace_capacity_pending");
    assert_eq!(error.disposition(), RetryDisposition::Retryable);
}

struct FailingStagedProvider {
    inner: KubernetesDryRunProvider,
}

impl SandboxProvider for FailingStagedProvider {
    fn capability_report(&self) -> sandboxwich_core::ProviderCapabilityReport {
        self.inner.capability_report()
    }

    fn health_report(&self) -> sandboxwich_core::ProviderHealthReport {
        self.inner.health_report()
    }

    fn provision(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        self.inner.provision(sandbox_id, spec, cancelled)
    }

    fn provision_staged(
        &self,
        _sandbox_id: SandboxId,
        _spec: &SandboxProvisionSpec,
        _cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        report(ProvisioningStageUpdateRequest {
            stage: sandboxwich_core::ProvisioningStage::WorkspaceReady,
            resource_kind: Some(RuntimeResourceKind::PersistentVolumeClaim),
            resource_namespace: Some("sandboxwich-ci".to_string()),
            resource_name: Some("sandboxwich-pvc-test".to_string()),
            resource_uid: Some("uid-workspace".to_string()),
            observed_generation: None,
            attempt_count: 1,
            last_error_class: None,
            last_error_code: None,
            last_error: None,
        })?;
        Err(anyhow::Error::new(ProviderError::classified(
            sandboxwich_core::ProvisioningErrorClass::RetryableCapacity,
            LifecycleReasonCode::WorkspaceCapacityPending,
            anyhow::anyhow!("volume remains unbound"),
        )))
    }

    fn exec_handoff(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        self.inner
            .exec_handoff(sandbox_id, spec, request, cancelled)
    }

    fn create_snapshot(
        &self,
        sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSnapshotHandle> {
        self.inner
            .create_snapshot(sandbox_id, snapshot_id, cancelled)
    }

    fn fork(
        &self,
        parent_sandbox_id: SandboxId,
        child_sandbox_id: SandboxId,
        snapshot_id: SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderForkHandle> {
        self.inner.fork(
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            spec,
            cancelled,
        )
    }

    fn stop(
        &self,
        sandbox_id: SandboxId,
        spec: &SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        self.inner.stop(sandbox_id, spec, cancelled)
    }
}

#[test]
fn provisioning_failure_reports_typed_error_against_last_durable_stage() {
    let sandbox_id = SandboxId::new();
    let mut reports = Vec::new();
    let result = execute_job_with_reporter(
        &job(
            JobKind::ProvisionSandbox,
            json!({ "sandboxId": sandbox_id }),
            WorkerCapability::ProvisionSandbox,
        ),
        None,
        &FailingStagedProvider { inner: provider() },
        &CancelSignal::never_cancelled(),
        &mut |report| {
            reports.push(report);
            Ok(())
        },
    );

    assert!(result.is_err());
    assert_eq!(reports.len(), 2);
    assert_eq!(
        reports[1].stage,
        sandboxwich_core::ProvisioningStage::WorkspaceReady
    );
    assert_eq!(
        reports[1].last_error_class,
        Some(sandboxwich_core::ProvisioningErrorClass::RetryableCapacity)
    );
    assert_eq!(
        reports[1].last_error_code.as_deref(),
        Some("workspace_capacity_pending")
    );
    assert!(
        reports[1]
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("workspace_capacity_pending"))
    );
}

#[test]
fn dispatches_command_job_to_provider_exec_handoff() {
    let sandbox_id = SandboxId::new();
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: sandboxwich_core::MemoryLimit::FourG,
        network_egress: Default::default(),
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };
    let outcome = execute_job(
        &job(
            JobKind::RunCommand,
            json!({
                "sandboxId": sandbox_id,
                "provisionSpec": spec,
                "argv": ["echo", "hello"],
                "env": {}
            }),
            WorkerCapability::RunCommand,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect("command job should execute");
    let WorkerJobResult::RunCommand { result } = completed_result(outcome) else {
        panic!("expected run command result");
    };

    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("\"operation\":\"exec\""));
    assert!(result.stdout.contains("\"memoryLimit\":\"4g\""));
}

#[test]
fn command_stdin_is_decoded_for_dispatch_but_absent_from_dry_run_result() {
    let sandbox_id = SandboxId::new();
    let marker = b"apex-private-input";
    let outcome = execute_job(
        &job(
            JobKind::RunCommand,
            json!({
                "sandboxId": sandbox_id,
                "provisionSpec": SandboxProvisionSpec::default(),
                "argv": ["sha256sum"],
                "env": {},
                "stdin": "YXBleC1wcml2YXRlLWlucHV0"
            }),
            WorkerCapability::RunCommand,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect("command job should decode bounded stdin");
    let WorkerJobResult::RunCommand { result } = completed_result(outcome) else {
        panic!("expected run command result");
    };

    assert!(
        !result
            .stdout
            .as_bytes()
            .windows(marker.len())
            .any(|w| w == marker)
    );
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("apex-private-input")
    );
}

#[test]
fn oversized_command_stdin_is_rejected_before_provider_dispatch() {
    let sandbox_id = SandboxId::new();
    let encoded = general_purpose::STANDARD.encode(vec![b'x'; MAX_COMMAND_STDIN_BYTES + 1]);
    let error = execute_job(
        &job(
            JobKind::RunCommand,
            json!({
                "sandboxId": sandbox_id,
                "provisionSpec": SandboxProvisionSpec::default(),
                "argv": ["true"],
                "env": {},
                "stdin": encoded
            }),
            WorkerCapability::RunCommand,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect_err("oversized stdin must fail before provider dispatch");

    assert!(error.to_string().contains("command_stdin_too_large"));
    assert!(!error.to_string().contains(&"x".repeat(64)));
}

#[test]
fn materialization_dispatches_fetched_bytes_and_returns_only_safe_receipt() {
    let sandbox_id = SandboxId::new();
    let file_id = sandboxwich_core::FileId::new();
    let content = b"private-apex-archive";
    let digest = format!("{:x}", sha2::Sha256::digest(content));
    let outcome = execute_materialization_job(
        &job(
            JobKind::MaterializeFile,
            json!({
                "sandboxId": sandbox_id,
                "fileId": file_id,
                "destination": "apex_task",
                "expectedSha256": digest,
            }),
            WorkerCapability::MaterializeFile,
        ),
        content,
        &attesting_materialization_provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect("materialization should execute");
    let WorkerJobResult::MaterializeFile { receipt } = completed_result(outcome) else {
        panic!("expected materialization receipt");
    };
    assert_eq!(receipt.sandbox_id, sandbox_id);
    assert_eq!(receipt.file_id, file_id);
    assert_eq!(receipt.sha256, digest);
    assert_eq!(receipt.destination_sha256, digest);
    assert_eq!(receipt.size_bytes, content.len() as u64);
    assert_eq!(
        receipt.cleanup_owner,
        sandboxwich_core::MaterializeFileCleanupOwner::ControlPlane
    );
    let serialized = serde_json::to_string(&receipt).unwrap();
    assert!(!serialized.contains("private-apex-archive"));
    assert!(!serialized.contains("transientContentBase64"));
}

#[test]
fn dry_run_provider_cannot_produce_materialization_attestation() {
    let content = b"private-apex-archive";
    let digest = format!("{:x}", sha2::Sha256::digest(content));
    let error = provider()
        .materialize_file(
            SandboxId::new(),
            sandboxwich_core::MaterializeFileDestination::ApexTask,
            &digest,
            content,
            None,
            &CancelSignal::never_cancelled(),
        )
        .expect_err("dry-run does not observe a destination");

    assert!(error.to_string().contains("attestation"));
}

/// Test double whose `exec_handoff` always returns a fixed
/// `AgentCommandResult`, letting tests exercise a specific exit code without
/// a real cluster. Every other `SandboxProvider` method delegates to a real
/// dry-run provider.
struct FixedExecResultProvider {
    inner: KubernetesDryRunProvider,
    result: AgentCommandResult,
}

impl SandboxProvider for FixedExecResultProvider {
    fn capability_report(&self) -> sandboxwich_core::ProviderCapabilityReport {
        self.inner.capability_report()
    }

    fn health_report(&self) -> sandboxwich_core::ProviderHealthReport {
        self.inner.health_report()
    }

    fn provision(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        self.inner.provision(sandbox_id, spec, cancelled)
    }

    fn exec_handoff(
        &self,
        _sandbox_id: sandboxwich_core::SandboxId,
        _spec: &SandboxProvisionSpec,
        _request: AgentCommandRequest,
        _cancelled: &CancelSignal,
    ) -> anyhow::Result<AgentCommandResult> {
        Ok(self.result.clone())
    }

    fn create_snapshot(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        snapshot_id: sandboxwich_core::SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSnapshotHandle> {
        self.inner
            .create_snapshot(sandbox_id, snapshot_id, cancelled)
    }

    fn fork(
        &self,
        parent_sandbox_id: sandboxwich_core::SandboxId,
        child_sandbox_id: sandboxwich_core::SandboxId,
        snapshot_id: sandboxwich_core::SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderForkHandle> {
        self.inner.fork(
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            spec,
            cancelled,
        )
    }

    fn stop(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        spec: &SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        self.inner.stop(sandbox_id, spec, cancelled)
    }
}

#[test]
fn run_command_job_completes_the_lease_even_when_the_command_exits_non_zero() {
    // Regression test: a command that runs to completion but exits non-zero
    // (e.g. `false`, a failing test suite) used to be reported as a *lease*
    // failure (`FailLeaseRequest { retry: false }`), which discarded the
    // command's stdout entirely and conflated "the command ran and failed"
    // with "the worker could not run it". It must instead complete the
    // lease with the full typed result; the API derives the command's own
    // Finished/Failed status from `exit_code`.
    let sandbox_id = SandboxId::new();
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: sandboxwich_core::MemoryLimit::FourG,
        network_egress: Default::default(),
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };
    let now = Utc::now();
    let provider = FixedExecResultProvider {
        inner: provider(),
        result: AgentCommandResult {
            exit_code: Some(1),
            stdout: "partial output before failure\n".to_string(),
            stderr: "boom\n".to_string(),
            started_at: now,
            finished_at: now,
        },
    };

    let outcome = execute_job(
        &job(
            JobKind::RunCommand,
            json!({
                "sandboxId": sandbox_id,
                "provisionSpec": spec,
                "argv": ["false"],
                "env": {}
            }),
            WorkerCapability::RunCommand,
        ),
        &provider,
        &CancelSignal::never_cancelled(),
    )
    .expect("a command that ran and exited non-zero is still a completed lease");
    let WorkerJobResult::RunCommand { result } = completed_result(outcome) else {
        panic!("expected run command result");
    };

    assert_eq!(result.exit_code, Some(1));
    assert_eq!(result.stdout, "partial output before failure\n");
    assert_eq!(result.stderr, "boom\n");
}

#[test]
fn dispatches_snapshot_and_fork_jobs_to_provider_metadata() {
    let sandbox_id = SandboxId::new();
    let child_sandbox_id = SandboxId::new();
    let snapshot_id = SnapshotId::new();
    let provider = provider();

    let snapshot = completed_result(
        execute_job(
            &job(
                JobKind::CreateSnapshot,
                json!({
                    "sandboxId": sandbox_id,
                    "snapshotId": snapshot_id
                }),
                WorkerCapability::Snapshot,
            ),
            &provider,
            &CancelSignal::never_cancelled(),
        )
        .expect("snapshot job should execute"),
    );
    let WorkerJobResult::CreateSnapshot { handle: snapshot } = snapshot else {
        panic!("expected create snapshot result");
    };
    assert!(snapshot.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::VolumeSnapshot
            && resource.purpose == RuntimeResourcePurpose::Snapshot
    }));

    let fork = completed_result(
        execute_job(
            &job(
                JobKind::ForkSandbox,
                json!({
                    "parentSandboxId": sandbox_id,
                    "childSandboxId": child_sandbox_id,
                    "snapshotId": snapshot_id
                }),
                WorkerCapability::Snapshot,
            ),
            &provider,
            &CancelSignal::never_cancelled(),
        )
        .expect("fork job should execute"),
    );
    let WorkerJobResult::ForkSandbox { handle: fork } = fork else {
        panic!("expected fork result");
    };
    assert_eq!(fork.child_sandbox_id, child_sandbox_id);
    assert!(fork.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::PersistentVolumeClaim
            && resource.source_snapshot_id == Some(snapshot_id)
    }));
}

#[test]
fn dispatch_rejects_malformed_structured_payloads() {
    let error = execute_job(
        &job(
            JobKind::RunCommand,
            json!({ "argv": ["echo", "hello"] }),
            WorkerCapability::RunCommand,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect_err("missing sandboxId should fail");

    assert!(error.to_string().contains("sandboxId"));
}

#[test]
fn run_command_without_provision_spec_is_rejected_rather_than_defaulted() {
    let sandbox_id = SandboxId::new();
    let error = execute_job(
        &job(
            JobKind::RunCommand,
            json!({
                "sandboxId": sandbox_id,
                "argv": ["echo", "hello"],
                "env": {}
            }),
            WorkerCapability::RunCommand,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect_err("missing provisionSpec on RunCommand should fail, not default");

    assert!(error.to_string().contains("provisionSpec"));
}

#[test]
fn maestro_hosted_runner_without_provision_spec_is_rejected_rather_than_defaulted() {
    let provider = ResidentTestProvider::terminal_failure();
    let cancellation = LeaseCancellation::new();
    let mut job = resident_job(ResidentProcessRestartPolicy::Never);
    let payload = job
        .payload
        .as_object_mut()
        .expect("resident job payload is an object");
    payload.insert(
        "name".into(),
        json!(MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME),
    );
    let error = execute_isolated_resident_process_job(
        &job,
        sandboxwich_core::LeaseId::new(),
        None,
        &provider,
        &cancellation.signal,
        &cancellation,
        &mut |_| Ok(()),
    )
    .expect_err("missing provisionSpec on Maestro runner should fail, not default");

    assert!(error.to_string().contains("provisionSpec"));
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn stop_sandbox_job_tears_down_resources_via_provider() {
    let sandbox_id = SandboxId::new();
    let outcome = execute_job(
        &job(
            JobKind::StopSandbox,
            json!({ "sandboxId": sandbox_id }),
            WorkerCapability::K8sPod,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect("stop job should execute");
    let WorkerJobResult::StopSandbox {
        sandbox_id: stopped_id,
        ..
    } = completed_result(outcome)
    else {
        panic!("expected stop sandbox result");
    };
    assert_eq!(stopped_id, sandbox_id);
}

#[test]
fn stop_sandbox_job_rejects_an_invalid_persisted_teardown_hint() {
    let error = execute_job(
        &job(
            JobKind::StopSandbox,
            json!({
                "sandboxId": SandboxId::new(),
                "deleteGkeFqdnPolicy": "yes"
            }),
            WorkerCapability::K8sPod,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect_err("a malformed persisted teardown hint must fail closed");

    assert!(error.to_string().contains("deleteGkeFqdnPolicy"));
}

#[test]
fn stop_sandbox_uses_provision_tenant_when_routing_identity_was_not_persisted() {
    let spec = teardown_spec_from_payload(&json!({
        "provisionSpec": {
            "provider_external_id": null,
            "provider_routing_scope": null,
            "tenant_id": "org:workspace"
        }
    }))
    .expect("valid teardown payload");

    assert_eq!(spec.provider_external_id, None);
    assert_eq!(
        spec.provider_routing_scope.as_deref(),
        Some("org:workspace")
    );
}

#[test]
fn resume_sandbox_job_restores_the_workspace_from_its_snapshot() {
    let sandbox_id = SandboxId::new();
    let snapshot_id = SnapshotId::new();
    let outcome = execute_job(
        &job(
            JobKind::ResumeSandbox,
            json!({
                "sandboxId": sandbox_id,
                "snapshotId": snapshot_id
            }),
            WorkerCapability::Snapshot,
        ),
        // Through the dispatch enum the worker binary actually runs on, not the
        // concrete provider: a missing arm there falls through to the trait's
        // fail-closed default, which a test calling the provider directly
        // cannot see.
        &RuntimeProvider::DryRun(provider()),
        &CancelSignal::never_cancelled(),
    )
    .expect("resume job should execute");
    let WorkerJobResult::ResumeSandbox { handle } = completed_result(outcome) else {
        panic!("expected resume result");
    };
    // The restored sandbox keeps its own identity -- a resume is not a fork --
    // and its workspace volume is cloned from the snapshot rather than created
    // empty, which is the whole point of the operation.
    assert_eq!(handle.sandbox_id, sandbox_id);
    assert_eq!(handle.snapshot_id, snapshot_id);
    assert!(handle.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::PersistentVolumeClaim
            && resource.sandbox_id == sandbox_id
            && resource.source_snapshot_id == Some(snapshot_id)
    }));
    assert!(
        handle
            .resources
            .iter()
            .any(|resource| resource.resource_kind == RuntimeResourceKind::Pod)
    );
}

#[test]
fn resume_sandbox_job_refuses_an_ephemeral_workspace() {
    // Nothing durable was ever written for an ephemeral workspace, so a
    // "successful" resume would hand back an empty box; fail closed instead.
    let error = execute_job(
        &job(
            JobKind::ResumeSandbox,
            json!({
                "sandboxId": SandboxId::new(),
                "snapshotId": SnapshotId::new(),
                "provisionSpec": { "workspace_mode": "ephemeral" }
            }),
            WorkerCapability::Snapshot,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect_err("resuming an ephemeral workspace must fail");

    assert!(error.to_string().contains("workspace_mode=persistent"));
}

#[test]
fn resume_sandbox_job_requires_a_snapshot_to_restore_from() {
    let error = execute_job(
        &job(
            JobKind::ResumeSandbox,
            json!({ "sandboxId": SandboxId::new() }),
            WorkerCapability::Snapshot,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect_err("a resume job without a snapshot must fail rather than provision an empty box");

    assert!(error.to_string().contains("snapshotId"));
}

#[test]
fn default_registration_capabilities_cover_supported_worker_jobs() {
    let capabilities = capabilities_from_args(
        Vec::new(),
        IsolationProfile::Development,
        None,
        false,
        false,
    )
    .expect("development capability defaults are valid");

    assert!(capabilities.contains(&WorkerCapability::ProvisionSandbox));
    assert!(capabilities.contains(&WorkerCapability::RunCommand));
    assert!(!capabilities.contains(&WorkerCapability::AgentPrompt));
    assert!(capabilities.contains(&WorkerCapability::Snapshot));
    assert!(capabilities.contains(&WorkerCapability::K8sPod));
    assert!(!capabilities.contains(&WorkerCapability::GvisorSandbox));
    assert!(!capabilities.contains(&WorkerCapability::SandboxedContainer));
    assert!(!capabilities.contains(&WorkerCapability::VirtualMachine));
    assert!(!capabilities.contains(&WorkerCapability::ApexTrustedSupervisorV1));
    assert!(!capabilities.contains(&WorkerCapability::UidIsolatedResidentProcess));
}

#[test]
fn dry_run_registration_does_not_advertise_materialization_attestation() {
    let capabilities = vec![
        WorkerCapability::ProvisionSandbox,
        WorkerCapability::MaterializeFile,
    ];

    let dry_run = capabilities_for_provider_mode(capabilities.clone(), ProviderModeArg::DryRun);
    assert!(!dry_run.contains(&WorkerCapability::MaterializeFile));

    let apply = capabilities_for_provider_mode(capabilities, ProviderModeArg::Apply);
    assert!(apply.contains(&WorkerCapability::MaterializeFile));
}

#[test]
fn provider_isolated_sidecar_label_requires_apply_digest_and_runtime_class() {
    let digest = "registry.example/orb-sidecar@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(
        validate_provider_isolated_sidecar_config(
            ProviderModeArg::DryRun,
            Some("gvisor"),
            Some(digest),
        )
        .is_err()
    );
    assert!(
        validate_provider_isolated_sidecar_config(
            ProviderModeArg::Apply,
            Some("gvisor"),
            Some("registry.example/orb-sidecar:latest"),
        )
        .is_err()
    );
    assert!(
        validate_provider_isolated_sidecar_config(ProviderModeArg::Apply, None, Some(digest))
            .is_err()
    );
    assert!(
        validate_provider_isolated_sidecar_config(
            ProviderModeArg::Apply,
            Some("gvisor"),
            Some(digest),
        )
        .unwrap()
    );

    let mut labels = BTreeMap::new();
    add_provider_isolated_resident_process_label(&mut labels, true);
    assert_eq!(
        labels.get(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL),
        Some(&PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL_VALUE.to_string())
    );
    add_provider_isolated_resident_process_image_label(&mut labels, Some(digest));
    assert_eq!(
        labels
            .get(PROVIDER_ISOLATED_RESIDENT_PROCESS_IMAGE_LABEL)
            .map(String::as_str),
        Some(digest)
    );
    add_provider_isolated_resident_process_label(&mut labels, false);
    add_provider_isolated_resident_process_image_label(&mut labels, None);
    assert!(!labels.contains_key(PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL));
    assert!(!labels.contains_key(PROVIDER_ISOLATED_RESIDENT_PROCESS_IMAGE_LABEL));
}

#[test]
fn provider_isolated_sidecar_restart_policy_is_bounded_like_the_guest_supervisor() {
    let provider = ResidentTestProvider::terminal_failure();
    let cancellation = LeaseCancellation::new();
    let mut observations = Vec::new();
    let outcome = execute_isolated_resident_process_job(
        &resident_job(ResidentProcessRestartPolicy::OnFailure),
        sandboxwich_core::LeaseId::new(),
        Some(resident_bootstrap()),
        &provider,
        &cancellation.signal,
        &cancellation,
        &mut |observation| {
            observations.push(observation);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        provider.calls.load(std::sync::atomic::Ordering::SeqCst),
        MAX_RESIDENT_PROCESS_ATTEMPTS as usize
    );
    assert_eq!(observations.len(), MAX_RESIDENT_PROCESS_ATTEMPTS as usize);
    let WorkerJobResult::RunResidentProcess {
        exit_code: Some(1), ..
    } = completed_result(outcome)
    else {
        panic!("expected terminal failed resident result")
    };
}

#[test]
fn provider_isolated_resident_retains_bootstrap_and_lease_across_capacity_pressure() {
    let provider = ResidentTestProvider::capacity_then_terminal(1);
    let cancellation = LeaseCancellation::new();
    let mut observations = Vec::new();
    let outcome = execute_isolated_resident_process_job(
        &resident_job(ResidentProcessRestartPolicy::Never),
        sandboxwich_core::LeaseId::new(),
        Some(resident_bootstrap()),
        &provider,
        &cancellation.signal,
        &cancellation,
        &mut |observation| {
            observations.push(observation);
            Ok(())
        },
    )
    .expect("capacity pressure should retry inside the original resident lease");

    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(
        observations.len(),
        1,
        "capacity rejection must not publish a premature bootstrap acknowledgement"
    );
    let WorkerJobResult::RunResidentProcess {
        exit_code: Some(1), ..
    } = completed_result(outcome)
    else {
        panic!("expected the post-capacity resident execution result")
    };
}

#[test]
fn provider_isolated_resident_does_not_retry_untyped_failures() {
    let provider = ResidentTestProvider::cancelled_error();
    let cancellation = LeaseCancellation::new();
    let error = execute_isolated_resident_process_job(
        &resident_job(ResidentProcessRestartPolicy::Never),
        sandboxwich_core::LeaseId::new(),
        Some(resident_bootstrap()),
        &provider,
        &cancellation.signal,
        &cancellation,
        &mut |_| Ok(()),
    )
    .expect_err("an untyped failure must remain fail closed");

    assert!(error.to_string().contains("injected cancellation"));
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn provider_isolated_sidecar_distinguishes_desired_stop_from_lease_loss() {
    for (reason, expect_complete) in [
        (LeaseCancellationReason::DesiredStop, true),
        (LeaseCancellationReason::LeaseLost, false),
        (LeaseCancellationReason::Shutdown, false),
    ] {
        let provider = ResidentTestProvider::cancelled_error();
        let cancellation = LeaseCancellation::new();
        cancellation.cancel(reason);
        let mut observations = Vec::new();
        let outcome = execute_isolated_resident_process_job(
            &resident_job(ResidentProcessRestartPolicy::Never),
            sandboxwich_core::LeaseId::new(),
            Some(resident_bootstrap()),
            &provider,
            &cancellation.signal,
            &cancellation,
            &mut |observation| {
                observations.push(observation);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            observations.last().map(|value| value.state),
            Some(if expect_complete {
                IsolatedResidentProcessState::Succeeded
            } else {
                IsolatedResidentProcessState::Failed
            })
        );
        match outcome {
            WorkerJobOutcome::Complete(WorkerJobResult::RunResidentProcess {
                exit_code: Some(0),
                ..
            }) if expect_complete => {}
            WorkerJobOutcome::Fail { retry: true, .. } if !expect_complete => {}
            other => panic!("unexpected cancellation outcome for {reason:?}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn panicked_resident_task_stops_renewal_and_reconciles_the_exact_lease() {
    let lease_id = sandboxwich_core::LeaseId::new();
    let process_id = Uuid::new_v4();
    let generation = 7;
    let cancellation = LeaseCancellation::new();
    let metadata = ResidentTaskMetadata {
        lease_id,
        process_id,
        generation,
        cancellation: cancellation.clone(),
    };
    let renewals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let renewal_started = Arc::new(tokio::sync::Notify::new());
    let mut tasks = tokio::task::JoinSet::new();
    let task = tasks.spawn({
        let renewals = renewals.clone();
        let renewal_started = renewal_started.clone();
        async move {
            let renewal_notifier = renewal_started.clone();
            let _renewal = AbortOnDropTask::new(tokio::spawn(async move {
                loop {
                    renewals.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    renewal_notifier.notify_one();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }));
            renewal_started.notified().await;
            panic!("injected resident supervisor panic");
        }
    });
    let mut metadata_by_task = std::collections::HashMap::from([(task.id(), metadata)]);

    let join_error = tasks
        .join_next_with_id()
        .await
        .expect("resident task should finish")
        .expect_err("injected panic should reach the supervisor");
    let exact_metadata = metadata_by_task
        .remove(&join_error.id())
        .expect("panic must retain its exact lease metadata");
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let failures = Arc::new(std::sync::Mutex::new(Vec::new()));
    reconcile_lost_resident_task_with(
        exact_metadata,
        {
            let observations = observations.clone();
            move |process_id, generation, lease_id, state| async move {
                observations
                    .lock()
                    .unwrap()
                    .push((process_id, generation, lease_id, state));
                Ok(())
            }
        },
        {
            let failures = failures.clone();
            move |lease_id, retry| async move {
                failures.lock().unwrap().push((lease_id, retry));
                Ok(())
            }
        },
    )
    .await;

    assert!(cancellation.signal.is_cancelled());
    assert_eq!(cancellation.reason(), LeaseCancellationReason::LeaseLost);
    assert_eq!(
        *observations.lock().unwrap(),
        vec![(
            process_id,
            generation,
            lease_id,
            ResidentProcessObservedState::Lost
        )]
    );
    assert_eq!(*failures.lock().unwrap(), vec![(lease_id, true)]);

    tokio::time::sleep(Duration::from_millis(20)).await;
    let renewals_after_abort = renewals.load(std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        renewals.load(std::sync::atomic::Ordering::SeqCst),
        renewals_after_abort,
        "dropping the panicked task must abort its detached renewal loop"
    );
}

#[test]
fn desired_stop_cancellation_uses_the_typed_api_error_code() {
    let stopped = anyhow::Error::new(WorkerRequestError::Status {
        status: reqwest::StatusCode::CONFLICT,
        body: serde_json::to_string(&ErrorEnvelope {
            ok: false,
            code: "resident_process_stopped".to_string(),
            message: "stopped".to_string(),
            details: None,
        })
        .unwrap(),
    });
    assert!(is_resident_desired_stop(&stopped));

    let prose_only = anyhow::Error::new(WorkerRequestError::Status {
        status: reqwest::StatusCode::CONFLICT,
        body: "resident_process_stopped".to_string(),
    });
    assert!(!is_resident_desired_stop(&prose_only));
}

#[test]
fn resident_observation_trace_extracts_only_the_stable_api_code() {
    let error = anyhow::Error::new(WorkerRequestError::Status {
        status: reqwest::StatusCode::CONFLICT,
        body: serde_json::to_string(&ErrorEnvelope {
            ok: false,
            code: "placement_attestation_not_live".to_string(),
            message: "pod identity does not match".to_string(),
            details: None,
        })
        .unwrap(),
    });

    assert_eq!(
        worker_request_error_code(&error).as_deref(),
        Some("placement_attestation_not_live")
    );
}

#[tokio::test]
async fn resident_observation_retries_transient_failures_under_the_existing_lease() {
    let cancellation = LeaseCancellation::new();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    retry_resident_observation_until_acknowledged_with(&cancellation, Duration::ZERO, {
        let attempts = attempts.clone();
        move || {
            let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(anyhow::Error::new(WorkerRequestError::Status {
                        status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        body: "temporary control-plane outage".to_string(),
                    }))
                } else {
                    Ok(())
                }
            }
        }
    })
    .await
    .expect("a transient observation failure must retry without releasing the lease");

    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "the same renewing lease retries until its observation is acknowledged"
    );
    assert!(!cancellation.signal.is_cancelled());
}

#[tokio::test]
async fn resident_observation_stops_retrying_after_confirmed_cancellation() {
    let cancellation = LeaseCancellation::new();
    cancellation.cancel(LeaseCancellationReason::LeaseLost);
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let result =
        retry_resident_observation_until_acknowledged_with(&cancellation, Duration::ZERO, {
            let attempts = attempts.clone();
            move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Ok(()) }
            }
        })
        .await;

    assert!(result.is_err());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_resident_task_retains_exact_metadata_for_reconciliation() {
    let lease_id = sandboxwich_core::LeaseId::new();
    let process_id = Uuid::new_v4();
    let generation = 11;
    let cancellation = LeaseCancellation::new();
    let metadata = ResidentTaskMetadata {
        lease_id,
        process_id,
        generation,
        cancellation: cancellation.clone(),
    };
    let mut tasks = tokio::task::JoinSet::new();
    let task = tasks.spawn(async { Err::<(), _>(anyhow::anyhow!("injected resident task error")) });
    let mut metadata_by_task = std::collections::HashMap::from([(task.id(), metadata)]);

    let (task_id, result) = tasks
        .join_next_with_id()
        .await
        .expect("resident task should finish")
        .expect("the task itself must not panic");
    let error = result.expect_err("injected task error should reach the drain supervisor");
    assert!(error.to_string().contains("injected resident task error"));
    let exact_metadata = metadata_by_task
        .remove(&task_id)
        .expect("an erroring task must retain its own lease metadata");
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let failures = Arc::new(std::sync::Mutex::new(Vec::new()));
    reconcile_lost_resident_task_with(
        exact_metadata,
        {
            let observations = observations.clone();
            move |process_id, generation, lease_id, state| async move {
                observations
                    .lock()
                    .unwrap()
                    .push((process_id, generation, lease_id, state));
                Ok(())
            }
        },
        {
            let failures = failures.clone();
            move |lease_id, retry| async move {
                failures.lock().unwrap().push((lease_id, retry));
                Ok(())
            }
        },
    )
    .await;

    assert!(cancellation.signal.is_cancelled());
    assert_eq!(cancellation.reason(), LeaseCancellationReason::LeaseLost);
    assert_eq!(
        *observations.lock().unwrap(),
        vec![(
            process_id,
            generation,
            lease_id,
            ResidentProcessObservedState::Lost
        )]
    );
    assert_eq!(*failures.lock().unwrap(), vec![(lease_id, true)]);
}

#[tokio::test]
async fn resident_shutdown_drain_preserves_the_lease_until_clean_completion() {
    let cancellation = LeaseCancellation::new();
    let release = Arc::new(tokio::sync::Notify::new());
    let mut tasks = tokio::task::JoinSet::new();
    let task = tasks.spawn({
        let cancellation = cancellation.clone();
        let release = release.clone();
        async move {
            release.notified().await;
            cancellation.reason()
        }
    });
    let cancellations = std::collections::HashMap::from([(task.id(), cancellation.clone())]);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        release.notify_one();
    });
    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();

    let drain = drain_resident_tasks_to_channel_until_deadline(
        &mut tasks,
        &cancellations,
        Instant::now() + Duration::from_secs(1),
        Duration::from_millis(100),
        result_tx,
    )
    .await;

    assert!(!drain.forced_release);
    assert!(!drain.timed_out);
    let (_, reason) = result_rx
        .recv()
        .await
        .expect("the clean resident completion is reaped")
        .expect("the resident task does not panic");
    assert_eq!(reason, LeaseCancellationReason::None);
    assert!(!cancellation.signal.is_cancelled());
}

#[tokio::test]
async fn resident_shutdown_drain_releases_the_exact_lease_before_the_deadline() {
    let cancellation = LeaseCancellation::new();
    let mut tasks = tokio::task::JoinSet::new();
    let task = tasks.spawn({
        let cancellation = cancellation.clone();
        async move {
            while !cancellation.signal.is_cancelled() {
                tokio::task::yield_now().await;
            }
            cancellation.reason()
        }
    });
    let task_id = task.id();
    let lease_id = sandboxwich_core::LeaseId::new();
    let metadata = std::collections::HashMap::from([(
        task_id,
        ResidentTaskMetadata {
            lease_id,
            process_id: Uuid::new_v4(),
            generation: 19,
            cancellation: cancellation.clone(),
        },
    )]);
    let deadline = Instant::now() + Duration::from_millis(150);
    let cancellations = metadata
        .iter()
        .map(|(task_id, metadata)| (*task_id, metadata.cancellation.clone()))
        .collect();
    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();

    let drain = drain_resident_tasks_to_channel_until_deadline(
        &mut tasks,
        &cancellations,
        deadline,
        Duration::from_millis(100),
        result_tx,
    )
    .await;

    assert!(drain.forced_release);
    assert!(!drain.timed_out);
    assert!(Instant::now() < deadline);
    let (reaped_task_id, reason) = result_rx
        .recv()
        .await
        .expect("the fenced resident release is reaped")
        .expect("the resident task does not panic");
    assert_eq!(reaped_task_id, task_id);
    assert_eq!(metadata[&reaped_task_id].lease_id, lease_id);
    assert_eq!(reason, LeaseCancellationReason::Shutdown);
}

#[tokio::test]
async fn resident_shutdown_drain_forces_only_the_still_active_lease_before_deadline() {
    let clean_cancellation = LeaseCancellation::new();
    let pending_cancellation = LeaseCancellation::new();
    let clean_release = Arc::new(tokio::sync::Notify::new());
    let mut tasks = tokio::task::JoinSet::new();
    let clean_task = tasks.spawn({
        let cancellation = clean_cancellation.clone();
        let release = clean_release.clone();
        async move {
            release.notified().await;
            cancellation.reason()
        }
    });
    let pending_task = tasks.spawn({
        let cancellation = pending_cancellation.clone();
        async move {
            while !cancellation.signal.is_cancelled() {
                tokio::task::yield_now().await;
            }
            cancellation.reason()
        }
    });
    let cancellations = std::collections::HashMap::from([
        (clean_task.id(), clean_cancellation.clone()),
        (pending_task.id(), pending_cancellation.clone()),
    ]);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        clean_release.notify_one();
    });
    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();

    let drain = drain_resident_tasks_to_channel_until_deadline(
        &mut tasks,
        &cancellations,
        Instant::now() + Duration::from_millis(150),
        Duration::from_millis(100),
        result_tx,
    )
    .await;

    assert!(drain.forced_release);
    assert!(!drain.timed_out);
    assert_eq!(clean_cancellation.reason(), LeaseCancellationReason::None);
    assert_eq!(
        pending_cancellation.reason(),
        LeaseCancellationReason::Shutdown
    );
    let mut reasons = Vec::new();
    while let Ok(Some(result)) =
        tokio::time::timeout(Duration::from_millis(20), result_rx.recv()).await
    {
        let (_, reason) = result.expect("resident drain task does not panic");
        reasons.push(reason);
    }
    assert_eq!(
        reasons,
        vec![
            LeaseCancellationReason::None,
            LeaseCancellationReason::Shutdown
        ]
    );
}

#[tokio::test]
async fn worker_shutdown_publishes_and_decodes_the_exact_durable_drain_tuple() {
    use axum::{Json, Router, body::to_bytes, extract::Request, extract::State};

    async fn record_drain(
        State((bodies, worker_id)): State<(Arc<std::sync::Mutex<Vec<serde_json::Value>>>, Uuid)>,
        request: Request,
    ) -> Json<serde_json::Value> {
        let body = to_bytes(request.into_body(), 4_096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        bodies.lock().unwrap().push(body.clone());
        Json(serde_json::json!({
            "drainReceipt": {
                "shutdownId": body["shutdownId"],
                "workerId": worker_id,
                "hardDeadline": body["hardDeadline"],
                "leases": [{ "leaseId": Uuid::new_v4() }]
            }
        }))
    }

    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let worker_id = Uuid::new_v4();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .fallback(record_drain)
                .with_state((bodies.clone(), worker_id)),
        )
        .into_future(),
    );
    let shutdown_id = Uuid::new_v4();
    let hard_deadline = chrono::Utc::now() + chrono::Duration::seconds(30);
    let request = WorkerDrainRequest {
        shutdown_id,
        hard_deadline,
    };

    let receipt = publish_worker_drain_receipt(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        worker_id,
        &request,
    )
    .await
    .expect("typed drain receipt is decoded");

    assert_eq!(receipt.shutdown_id, shutdown_id);
    assert_eq!(receipt.worker_id.0, worker_id);
    assert_eq!(receipt.hard_deadline, hard_deadline);
    assert_eq!(receipt.leases.len(), 1);
    assert_ne!(receipt.leases[0].lease_id.0, Uuid::nil());
    assert_eq!(
        *bodies.lock().unwrap(),
        vec![serde_json::json!({
            "shutdownId": shutdown_id,
            "hardDeadline": hard_deadline,
        })]
    );
    server.abort();
}

#[test]
fn durable_drain_receipt_revokes_only_uncaptured_local_authority() {
    let captured_lease_id = sandboxwich_core::LeaseId::new();
    let uncaptured_lease_id = sandboxwich_core::LeaseId::new();
    let captured_cancellation = LeaseCancellation::new();
    let uncaptured_cancellation = LeaseCancellation::new();
    let resident_authority = vec![
        (captured_lease_id, captured_cancellation.clone()),
        (uncaptured_lease_id, uncaptured_cancellation.clone()),
    ];
    let captured_lease_ids = std::collections::HashSet::from([captured_lease_id]);

    revoke_uncaptured_resident_authority(resident_authority, &captured_lease_ids);

    assert_eq!(
        captured_cancellation.reason(),
        LeaseCancellationReason::None
    );
    assert_eq!(
        uncaptured_cancellation.reason(),
        LeaseCancellationReason::LeaseLost
    );
}

#[tokio::test]
async fn shutdown_plan_owns_one_absolute_deadline_from_the_request() {
    let shutdown = ShutdownState::new(Duration::from_millis(100));
    let first = shutdown.request_now();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let replay = shutdown.request_now();

    assert!(shutdown.is_requested());
    assert_eq!(first.request.shutdown_id, replay.request.shutdown_id);
    assert_eq!(first.request.hard_deadline, replay.request.hard_deadline);
    assert_eq!(first.deadline, replay.deadline);
    assert!(
        first.deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(90),
        "work after the signal must consume the original deadline"
    );
}

#[tokio::test]
async fn worker_drain_receipt_starts_when_shutdown_is_requested() {
    let shutdown = ShutdownState::new(Duration::from_millis(100));
    let request_shutdown = shutdown.clone();
    let started = Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        request_shutdown.request_now();
    });

    let plan = shutdown.wait_for_plan().await;

    assert!(
        started.elapsed() < Duration::from_millis(40),
        "publishing the durable worker drain receipt must not wait for in-flight work"
    );
    assert!(plan.deadline > Instant::now());
}

#[test]
fn durable_drain_timeout_stays_inside_the_api_deadline_window() {
    assert_eq!(durable_drain_timeout(0), Duration::from_secs(1));
    assert_eq!(durable_drain_timeout(300), Duration::from_secs(300));
    assert_eq!(durable_drain_timeout(7_200), Duration::from_secs(3_600));
}

#[tokio::test]
async fn ordinary_and_fast_lane_claim_responses_after_shutdown_are_fenced_releases() {
    let shutdown = ShutdownState::new(Duration::from_secs(1));
    shutdown.request_now();
    let ordinary_lease_id = sandboxwich_core::LeaseId::new();
    let fast_lane_lease_id = sandboxwich_core::LeaseId::new();
    let released = Arc::new(std::sync::Mutex::new(Vec::new()));

    for claimed_lease_id in [ordinary_lease_id, fast_lane_lease_id] {
        let admitted = admit_or_release_claimed_work(Some(claimed_lease_id), &shutdown, {
            let released = released.clone();
            move |lease_id| async move {
                released.lock().unwrap().push(lease_id);
                Ok(())
            }
        })
        .await
        .expect("shutdown-raced claim is released");
        assert_eq!(admitted, None);
    }
    assert_eq!(
        *released.lock().unwrap(),
        vec![ordinary_lease_id, fast_lane_lease_id]
    );

    let running = ShutdownState::new(Duration::from_secs(1));
    assert_eq!(
        admit_or_release_claimed_work(Some(ordinary_lease_id), &running, |_| async {
            panic!("a claim before shutdown must remain admitted")
        })
        .await
        .unwrap(),
        Some(ordinary_lease_id)
    );
}

#[tokio::test]
async fn shutdown_watchdog_preserves_the_resident_release_budget() {
    let shutdown = ShutdownState::new(Duration::from_millis(100));
    shutdown.request_now();
    let started = Instant::now();

    drain_watchdog(shutdown, Duration::from_millis(40)).await;

    assert!(started.elapsed() >= Duration::from_millis(45));
    assert!(
        started.elapsed() < Duration::from_millis(90),
        "in-flight work must stop before the resident release budget begins"
    );
}

#[tokio::test]
async fn resident_reconciliation_is_bounded_by_the_shutdown_deadline() {
    let started = Instant::now();
    let result = complete_before_shutdown_deadline(
        started + Duration::from_millis(30),
        std::future::pending::<()>(),
    )
    .await;

    assert!(result.is_none());
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[tokio::test]
async fn resident_completion_is_delivered_for_reconciliation_while_a_peer_is_running() {
    let clean_cancellation = LeaseCancellation::new();
    let pending_cancellation = LeaseCancellation::new();
    let clean_release = Arc::new(tokio::sync::Notify::new());
    let mut tasks = tokio::task::JoinSet::new();
    let clean_task = tasks.spawn({
        let release = clean_release.clone();
        async move {
            release.notified().await;
        }
    });
    let pending_task = tasks.spawn({
        let cancellation = pending_cancellation.clone();
        async move {
            while !cancellation.signal.is_cancelled() {
                tokio::task::yield_now().await;
            }
        }
    });
    let cancellations = std::collections::HashMap::from([
        (clean_task.id(), clean_cancellation),
        (pending_task.id(), pending_cancellation),
    ]);
    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
    let started = Instant::now();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        clean_release.notify_one();
    });

    let drain_future = drain_resident_tasks_to_channel_until_deadline(
        &mut tasks,
        &cancellations,
        started + Duration::from_millis(150),
        Duration::from_millis(100),
        result_tx,
    );
    let receive_future = async {
        let first = result_rx
            .recv()
            .await
            .expect("the clean completion is delivered immediately");
        first.expect("the clean resident task does not panic");
        let first_result_at = started.elapsed();
        while result_rx.recv().await.is_some() {}
        first_result_at
    };
    let (drain, first_result_at) = tokio::join!(drain_future, receive_future);

    assert!(drain.forced_release);
    assert!(!drain.timed_out);
    assert!(
        first_result_at < Duration::from_millis(40),
        "reconciliation delivery must not wait for the peer's grace deadline"
    );
}

#[tokio::test]
async fn production_resident_task_result_dispatches_failure_and_panic_reconciliation() {
    use axum::{
        Router,
        extract::{Request, State},
        response::Json,
    };

    async fn record_request(
        State(requests): State<Arc<std::sync::Mutex<Vec<String>>>>,
        request: Request,
    ) -> Json<serde_json::Value> {
        requests
            .lock()
            .unwrap()
            .push(request.uri().path().to_string());
        // The production reconciliation deliberately continues from a failed
        // observation to lease failure. A malformed success body keeps this
        // fixture small while still proving both real HTTP paths are invoked.
        Json(serde_json::json!({}))
    }

    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .fallback(record_request)
                .with_state(requests.clone()),
        )
        .into_future(),
    );

    for should_panic in [false, true] {
        let lease_id = sandboxwich_core::LeaseId::new();
        let process_id = Uuid::new_v4();
        let cancellation = LeaseCancellation::new();
        let metadata = ResidentTaskMetadata {
            lease_id,
            process_id,
            generation: 13,
            cancellation: cancellation.clone(),
        };
        let mut tasks = tokio::task::JoinSet::new();
        let task = tasks.spawn(async move {
            assert!(!should_panic, "injected resident task panic");
            Err::<LeaseResponse, _>(anyhow::anyhow!("injected resident task error"))
        });
        let mut metadata_by_task = std::collections::HashMap::from([(task.id(), metadata)]);
        let result = tasks.join_next_with_id().await.unwrap();

        reconcile_resident_task_result(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            result,
            &mut metadata_by_task,
            false,
        )
        .await;

        assert!(metadata_by_task.is_empty());
        assert_eq!(cancellation.reason(), LeaseCancellationReason::LeaseLost);
        let recorded = requests.lock().unwrap();
        assert!(recorded.contains(&format!("/resident-processes/{process_id}/observations")));
        assert!(recorded.contains(&format!("/leases/{lease_id}/fail")));
    }
    server.abort();
}

#[test]
fn standalone_register_path_defaults_safe_and_requires_explicit_apply_for_materialization() {
    let parse = |extra: &[&str]| {
        let mut argv = vec!["sandboxwich-worker", "register", "--name", "standalone"];
        argv.extend_from_slice(extra);
        let cli = Cli::try_parse_from(argv).expect("standalone register parses");
        let Command::Register(args) = cli.command else {
            panic!("expected register command")
        };
        capabilities_for_provider_mode(
            capabilities_from_args(
                args.capability,
                IsolationProfile::Development,
                None,
                false,
                false,
            )
            .unwrap(),
            args.provider_mode,
        )
    };

    assert!(!parse(&[]).contains(&WorkerCapability::MaterializeFile));
    assert!(parse(&["--provider-mode", "apply"]).contains(&WorkerCapability::MaterializeFile));
}

#[test]
fn standalone_work_paths_filter_dry_run_materialization_claims() {
    let worker_id = "00000000-0000-0000-0000-000000000001";
    for command in ["work-once", "work-loop"] {
        let dry_run = Cli::try_parse_from(["sandboxwich-worker", command, worker_id])
            .expect("dry-run work command parses");
        let dry_run_mode = match dry_run.command {
            Command::WorkOnce(args) => args.provider.provider_mode,
            Command::WorkLoop(args) => args.provider.provider_mode,
            _ => panic!("expected work command"),
        };
        let dry_run_kinds = claim_kinds_for_provider_mode(dry_run_mode)
            .expect("dry-run claim must be explicitly filtered");
        assert!(!dry_run_kinds.contains(&JobKind::MaterializeFile));

        let apply = Cli::try_parse_from([
            "sandboxwich-worker",
            command,
            worker_id,
            "--provider-mode",
            "apply",
        ])
        .expect("apply work command parses");
        let apply_mode = match apply.command {
            Command::WorkOnce(args) => args.provider.provider_mode,
            Command::WorkLoop(args) => args.provider.provider_mode,
            _ => panic!("expected work command"),
        };
        assert!(claim_kinds_for_provider_mode(apply_mode).is_none());
    }
}

#[test]
fn reconcile_command_is_a_one_shot_path_separate_from_worker_claiming() {
    let cli = Cli::try_parse_from([
        "sandboxwich-worker",
        "reconcile",
        "--name",
        "sandboxwich-reconciler",
        "--confirm-apply",
        "--orphan-reconciliation-apply",
    ]);

    assert!(cli.is_ok(), "the out-of-band reconcile command must parse");
}

#[tokio::test]
async fn runtime_inventory_fetch_exhausts_sandbox_pages_and_bounds_overflow() {
    use axum::{Json, Router, extract::Request};

    let sandbox_ids = (0..205).map(|_| SandboxId::new()).collect::<Vec<_>>();
    let expected = sandbox_ids.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new().fallback(move |request: Request| {
                let sandbox_ids = sandbox_ids.clone();
                async move {
                    let query = request.uri().query().unwrap_or_default();
                    let resource_only = query.contains("include_sandbox_ids=false");
                    let second_sandbox_page = query.contains("sandbox_after=next-sandbox-page");
                    let (page_ids, complete, sandbox_next_cursor) = if resource_only {
                        (Vec::new(), true, None)
                    } else if second_sandbox_page {
                        (sandbox_ids[200..].to_vec(), true, None)
                    } else {
                        (
                            sandbox_ids[..200].to_vec(),
                            false,
                            Some("next-sandbox-page".to_string()),
                        )
                    };
                    Json(RuntimeResourceInventoryResponse {
                        ok: true,
                        provider: "kubernetes".to_string(),
                        cluster: Some("cluster-a".to_string()),
                        namespace: "sandboxes".to_string(),
                        sandbox_ids: page_ids,
                        complete,
                        resources: Vec::new(),
                        active_resident_lease_ids: Vec::new(),
                        sandbox_next_cursor,
                        next_cursor: None,
                    })
                }
            }),
        )
        .into_future(),
    );

    let inventory = fetch_runtime_resource_inventory(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        Uuid::new_v4(),
        "sandboxes",
        205,
    )
    .await
    .expect("all independently paginated sandbox fences are aggregated");
    assert!(inventory.complete);
    assert!(inventory.next_cursor.is_none());
    assert!(inventory.sandbox_next_cursor.is_none());
    assert_eq!(
        inventory
            .sandbox_ids
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        expected.into_iter().collect()
    );

    let error = fetch_runtime_resource_inventory(
        &reqwest::Client::new(),
        &format!("http://{address}"),
        Uuid::new_v4(),
        "sandboxes",
        200,
    )
    .await
    .expect_err("a remaining sandbox cursor at max_scanned must fail closed");
    assert!(
        error
            .to_string()
            .contains("runtime sandbox inventory exceeded max_scanned=200")
    );
    server.abort();
}

#[test]
fn reconcile_scope_validation_names_the_incomplete_boundary() {
    let mut inventory = RuntimeResourceInventoryResponse {
        ok: true,
        provider: "kubernetes".to_string(),
        cluster: Some("cluster-a".to_string()),
        namespace: "sandboxes".to_string(),
        sandbox_ids: Vec::new(),
        complete: true,
        resources: Vec::new(),
        active_resident_lease_ids: Vec::new(),
        sandbox_next_cursor: None,
        next_cursor: None,
    };
    validate_reconciliation_inventory_scope(&inventory, "cluster-a", "sandboxes")
        .expect("matching complete scope");

    inventory.complete = false;
    let error = validate_reconciliation_inventory_scope(&inventory, "cluster-a", "sandboxes")
        .expect_err("incomplete scope must fail the one-shot Job");
    assert!(error.to_string().contains("inventory was incomplete"));
}

#[test]
fn full_resident_supervisor_excludes_only_resident_claims() {
    let dry_run = claim_kinds_for_work_loop(ProviderModeArg::DryRun, false)
        .expect("dry-run claim is explicitly filtered");
    assert!(!dry_run.contains(&JobKind::RunResidentProcess));
    assert!(!dry_run.contains(&JobKind::MaterializeFile));
    assert!(dry_run.contains(&JobKind::RunCommand));

    let apply = claim_kinds_for_work_loop(ProviderModeArg::Apply, false)
        .expect("a full apply worker must use an explicit non-resident filter");
    assert!(!apply.contains(&JobKind::RunResidentProcess));
    assert!(apply.contains(&JobKind::MaterializeFile));
    assert!(apply.contains(&JobKind::RunCommand));

    assert!(claim_kinds_for_work_loop(ProviderModeArg::Apply, true).is_none());
}

#[test]
fn provision_fast_lane_claims_only_resident_processes() {
    assert_eq!(
        claim_kinds_during_provision(ProviderModeArg::Apply),
        Some(vec![JobKind::RunResidentProcess])
    );
    assert_eq!(
        claim_kinds_during_provision(ProviderModeArg::DryRun),
        Some(Vec::new())
    );
}

#[test]
fn capabilities_from_args_report_only_the_typed_isolation_profile() {
    let gvisor = capabilities_from_args(
        Vec::new(),
        IsolationProfile::Gvisor,
        Some("gvisor"),
        false,
        false,
    )
    .expect("gVisor with a RuntimeClass is valid");
    assert!(gvisor.contains(&WorkerCapability::SandboxedContainer));
    assert!(!gvisor.contains(&WorkerCapability::VirtualMachine));
    assert!(!gvisor.contains(&WorkerCapability::GvisorSandbox));

    let kata = capabilities_from_args(
        Vec::new(),
        IsolationProfile::Kata,
        Some("kata-qemu"),
        false,
        false,
    )
    .expect("Kata with a RuntimeClass is valid");
    assert!(kata.contains(&WorkerCapability::VirtualMachine));
    assert!(!kata.contains(&WorkerCapability::SandboxedContainer));
    assert!(!kata.contains(&WorkerCapability::GvisorSandbox));

    let development = capabilities_from_args(
        Vec::new(),
        IsolationProfile::Development,
        Some("arbitrary-runtime"),
        false,
        false,
    )
    .expect("development may render an operator-owned RuntimeClass");
    assert!(!development.contains(&WorkerCapability::SandboxedContainer));
    assert!(!development.contains(&WorkerCapability::VirtualMachine));
    assert!(!development.contains(&WorkerCapability::GvisorSandbox));
}

#[test]
fn apex_registration_requires_and_composes_with_sandboxed_container() {
    assert!(
        capabilities_from_args(Vec::new(), IsolationProfile::Development, None, false, true,)
            .is_err()
    );
    let capabilities = capabilities_from_args(
        Vec::new(),
        IsolationProfile::Gvisor,
        Some("gvisor"),
        false,
        true,
    )
    .expect("APEX with gVisor is valid");
    assert!(capabilities.contains(&WorkerCapability::SandboxedContainer));
    assert!(capabilities.contains(&WorkerCapability::ApexTrustedSupervisorV1));
    assert!(capabilities.contains(&WorkerCapability::ApexTaskInstructions));
    assert!(!capabilities.contains(&WorkerCapability::VirtualMachine));
}

#[test]
fn capabilities_from_args_reject_invalid_isolation_configuration() {
    assert!(
        capabilities_from_args(Vec::new(), IsolationProfile::Gvisor, None, false, false,).is_err()
    );
    assert!(
        capabilities_from_args(Vec::new(), IsolationProfile::Kata, None, false, false,).is_err()
    );
    for hostile_override in [
        CapabilityArg::SandboxedContainer,
        CapabilityArg::VirtualMachine,
        CapabilityArg::GvisorSandbox,
    ] {
        assert!(
            capabilities_from_args(
                vec![hostile_override],
                IsolationProfile::Development,
                None,
                false,
                false,
            )
            .is_err()
        );
    }
}

#[test]
fn isolation_profile_cli_is_typed_validated_and_passed_to_provider() {
    let missing_runtime_class = Cli::try_parse_from([
        "sandboxwich-worker",
        "provider-capabilities",
        "--isolation-profile",
        "gvisor",
    ])
    .expect("gVisor is a typed isolation profile");
    let Command::ProviderCapabilities(args) = missing_runtime_class.command else {
        panic!("expected provider-capabilities command");
    };
    assert!(provider_from_args(args).is_err());

    let kata = Cli::try_parse_from([
        "sandboxwich-worker",
        "provider-capabilities",
        "--isolation-profile",
        "kata",
        "--runtime-class-name",
        "kata-qemu",
    ])
    .expect("Kata profile and operator-owned RuntimeClass parse");
    let Command::ProviderCapabilities(args) = kata.command else {
        panic!("expected provider-capabilities command");
    };
    let report = provider_from_args(args)
        .expect("Kata with a RuntimeClass is valid")
        .capability_report();
    assert_eq!(
        report.labels.get("isolation_profile"),
        Some(&"kata".to_string())
    );
    assert_eq!(
        report.labels.get("runtime_class_name"),
        Some(&"kata-qemu".to_string())
    );
    // The dry-run provider report describes configured isolation but never
    // claims the VM boundary; only real (apply-mode) provisioning does.
    assert!(
        !report
            .capabilities
            .contains(&WorkerCapability::VirtualMachine)
    );
    assert!(
        !report
            .capabilities
            .contains(&WorkerCapability::SandboxedContainer)
    );

    assert!(
        Cli::try_parse_from([
            "sandboxwich-worker",
            "provider-capabilities",
            "--isolation-profile",
            "untyped-runtime",
        ])
        .is_err()
    );
}

#[test]
fn run_registration_labels_include_actual_placement_proof() {
    let image = "registry.example/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut labels = BTreeMap::from([
        ("provider_mode".to_string(), "forged".to_string()),
        ("runtime_image".to_string(), "forged:latest".to_string()),
    ]);

    add_placement_proof_labels(&mut labels, ProviderModeArg::Apply, Some(image), false);

    assert_eq!(labels.get("provider_mode"), Some(&"apply".to_string()));
    assert_eq!(labels.get("runtime_image"), Some(&image.to_string()));
    assert!(!labels.contains_key("runtime_profile"));
}

#[test]
fn apex_registration_labels_include_closed_runtime_profile() {
    let mut labels = BTreeMap::new();

    add_placement_proof_labels(
        &mut labels,
        ProviderModeArg::DryRun,
        Some(
            "registry.example/sandbox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        true,
    );

    assert_eq!(labels.get("provider_mode"), Some(&"dry_run".to_string()));
    assert_eq!(
        labels.get("runtime_profile"),
        Some(&"apex_trusted_supervisor_v1".to_string())
    );
}

#[test]
fn default_registration_capabilities_include_fqdn_when_a_backend_is_enabled() {
    let capabilities =
        capabilities_from_args(Vec::new(), IsolationProfile::Development, None, true, false)
            .expect("development FQDN defaults are valid");

    assert!(capabilities.contains(&WorkerCapability::FqdnEgress));
}

#[test]
fn explicit_registration_capabilities_can_select_fqdn_egress() {
    let capabilities = capabilities_from_args(
        vec![CapabilityArg::FqdnEgress],
        IsolationProfile::Development,
        None,
        false,
        false,
    )
    .expect("functional capability override is valid");

    assert_eq!(capabilities, vec![WorkerCapability::FqdnEgress]);
}

#[test]
fn capability_derivation_preserves_explicit_fqdn_semantics_across_isolation_profiles() {
    for (profile, runtime_class_name, isolation_capability) in [
        (IsolationProfile::Development, None, None),
        (
            IsolationProfile::Gvisor,
            Some("gvisor"),
            Some(WorkerCapability::SandboxedContainer),
        ),
        (
            IsolationProfile::Kata,
            Some("kata-qemu"),
            Some(WorkerCapability::VirtualMachine),
        ),
    ] {
        for fqdn_egress_backend in [false, true] {
            let defaults = capabilities_from_args(
                Vec::new(),
                profile,
                runtime_class_name,
                fqdn_egress_backend,
                false,
            )
            .expect("default capability derivation is valid");
            assert_eq!(
                defaults.contains(&WorkerCapability::FqdnEgress),
                fqdn_egress_backend,
                "default FQDN capability must track backend availability for {profile:?}"
            );
            assert_eq!(
                defaults
                    .iter()
                    .find(|capability| {
                        matches!(
                            capability,
                            WorkerCapability::SandboxedContainer | WorkerCapability::VirtualMachine
                        )
                    })
                    .cloned(),
                isolation_capability.clone(),
                "default isolation capability must track the typed profile"
            );

            let explicit = capabilities_from_args(
                vec![CapabilityArg::RunCommand],
                profile,
                runtime_class_name,
                fqdn_egress_backend,
                false,
            )
            .expect("explicit capability derivation is valid");
            let mut expected = vec![WorkerCapability::RunCommand];
            if let Some(isolation_capability) = isolation_capability.as_ref() {
                expected.push(isolation_capability.clone());
            }
            assert_eq!(
                explicit, expected,
                "an FQDN backend must not broaden an explicit capability list"
            );
        }
    }
}

#[test]
fn empty_provider_options_are_normalized_to_absent() {
    assert_eq!(non_empty(None), None);
    assert_eq!(non_empty(Some("   ".to_string())), None);
    assert_eq!(
        non_empty(Some("local-path".to_string())),
        Some("local-path".to_string())
    );
}

#[test]
fn egress_gateway_image_is_an_explicit_provider_contract() {
    let gateway = Cli::try_parse_from([
        "sandboxwich-worker",
        "provider-capabilities",
        "--egress-gateway-image",
        "ghcr.io/evalops/sandboxwich-worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ])
    .expect("gateway image is a supported provider option");
    assert!(matches!(
        gateway.command,
        Command::ProviderCapabilities(ProviderArgs {
            egress_gateway_image: Some(_),
            ..
        })
    ));
}

#[test]
fn node_local_dns_addresses_are_typed_provider_options() {
    let cli = Cli::try_parse_from([
        "sandboxwich-worker",
        "provider-capabilities",
        "--dns-service-ip",
        "169.254.20.10",
        "--dns-service-ip",
        "fd00::53",
    ])
    .expect("typed IPv4 and IPv6 DNS endpoints should parse");
    assert!(matches!(
        cli.command,
        Command::ProviderCapabilities(ProviderArgs { dns_service_ips, .. })
            if dns_service_ips == vec![
                "169.254.20.10".parse::<IpAddr>().unwrap(),
                "fd00::53".parse::<IpAddr>().unwrap()
            ]
    ));

    assert!(
        Cli::try_parse_from([
            "sandboxwich-worker",
            "provider-capabilities",
            "--dns-service-ip",
            "not-an-ip",
        ])
        .is_err()
    );
}

#[test]
fn egress_gateway_health_is_an_explicit_local_probe_command() {
    let health = Cli::try_parse_from(["sandboxwich-worker", "egress-gateway-health"])
        .expect("gateway health is a supported worker command");
    assert!(matches!(
        health.command,
        Command::EgressGatewayHealth(EgressGatewayHealthArgs { address })
            if address == "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
    ));
}

#[test]
fn classify_retry_flags_transient_infrastructure_errors_as_retryable() {
    let timeout = anyhow::Error::new(ProviderError::retryable(anyhow::anyhow!("timeout")));
    assert!(classify_retry(&timeout));
}

#[test]
fn classify_retry_treats_permanent_provider_errors_as_non_retryable() {
    let immutable_field = anyhow::anyhow!("immutable field");
    assert!(!classify_retry(&immutable_field));

    let malformed_payload = anyhow::anyhow!("timeout text alone is not a retry contract");
    assert!(!classify_retry(&malformed_payload));
}

fn recoverable_status_error() -> WorkerRequestError {
    WorkerRequestError::Status {
        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        body: "internal error".to_string(),
    }
}

fn permanent_status_error() -> WorkerRequestError {
    WorkerRequestError::Status {
        status: reqwest::StatusCode::NOT_FOUND,
        body: "lease_expired".to_string(),
    }
}

#[test]
fn worker_request_error_treats_5xx_429_and_408_as_recoverable() {
    for status in [
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        reqwest::StatusCode::BAD_GATEWAY,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        reqwest::StatusCode::REQUEST_TIMEOUT,
    ] {
        let error = WorkerRequestError::Status {
            status,
            body: String::new(),
        };
        assert!(error.is_recoverable(), "{status} should be recoverable");
    }
}

#[test]
fn worker_request_error_treats_4xx_rejections_as_permanent() {
    // These are exactly the durable rejections the audit called out:
    // 401 (bad/expired credentials), 404 (lease_expired), 409
    // (idempotency_key_reused). Retrying them delays cancel propagation
    // and burns the whole retry budget on a request that can never
    // succeed.
    for status in [
        reqwest::StatusCode::UNAUTHORIZED,
        reqwest::StatusCode::NOT_FOUND,
        reqwest::StatusCode::CONFLICT,
        reqwest::StatusCode::BAD_REQUEST,
    ] {
        let error = WorkerRequestError::Status {
            status,
            body: String::new(),
        };
        assert!(!error.is_recoverable(), "{status} should be permanent");
    }
}

#[test]
fn worker_request_error_decode_failures_are_permanent() {
    let error = WorkerRequestError::Decode(
        serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
    );
    assert!(!error.is_recoverable());
}

#[tokio::test]
async fn with_retries_recovers_after_transient_failures() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempts = AtomicU32::new(0);
    let result = with_retries("test op", 3, || {
        let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            if attempt < 3 {
                Err(recoverable_status_error())
            } else {
                Ok(attempt)
            }
        }
    })
    .await;

    assert_eq!(result.expect("should eventually succeed"), 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn with_retries_gives_up_after_bounded_attempts() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempts = AtomicU32::new(0);
    let result: anyhow::Result<()> = with_retries("test op", 3, || {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err(recoverable_status_error()) }
    })
    .await;

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn with_retries_stops_immediately_on_a_permanent_error() {
    // Regression test for "worker retries permanent 4xx responses": a
    // 401/404/409 must not be retried at all, so cancel propagation isn't
    // delayed and the retry budget isn't wasted on a request that can
    // never succeed.
    use std::sync::atomic::{AtomicU32, Ordering};

    let attempts = AtomicU32::new(0);
    let result: anyhow::Result<()> = with_retries("test op", 5, || {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err(permanent_status_error()) }
    })
    .await;

    assert!(result.is_err());
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a permanent error must stop the retry loop after the first attempt, not spend the \
             full 5-attempt budget"
    );
}

#[test]
fn mutation_gate_warning_fires_only_when_both_halves_are_set() {
    assert!(mutation_gate_force_enabled_warning(false, false, "sandboxwich-sandboxes").is_none());
    assert!(mutation_gate_force_enabled_warning(true, false, "sandboxwich-sandboxes").is_none());
    assert!(mutation_gate_force_enabled_warning(false, true, "sandboxwich-sandboxes").is_none());

    let warning = mutation_gate_force_enabled_warning(true, true, "sandboxwich-sandboxes")
        .expect("both halves set should produce a warning");
    assert!(warning.contains("force-enabled"));
    assert!(warning.contains(KUBERNETES_MUTATION_ENV));
    assert!(warning.contains("sandboxwich-sandboxes"));
    assert!(warning.contains("GH-76"));
}

#[test]
fn orphan_reconciliation_apply_requires_both_opt_ins() {
    assert!(!orphan_reconciliation_apply_enabled(false, None));
    assert!(!orphan_reconciliation_apply_enabled(true, None));
    assert!(!orphan_reconciliation_apply_enabled(false, Some("1")));
    assert!(!orphan_reconciliation_apply_enabled(true, Some("true")));
    assert!(orphan_reconciliation_apply_enabled(true, Some("1")));
}

#[test]
fn idle_heartbeat_is_immediate_then_bounded_to_once_per_minute() {
    let started = Instant::now();
    assert!(idle_heartbeat_due(None, started));
    assert!(!idle_heartbeat_due(
        Some(started),
        started + IDLE_HEARTBEAT_INTERVAL - Duration::from_millis(1)
    ));
    assert!(idle_heartbeat_due(
        Some(started),
        started + IDLE_HEARTBEAT_INTERVAL
    ));
}

#[test]
fn resolv_conf_nameservers_capture_the_cluster_dns_endpoints() {
    let resolvers = resolver_ips_from_resolv_conf(
        r#"
        # Generated by the kubelet
        nameserver 10.70.0.10
        nameserver 169.254.20.10 # NodeLocal DNSCache
        nameserver fd00::53
        search evalops.svc.cluster.local svc.cluster.local cluster.local
        options ndots:5
        nameserver not-an-address
        "#,
    );

    assert_eq!(
        resolvers,
        vec![
            "10.70.0.10".parse::<IpAddr>().unwrap(),
            "169.254.20.10".parse::<IpAddr>().unwrap(),
            "fd00::53".parse::<IpAddr>().unwrap(),
        ]
    );
}

#[test]
fn runtime_dns_endpoints_merge_operator_and_discovered_resolvers() {
    let endpoints = merge_dns_service_ips(
        vec!["169.254.20.10".parse::<IpAddr>().unwrap()],
        vec![
            "10.70.0.10".parse::<IpAddr>().unwrap(),
            "169.254.20.10".parse::<IpAddr>().unwrap(),
        ],
    );

    assert_eq!(
        endpoints,
        vec![
            "10.70.0.10".parse::<IpAddr>().unwrap(),
            "169.254.20.10".parse::<IpAddr>().unwrap(),
        ]
    );
}
