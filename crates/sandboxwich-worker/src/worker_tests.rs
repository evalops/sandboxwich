use super::*;
use crate::provider::SandboxTeardownSpec;
use chrono::Utc;
use sandboxwich_core::{
    ExecutionClass, Job, JobId, JobStatus, RuntimeResourceKind, RuntimeResourcePurpose, SandboxId,
    SnapshotId,
};

fn provider() -> KubernetesDryRunProvider {
    KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        Some("local-path-snapshot".to_string()),
    )
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
        "workspace_capacity_pending",
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
            "workspace_capacity_pending",
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: sandboxwich_core::MemoryLimit::FourG,
        network_egress: Default::default(),
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: sandboxwich_core::MemoryLimit::FourG,
        network_egress: Default::default(),
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
fn resume_sandbox_job_fails_instead_of_silently_succeeding() {
    let sandbox_id = SandboxId::new();
    let outcome = execute_job(
        &job(
            JobKind::ResumeSandbox,
            json!({ "sandboxId": sandbox_id }),
            WorkerCapability::K8sPod,
        ),
        &provider(),
        &CancelSignal::never_cancelled(),
    )
    .expect("resume job should execute (and report a job failure)");
    match outcome {
        WorkerJobOutcome::Fail { error, retry } => {
            assert!(!retry, "resume is a permanent decision, not worth retrying");
            assert!(error.contains(&sandbox_id.to_string()));
        }
        WorkerJobOutcome::Complete(_) => {
            panic!("resume must not silently report success")
        }
    }
}

#[test]
fn default_registration_capabilities_cover_supported_worker_jobs() {
    let capabilities =
        capabilities_from_args(Vec::new(), IsolationProfile::Development, None, false)
            .expect("development capability defaults are valid");

    assert!(capabilities.contains(&WorkerCapability::ProvisionSandbox));
    assert!(capabilities.contains(&WorkerCapability::RunCommand));
    assert!(!capabilities.contains(&WorkerCapability::AgentPrompt));
    assert!(capabilities.contains(&WorkerCapability::Snapshot));
    assert!(capabilities.contains(&WorkerCapability::K8sPod));
    assert!(!capabilities.contains(&WorkerCapability::GvisorSandbox));
    assert!(!capabilities.contains(&WorkerCapability::SandboxedContainer));
    assert!(!capabilities.contains(&WorkerCapability::VirtualMachine));
}

#[test]
fn capabilities_from_args_report_only_the_typed_isolation_profile() {
    let gvisor =
        capabilities_from_args(Vec::new(), IsolationProfile::Gvisor, Some("gvisor"), false)
            .expect("gVisor with a RuntimeClass is valid");
    assert!(gvisor.contains(&WorkerCapability::SandboxedContainer));
    assert!(!gvisor.contains(&WorkerCapability::VirtualMachine));
    assert!(!gvisor.contains(&WorkerCapability::GvisorSandbox));

    let kata = capabilities_from_args(Vec::new(), IsolationProfile::Kata, Some("kata-qemu"), false)
        .expect("Kata with a RuntimeClass is valid");
    assert!(kata.contains(&WorkerCapability::VirtualMachine));
    assert!(!kata.contains(&WorkerCapability::SandboxedContainer));
    assert!(!kata.contains(&WorkerCapability::GvisorSandbox));

    let development = capabilities_from_args(
        Vec::new(),
        IsolationProfile::Development,
        Some("arbitrary-runtime"),
        false,
    )
    .expect("development may render an operator-owned RuntimeClass");
    assert!(!development.contains(&WorkerCapability::SandboxedContainer));
    assert!(!development.contains(&WorkerCapability::VirtualMachine));
    assert!(!development.contains(&WorkerCapability::GvisorSandbox));
}

#[test]
fn capabilities_from_args_reject_invalid_isolation_configuration() {
    assert!(capabilities_from_args(Vec::new(), IsolationProfile::Gvisor, None, false).is_err());
    assert!(capabilities_from_args(Vec::new(), IsolationProfile::Kata, None, false).is_err());
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
    assert!(
        report
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
fn default_registration_capabilities_include_fqdn_when_a_backend_is_enabled() {
    let capabilities =
        capabilities_from_args(Vec::new(), IsolationProfile::Development, None, true)
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
    )
    .expect("functional capability override is valid");

    assert_eq!(capabilities, vec![WorkerCapability::FqdnEgress]);
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
