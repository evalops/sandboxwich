mod egress_gateway;
mod provider;

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use provider::{
    CancelSignal, DEFAULT_MAX_CAPTURED_OUTPUT_BYTES, KUBERNETES_MUTATION_ENV,
    KubernetesApplyProvider, KubernetesDryRunProvider, ProviderError, ReconciliationLimits,
    RetryDisposition, SandboxProvider, image_is_digest_pinned,
};
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, ClaimLeaseRequest, ClaimLeaseResponse,
    CompleteLeaseRequest, FailLeaseRequest, JobKind, LeaseResponse, ProvisioningOperationResponse,
    ProvisioningStageUpdateRequest, RegisterWorkerRequest, RenewLeaseRequest,
    RuntimeResourceInventoryResponse, SandboxProvisionSpec, WorkerCapability,
    WorkerHeartbeatRequest, WorkerJobResult, WorkerResponse, build_api_client,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-worker")]
#[command(about = "Host-side worker for sandbox orchestration")]
struct Cli {
    #[arg(long, env = "SANDBOXWICH_API", default_value = "http://127.0.0.1:3217")]
    api: String,

    /// For `register`/`run`: a tenant-wide token, used only to authenticate
    /// the initial `POST /workers/register` call. `run` then mints and
    /// switches to a worker-scoped token (GH-64) for everything after
    /// registration, so this value is never reused for lease/guest-health
    /// calls in that path. For every other subcommand (`work-loop`, `claim`,
    /// `renew`, `complete`, `fail`, `heartbeat`), pass the worker-scoped
    /// token returned by `register` here instead -- those routes reject
    /// tenant-wide tokens.
    #[arg(long, env = "SANDBOXWICH_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "SANDBOXWICH_TENANT")]
    tenant: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    EgressGateway(EgressGatewayArgs),
    Capabilities,
    ProviderCapabilities(ProviderArgs),
    ProviderHealth(ProviderArgs),
    ProviderSmoke(ProviderArgs),
    ProviderApplyPlan(ProviderApplyArgs),
    ProviderApplySmoke(ProviderApplyArgs),
    Register(RegisterArgs),
    Heartbeat(HeartbeatArgs),
    Claim(ClaimArgs),
    Renew(RenewArgs),
    Complete(CompleteArgs),
    Fail(FailArgs),
    Run(RunArgs),
    WorkOnce(WorkOnceArgs),
    WorkLoop(WorkLoopArgs),
}

#[derive(Debug, Args)]
struct EgressGatewayArgs {
    #[arg(
        long,
        env = "SANDBOXWICH_EGRESS_GATEWAY_BIND",
        default_value = "0.0.0.0:8080"
    )]
    bind: SocketAddr,

    #[arg(long, env = "SANDBOXWICH_EGRESS_GATEWAY_POLICY")]
    policy: String,
}

#[derive(Debug, Args)]
struct RegisterArgs {
    #[arg(long)]
    name: String,

    #[arg(long, default_value = "kubernetes")]
    provider: String,

    #[arg(long = "capability", value_enum)]
    capability: Vec<CapabilityArg>,

    #[arg(long = "label", value_parser = parse_label)]
    label: Vec<(String, String)>,

    #[arg(long)]
    max_concurrent_jobs: Option<u32>,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long)]
    name: String,

    #[arg(long = "provider", default_value = "kubernetes")]
    worker_provider: String,

    #[arg(long = "capability", value_enum)]
    capability: Vec<CapabilityArg>,

    #[arg(long = "label", value_parser = parse_label)]
    label: Vec<(String, String)>,

    #[arg(long)]
    max_concurrent_jobs: Option<u32>,

    #[arg(long)]
    lease_seconds: Option<u64>,

    #[arg(long, default_value_t = 1000)]
    idle_sleep_ms: u64,

    #[arg(long)]
    max_iterations: Option<u64>,

    /// How long to wait for an in-flight lease to finish after a shutdown signal
    /// (SIGTERM/SIGINT) is received before giving up and exiting anyway.
    #[arg(long, default_value_t = DEFAULT_DRAIN_TIMEOUT_SECS)]
    drain_timeout_secs: u64,

    #[command(flatten)]
    provider: RuntimeProviderArgs,
}

#[derive(Debug, Args)]
struct HeartbeatArgs {
    worker_id: Uuid,

    #[arg(long = "label", value_parser = parse_label)]
    label: Vec<(String, String)>,

    #[arg(long)]
    max_concurrent_jobs: Option<u32>,
}

#[derive(Debug, Clone, Copy, Args)]
struct ClaimArgs {
    worker_id: Uuid,

    #[arg(long)]
    lease_seconds: Option<u64>,

    #[arg(skip)]
    operation_id: Option<Uuid>,
}

#[derive(Debug, Args)]
struct WorkOnceArgs {
    worker_id: Uuid,

    #[arg(long)]
    lease_seconds: Option<u64>,

    #[command(flatten)]
    provider: RuntimeProviderArgs,
}

#[derive(Debug, Args)]
struct WorkLoopArgs {
    worker_id: Uuid,

    #[arg(long)]
    lease_seconds: Option<u64>,

    #[arg(long, default_value_t = 1000)]
    idle_sleep_ms: u64,

    #[arg(long)]
    max_iterations: Option<u64>,

    #[arg(long = "label", value_parser = parse_label)]
    label: Vec<(String, String)>,

    /// How long to wait for an in-flight lease to finish after a shutdown signal
    /// (SIGTERM/SIGINT) is received before giving up and exiting anyway.
    #[arg(long, default_value_t = DEFAULT_DRAIN_TIMEOUT_SECS)]
    drain_timeout_secs: u64,

    #[command(flatten)]
    provider: RuntimeProviderArgs,
}

#[derive(Debug, Args)]
struct RenewArgs {
    lease_id: Uuid,

    #[arg(long)]
    lease_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct CompleteArgs {
    lease_id: Uuid,

    #[arg(long, default_value = "")]
    stdout: String,

    #[arg(long, default_value = "")]
    stderr: String,

    #[arg(long, default_value_t = 0)]
    exit_code: i32,
}

#[derive(Debug, Args)]
struct FailArgs {
    lease_id: Uuid,

    #[arg(long)]
    error: String,

    #[arg(long, default_value_t = false)]
    retry: bool,
}

#[derive(Clone, Debug, Args)]
struct ProviderArgs {
    #[arg(long, default_value = "k3s-dev")]
    cluster: String,

    #[arg(long, default_value = "sandboxwich")]
    namespace: String,

    #[arg(long)]
    storage_class: Option<String>,

    #[arg(long)]
    snapshot_class: Option<String>,

    #[arg(long, env = "SANDBOXWICH_RUNTIME_IMAGE")]
    runtime_image: Option<String>,

    #[arg(long, env = "SANDBOXWICH_EGRESS_GATEWAY_IMAGE")]
    egress_gateway_image: Option<String>,

    #[arg(long, env = "SANDBOXWICH_WORKSPACE_STORAGE")]
    workspace_storage: Option<String>,

    #[arg(long)]
    ssh_authorized_keys_secret: Option<String>,

    #[arg(long, env = "SANDBOXWICH_RUNTIME_CLASS_NAME")]
    runtime_class_name: Option<String>,

    /// Enable CiliumNetworkPolicy `toFQDNs` rendering for host allow rules.
    /// The cluster must have Cilium CRDs and DNS proxy enforcement installed.
    #[arg(long, env = "SANDBOXWICH_CILIUM_FQDN_EGRESS", default_value_t = false)]
    cilium_fqdn_egress: bool,

    /// Dedicated namespace sandbox pods/services/PVCs/NetworkPolicies are
    /// deployed into, separate from the control-plane namespace (GH-76).
    /// Unset falls back to the control-plane `--namespace`, preserving
    /// pre-existing single-namespace deployments; the checked-in worker
    /// Deployment manifest sets this explicitly to
    /// `DEFAULT_SANDBOX_NAMESPACE`.
    #[arg(long, env = "SANDBOXWICH_SANDBOX_NAMESPACE")]
    sandbox_namespace: Option<String>,

    /// Namespace running cluster DNS, used to scope the always-on DNS
    /// egress rule (GH-66).
    #[arg(long, env = "SANDBOXWICH_DNS_NAMESPACE")]
    dns_namespace: Option<String>,

    /// Additional CIDRs excluded from every egress allow rule that
    /// overlaps them, via NetworkPolicy `except`, so sandboxes can never
    /// reach the control plane or cloud metadata endpoints regardless of
    /// egress mode (GH-66). Merged with (not replacing)
    /// `DEFAULT_EGRESS_EXCLUDED_CIDRS`; see
    /// `--egress-excluded-cidrs-replace` to opt out of the merge.
    #[arg(
        long = "egress-excluded-cidr",
        env = "SANDBOXWICH_EGRESS_EXCLUDED_CIDRS",
        value_delimiter = ','
    )]
    egress_excluded_cidrs: Vec<String>,

    /// Replace the default excluded CIDR set outright instead of merging
    /// `--egress-excluded-cidr` into it. Only set this if you are
    /// deliberately replacing the metadata/control-plane carve-out with an
    /// equivalent value for your environment (e.g. a non-k3s cluster where
    /// the k3s-shaped defaults are meaningless) -- leaving this unset is
    /// the safe default and always keeps `169.254.0.0/16` excluded.
    #[arg(
        long = "egress-excluded-cidrs-replace",
        default_value_t = false,
        env = "SANDBOXWICH_EGRESS_EXCLUDED_CIDRS_REPLACE"
    )]
    egress_excluded_cidrs_replace: bool,

    /// Namespace containing pods allowed to reach a sandbox's ssh/desktop
    /// ports via the rendered ingress NetworkPolicy (GH-67). Defaults to
    /// the control-plane namespace.
    #[arg(long, env = "SANDBOXWICH_INGRESS_NAMESPACE")]
    ingress_namespace: Option<String>,

    /// Pod selector label (key=value, repeatable) identifying which pods
    /// in the ingress namespace may reach a sandbox's ssh/desktop ports
    /// (GH-67). Defaults to app.kubernetes.io/part-of=sandboxwich.
    #[arg(long = "ingress-selector-label", value_parser = parse_label)]
    ingress_selector_label: Vec<(String, String)>,

    /// Secret mounted read-only as a file (SANDBOXWICH_VNC_PASSWORD_FILE)
    /// in the sandbox container (GH-67).
    #[arg(long, env = "SANDBOXWICH_VNC_PASSWORD_SECRET")]
    vnc_password_secret: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct RuntimeProviderArgs {
    #[command(flatten)]
    provider: ProviderArgs,

    #[arg(long, value_enum, default_value_t = ProviderModeArg::DryRun)]
    provider_mode: ProviderModeArg,

    #[arg(long, default_value = "kubectl")]
    kubectl: String,

    #[arg(long)]
    kubectl_context: Option<String>,

    #[arg(long, default_value_t = false)]
    confirm_apply: bool,

    /// Bound applied to every `kubectl` invocation (wait/get/exec/delete); a
    /// hung `kubectl` (e.g. talking to an unreachable API server) is killed
    /// once this elapses instead of wedging the worker forever. A value of
    /// `0` falls back to the default rather than disabling the bound.
    #[arg(
        long,
        env = "SANDBOXWICH_KUBECTL_COMMAND_TIMEOUT_SECS",
        default_value_t = provider::DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS
    )]
    kubectl_command_timeout_secs: u64,

    /// Cap on the stdout/stderr captured from each kubectl invocation before it's
    /// stored in job results and provider metadata. Mirrors sandboxwich-agent's
    /// equivalent flag.
    #[arg(
        long,
        env = "SANDBOXWICH_MAX_CAPTURED_OUTPUT_BYTES",
        default_value_t = DEFAULT_MAX_CAPTURED_OUTPUT_BYTES
    )]
    max_captured_output_bytes: u64,

    #[arg(
        long,
        env = "SANDBOXWICH_ORPHAN_RECONCILIATION_INTERVAL_SECS",
        default_value_t = 60
    )]
    orphan_reconciliation_interval_secs: u64,

    #[arg(long, default_value_t = 200)]
    orphan_reconciliation_max_scanned: usize,

    #[arg(long, default_value_t = 20)]
    orphan_reconciliation_max_deleted: usize,

    #[arg(long, default_value_t = 10)]
    orphan_reconciliation_max_elapsed_secs: u64,

    #[arg(long, default_value_t = false)]
    orphan_reconciliation_apply: bool,
}

#[derive(Debug, Args)]
struct ProviderApplyArgs {
    #[command(flatten)]
    provider: ProviderArgs,

    #[arg(long, default_value = "kubectl")]
    kubectl: String,

    #[arg(long)]
    kubectl_context: Option<String>,

    #[arg(long, default_value_t = false)]
    confirm_apply: bool,

    #[arg(long, default_value_t = false)]
    keep_resources: bool,

    /// Bound applied to every `kubectl` invocation (wait/get/exec/delete); a
    /// hung `kubectl` (e.g. talking to an unreachable API server) is killed
    /// once this elapses instead of wedging the worker forever. A value of
    /// `0` falls back to the default rather than disabling the bound.
    #[arg(
        long,
        env = "SANDBOXWICH_KUBECTL_COMMAND_TIMEOUT_SECS",
        default_value_t = provider::DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS
    )]
    kubectl_command_timeout_secs: u64,

    /// Cap on the stdout/stderr captured from each kubectl invocation before it's
    /// stored in job results and provider metadata. Mirrors sandboxwich-agent's
    /// equivalent flag.
    #[arg(
        long,
        env = "SANDBOXWICH_MAX_CAPTURED_OUTPUT_BYTES",
        default_value_t = DEFAULT_MAX_CAPTURED_OUTPUT_BYTES
    )]
    max_captured_output_bytes: u64,
}

#[derive(Clone, Debug, ValueEnum)]
enum CapabilityArg {
    ProvisionSandbox,
    RunCommand,
    Snapshot,
    DesktopStream,
    FqdnEgress,
    K8sPod,
    GvisorSandbox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ProviderModeArg {
    DryRun,
    Apply,
}

enum RuntimeProvider {
    DryRun(KubernetesDryRunProvider),
    Apply(KubernetesApplyProvider),
}

impl RuntimeProvider {
    fn reconcile_orphans(
        &self,
        inventory: anyhow::Result<RuntimeResourceInventoryResponse>,
        limits: ReconciliationLimits,
        apply: bool,
    ) -> anyhow::Result<Option<(usize, usize, bool)>> {
        match self {
            Self::DryRun(_) => Ok(None),
            Self::Apply(provider) => {
                let outcome = provider.reconcile_orphans(
                    inventory,
                    limits,
                    apply,
                    &CancelSignal::never_cancelled(),
                )?;
                Ok(Some((
                    outcome.decisions.len(),
                    outcome.deleted,
                    outcome.apply,
                )))
            }
        }
    }
}

impl SandboxProvider for RuntimeProvider {
    fn capability_report(&self) -> sandboxwich_core::ProviderCapabilityReport {
        match self {
            Self::DryRun(provider) => provider.capability_report(),
            Self::Apply(provider) => provider.capability_report(),
        }
    }

    fn health_report(&self) -> sandboxwich_core::ProviderHealthReport {
        match self {
            Self::DryRun(provider) => provider.health_report(),
            Self::Apply(provider) => provider.health_report(),
        }
    }

    fn provision(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        match self {
            Self::DryRun(provider) => provider.provision(sandbox_id, spec, cancelled),
            Self::Apply(provider) => provider.provision(sandbox_id, spec, cancelled),
        }
    }

    fn provision_staged(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
        report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        match self {
            Self::DryRun(provider) => {
                provider.provision_staged(sandbox_id, spec, cancelled, report)
            }
            Self::Apply(provider) => provider.provision_staged(sandbox_id, spec, cancelled, report),
        }
    }

    fn exec_handoff(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        spec: &SandboxProvisionSpec,
        request: AgentCommandRequest,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::AgentCommandResult> {
        match self {
            Self::DryRun(provider) => provider.exec_handoff(sandbox_id, spec, request, cancelled),
            Self::Apply(provider) => provider.exec_handoff(sandbox_id, spec, request, cancelled),
        }
    }

    fn create_snapshot(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        snapshot_id: sandboxwich_core::SnapshotId,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderSnapshotHandle> {
        match self {
            Self::DryRun(provider) => provider.create_snapshot(sandbox_id, snapshot_id, cancelled),
            Self::Apply(provider) => provider.create_snapshot(sandbox_id, snapshot_id, cancelled),
        }
    }

    fn fork(
        &self,
        parent_sandbox_id: sandboxwich_core::SandboxId,
        child_sandbox_id: sandboxwich_core::SandboxId,
        snapshot_id: sandboxwich_core::SnapshotId,
        spec: &SandboxProvisionSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<sandboxwich_core::ProviderForkHandle> {
        match self {
            Self::DryRun(provider) => provider.fork(
                parent_sandbox_id,
                child_sandbox_id,
                snapshot_id,
                spec,
                cancelled,
            ),
            Self::Apply(provider) => provider.fork(
                parent_sandbox_id,
                child_sandbox_id,
                snapshot_id,
                spec,
                cancelled,
            ),
        }
    }

    fn stop(
        &self,
        sandbox_id: sandboxwich_core::SandboxId,
        spec: &provider::SandboxTeardownSpec,
        cancelled: &CancelSignal,
    ) -> anyhow::Result<()> {
        match self {
            Self::DryRun(provider) => provider.stop(sandbox_id, spec, cancelled),
            Self::Apply(provider) => provider.stop(sandbox_id, spec, cancelled),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let api = cli.api.trim_end_matches('/').to_string();
    let client = build_api_client(cli.api_token.as_deref(), cli.tenant.as_deref())?;

    match cli.command {
        Command::EgressGateway(args) => {
            let policy = serde_json::from_str(&args.policy)
                .context("parse SANDBOXWICH_EGRESS_GATEWAY_POLICY")?;
            egress_gateway::run_egress_gateway(args.bind, policy).await?;
        }
        Command::Capabilities => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "worker": "sandboxwich-worker",
                    "capabilities": [
                        "provision_sandbox",
                        "run_command",
                        "agent_prompt",
                        "snapshot",
                        "desktop_stream",
                        "k8s_pod",
                        "gvisor_sandbox"
                    ]
                }))?
            );
        }
        Command::ProviderCapabilities(args) => {
            let provider = provider_from_args(args);
            println!(
                "{}",
                serde_json::to_string_pretty(&provider.capability_report())?
            );
        }
        Command::ProviderHealth(args) => {
            let provider = provider_from_args(args);
            println!(
                "{}",
                serde_json::to_string_pretty(&provider.health_report())?
            );
        }
        Command::ProviderSmoke(args) => {
            let provider = provider_from_args(args);
            let sandbox_id = sandboxwich_core::SandboxId::new();
            let child_sandbox_id = sandboxwich_core::SandboxId::new();
            let snapshot_id = sandboxwich_core::SnapshotId::new();
            let spec = SandboxProvisionSpec::default();
            let exec = provider.exec_handoff(
                sandbox_id,
                &spec,
                AgentCommandRequest {
                    argv: vec!["echo".to_string(), "sandboxwich".to_string()],
                    cwd: None,
                    env: BTreeMap::new(),
                    timeout_secs: None,
                },
                &CancelSignal::never_cancelled(),
            )?;
            let provision =
                provider.provision(sandbox_id, &spec, &CancelSignal::never_cancelled())?;
            let snapshot = provider.create_snapshot(
                sandbox_id,
                snapshot_id,
                &CancelSignal::never_cancelled(),
            )?;
            let fork = provider.fork(
                sandbox_id,
                child_sandbox_id,
                snapshot_id,
                &spec,
                &CancelSignal::never_cancelled(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "provider": provider.capability_report(),
                    "health": provider.health_report(),
                    "provision": provision,
                    "exec": exec,
                    "snapshot": snapshot,
                    "fork": fork
                }))?
            );
        }
        Command::ProviderApplyPlan(args) => {
            let provider = apply_provider_from_args(args)?;
            let plan = provider.smoke_plan(
                sandboxwich_core::SandboxId::new(),
                sandboxwich_core::SandboxId::new(),
                sandboxwich_core::SnapshotId::new(),
            );
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Command::ProviderApplySmoke(args) => {
            let confirm_apply = args.confirm_apply;
            let cleanup = !args.keep_resources;
            let provider = apply_provider_from_args(args)?;
            let plan = provider.smoke_plan(
                sandboxwich_core::SandboxId::new(),
                sandboxwich_core::SandboxId::new(),
                sandboxwich_core::SnapshotId::new(),
            );
            let outcome = provider.apply_smoke(
                plan,
                confirm_apply,
                KubernetesApplyProvider::mutation_enabled_from_env(),
                cleanup,
            )?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        Command::Register(args) => {
            let response = register_worker(
                &client,
                &api,
                args.name,
                args.provider,
                capabilities_from_args(args.capability, None, false),
                args.label.into_iter().collect(),
                // Standalone registration may be consumed by multiple
                // work-once/work-loop processes, so preserve the operator's
                // declared aggregate capacity.
                args.max_concurrent_jobs,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Heartbeat(args) => {
            let response = client
                .post(format!("{api}/workers/{}/heartbeat", args.worker_id))
                .json(&WorkerHeartbeatRequest {
                    max_concurrent_jobs: args.max_concurrent_jobs,
                    labels: args.label.into_iter().collect(),
                })
                .send()
                .await?;
            print_json::<WorkerResponse>(response).await?;
        }
        Command::Claim(args) => {
            let response = claim(&client, &api, args).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Renew(args) => {
            let response = client
                .post(format!("{api}/leases/{}/renew", args.lease_id))
                .json(&RenewLeaseRequest {
                    lease_seconds: args.lease_seconds,
                })
                .send()
                .await?;
            print_json::<LeaseResponse>(response).await?;
        }
        Command::Complete(args) => {
            let now = chrono::Utc::now();
            let response = client
                .post(format!("{api}/leases/{}/complete", args.lease_id))
                .json(&CompleteLeaseRequest {
                    result: Some(WorkerJobResult::RunCommand {
                        result: AgentCommandResult {
                            exit_code: Some(args.exit_code),
                            stdout: args.stdout,
                            stderr: args.stderr,
                            started_at: now,
                            finished_at: now,
                        },
                    }),
                })
                .send()
                .await?;
            print_json::<LeaseResponse>(response).await?;
        }
        Command::Fail(args) => {
            let response = client
                .post(format!("{api}/leases/{}/fail", args.lease_id))
                .json(&FailLeaseRequest {
                    error: args.error,
                    retry: args.retry,
                })
                .send()
                .await?;
            print_json::<LeaseResponse>(response).await?;
        }
        Command::Run(args) => {
            let runtime_class_name = args.provider.provider.runtime_class_name.as_deref();
            let fqdn_egress_backend = args.provider.provider.cilium_fqdn_egress
                || args
                    .provider
                    .provider
                    .egress_gateway_image
                    .as_deref()
                    .is_some_and(image_is_digest_pinned);
            let capabilities =
                capabilities_from_args(args.capability, runtime_class_name, fqdn_egress_backend);
            let labels: BTreeMap<_, _> = args.label.into_iter().collect();
            let response = register_worker(
                &client,
                &api,
                args.name,
                args.worker_provider,
                capabilities,
                labels.clone(),
                args.max_concurrent_jobs,
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "registered": response.worker
                }))?
            );
            // GH-64: registration mints a credential scoped to this worker's
            // id, distinct from the tenant token used above to register.
            // Guest-facing routes (lease claim/renew/complete/fail/output,
            // guest-health) now reject tenant-wide tokens outright, so the
            // rest of this process -- its own heartbeat/claim/renew/
            // complete/fail calls, and whatever it injects into the
            // sandboxes it provisions -- must use the worker token instead
            // of `cli.api_token` from here on.
            let worker_token = response.worker_token.context(
                "registration response did not include a worker-scoped token; is \
                 sandboxwich-api up to date? (see GH-64)",
            )?;
            let worker_client = build_api_client(Some(&worker_token), cli.tenant.as_deref())
                .context("failed to build worker-scoped API client")?;
            work_loop(
                &worker_client,
                &api,
                WorkLoopArgs {
                    worker_id: response.worker.id.0,
                    lease_seconds: args.lease_seconds,
                    idle_sleep_ms: args.idle_sleep_ms,
                    max_iterations: args.max_iterations,
                    drain_timeout_secs: args.drain_timeout_secs,
                    label: labels.into_iter().collect(),
                    provider: args.provider,
                },
            )
            .await?;
        }
        Command::WorkOnce(args) => {
            let provider = Arc::new(runtime_provider_from_args(args.provider)?);
            let response = claim(
                &client,
                &api,
                ClaimArgs {
                    worker_id: args.worker_id,
                    lease_seconds: args.lease_seconds,
                    operation_id: Some(Uuid::now_v7()),
                },
            )
            .await?;
            let Some(lease) = response.lease else {
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            };
            let response = handle_lease(&client, &api, lease, provider).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::WorkLoop(args) => {
            // Direct invocation authenticates the worker process itself;
            // credentials are deliberately not passed into the provider or
            // any guest it creates.
            work_loop(&client, &api, args).await?;
        }
    }

    Ok(())
}

fn provider_from_args(args: ProviderArgs) -> KubernetesDryRunProvider {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        args.cluster,
        args.namespace,
        non_empty(args.storage_class),
        non_empty(args.snapshot_class),
    )
    .with_runtime_image(non_empty(args.runtime_image))
    .with_egress_gateway_image(non_empty(args.egress_gateway_image))
    .with_workspace_storage(non_empty(args.workspace_storage))
    .with_ssh_authorized_keys_secret(non_empty(args.ssh_authorized_keys_secret))
    .with_runtime_class_name(non_empty(args.runtime_class_name))
    .with_cilium_fqdn_egress(args.cilium_fqdn_egress)
    .with_sandbox_namespace(non_empty(args.sandbox_namespace))
    .with_dns_namespace(non_empty(args.dns_namespace));
    let provider = if args.egress_excluded_cidrs_replace {
        provider.with_egress_excluded_cidrs_replace(args.egress_excluded_cidrs)
    } else {
        provider.with_egress_excluded_cidrs(args.egress_excluded_cidrs)
    };
    provider
        .with_ingress_namespace(non_empty(args.ingress_namespace))
        .with_ingress_pod_selector(args.ingress_selector_label)
        .with_vnc_password_secret(non_empty(args.vnc_password_secret))
}

/// GH-76: `--confirm-apply` and `SANDBOXWICH_K8S_ENABLE_MUTATION=1` are a
/// deliberate double opt-in meant to require both a per-invocation flag and
/// an explicit environment toggle before this process will mutate cluster
/// state. The checked-in worker Deployment (deploy/kubernetes/worker.yaml)
/// sets both unconditionally, because the worker's whole job is to apply
/// sandbox manifests -- there is no working production deployment where the
/// gate is ever actually closed. That's a documented, deliberate choice
/// (see the SECURITY NOTE in the manifest), not silent: this returns a
/// message to surface on every process start so operators see it in logs
/// rather than only in a YAML comment.
fn mutation_gate_force_enabled_warning(
    confirm_apply: bool,
    mutation_enabled: bool,
    sandbox_namespace: &str,
) -> Option<String> {
    if confirm_apply && mutation_enabled {
        Some(format!(
            "warning: Kubernetes mutation gate is force-enabled (--confirm-apply and \
             {KUBERNETES_MUTATION_ENV}=1 are both set); this process will apply/delete real \
             resources in namespace \"{sandbox_namespace}\" for every claimed job with no \
             further per-job confirmation. This is the intended configuration for the \
             checked-in worker Deployment (see deploy/kubernetes/worker.yaml and GH-76 for the \
             residual-risk rationale) -- if this is unexpected, unset {KUBERNETES_MUTATION_ENV} \
             or drop --confirm-apply."
        ))
    } else {
        None
    }
}

fn orphan_reconciliation_apply_enabled(flag: bool, environment: Option<&str>) -> bool {
    flag && environment == Some("1")
}

/// `0` is documented as "fall back to the default" rather than "disable the
/// bound": an unbounded `kubectl` wait is exactly the hang this timeout
/// exists to prevent, so silently accepting `0` as infinite would defeat it.
fn kubectl_command_timeout(secs: u64) -> Duration {
    if secs == 0 {
        Duration::from_secs(provider::DEFAULT_KUBECTL_COMMAND_TIMEOUT_SECS)
    } else {
        Duration::from_secs(secs)
    }
}

fn require_explicit_runtime_image_for_apply(args: &ProviderArgs) -> anyhow::Result<()> {
    if non_empty(args.runtime_image.clone()).is_some() {
        return Ok(());
    }
    anyhow::bail!(
        "apply mode requires --runtime-image or SANDBOXWICH_RUNTIME_IMAGE; \
         refusing the default private guest image so clusters without ghcr.io \
         credentials cannot silently ImagePullBackOff"
    )
}

fn apply_provider_from_args(args: ProviderApplyArgs) -> anyhow::Result<KubernetesApplyProvider> {
    require_explicit_runtime_image_for_apply(&args.provider)?;
    let provider = provider_from_args(args.provider);
    let mutation_enabled = KubernetesApplyProvider::mutation_enabled_from_env();
    if let Some(warning) = mutation_gate_force_enabled_warning(
        args.confirm_apply,
        mutation_enabled,
        provider.effective_sandbox_namespace(),
    ) {
        eprintln!("{warning}");
    }
    Ok(KubernetesApplyProvider::new(provider, args.kubectl)
        .with_kubectl_context(args.kubectl_context)
        .with_mutation_gate(args.confirm_apply, mutation_enabled)
        .with_kubectl_command_timeout(kubectl_command_timeout(args.kubectl_command_timeout_secs))
        .with_max_captured_output_bytes(args.max_captured_output_bytes))
}

fn runtime_provider_from_args(args: RuntimeProviderArgs) -> anyhow::Result<RuntimeProvider> {
    if matches!(args.provider_mode, ProviderModeArg::Apply) {
        require_explicit_runtime_image_for_apply(&args.provider)?;
    }
    let provider = provider_from_args(args.provider);
    Ok(match args.provider_mode {
        ProviderModeArg::DryRun => RuntimeProvider::DryRun(provider),
        ProviderModeArg::Apply => {
            let mutation_enabled = KubernetesApplyProvider::mutation_enabled_from_env();
            if let Some(warning) = mutation_gate_force_enabled_warning(
                args.confirm_apply,
                mutation_enabled,
                provider.effective_sandbox_namespace(),
            ) {
                eprintln!("{warning}");
            }
            RuntimeProvider::Apply(
                KubernetesApplyProvider::new(provider, args.kubectl)
                    .with_kubectl_context(args.kubectl_context)
                    .with_mutation_gate(args.confirm_apply, mutation_enabled)
                    .with_kubectl_command_timeout(kubectl_command_timeout(
                        args.kubectl_command_timeout_secs,
                    ))
                    .with_max_captured_output_bytes(args.max_captured_output_bytes),
            )
        }
    })
}

async fn claim(
    client: &reqwest::Client,
    api: &str,
    args: ClaimArgs,
) -> Result<ClaimLeaseResponse, WorkerRequestError> {
    let response = client
        .post(format!("{api}/workers/{}/leases/claim", args.worker_id))
        .header(
            "idempotency-key",
            args.operation_id.unwrap_or_else(Uuid::now_v7).to_string(),
        )
        .json(&ClaimLeaseRequest {
            lease_seconds: args.lease_seconds,
            // The host-side worker legitimately dispatches every job kind and sandbox
            // its capabilities cover (it's what runs `kubectl exec` etc. on behalf of
            // whichever sandbox a job targets), so it intentionally claims unfiltered
            // -- unlike `sandboxwich-agent`'s guest daemon, which scopes claims to its
            // own sandbox and to `run_command` only.
            sandbox_id: None,
            kinds: None,
        })
        .send()
        .await?;
    decode_json::<ClaimLeaseResponse>(response).await
}

async fn register_worker(
    client: &reqwest::Client,
    api: &str,
    name: String,
    provider: String,
    capabilities: Vec<WorkerCapability>,
    labels: BTreeMap<String, String>,
    max_concurrent_jobs: Option<u32>,
) -> Result<WorkerResponse, WorkerRequestError> {
    let response = client
        .post(format!("{api}/workers/register"))
        .json(&RegisterWorkerRequest {
            name,
            provider,
            capabilities,
            max_concurrent_jobs,
            labels,
        })
        .send()
        .await?;
    decode_json::<WorkerResponse>(response).await
}

async fn heartbeat_worker(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    labels: BTreeMap<String, String>,
) -> Result<WorkerResponse, WorkerRequestError> {
    let response = client
        .post(format!("{api}/workers/{worker_id}/heartbeat"))
        .json(&WorkerHeartbeatRequest {
            max_concurrent_jobs: None,
            labels,
        })
        .send()
        .await?;
    decode_json::<WorkerResponse>(response).await
}

async fn drain_worker(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
) -> Result<(), WorkerRequestError> {
    let response = client
        .post(format!("{api}/workers/{worker_id}/drain"))
        .send()
        .await?;
    let _: WorkerResponse = decode_json(response).await?;
    Ok(())
}

/// Maximum number of attempts (including the first) for a single bounded retry
/// around a control-plane API call.
const API_RETRY_ATTEMPTS: u32 = 5;
/// Starting delay between retries; doubles (capped at [`RETRY_MAX_DELAY`]) after
/// each failed attempt.
const RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);
/// Minimum lease-renewal interval, so short/dry-run leases don't hammer the API.
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(5);
/// Default bound on how long `work_loop` waits for an in-flight lease to finish
/// after a shutdown signal before giving up and exiting anyway (see
/// `wait_for_shutdown_signal` and the `--drain-timeout-secs` flag).
const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 300;
/// How often the drain watchdog polls the shutdown flag while a lease is being
/// handled. Small relative to any realistic drain timeout, so it doesn't add
/// meaningful latency to the shutdown-requested -> timeout-elapsed window.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Fallback lease duration used to size the renewal interval if a lease's
/// `expires_at`/`leased_at` pair is somehow non-positive.
const FALLBACK_LEASE_DURATION: Duration = Duration::from_secs(30);

/// Error from a control-plane HTTP call, distinguishing transient/recoverable
/// failures (connection issues, timeouts, 5xx, 429) from failures that should
/// not be retried. Mirrors `sandboxwich-agent`'s `AgentRequestError`: before
/// this type existed, every HTTP failure collapsed into a plain
/// `anyhow::Error` string in `decode_json`, so `with_retries` could not tell a
/// dropped connection (worth retrying) apart from a `401`/`404`/`409` (a
/// permanent rejection -- e.g. `lease_expired`, `idempotency_key_reused` --
/// that retrying only delays cancel propagation and burns the full retry
/// budget on). `with_retries` uses `is_recoverable` to stop immediately on the
/// latter.
#[derive(Debug)]
enum WorkerRequestError {
    Transport(reqwest::Error),
    Status {
        status: reqwest::StatusCode,
        body: String,
    },
    Decode(serde_json::Error),
}

impl std::fmt::Display for WorkerRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerRequestError::Transport(error) => write!(f, "request failed: {error}"),
            WorkerRequestError::Status { status, body } => {
                write!(f, "request failed with {status}: {body}")
            }
            WorkerRequestError::Decode(error) => {
                write!(f, "failed to decode response body: {error}")
            }
        }
    }
}

impl std::error::Error for WorkerRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WorkerRequestError::Transport(error) => Some(error),
            WorkerRequestError::Status { .. } => None,
            WorkerRequestError::Decode(error) => Some(error),
        }
    }
}

impl From<reqwest::Error> for WorkerRequestError {
    fn from(error: reqwest::Error) -> Self {
        WorkerRequestError::Transport(error)
    }
}

impl WorkerRequestError {
    /// Whether this failure looks transient (worth retrying) rather than a
    /// durable rejection. A decode failure is never recoverable: the server
    /// answered successfully with a body this worker cannot parse, and
    /// retrying the identical request will get the identical body.
    fn is_recoverable(&self) -> bool {
        match self {
            WorkerRequestError::Transport(error) => {
                error.is_timeout() || error.is_connect() || error.is_request()
            }
            WorkerRequestError::Status { status, .. } => {
                status.is_server_error()
                    || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || *status == reqwest::StatusCode::REQUEST_TIMEOUT
            }
            WorkerRequestError::Decode(_) => false,
        }
    }
}

/// Runs `f` up to `attempts` times with exponential backoff between failures.
/// Transient control-plane hiccups (a dropped connection, a 5xx, a timeout) should
/// not be fatal to the worker process; this bounds how long we tolerate them before
/// surfacing the error to the caller. A permanent failure (see
/// `WorkerRequestError::is_recoverable`) stops the retry loop immediately instead
/// of burning the full attempt budget and backoff delay on a request that will
/// never succeed.
async fn with_retries<T, F, Fut>(operation: &str, attempts: u32, f: F) -> anyhow::Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, WorkerRequestError>>,
{
    let mut delay = RETRY_BASE_DELAY;
    let mut last_error = None;
    for attempt in 1..=attempts.max(1) {
        match f().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if !error.is_recoverable() {
                    eprintln!(
                        "warning: {operation} failed with a permanent error, not retrying: {error}"
                    );
                    last_error = Some(error);
                    break;
                }
                if attempt == attempts.max(1) {
                    last_error = Some(error);
                    break;
                }
                eprintln!(
                    "warning: {operation} failed (attempt {attempt}/{attempts}), retrying in {delay:?}: {error}"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RETRY_MAX_DELAY);
                last_error = Some(error);
            }
        }
    }
    Err(last_error
        .map(anyhow::Error::new)
        .unwrap_or_else(|| anyhow::anyhow!("{operation} failed with no error recorded")))
}

/// Uses the provider's typed retry contract. Untyped errors are permanent;
/// user-visible prose never controls scheduling behavior.
fn classify_retry(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ProviderError>())
        .map(|error| {
            debug_assert_eq!(
                error.disposition(),
                match error.error_class() {
                    sandboxwich_core::ProvisioningErrorClass::RetryableProvider
                    | sandboxwich_core::ProvisioningErrorClass::RetryableCapacity => {
                        RetryDisposition::Retryable
                    }
                    sandboxwich_core::ProvisioningErrorClass::TerminalContract
                    | sandboxwich_core::ProvisioningErrorClass::TerminalSecurity => {
                        RetryDisposition::Permanent
                    }
                }
            );
            error.disposition()
        })
        .unwrap_or(RetryDisposition::Permanent)
        == RetryDisposition::Retryable
}

/// Waits for SIGTERM or SIGINT (`Ctrl-C`). On non-Unix targets, only `Ctrl-C`
/// is available. Kubernetes sends SIGTERM to stop a pod, so this must not
/// only cover `ctrl_c()` -- that alone never fires under a real Deployment.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("warning: failed to install SIGTERM handler: {error:#}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Spawns a background task that sets `shutdown` once a shutdown signal
/// arrives, so the main work loop (which is not itself listening for
/// signals mid-iteration) can observe it via a plain flag check.
fn spawn_shutdown_listener() -> Arc<std::sync::atomic::AtomicBool> {
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = shutdown.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        eprintln!(
            "worker: received shutdown signal; will stop claiming new leases and let any \
             in-flight lease finish (bounded by --drain-timeout-secs)"
        );
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    shutdown
}

/// Sleeps for `duration`, but wakes early (and returns) as soon as `shutdown`
/// is observed, so an idle worker doesn't sit through a full idle-sleep
/// interval after a shutdown signal before exiting.
async fn sleep_or_shutdown(duration: Duration, shutdown: &std::sync::atomic::AtomicBool) {
    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(SHUTDOWN_POLL_INTERVAL.min(duration)).await;
    }
}

/// Resolves once `shutdown` has been observed *and* an additional
/// `drain_timeout` has elapsed since. Raced against an in-flight lease's
/// future so a job that never finishes can't hang the worker forever once a
/// shutdown has been requested; the lease itself is left to expire and be
/// reclaimed by another worker if this fires.
async fn drain_watchdog(shutdown: Arc<std::sync::atomic::AtomicBool>, drain_timeout: Duration) {
    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(SHUTDOWN_POLL_INTERVAL).await;
    }
    tokio::time::sleep(drain_timeout).await;
}

async fn fetch_runtime_resource_inventory(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    namespace: &str,
    max_scanned: usize,
) -> anyhow::Result<RuntimeResourceInventoryResponse> {
    let mut resources = Vec::new();
    let mut cursor = None;
    let mut scope = None;
    let mut sandbox_ids = std::collections::HashSet::new();
    let mut complete = true;
    while resources.len() < max_scanned {
        let page_limit = (max_scanned - resources.len()).min(200);
        let mut url = format!(
            "{api}/workers/{worker_id}/runtime-resource-inventory?namespace={namespace}&limit={page_limit}"
        );
        if let Some(after) = cursor.as_deref() {
            url.push_str("&after=");
            url.push_str(after);
        }
        let response = client.get(url).send().await?;
        let page = decode_json::<RuntimeResourceInventoryResponse>(response).await?;
        scope.get_or_insert_with(|| {
            (
                page.provider.clone(),
                page.cluster.clone(),
                page.namespace.clone(),
            )
        });
        sandbox_ids.extend(page.sandbox_ids);
        complete &= page.complete;
        resources.extend(page.resources);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    let (provider, cluster, namespace) =
        scope.unwrap_or_else(|| ("kubernetes".to_string(), None, namespace.to_string()));
    if cursor.is_some() {
        anyhow::bail!("runtime resource inventory exceeded max_scanned={max_scanned}");
    }
    Ok(RuntimeResourceInventoryResponse {
        ok: true,
        provider,
        cluster,
        namespace,
        sandbox_ids: sandbox_ids.into_iter().collect(),
        complete,
        resources,
        next_cursor: cursor,
    })
}

async fn work_loop(client: &reqwest::Client, api: &str, args: WorkLoopArgs) -> anyhow::Result<()> {
    let reconciliation_namespace = args
        .provider
        .provider
        .sandbox_namespace
        .clone()
        .unwrap_or_else(|| args.provider.provider.namespace.clone());
    let reconciliation_interval =
        Duration::from_secs(args.provider.orphan_reconciliation_interval_secs.max(1));
    let reconciliation_limits = ReconciliationLimits {
        max_scanned: args.provider.orphan_reconciliation_max_scanned.max(1),
        max_deleted: args.provider.orphan_reconciliation_max_deleted,
        max_elapsed: Duration::from_secs(
            args.provider.orphan_reconciliation_max_elapsed_secs.max(1),
        ),
    };
    let reconciliation_apply = orphan_reconciliation_apply_enabled(
        args.provider.orphan_reconciliation_apply,
        std::env::var("SANDBOXWICH_ORPHAN_RECONCILIATION_APPLY")
            .ok()
            .as_deref(),
    );
    let provider = Arc::new(runtime_provider_from_args(args.provider)?);
    let labels: BTreeMap<_, _> = args.label.into_iter().collect();
    let drain_timeout = Duration::from_secs(args.drain_timeout_secs);
    let shutdown = spawn_shutdown_listener();
    let mut iterations = 0_u64;
    let mut last_reconciliation = None;

    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!(
                "worker: shutdown requested, exiting work loop before claiming further leases"
            );
            break;
        }
        if args
            .max_iterations
            .map(|max_iterations| iterations >= max_iterations)
            .unwrap_or(false)
        {
            break;
        }
        iterations += 1;

        if let Err(error) = with_retries("worker heartbeat", API_RETRY_ATTEMPTS, || {
            heartbeat_worker(client, api, args.worker_id, labels.clone())
        })
        .await
        {
            eprintln!(
                "error: heartbeat failed after {API_RETRY_ATTEMPTS} attempts, skipping this iteration: {error:#}"
            );
            sleep_or_shutdown(Duration::from_millis(args.idle_sleep_ms), &shutdown).await;
            continue;
        }

        if last_reconciliation
            .is_none_or(|last: std::time::Instant| last.elapsed() >= reconciliation_interval)
        {
            let inventory = fetch_runtime_resource_inventory(
                client,
                api,
                args.worker_id,
                &reconciliation_namespace,
                reconciliation_limits.max_scanned,
            )
            .await;
            let reconciliation_provider = provider.clone();
            let reconciliation = tokio::task::spawn_blocking(move || {
                reconciliation_provider.reconcile_orphans(
                    inventory,
                    reconciliation_limits,
                    reconciliation_apply,
                )
            })
            .await
            .unwrap_or_else(|error| {
                Err(anyhow::anyhow!(
                    "orphan reconciliation task panicked or was cancelled: {error}"
                ))
            });
            match reconciliation {
                Ok(Some((scanned, deleted, apply))) => eprintln!(
                    "worker: orphan reconciliation completed scanned={scanned} deleted={deleted} apply={apply}"
                ),
                Ok(None) => {}
                Err(error) => eprintln!("error: orphan reconciliation failed closed: {error:#}"),
            }
            last_reconciliation = Some(std::time::Instant::now());
        }

        // Re-check right before claiming: a signal received during the heartbeat
        // call/sleep above must still stop us from picking up new work.
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!(
                "worker: shutdown requested, exiting work loop before claiming further leases"
            );
            break;
        }

        let claim_args = ClaimArgs {
            worker_id: args.worker_id,
            lease_seconds: args.lease_seconds,
            operation_id: Some(Uuid::now_v7()),
        };
        let response = match with_retries("claim lease", API_RETRY_ATTEMPTS, || {
            claim(client, api, claim_args)
        })
        .await
        {
            Ok(response) => response,
            Err(error) => {
                eprintln!(
                    "error: claim failed after {API_RETRY_ATTEMPTS} attempts, skipping this iteration: {error:#}"
                );
                sleep_or_shutdown(Duration::from_millis(args.idle_sleep_ms), &shutdown).await;
                continue;
            }
        };

        let Some(lease) = response.lease else {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "iteration": iterations,
                    "idle": true
                }))?
            );
            if args
                .max_iterations
                .map(|max_iterations| iterations < max_iterations)
                .unwrap_or(true)
            {
                sleep_or_shutdown(Duration::from_millis(args.idle_sleep_ms), &shutdown).await;
            }
            continue;
        };

        // Once a lease is claimed, always see it through (bounded by the drain
        // watchdog below) rather than abandoning it -- the claim already
        // happened, so not finishing it just delays the job until the lease
        // expires and gets reclaimed by another worker.
        let lease_id = lease.id;
        let handle_future = handle_lease(client, api, lease, provider.clone());
        let outcome = tokio::select! {
            result = handle_future => Some(result),
            _ = drain_watchdog(shutdown.clone(), drain_timeout) => None,
        };
        let Some(outcome) = outcome else {
            eprintln!(
                "warning: lease {lease_id} did not finish within the {drain_timeout:?} drain \
                 timeout after shutdown was requested; exiting anyway (the lease will expire and \
                 be reclaimed by another worker)"
            );
            break;
        };

        match outcome {
            Ok(response) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "iteration": iterations,
                        "lease": response.lease
                    }))?
                );
            }
            Err(error) => {
                // The job's side effects (if any) already happened; the lease will
                // simply expire and be reclaimed rather than killing the worker.
                eprintln!("error: handling leased job failed, continuing: {error:#}");
            }
        }
    }

    if let Err(error) = with_retries("mark worker draining", API_RETRY_ATTEMPTS, || {
        drain_worker(client, api, args.worker_id)
    })
    .await
    {
        eprintln!("warning: failed to mark worker draining before exit: {error:#}");
    }
    Ok(())
}

async fn handle_lease<P>(
    client: &reqwest::Client,
    api: &str,
    lease: sandboxwich_core::JobLease,
    provider: Arc<P>,
) -> anyhow::Result<LeaseResponse>
where
    P: SandboxProvider + Send + Sync + 'static,
{
    let lease_id = lease.id;

    // Renew the lease in the background for as long as the job is running so long
    // jobs don't have their lease expire (and get re-claimed/duplicated) mid-flight.
    let renew_interval = (lease.expires_at - lease.leased_at)
        .to_std()
        .map(|duration| (duration / 2).max(MIN_RENEW_INTERVAL))
        .unwrap_or(FALLBACK_LEASE_DURATION);
    let renew_client = client.clone();
    let renew_api = api.to_string();
    // Job execution can't be forcibly aborted once it's running on the blocking-pool
    // thread below (blocking tasks can't be cancelled by Tokio), so instead of just
    // logging and looping forever when renewal is lost, flip this signal: the exec
    // path polls it and kills its own `kubectl` invocation, so the job stops running
    // instead of continuing (and possibly being re-queued and executed a second time
    // elsewhere) against a lease this worker can no longer prove is still its own.
    let cancelled = CancelSignal::new();
    let renew_cancelled = cancelled.clone();
    let renew_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(renew_interval).await;
            let payload = RenewLeaseRequest {
                lease_seconds: None,
            };
            let result = with_retries("lease renewal", 3, || async {
                let response = renew_client
                    .post(format!("{renew_api}/leases/{lease_id}/renew"))
                    .json(&payload)
                    .send()
                    .await?;
                decode_json::<LeaseResponse>(response).await
            })
            .await;
            if let Err(error) = result {
                eprintln!(
                    "warning: renewing lease {lease_id} failed after retries: {error:#}; \
                     cancelling the running job instead of letting it keep executing against \
                     a lease we can no longer prove is still ours"
                );
                renew_cancelled.cancel();
                return;
            }
        }
    });

    // Job execution shells out to `kubectl` and blocks synchronously; run it on a
    // blocking-pool thread so it can't stall the async runtime (and the heartbeat/
    // renewal tasks running alongside it).
    let job = lease.job.clone();
    let lease_attempt = lease.attempt;
    let exec_provider = provider.clone();
    let exec_cancelled = cancelled.clone();
    let reporter_client = client.clone();
    let reporter_api = api.to_string();
    let reporter_runtime = tokio::runtime::Handle::current();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut reporter = |update| {
            let (method, url, request) =
                provisioning_stage_request(&reporter_api, lease_id, lease_attempt, update);
            reporter_runtime.block_on(with_retries(
                "report provisioning stage",
                API_RETRY_ATTEMPTS,
                || async {
                    let response = reporter_client
                        .request(method.clone(), &url)
                        .json(&request)
                        .send()
                        .await?;
                    decode_json::<ProvisioningOperationResponse>(response).await
                },
            ))?;
            Ok(())
        };
        execute_job_with_reporter(&job, exec_provider.as_ref(), &exec_cancelled, &mut reporter)
    })
    .await
    .unwrap_or_else(|join_error| {
        Err(anyhow::anyhow!(
            "job execution task panicked or was cancelled: {join_error}"
        ))
    });

    renew_task.abort();
    let _ = renew_task.await;

    match outcome {
        Ok(WorkerJobOutcome::Complete(result)) => {
            let payload = CompleteLeaseRequest {
                result: Some(result),
            };
            with_retries("complete lease", API_RETRY_ATTEMPTS, || async {
                let response = client
                    .post(format!("{api}/leases/{lease_id}/complete"))
                    .json(&payload)
                    .send()
                    .await?;
                decode_json::<LeaseResponse>(response).await
            })
            .await
        }
        Ok(WorkerJobOutcome::Fail { error, retry }) => {
            let payload = FailLeaseRequest { error, retry };
            with_retries("fail lease", API_RETRY_ATTEMPTS, || async {
                let response = client
                    .post(format!("{api}/leases/{lease_id}/fail"))
                    .json(&payload)
                    .send()
                    .await?;
                decode_json::<LeaseResponse>(response).await
            })
            .await
        }
        Err(error) => {
            let payload = FailLeaseRequest {
                error: error.to_string(),
                retry: classify_retry(&error),
            };
            with_retries("fail lease", API_RETRY_ATTEMPTS, || async {
                let response = client
                    .post(format!("{api}/leases/{lease_id}/fail"))
                    .json(&payload)
                    .send()
                    .await?;
                decode_json::<LeaseResponse>(response).await
            })
            .await
        }
    }
}

#[derive(Debug)]
enum WorkerJobOutcome {
    Complete(WorkerJobResult),
    Fail { error: String, retry: bool },
}

fn provisioning_stage_request(
    api: &str,
    lease_id: sandboxwich_core::LeaseId,
    lease_attempt: i64,
    mut request: ProvisioningStageUpdateRequest,
) -> (reqwest::Method, String, ProvisioningStageUpdateRequest) {
    request.attempt_count = lease_attempt;
    (
        reqwest::Method::PUT,
        format!(
            "{}/leases/{lease_id}/provisioning",
            api.trim_end_matches('/')
        ),
        request,
    )
}

#[cfg(test)]
fn execute_job(
    job: &sandboxwich_core::Job,
    provider: &impl SandboxProvider,
    cancelled: &CancelSignal,
) -> anyhow::Result<WorkerJobOutcome> {
    execute_job_with_reporter(job, provider, cancelled, &mut |_| Ok(()))
}

fn execute_job_with_reporter(
    job: &sandboxwich_core::Job,
    provider: &impl SandboxProvider,
    cancelled: &CancelSignal,
    report: &mut dyn FnMut(ProvisioningStageUpdateRequest) -> anyhow::Result<()>,
) -> anyhow::Result<WorkerJobOutcome> {
    match job.kind {
        JobKind::ProvisionSandbox => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            let spec = provision_spec_from_payload(&job.payload)?;
            let mut last_stage = sandboxwich_core::ProvisioningStage::WorkspacePlanned;
            let mut tracking_reporter = |update: ProvisioningStageUpdateRequest| {
                last_stage = update.stage.clone();
                report(update)
            };
            let handle = match provider.provision_staged(
                sandbox_id,
                &spec,
                cancelled,
                &mut tracking_reporter,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    if let Some(provider_error) = error
                        .chain()
                        .find_map(|cause| cause.downcast_ref::<ProviderError>())
                    {
                        report(ProvisioningStageUpdateRequest {
                            stage: last_stage,
                            resource_kind: None,
                            resource_namespace: None,
                            resource_name: None,
                            resource_uid: None,
                            observed_generation: None,
                            attempt_count: job.attempts.max(1),
                            last_error_class: Some(provider_error.error_class()),
                            last_error_code: Some(provider_error.reason_code().to_string()),
                            last_error: Some(provider_error.to_string()),
                        })?;
                    }
                    return Err(error);
                }
            };
            Ok(WorkerJobOutcome::Complete(
                WorkerJobResult::ProvisionSandbox { handle },
            ))
        }
        JobKind::RunCommand => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            // Unlike ProvisionSandbox/ForkSandbox, RunCommand must not silently default
            // an absent provisionSpec: exec_handoff only (re-)provisions when the pod is
            // missing, so a defaulted spec that drifts from what actually provisioned the
            // pod would apply against an immutable Pod field and hard-fail every command.
            let spec = required_provision_spec_from_payload(&job.payload)?;
            let result = provider.exec_handoff(
                sandbox_id,
                &spec,
                agent_request_from_payload(&job.payload)?,
                cancelled,
            )?;
            // A non-zero exit code means the command actually ran to completion inside
            // the sandbox -- that is a successful *lease* outcome (the worker did what
            // it was asked), not an infrastructure failure. Previously this branch
            // reported the lease itself as failed (`FailLeaseRequest { retry: false }`),
            // which discarded the typed `AgentCommandResult` (dropping stdout entirely,
            // since only `stderr` was forwarded as the error text) and conflated "the
            // command exited 1" with "the worker couldn't run it at all". Always
            // complete the lease with the full result; the API's
            // `apply_completed_job_on_connection` derives the command's own
            // Finished/Failed status from `exit_code`.
            Ok(WorkerJobOutcome::Complete(WorkerJobResult::RunCommand {
                result,
            }))
        }
        JobKind::RunPrompt => Ok(WorkerJobOutcome::Complete(WorkerJobResult::RunPrompt {
            output: prompt_output_from_payload(&job.payload)?,
        })),
        JobKind::CreateSnapshot => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            let snapshot_id = snapshot_id_from_payload(&job.payload)?;
            let handle = provider.create_snapshot(sandbox_id, snapshot_id, cancelled)?;
            Ok(WorkerJobOutcome::Complete(
                WorkerJobResult::CreateSnapshot { handle },
            ))
        }
        JobKind::ForkSandbox => {
            let parent_sandbox_id = parent_sandbox_id_from_payload(&job.payload)?;
            let child_sandbox_id = child_sandbox_id_from_payload(&job.payload)?;
            let snapshot_id = snapshot_id_from_payload(&job.payload)?;
            let spec = provision_spec_from_payload(&job.payload)?;
            let handle = provider.fork(
                parent_sandbox_id,
                child_sandbox_id,
                snapshot_id,
                &spec,
                cancelled,
            )?;
            Ok(WorkerJobOutcome::Complete(WorkerJobResult::ForkSandbox {
                handle,
            }))
        }
        JobKind::StopSandbox => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            let teardown_spec = teardown_spec_from_payload(&job.payload)?;
            // Actually tear down the sandbox's resources; propagate provider errors so
            // the job is failed (and retried per its classification) instead of the
            // control plane recording a "stopped" sandbox that keeps running.
            provider.stop(sandbox_id, &teardown_spec, cancelled)?;
            Ok(WorkerJobOutcome::Complete(WorkerJobResult::StopSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id,
            }))
        }
        JobKind::ResumeSandbox => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            // Decision: stopping a sandbox tears down its Pod/PVC/Services/NetworkPolicy
            // (see StopSandbox above and provider::SandboxProvider::stop), so there is no
            // live workload left to resume. Rather than silently reporting success on a
            // sandbox that in fact no longer exists, fail the job explicitly and point
            // callers at provisioning a replacement (optionally forked from a snapshot).
            // A "true" resume (restoring a stopped-but-not-deleted sandbox) is not
            // implemented; revisit if StopSandbox gains a suspend-in-place mode.
            Ok(WorkerJobOutcome::Fail {
                error: format!(
                    "resume is not supported: stopping sandbox {sandbox_id} tears down its resources; provision a new sandbox (or fork from a snapshot) instead"
                ),
                retry: false,
            })
        }
    }
}

fn parse_label(value: &str) -> Result<(String, String), String> {
    let Some((key, value)) = value.split_once('=') else {
        return Err("labels must be formatted as key=value".to_string());
    };
    if key.trim().is_empty() {
        return Err("label key cannot be empty".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}

fn agent_request_from_payload(payload: &serde_json::Value) -> anyhow::Result<AgentCommandRequest> {
    let argv = payload
        .get("argv")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("job payload is missing argv"))?;
    let argv = serde_json::from_value(argv).context("job payload argv is invalid")?;
    let cwd = match payload.get("cwd") {
        Some(value) if !value.is_null() => {
            Some(serde_json::from_value(value.clone()).context("job payload cwd is invalid")?)
        }
        _ => None,
    };
    let env = payload
        .get("env")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("job payload env is invalid")?
        .unwrap_or_else(BTreeMap::new);
    let timeout_secs = payload.get("timeoutSecs").and_then(|value| value.as_u64());

    Ok(AgentCommandRequest {
        argv,
        cwd,
        env,
        timeout_secs,
    })
}

fn prompt_output_from_payload(payload: &serde_json::Value) -> anyhow::Result<String> {
    let instructions = payload
        .get("instructions")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("prompt job is missing instructions"))?;
    Ok(format!(
        "dry-run prompt accepted: {}",
        instructions.lines().next().unwrap_or_default()
    ))
}

fn provision_spec_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<SandboxProvisionSpec> {
    payload
        .get("provisionSpec")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("job payload provisionSpec is invalid")
        .map(|spec| spec.unwrap_or_default())
}

/// Like [`provision_spec_from_payload`], but rejects a missing `provisionSpec`
/// instead of defaulting it. Used for RunCommand, where a defaulted spec that
/// disagrees with whatever spec the sandbox was actually provisioned with would
/// silently corrupt exec's "only provision if missing" fast path.
fn required_provision_spec_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<SandboxProvisionSpec> {
    let value = payload
        .get("provisionSpec")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("job payload is missing provisionSpec"))?;
    serde_json::from_value(value).context("job payload provisionSpec is invalid")
}

fn sandbox_id_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<sandboxwich_core::SandboxId> {
    Ok(sandboxwich_core::SandboxId(uuid_from_payload(
        payload,
        "sandboxId",
    )?))
}

fn teardown_spec_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<provider::SandboxTeardownSpec> {
    let delete_gke_fqdn_policy = match payload.get("deleteGkeFqdnPolicy") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("job payload deleteGkeFqdnPolicy is invalid"))?,
    };
    Ok(provider::SandboxTeardownSpec {
        delete_gke_fqdn_policy,
    })
}

fn parent_sandbox_id_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<sandboxwich_core::SandboxId> {
    Ok(sandboxwich_core::SandboxId(uuid_from_payload(
        payload,
        "parentSandboxId",
    )?))
}

fn child_sandbox_id_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<sandboxwich_core::SandboxId> {
    Ok(sandboxwich_core::SandboxId(uuid_from_payload(
        payload,
        "childSandboxId",
    )?))
}

fn snapshot_id_from_payload(
    payload: &serde_json::Value,
) -> anyhow::Result<sandboxwich_core::SnapshotId> {
    Ok(sandboxwich_core::SnapshotId(uuid_from_payload(
        payload,
        "snapshotId",
    )?))
}

fn uuid_from_payload(payload: &serde_json::Value, field: &'static str) -> anyhow::Result<Uuid> {
    payload
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("job payload is missing {field}"))?
        .parse()
        .with_context(|| format!("job payload {field} is invalid"))
}

fn capabilities_from_args(
    capabilities: Vec<CapabilityArg>,
    runtime_class_name: Option<&str>,
    fqdn_egress_backend: bool,
) -> Vec<WorkerCapability> {
    if capabilities.is_empty() {
        let mut defaults = vec![
            WorkerCapability::K8sPod,
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::RunCommand,
            WorkerCapability::Snapshot,
            WorkerCapability::DesktopStream,
        ];
        if runtime_class_name.is_some_and(|value| !value.trim().is_empty()) {
            defaults.push(WorkerCapability::GvisorSandbox);
        }
        if fqdn_egress_backend {
            defaults.push(WorkerCapability::FqdnEgress);
        }
        defaults
    } else {
        capabilities.into_iter().map(to_capability).collect()
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

async fn print_json<T>(response: reqwest::Response) -> anyhow::Result<()>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value = decode_json::<T>(response).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn decode_json<T>(response: reqwest::Response) -> Result<T, WorkerRequestError>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(WorkerRequestError::Status { status, body });
    }

    serde_json::from_str(&body).map_err(WorkerRequestError::Decode)
}

fn to_capability(value: CapabilityArg) -> WorkerCapability {
    match value {
        CapabilityArg::ProvisionSandbox => WorkerCapability::ProvisionSandbox,
        CapabilityArg::RunCommand => WorkerCapability::RunCommand,
        CapabilityArg::Snapshot => WorkerCapability::Snapshot,
        CapabilityArg::DesktopStream => WorkerCapability::DesktopStream,
        CapabilityArg::FqdnEgress => WorkerCapability::FqdnEgress,
        CapabilityArg::K8sPod => WorkerCapability::K8sPod,
        CapabilityArg::GvisorSandbox => WorkerCapability::GvisorSandbox,
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
