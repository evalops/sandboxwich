mod provider;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use provider::{
    CancelSignal, KUBERNETES_MUTATION_ENV, KubernetesApplyProvider, KubernetesDryRunProvider,
    SandboxProvider,
};
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, ClaimLeaseRequest, ClaimLeaseResponse,
    CompleteLeaseRequest, FailLeaseRequest, JobKind, LeaseResponse, RegisterWorkerRequest,
    RenewLeaseRequest, SandboxProvisionSpec, WorkerCapability, WorkerHeartbeatRequest,
    WorkerJobResult, WorkerResponse, build_api_client,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-worker")]
#[command(about = "Host-side worker for sandbox orchestration")]
struct Cli {
    #[arg(long, env = "SANDBOXWICH_API", default_value = "http://127.0.0.1:3217")]
    api: String,

    #[arg(long, env = "SANDBOXWICH_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "SANDBOXWICH_TENANT")]
    tenant: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

    #[arg(long, env = "SANDBOXWICH_WORKSPACE_STORAGE")]
    workspace_storage: Option<String>,

    #[arg(long)]
    ssh_authorized_keys_secret: Option<String>,

    #[arg(long, env = "SANDBOXWICH_RUNTIME_CLASS_NAME")]
    runtime_class_name: Option<String>,

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

    /// CIDRs excluded from any `0.0.0.0/0` egress rule via NetworkPolicy
    /// `except`, so sandboxes can never reach the control plane or cloud
    /// metadata endpoints even in AllowAll mode (GH-66).
    #[arg(
        long = "egress-excluded-cidr",
        env = "SANDBOXWICH_EGRESS_EXCLUDED_CIDRS",
        value_delimiter = ','
    )]
    egress_excluded_cidrs: Vec<String>,

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

    /// Secret providing SANDBOXWICH_VNC_PASSWORD to the sandbox container
    /// (GH-67).
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
}

#[derive(Clone, Debug, ValueEnum)]
enum CapabilityArg {
    ProvisionSandbox,
    RunCommand,
    AgentPrompt,
    Snapshot,
    DesktopStream,
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
    ) -> anyhow::Result<sandboxwich_core::ProviderSandboxHandle> {
        match self {
            Self::DryRun(provider) => provider.provision(sandbox_id, spec),
            Self::Apply(provider) => provider.provision(sandbox_id, spec),
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
    ) -> anyhow::Result<sandboxwich_core::ProviderSnapshotHandle> {
        match self {
            Self::DryRun(provider) => provider.create_snapshot(sandbox_id, snapshot_id),
            Self::Apply(provider) => provider.create_snapshot(sandbox_id, snapshot_id),
        }
    }

    fn fork(
        &self,
        parent_sandbox_id: sandboxwich_core::SandboxId,
        child_sandbox_id: sandboxwich_core::SandboxId,
        snapshot_id: sandboxwich_core::SnapshotId,
        spec: &SandboxProvisionSpec,
    ) -> anyhow::Result<sandboxwich_core::ProviderForkHandle> {
        match self {
            Self::DryRun(provider) => {
                provider.fork(parent_sandbox_id, child_sandbox_id, snapshot_id, spec)
            }
            Self::Apply(provider) => {
                provider.fork(parent_sandbox_id, child_sandbox_id, snapshot_id, spec)
            }
        }
    }

    fn stop(&self, sandbox_id: sandboxwich_core::SandboxId) -> anyhow::Result<()> {
        match self {
            Self::DryRun(provider) => provider.stop(sandbox_id),
            Self::Apply(provider) => provider.stop(sandbox_id),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let api = cli.api.trim_end_matches('/').to_string();
    let client = build_api_client(cli.api_token.as_deref(), cli.tenant.as_deref())?;

    match cli.command {
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
            let provision = provider.provision(sandbox_id, &spec)?;
            let snapshot = provider.create_snapshot(sandbox_id, snapshot_id)?;
            let fork = provider.fork(sandbox_id, child_sandbox_id, snapshot_id, &spec)?;
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
            let provider = apply_provider_from_args(args);
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
            let provider = apply_provider_from_args(args);
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
                capabilities_from_args(args.capability, None),
                args.label.into_iter().collect(),
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
            let capabilities = capabilities_from_args(args.capability, runtime_class_name);
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
            work_loop(
                &client,
                &api,
                WorkLoopArgs {
                    worker_id: response.worker.id.0,
                    lease_seconds: args.lease_seconds,
                    idle_sleep_ms: args.idle_sleep_ms,
                    max_iterations: args.max_iterations,
                    label: labels.into_iter().collect(),
                    provider: args.provider,
                },
            )
            .await?;
        }
        Command::WorkOnce(args) => {
            let provider = Arc::new(runtime_provider_from_args(args.provider));
            let response = claim(
                &client,
                &api,
                ClaimArgs {
                    worker_id: args.worker_id,
                    lease_seconds: args.lease_seconds,
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
            work_loop(&client, &api, args).await?;
        }
    }

    Ok(())
}

fn provider_from_args(args: ProviderArgs) -> KubernetesDryRunProvider {
    KubernetesDryRunProvider::with_snapshot_class(
        args.cluster,
        args.namespace,
        non_empty(args.storage_class),
        non_empty(args.snapshot_class),
    )
    .with_runtime_image(non_empty(args.runtime_image))
    .with_workspace_storage(non_empty(args.workspace_storage))
    .with_ssh_authorized_keys_secret(non_empty(args.ssh_authorized_keys_secret))
    .with_runtime_class_name(non_empty(args.runtime_class_name))
    .with_sandbox_namespace(non_empty(args.sandbox_namespace))
    .with_dns_namespace(non_empty(args.dns_namespace))
    .with_egress_excluded_cidrs(args.egress_excluded_cidrs)
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

fn apply_provider_from_args(args: ProviderApplyArgs) -> KubernetesApplyProvider {
    let provider = provider_from_args(args.provider);
    let mutation_enabled = KubernetesApplyProvider::mutation_enabled_from_env();
    if let Some(warning) = mutation_gate_force_enabled_warning(
        args.confirm_apply,
        mutation_enabled,
        provider.effective_sandbox_namespace(),
    ) {
        eprintln!("{warning}");
    }
    KubernetesApplyProvider::new(provider, args.kubectl)
        .with_kubectl_context(args.kubectl_context)
        .with_mutation_gate(args.confirm_apply, mutation_enabled)
        .with_kubectl_command_timeout(kubectl_command_timeout(args.kubectl_command_timeout_secs))
}

fn runtime_provider_from_args(args: RuntimeProviderArgs) -> RuntimeProvider {
    let provider = provider_from_args(args.provider);
    match args.provider_mode {
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
                    )),
            )
        }
    }
}

async fn claim(
    client: &reqwest::Client,
    api: &str,
    args: ClaimArgs,
) -> anyhow::Result<ClaimLeaseResponse> {
    let response = client
        .post(format!("{api}/workers/{}/leases/claim", args.worker_id))
        .json(&ClaimLeaseRequest {
            lease_seconds: args.lease_seconds,
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
) -> anyhow::Result<WorkerResponse> {
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
) -> anyhow::Result<WorkerResponse> {
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

/// Maximum number of attempts (including the first) for a single bounded retry
/// around a control-plane API call.
const API_RETRY_ATTEMPTS: u32 = 5;
/// Starting delay between retries; doubles (capped at [`RETRY_MAX_DELAY`]) after
/// each failed attempt.
const RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);
/// Minimum lease-renewal interval, so short/dry-run leases don't hammer the API.
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(5);
/// Fallback lease duration used to size the renewal interval if a lease's
/// `expires_at`/`leased_at` pair is somehow non-positive.
const FALLBACK_LEASE_DURATION: Duration = Duration::from_secs(30);

/// Runs `f` up to `attempts` times with exponential backoff between failures.
/// Transient control-plane hiccups (a dropped connection, a 5xx, a timeout) should
/// not be fatal to the worker process; this bounds how long we tolerate them before
/// surfacing the error to the caller.
async fn with_retries<T, F, Fut>(operation: &str, attempts: u32, f: F) -> anyhow::Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut delay = RETRY_BASE_DELAY;
    let mut last_error = None;
    for attempt in 1..=attempts.max(1) {
        match f().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if attempt == attempts.max(1) {
                    last_error = Some(error);
                    break;
                }
                eprintln!(
                    "warning: {operation} failed (attempt {attempt}/{attempts}), retrying in {delay:?}: {error:#}"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RETRY_MAX_DELAY);
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{operation} failed with no error recorded")))
}

/// Heuristically classifies whether an error looks like a transient infrastructure
/// problem (network blip, timeout, rate limit, control-plane unavailability) as
/// opposed to a permanent/logical failure (bad manifest, immutable field conflict,
/// malformed payload). Provider errors here are plain `anyhow` strings rather than
/// structured types, so this inspects the rendered error chain for well-known
/// transient markers.
fn classify_retry(error: &anyhow::Error) -> bool {
    const TRANSIENT_MARKERS: &[&str] = &[
        "timeout",
        "timed out",
        "connection refused",
        "connection reset",
        "temporarily unavailable",
        "context deadline exceeded",
        "too many requests",
        "service unavailable",
        "dial tcp",
        "unable to connect to the server",
        "broken pipe",
        "i/o error",
        " 429",
        " 503",
        // Emitted when `run_kubectl_command`'s cancellation race (see
        // `CancelSignal`) kills a `kubectl exec` because this job's lease
        // renewal failed. We can't always tell whether that means the lease
        // is genuinely gone (the common case, in which the server's expiry
        // sweep has already re-queued the job elsewhere and this retry flag
        // is moot) or was a transient renewal blip against a still-active
        // lease (in which case marking this non-retryable would silently
        // drop the job) -- treat it as retryable so the latter, worse case
        // can't happen.
        "lease renewal was lost",
    ];
    error.chain().any(|cause| {
        let text = cause.to_string().to_lowercase();
        TRANSIENT_MARKERS.iter().any(|marker| text.contains(marker))
    })
}

async fn work_loop(client: &reqwest::Client, api: &str, args: WorkLoopArgs) -> anyhow::Result<()> {
    let provider = Arc::new(runtime_provider_from_args(args.provider));
    let labels: BTreeMap<_, _> = args.label.into_iter().collect();
    let mut iterations = 0_u64;

    loop {
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
            tokio::time::sleep(Duration::from_millis(args.idle_sleep_ms)).await;
            continue;
        }

        let claim_args = ClaimArgs {
            worker_id: args.worker_id,
            lease_seconds: args.lease_seconds,
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
                tokio::time::sleep(Duration::from_millis(args.idle_sleep_ms)).await;
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
                tokio::time::sleep(Duration::from_millis(args.idle_sleep_ms)).await;
            }
            continue;
        };

        match handle_lease(client, api, lease, provider.clone()).await {
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
    let exec_provider = provider.clone();
    let exec_cancelled = cancelled.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        execute_job(&job, exec_provider.as_ref(), &exec_cancelled)
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

fn execute_job(
    job: &sandboxwich_core::Job,
    provider: &impl SandboxProvider,
    cancelled: &CancelSignal,
) -> anyhow::Result<WorkerJobOutcome> {
    match job.kind {
        JobKind::ProvisionSandbox => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            let spec = provision_spec_from_payload(&job.payload)?;
            let handle = provider.provision(sandbox_id, &spec)?;
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
            if result.exit_code.unwrap_or(1) == 0 {
                Ok(WorkerJobOutcome::Complete(WorkerJobResult::RunCommand {
                    result,
                }))
            } else {
                Ok(WorkerJobOutcome::Fail {
                    error: result.stderr,
                    retry: false,
                })
            }
        }
        JobKind::RunPrompt => Ok(WorkerJobOutcome::Complete(WorkerJobResult::RunPrompt {
            output: prompt_output_from_payload(&job.payload)?,
        })),
        JobKind::CreateSnapshot => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            let snapshot_id = snapshot_id_from_payload(&job.payload)?;
            let handle = provider.create_snapshot(sandbox_id, snapshot_id)?;
            Ok(WorkerJobOutcome::Complete(
                WorkerJobResult::CreateSnapshot { handle },
            ))
        }
        JobKind::ForkSandbox => {
            let parent_sandbox_id = parent_sandbox_id_from_payload(&job.payload)?;
            let child_sandbox_id = child_sandbox_id_from_payload(&job.payload)?;
            let snapshot_id = snapshot_id_from_payload(&job.payload)?;
            let spec = provision_spec_from_payload(&job.payload)?;
            let handle = provider.fork(parent_sandbox_id, child_sandbox_id, snapshot_id, &spec)?;
            Ok(WorkerJobOutcome::Complete(WorkerJobResult::ForkSandbox {
                handle,
            }))
        }
        JobKind::StopSandbox => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            // Actually tear down the sandbox's resources; propagate provider errors so
            // the job is failed (and retried per its classification) instead of the
            // control plane recording a "stopped" sandbox that keeps running.
            provider.stop(sandbox_id)?;
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
) -> Vec<WorkerCapability> {
    if capabilities.is_empty() {
        let mut defaults = vec![
            WorkerCapability::K8sPod,
            WorkerCapability::ProvisionSandbox,
            WorkerCapability::RunCommand,
            WorkerCapability::AgentPrompt,
            WorkerCapability::Snapshot,
            WorkerCapability::DesktopStream,
        ];
        if runtime_class_name.is_some_and(|value| !value.trim().is_empty()) {
            defaults.push(WorkerCapability::GvisorSandbox);
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

async fn decode_json<T>(response: reqwest::Response) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read response body")?;
    if !status.is_success() {
        bail!("request failed with {status}: {body}");
    }

    serde_json::from_str(&body).context("failed to decode response body")
}

fn to_capability(value: CapabilityArg) -> WorkerCapability {
    match value {
        CapabilityArg::ProvisionSandbox => WorkerCapability::ProvisionSandbox,
        CapabilityArg::RunCommand => WorkerCapability::RunCommand,
        CapabilityArg::AgentPrompt => WorkerCapability::AgentPrompt,
        CapabilityArg::Snapshot => WorkerCapability::Snapshot,
        CapabilityArg::DesktopStream => WorkerCapability::DesktopStream,
        CapabilityArg::K8sPod => WorkerCapability::K8sPod,
        CapabilityArg::GvisorSandbox => WorkerCapability::GvisorSandbox,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sandboxwich_core::{
        Job, JobId, JobStatus, RuntimeResourceKind, RuntimeResourcePurpose, SandboxId, SnapshotId,
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
    fn dispatches_command_job_to_provider_exec_handoff() {
        let sandbox_id = SandboxId::new();
        let spec = SandboxProvisionSpec {
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
        let capabilities = capabilities_from_args(Vec::new(), None);

        assert!(capabilities.contains(&WorkerCapability::ProvisionSandbox));
        assert!(capabilities.contains(&WorkerCapability::RunCommand));
        assert!(capabilities.contains(&WorkerCapability::AgentPrompt));
        assert!(capabilities.contains(&WorkerCapability::Snapshot));
        assert!(capabilities.contains(&WorkerCapability::K8sPod));
        assert!(!capabilities.contains(&WorkerCapability::GvisorSandbox));
    }

    #[test]
    fn default_registration_capabilities_include_gvisor_when_runtime_class_is_configured() {
        let capabilities = capabilities_from_args(Vec::new(), Some("gvisor"));

        assert!(capabilities.contains(&WorkerCapability::GvisorSandbox));
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
    fn classify_retry_flags_transient_infrastructure_errors_as_retryable() {
        let timeout = anyhow::anyhow!(
            "kubectl apply sandbox manifests failed with exit status: 1: Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout"
        );
        assert!(classify_retry(&timeout));

        let reset = anyhow::anyhow!("failed to run kubectl for execute sandbox command")
            .context("read tcp 10.0.0.1:6443->10.0.0.2:51522: connection reset by peer");
        assert!(classify_retry(&reset));

        let rate_limited = anyhow::anyhow!(
            "kubectl apply sandbox manifests failed with exit status: 1: Error from server (Too Many Requests): rate limited"
        );
        assert!(classify_retry(&rate_limited));

        let cancelled_by_lost_renewal = anyhow::anyhow!(
            "kubectl execute sandbox command was cancelled because lease renewal was lost; the \
             job is being abandoned so it isn't run twice"
        );
        assert!(classify_retry(&cancelled_by_lost_renewal));
    }

    #[test]
    fn classify_retry_treats_permanent_provider_errors_as_non_retryable() {
        let immutable_field = anyhow::anyhow!(
            "kubectl apply sandbox manifests failed with exit status: 1: Pod \"sandboxwich-x\" is invalid: spec.containers[0].resources: Forbidden: field is immutable"
        );
        assert!(!classify_retry(&immutable_field));

        let malformed_payload = anyhow::anyhow!("job payload is missing sandboxId");
        assert!(!classify_retry(&malformed_payload));
    }

    #[tokio::test]
    async fn with_retries_recovers_after_transient_failures() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let attempts = AtomicU32::new(0);
        let result = with_retries("test op", 3, || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if attempt < 3 {
                    Err(anyhow::anyhow!("connection reset by peer"))
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
            async { Err(anyhow::anyhow!("still broken")) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn mutation_gate_warning_fires_only_when_both_halves_are_set() {
        assert!(
            mutation_gate_force_enabled_warning(false, false, "sandboxwich-sandboxes").is_none()
        );
        assert!(
            mutation_gate_force_enabled_warning(true, false, "sandboxwich-sandboxes").is_none()
        );
        assert!(
            mutation_gate_force_enabled_warning(false, true, "sandboxwich-sandboxes").is_none()
        );

        let warning = mutation_gate_force_enabled_warning(true, true, "sandboxwich-sandboxes")
            .expect("both halves set should produce a warning");
        assert!(warning.contains("force-enabled"));
        assert!(warning.contains(KUBERNETES_MUTATION_ENV));
        assert!(warning.contains("sandboxwich-sandboxes"));
        assert!(warning.contains("GH-76"));
    }
}
