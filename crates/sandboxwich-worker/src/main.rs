mod provider;

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use provider::{KubernetesApplyProvider, KubernetesDryRunProvider, SandboxProvider};
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

#[derive(Debug, Args)]
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
    ) -> anyhow::Result<sandboxwich_core::AgentCommandResult> {
        match self {
            Self::DryRun(provider) => provider.exec_handoff(sandbox_id, spec, request),
            Self::Apply(provider) => provider.exec_handoff(sandbox_id, spec, request),
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
                },
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
            let provider = runtime_provider_from_args(args.provider);
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
            let response = handle_lease(&client, &api, lease, &provider).await?;
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

fn apply_provider_from_args(args: ProviderApplyArgs) -> KubernetesApplyProvider {
    KubernetesApplyProvider::new(provider_from_args(args.provider), args.kubectl)
        .with_kubectl_context(args.kubectl_context)
        .with_mutation_gate(
            args.confirm_apply,
            KubernetesApplyProvider::mutation_enabled_from_env(),
        )
}

fn runtime_provider_from_args(args: RuntimeProviderArgs) -> RuntimeProvider {
    let provider = provider_from_args(args.provider);
    match args.provider_mode {
        ProviderModeArg::DryRun => RuntimeProvider::DryRun(provider),
        ProviderModeArg::Apply => RuntimeProvider::Apply(
            KubernetesApplyProvider::new(provider, args.kubectl)
                .with_kubectl_context(args.kubectl_context)
                .with_mutation_gate(
                    args.confirm_apply,
                    KubernetesApplyProvider::mutation_enabled_from_env(),
                ),
        ),
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

async fn work_loop(client: &reqwest::Client, api: &str, args: WorkLoopArgs) -> anyhow::Result<()> {
    let provider = runtime_provider_from_args(args.provider);
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
        heartbeat_worker(client, api, args.worker_id, labels.clone()).await?;

        let response = claim(
            client,
            api,
            ClaimArgs {
                worker_id: args.worker_id,
                lease_seconds: args.lease_seconds,
            },
        )
        .await?;

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

        let response = handle_lease(client, api, lease, &provider).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "iteration": iterations,
                "lease": response.lease
            }))?
        );
    }

    Ok(())
}

async fn handle_lease(
    client: &reqwest::Client,
    api: &str,
    lease: sandboxwich_core::JobLease,
    provider: &impl SandboxProvider,
) -> anyhow::Result<LeaseResponse> {
    match execute_job(&lease.job, provider) {
        Ok(WorkerJobOutcome::Complete(result)) => {
            let response = client
                .post(format!("{api}/leases/{}/complete", lease.id))
                .json(&CompleteLeaseRequest {
                    result: Some(result),
                })
                .send()
                .await?;
            decode_json::<LeaseResponse>(response).await
        }
        Ok(WorkerJobOutcome::Fail { error, retry }) => {
            let response = client
                .post(format!("{api}/leases/{}/fail", lease.id))
                .json(&FailLeaseRequest { error, retry })
                .send()
                .await?;
            decode_json::<LeaseResponse>(response).await
        }
        Err(error) => {
            let response = client
                .post(format!("{api}/leases/{}/fail", lease.id))
                .json(&FailLeaseRequest {
                    error: error.to_string(),
                    retry: false,
                })
                .send()
                .await?;
            decode_json::<LeaseResponse>(response).await
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
            let spec = provision_spec_from_payload(&job.payload)?;
            let result = provider.exec_handoff(
                sandbox_id,
                &spec,
                agent_request_from_payload(&job.payload)?,
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
            Ok(WorkerJobOutcome::Complete(WorkerJobResult::StopSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id,
            }))
        }
        JobKind::ResumeSandbox => {
            let sandbox_id = sandbox_id_from_payload(&job.payload)?;
            Ok(WorkerJobOutcome::Complete(WorkerJobResult::ResumeSandbox {
                provider: "kubernetes".to_string(),
                sandbox_id,
            }))
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

    Ok(AgentCommandRequest { argv, cwd, env })
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
    value.and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
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
        )
        .expect_err("missing sandboxId should fail");

        assert!(error.to_string().contains("sandboxId"));
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
}
