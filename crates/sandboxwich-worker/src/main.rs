mod provider;

use std::{collections::BTreeMap, process::Command as ProcessCommand};

use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use provider::{KubernetesApplyProvider, KubernetesDryRunProvider, SandboxProvider};
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, ClaimLeaseRequest, ClaimLeaseResponse,
    CompleteLeaseRequest, FailLeaseRequest, JobKind, LeaseResponse, RegisterWorkerRequest,
    RenewLeaseRequest, WorkerCapability, WorkerHeartbeatRequest, WorkerResponse,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-worker")]
#[command(about = "Host-side worker for sandbox orchestration")]
struct Cli {
    #[arg(long, env = "SANDBOXWICH_API", default_value = "http://127.0.0.1:3217")]
    api: String,

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
    WorkOnce(ClaimArgs),
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
}

#[derive(Debug, Args)]
struct HeartbeatArgs {
    worker_id: Uuid,

    #[arg(long = "label", value_parser = parse_label)]
    label: Vec<(String, String)>,
}

#[derive(Debug, Args)]
struct ClaimArgs {
    worker_id: Uuid,

    #[arg(long)]
    lease_seconds: Option<u64>,
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

#[derive(Debug, Args)]
struct ProviderArgs {
    #[arg(long, default_value = "k3s-dev")]
    cluster: String,

    #[arg(long, default_value = "sandboxwich")]
    namespace: String,

    #[arg(long)]
    storage_class: Option<String>,

    #[arg(long)]
    snapshot_class: Option<String>,
}

#[derive(Debug, Args)]
struct ProviderApplyArgs {
    #[command(flatten)]
    provider: ProviderArgs,

    #[arg(long, default_value = "kubectl")]
    kubectl: String,

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let api = cli.api.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();

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
                        "k8s_pod"
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
            let exec = provider.exec_handoff(
                sandbox_id,
                AgentCommandRequest {
                    argv: vec!["echo".to_string(), "sandboxwich".to_string()],
                    cwd: None,
                    env: BTreeMap::new(),
                },
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "provider": provider.capability_report(),
                    "health": provider.health_report(),
                    "provision": provider.provision(sandbox_id),
                    "exec": exec,
                    "snapshot": provider.create_snapshot(sandbox_id, snapshot_id),
                    "fork": provider.fork(sandbox_id, child_sandbox_id, snapshot_id)
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
            let capabilities = if args.capability.is_empty() {
                vec![WorkerCapability::K8sPod, WorkerCapability::RunCommand]
            } else {
                args.capability.into_iter().map(to_capability).collect()
            };
            let response = client
                .post(format!("{api}/workers/register"))
                .json(&RegisterWorkerRequest {
                    name: args.name,
                    provider: args.provider,
                    capabilities,
                    labels: args.label.into_iter().collect(),
                })
                .send()
                .await?;
            print_json::<WorkerResponse>(response).await?;
        }
        Command::Heartbeat(args) => {
            let response = client
                .post(format!("{api}/workers/{}/heartbeat", args.worker_id))
                .json(&WorkerHeartbeatRequest {
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
            let response = client
                .post(format!("{api}/leases/{}/complete", args.lease_id))
                .json(&CompleteLeaseRequest {
                    result: Some(json!({
                        "stdout": args.stdout,
                        "stderr": args.stderr,
                        "exitCode": args.exit_code
                    })),
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
        Command::WorkOnce(args) => {
            let response = claim(&client, &api, args).await?;
            let Some(lease) = response.lease else {
                println!("{}", serde_json::to_string_pretty(&response)?);
                return Ok(());
            };
            match lease.job.kind {
                JobKind::RunCommand => {
                    let result =
                        execute_local_agent(agent_request_from_payload(&lease.job.payload)?)?;
                    let exit_code = result.exit_code.unwrap_or(1);
                    let endpoint = if exit_code == 0 { "complete" } else { "fail" };
                    let body = if exit_code == 0 {
                        serde_json::to_value(CompleteLeaseRequest {
                            result: Some(serde_json::to_value(&result)?),
                        })?
                    } else {
                        serde_json::to_value(FailLeaseRequest {
                            error: result.stderr.clone(),
                            retry: false,
                        })?
                    };
                    let response = client
                        .post(format!("{api}/leases/{}/{endpoint}", lease.id))
                        .json(&body)
                        .send()
                        .await?;
                    print_json::<LeaseResponse>(response).await?;
                }
                JobKind::RunPrompt => {
                    let response = client
                        .post(format!("{api}/leases/{}/complete", lease.id))
                        .json(&CompleteLeaseRequest {
                            result: Some(json!({
                                "output": prompt_output_from_payload(&lease.job.payload)?
                            })),
                        })
                        .send()
                        .await?;
                    print_json::<LeaseResponse>(response).await?;
                }
                _ => {
                    let response = client
                        .post(format!("{api}/leases/{}/fail", lease.id))
                        .json(&FailLeaseRequest {
                            error: "worker does not implement this job kind yet".to_string(),
                            retry: true,
                        })
                        .send()
                        .await?;
                    print_json::<LeaseResponse>(response).await?;
                }
            }
        }
    }

    Ok(())
}

fn provider_from_args(args: ProviderArgs) -> KubernetesDryRunProvider {
    KubernetesDryRunProvider::with_snapshot_class(
        args.cluster,
        args.namespace,
        args.storage_class,
        args.snapshot_class,
    )
}

fn apply_provider_from_args(args: ProviderApplyArgs) -> KubernetesApplyProvider {
    KubernetesApplyProvider::new(provider_from_args(args.provider), args.kubectl)
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

fn execute_local_agent(request: AgentCommandRequest) -> anyhow::Result<AgentCommandResult> {
    let Some((program, args)) = request.argv.split_first() else {
        bail!("argv must contain at least one item");
    };

    let started_at = Utc::now();
    let mut command = ProcessCommand::new(program);
    command.args(args);
    if let Some(cwd) = request.cwd {
        command.current_dir(cwd);
    }
    command.envs(request.env);

    let output = command.output().context("failed to execute command")?;
    let finished_at = Utc::now();

    Ok(AgentCommandResult {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        started_at,
        finished_at,
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
    }
}
