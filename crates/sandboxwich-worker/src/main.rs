use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sandboxwich_core::{
    ClaimLeaseRequest, ClaimLeaseResponse, CompleteLeaseRequest, FailLeaseRequest, JobKind,
    LeaseResponse, RegisterWorkerRequest, RenewLeaseRequest, WorkerCapability,
    WorkerHeartbeatRequest, WorkerResponse,
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

#[derive(Clone, Debug, ValueEnum)]
enum CapabilityArg {
    ProvisionSandbox,
    RunCommand,
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
                        "snapshot",
                        "desktop_stream",
                        "k8s_pod"
                    ]
                }))?
            );
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
                    let argv = lease
                        .job
                        .payload
                        .get("argv")
                        .and_then(|value| value.as_array())
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();
                    let response = client
                        .post(format!("{api}/leases/{}/complete", lease.id))
                        .json(&CompleteLeaseRequest {
                            result: Some(json!({
                                "stdout": format!("dry-run worker completed: {argv}\n"),
                                "stderr": "",
                                "exitCode": 0
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
        CapabilityArg::Snapshot => WorkerCapability::Snapshot,
        CapabilityArg::DesktopStream => WorkerCapability::DesktopStream,
        CapabilityArg::K8sPod => WorkerCapability::K8sPod,
    }
}
