use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sandboxwich_core::{
    RegisterWorkerRequest, WorkerCapability, WorkerHeartbeatRequest, WorkerResponse,
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
    }

    Ok(())
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
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read response body")?;
    if !status.is_success() {
        bail!("request failed with {status}: {body}");
    }

    let value: T = serde_json::from_str(&body).context("failed to decode response body")?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
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
