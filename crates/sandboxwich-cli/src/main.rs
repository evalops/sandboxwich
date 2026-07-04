use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use sandboxwich_core::{
    CommandListResponse, CommandRequest, CommandResponse, CreateSandboxRequest, EventListResponse,
    SandboxListResponse, SandboxResponse,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich")]
#[command(about = "A tiny CLI for disposable development sandboxes")]
struct Cli {
    #[arg(long, env = "SANDBOXWICH_API", default_value = "http://127.0.0.1:3217")]
    api: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    New(NewArgs),
    List,
    Get { sandbox_id: Uuid },
    Stop { sandbox_id: Uuid },
    Resume { sandbox_id: Uuid },
    Fork(ForkArgs),
    Exec(ExecArgs),
    Commands { sandbox_id: Uuid },
    Command { command_id: Uuid },
    Events { sandbox_id: Uuid },
}

#[derive(Debug, Args)]
struct NewArgs {
    #[arg(long)]
    name: Option<String>,

    #[arg(long)]
    template: Option<String>,

    #[arg(long)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct ForkArgs {
    sandbox_id: Uuid,

    #[arg(long)]
    name: Option<String>,

    #[arg(long)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct ExecArgs {
    sandbox_id: Uuid,

    #[arg(trailing_var_arg = true, required = true)]
    argv: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();
    let api = cli.api.trim_end_matches('/');

    match cli.command {
        Command::New(args) => {
            let response = client
                .post(format!("{api}/sandboxes"))
                .json(&CreateSandboxRequest {
                    name: args.name,
                    template: args.template,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::List => {
            let response = client.get(format!("{api}/sandboxes")).send().await?;
            print_json::<SandboxListResponse>(response).await?;
        }
        Command::Get { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}"))
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::Stop { sandbox_id } => {
            let response = client
                .post(format!("{api}/sandboxes/{sandbox_id}/stop"))
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::Resume { sandbox_id } => {
            let response = client
                .post(format!("{api}/sandboxes/{sandbox_id}/resume"))
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::Fork(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/fork", args.sandbox_id))
                .json(&CreateSandboxRequest {
                    name: args.name,
                    template: None,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::Exec(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/commands", args.sandbox_id))
                .json(&CommandRequest {
                    argv: args.argv,
                    cwd: None,
                    env: Default::default(),
                })
                .send()
                .await?;
            print_json::<CommandResponse>(response).await?;
        }
        Command::Commands { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/commands"))
                .send()
                .await?;
            print_json::<CommandListResponse>(response).await?;
        }
        Command::Command { command_id } => {
            let response = client
                .get(format!("{api}/commands/{command_id}"))
                .send()
                .await?;
            print_json::<CommandResponse>(response).await?;
        }
        Command::Events { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/events"))
                .send()
                .await?;
            print_json::<EventListResponse>(response).await?;
        }
    }

    Ok(())
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
