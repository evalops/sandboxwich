use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sandboxwich_core::{
    CapacityResponse, CommandListResponse, CommandRequest, CommandResponse,
    CreateDesktopSessionRequest, CreateSandboxRequest, CreateSnapshotRequest, DesktopAccessMode,
    DesktopAccessRequest, DesktopAccessResponse, DesktopSessionListResponse,
    DesktopSessionResponse, DesktopSessionStatus, EventListResponse, GuestHealthResponse,
    GuestStatus, JobListResponse, PromptQueuedResponse, PromptRequest, RequestSshKeyRequest,
    RuntimeResourceListResponse, SandboxListResponse, SandboxResponse, SnapshotCleanupResponse,
    SnapshotListResponse, SnapshotResponse, SshAccessRequest, SshAccessResponse,
    SshKeyListResponse, SshKeyResponse, SshKeyStatus, UpdateDesktopSessionRequest,
    UpdateGuestHealthRequest, UpdateSshKeyStatusRequest, WorkerListResponse, build_api_client,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich")]
#[command(about = "A tiny CLI for disposable development sandboxes")]
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
    New(NewArgs),
    List,
    Get { sandbox_id: Uuid },
    Resources { sandbox_id: Uuid },
    Stop { sandbox_id: Uuid },
    Resume { sandbox_id: Uuid },
    Fork(ForkArgs),
    CreateSnapshot(CreateSnapshotArgs),
    Snapshots { sandbox_id: Uuid },
    Snapshot { snapshot_id: Uuid },
    CleanupSnapshots,
    CreateDesktop(CreateDesktopArgs),
    Desktops { sandbox_id: Uuid },
    Desktop { desktop_session_id: Uuid },
    SetDesktopStatus(SetDesktopStatusArgs),
    DesktopAccess(DesktopAccessArgs),
    Ssh(SshAccessArgs),
    Scp(SshAccessArgs),
    Prompt(PromptArgs),
    Exec(ExecArgs),
    Commands { sandbox_id: Uuid },
    Command { command_id: Uuid },
    Workers,
    Capacity,
    Jobs,
    GuestHealth { sandbox_id: Uuid },
    SetGuestHealth(SetGuestHealthArgs),
    SshKeys { sandbox_id: Uuid },
    AddSshKey(AddSshKeyArgs),
    SetSshKeyStatus(SetSshKeyStatusArgs),
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
struct CreateSnapshotArgs {
    sandbox_id: Uuid,

    #[arg(long)]
    label: Option<String>,

    #[arg(long)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct CreateDesktopArgs {
    sandbox_id: Uuid,

    #[arg(long)]
    broker: Option<String>,

    #[arg(long)]
    broker_url: Option<String>,

    #[arg(long, value_enum)]
    access_mode: Option<DesktopAccessModeArg>,

    #[arg(long)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct SetDesktopStatusArgs {
    desktop_session_id: Uuid,

    #[arg(long, value_enum)]
    status: DesktopSessionStatusArg,

    #[arg(long)]
    broker: Option<String>,

    #[arg(long)]
    broker_url: Option<String>,

    #[arg(long, value_enum)]
    access_mode: Option<DesktopAccessModeArg>,

    #[arg(long)]
    ttl_seconds: Option<u64>,

    #[arg(long)]
    error: Option<String>,
}

#[derive(Debug, Args)]
struct DesktopAccessArgs {
    desktop_session_id: Uuid,

    #[arg(long)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct SshAccessArgs {
    sandbox_id: Uuid,

    #[arg(long)]
    principal: Option<String>,

    #[arg(long)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct PromptArgs {
    sandbox_id: Uuid,

    instructions: String,

    #[arg(long)]
    engine: Option<String>,

    #[arg(long)]
    model: Option<String>,

    #[arg(long)]
    effort: Option<String>,
}

#[derive(Debug, Args)]
struct ExecArgs {
    sandbox_id: Uuid,

    #[arg(trailing_var_arg = true, required = true)]
    argv: Vec<String>,
}

#[derive(Debug, Args)]
struct SetGuestHealthArgs {
    sandbox_id: Uuid,

    #[arg(long, value_enum)]
    status: GuestStatusArg,

    #[arg(long)]
    agent_version: Option<String>,

    #[arg(long)]
    message: Option<String>,
}

#[derive(Debug, Args)]
struct AddSshKeyArgs {
    sandbox_id: Uuid,

    #[arg(long)]
    public_key: String,

    #[arg(long)]
    principal: Option<String>,
}

#[derive(Debug, Args)]
struct SetSshKeyStatusArgs {
    ssh_key_id: Uuid,

    #[arg(long, value_enum)]
    status: SshKeyStatusArg,

    #[arg(long)]
    error: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum GuestStatusArg {
    Pending,
    Ready,
    Unreachable,
    Unhealthy,
    Terminated,
}

#[derive(Clone, Debug, ValueEnum)]
enum SshKeyStatusArg {
    Requested,
    Applied,
    Failed,
    Revoked,
}

#[derive(Clone, Debug, ValueEnum)]
enum DesktopAccessModeArg {
    Browser,
    Vnc,
    Rdp,
}

#[derive(Clone, Debug, ValueEnum)]
enum DesktopSessionStatusArg {
    Pending,
    Ready,
    Failed,
    Closed,
    Expired,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = build_api_client(cli.api_token.as_deref(), cli.tenant.as_deref())?;
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
        Command::Resources { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/runtime-resources"))
                .send()
                .await?;
            print_json::<RuntimeResourceListResponse>(response).await?;
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
        Command::CreateSnapshot(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/snapshots", args.sandbox_id))
                .json(&CreateSnapshotRequest {
                    label: args.label,
                    inventory: None,
                    provider_metadata: None,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<SnapshotResponse>(response).await?;
        }
        Command::Snapshots { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/snapshots"))
                .send()
                .await?;
            print_json::<SnapshotListResponse>(response).await?;
        }
        Command::Snapshot { snapshot_id } => {
            let response = client
                .get(format!("{api}/snapshots/{snapshot_id}"))
                .send()
                .await?;
            print_json::<SnapshotResponse>(response).await?;
        }
        Command::CleanupSnapshots => {
            let response = client
                .post(format!("{api}/snapshots/cleanup"))
                .send()
                .await?;
            print_json::<SnapshotCleanupResponse>(response).await?;
        }
        Command::CreateDesktop(args) => {
            let response = client
                .post(format!(
                    "{api}/sandboxes/{}/desktop-sessions",
                    args.sandbox_id
                ))
                .json(&CreateDesktopSessionRequest {
                    broker: args.broker,
                    broker_url: args.broker_url,
                    access_mode: args.access_mode.map(Into::into),
                    connection_metadata: None,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<DesktopSessionResponse>(response).await?;
        }
        Command::Desktops { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/desktop"))
                .send()
                .await?;
            print_json::<DesktopSessionListResponse>(response).await?;
        }
        Command::Desktop { desktop_session_id } => {
            let response = client
                .get(format!("{api}/desktop-sessions/{desktop_session_id}"))
                .send()
                .await?;
            print_json::<DesktopSessionResponse>(response).await?;
        }
        Command::SetDesktopStatus(args) => {
            let response = client
                .post(format!(
                    "{api}/desktop-sessions/{}/status",
                    args.desktop_session_id
                ))
                .json(&UpdateDesktopSessionRequest {
                    status: args.status.into(),
                    broker: args.broker,
                    broker_url: args.broker_url,
                    access_mode: args.access_mode.map(Into::into),
                    connection_metadata: None,
                    ttl_seconds: args.ttl_seconds,
                    error: args.error,
                })
                .send()
                .await?;
            print_json::<DesktopSessionResponse>(response).await?;
        }
        Command::DesktopAccess(args) => {
            let response = client
                .post(format!(
                    "{api}/desktop-sessions/{}/access",
                    args.desktop_session_id
                ))
                .json(&DesktopAccessRequest {
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<DesktopAccessResponse>(response).await?;
        }
        Command::Ssh(args) | Command::Scp(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/ssh-access", args.sandbox_id))
                .json(&SshAccessRequest {
                    principal: args.principal,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<SshAccessResponse>(response).await?;
        }
        Command::Prompt(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/prompt", args.sandbox_id))
                .json(&PromptRequest {
                    instructions: args.instructions,
                    engine: args.engine,
                    model: args.model,
                    effort: args.effort,
                })
                .send()
                .await?;
            print_json::<PromptQueuedResponse>(response).await?;
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
        Command::Workers => {
            let response = client.get(format!("{api}/workers")).send().await?;
            print_json::<WorkerListResponse>(response).await?;
        }
        Command::Capacity => {
            let response = client.get(format!("{api}/capacity")).send().await?;
            print_json::<CapacityResponse>(response).await?;
        }
        Command::Jobs => {
            let response = client.get(format!("{api}/jobs")).send().await?;
            print_json::<JobListResponse>(response).await?;
        }
        Command::GuestHealth { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/guest-health"))
                .send()
                .await?;
            print_json::<GuestHealthResponse>(response).await?;
        }
        Command::SetGuestHealth(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/guest-health", args.sandbox_id))
                .json(&UpdateGuestHealthRequest {
                    status: args.status.into(),
                    agent_version: args.agent_version,
                    checks: None,
                    message: args.message,
                })
                .send()
                .await?;
            print_json::<GuestHealthResponse>(response).await?;
        }
        Command::SshKeys { sandbox_id } => {
            let response = client
                .get(format!("{api}/sandboxes/{sandbox_id}/ssh-keys"))
                .send()
                .await?;
            print_json::<SshKeyListResponse>(response).await?;
        }
        Command::AddSshKey(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/ssh-keys", args.sandbox_id))
                .json(&RequestSshKeyRequest {
                    public_key: args.public_key,
                    principal: args.principal,
                })
                .send()
                .await?;
            print_json::<SshKeyResponse>(response).await?;
        }
        Command::SetSshKeyStatus(args) => {
            let response = client
                .post(format!("{api}/ssh-keys/{}/status", args.ssh_key_id))
                .json(&UpdateSshKeyStatusRequest {
                    status: args.status.into(),
                    error: args.error,
                })
                .send()
                .await?;
            print_json::<SshKeyResponse>(response).await?;
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

impl From<GuestStatusArg> for GuestStatus {
    fn from(value: GuestStatusArg) -> Self {
        match value {
            GuestStatusArg::Pending => Self::Pending,
            GuestStatusArg::Ready => Self::Ready,
            GuestStatusArg::Unreachable => Self::Unreachable,
            GuestStatusArg::Unhealthy => Self::Unhealthy,
            GuestStatusArg::Terminated => Self::Terminated,
        }
    }
}

impl From<SshKeyStatusArg> for SshKeyStatus {
    fn from(value: SshKeyStatusArg) -> Self {
        match value {
            SshKeyStatusArg::Requested => Self::Requested,
            SshKeyStatusArg::Applied => Self::Applied,
            SshKeyStatusArg::Failed => Self::Failed,
            SshKeyStatusArg::Revoked => Self::Revoked,
        }
    }
}

impl From<DesktopAccessModeArg> for DesktopAccessMode {
    fn from(value: DesktopAccessModeArg) -> Self {
        match value {
            DesktopAccessModeArg::Browser => Self::Browser,
            DesktopAccessModeArg::Vnc => Self::Vnc,
            DesktopAccessModeArg::Rdp => Self::Rdp,
        }
    }
}

impl From<DesktopSessionStatusArg> for DesktopSessionStatus {
    fn from(value: DesktopSessionStatusArg) -> Self {
        match value {
            DesktopSessionStatusArg::Pending => Self::Pending,
            DesktopSessionStatusArg::Ready => Self::Ready,
            DesktopSessionStatusArg::Failed => Self::Failed,
            DesktopSessionStatusArg::Closed => Self::Closed,
            DesktopSessionStatusArg::Expired => Self::Expired,
        }
    }
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
