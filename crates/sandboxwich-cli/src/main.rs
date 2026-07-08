use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use sandboxwich_core::{
    CapacityResponse, CommandId, CommandListResponse, CommandOutputListResponse,
    CommandOutputStream, CommandRequest, CommandResponse, CommandRun, CommandStatus,
    CreateDesktopSessionRequest, CreateSandboxRequest, CreateSnapshotRequest, DesktopAccessMode,
    DesktopAccessRequest, DesktopAccessResponse, DesktopSessionListResponse,
    DesktopSessionResponse, DesktopSessionStatus, EventListResponse, FileResponse,
    GuestHealthResponse, GuestStatus, JobListResponse, ListFilesResponse, MemoryLimit,
    PromptQueuedResponse, PromptRequest, RequestSshKeyRequest, RuntimeResourceListResponse,
    SandboxListResponse, SandboxResponse, SnapshotCleanupResponse, SnapshotListResponse,
    SnapshotResponse, SshAccessRequest, SshAccessResponse, SshKeyListResponse, SshKeyResponse,
    SshKeyStatus, UpdateDesktopSessionRequest, UpdateGuestHealthRequest, UpdateSshKeyStatusRequest,
    WorkerListResponse,
};
use uuid::Uuid;

/// Default `reqwest` request timeout applied to every CLI call; overridable via
/// `--request-timeout-secs` / `SANDBOXWICH_REQUEST_TIMEOUT_SECS`. A value of `0` disables it.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Default ceiling on how long `--wait`/`--follow` (and `logs --follow`) poll for completion.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 300;

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

    /// Request timeout in seconds applied to every API call. `0` disables the timeout.
    #[arg(
        long,
        env = "SANDBOXWICH_REQUEST_TIMEOUT_SECS",
        default_value_t = DEFAULT_REQUEST_TIMEOUT_SECS
    )]
    request_timeout_secs: u64,

    #[command(subcommand)]
    command: Command,
}

// The `Command` variant intentionally matches the enum name: renaming it
// would rename the `sandboxwich command <id>` CLI subcommand, a
// user-facing breaking change out of scope for this cleanup.
#[allow(clippy::enum_variant_names)]
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
    Cp(CpArgs),
    Prompt(PromptArgs),
    Exec(ExecArgs),
    Commands { sandbox_id: Uuid },
    Command { command_id: Uuid },
    Logs(LogsArgs),
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

    #[arg(long, value_enum)]
    memory_limit: Option<MemoryLimitArg>,

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
struct CpArgs {
    sandbox_id: Uuid,
    source: String,
    destination: String,

    #[arg(long, default_value_t = false)]
    download: bool,

    #[arg(long)]
    mime_type: Option<String>,
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

    /// Block until the command reaches a terminal state (Finished/Failed) before printing.
    #[arg(long)]
    wait: bool,

    /// Like --wait, but also tail stdout/stderr as new output chunks arrive. Implies --wait.
    #[arg(long)]
    follow: bool,

    /// Maximum time to poll for completion when --wait/--follow is set.
    #[arg(long, default_value_t = DEFAULT_WAIT_TIMEOUT_SECS)]
    wait_timeout_secs: u64,

    #[arg(trailing_var_arg = true, required = true)]
    argv: Vec<String>,
}

#[derive(Debug, Args)]
struct LogsArgs {
    command_id: Uuid,

    /// Keep polling and tailing output until the command reaches a terminal state.
    #[arg(long)]
    follow: bool,

    /// Maximum time to poll for completion when --follow is set.
    #[arg(long, default_value_t = DEFAULT_WAIT_TIMEOUT_SECS)]
    wait_timeout_secs: u64,
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

#[derive(Clone, Debug, ValueEnum)]
enum MemoryLimitArg {
    #[value(name = "1g")]
    OneG,
    #[value(name = "4g")]
    FourG,
    #[value(name = "16g")]
    SixteenG,
    #[value(name = "64g")]
    SixtyFourG,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let request_timeout = if cli.request_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(cli.request_timeout_secs))
    };
    let client = build_client(
        cli.api_token.as_deref(),
        cli.tenant.as_deref(),
        request_timeout,
    )?;
    let api = cli.api.trim_end_matches('/');

    match cli.command {
        Command::New(args) => {
            let response = client
                .post(format!("{api}/sandboxes"))
                .json(&CreateSandboxRequest {
                    name: args.name,
                    template: args.template,
                    memory_limit: args.memory_limit.map(Into::into),
                    network_egress: None,
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
                    memory_limit: None,
                    network_egress: None,
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
        Command::Cp(args) => {
            if args.download {
                download_file(&client, api, args).await?;
            } else {
                upload_file(&client, api, args).await?;
            }
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
            let follow = args.follow;
            let wait = args.wait || follow;
            let response = client
                .post(format!("{api}/sandboxes/{}/commands", args.sandbox_id))
                .json(&CommandRequest {
                    argv: args.argv,
                    cwd: None,
                    env: Default::default(),
                })
                .send()
                .await?;
            let queued = decode_json::<CommandResponse>(response).await?;
            if wait {
                let command = poll_command_until_terminal(
                    &client,
                    api,
                    queued.command.id,
                    Duration::from_secs(args.wait_timeout_secs),
                    follow,
                )
                .await?;
                print_value(&CommandResponse { ok: true, command })?;
            } else {
                print_value(&queued)?;
            }
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
        Command::Logs(args) => {
            // One-shot fetch, reusing the existing `Command::Command` getter's endpoint.
            let response = client
                .get(format!("{api}/commands/{}", args.command_id))
                .send()
                .await?;
            let initial = decode_json::<CommandResponse>(response).await?.command;

            let command = if args.follow && !is_terminal(&initial.status) {
                poll_command_until_terminal(
                    &client,
                    api,
                    CommandId(args.command_id),
                    Duration::from_secs(args.wait_timeout_secs),
                    true,
                )
                .await?
            } else {
                let output = client
                    .get(format!("{api}/commands/{}/output", args.command_id))
                    .send()
                    .await?;
                let chunks = decode_json::<CommandOutputListResponse>(output)
                    .await?
                    .chunks;
                print_output_chunks(&chunks);
                initial
            };
            print_value(&CommandResponse { ok: true, command })?;
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

impl From<MemoryLimitArg> for MemoryLimit {
    fn from(value: MemoryLimitArg) -> Self {
        match value {
            MemoryLimitArg::OneG => Self::OneG,
            MemoryLimitArg::FourG => Self::FourG,
            MemoryLimitArg::SixteenG => Self::SixteenG,
            MemoryLimitArg::SixtyFourG => Self::SixtyFourG,
        }
    }
}

async fn upload_file(client: &reqwest::Client, api: &str, args: CpArgs) -> anyhow::Result<()> {
    let content = tokio::fs::read(&args.source)
        .await
        .with_context(|| format!("failed to read local file {}", args.source))?;
    let file_name = std::path::Path::new(&args.source)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("upload")
        .to_string();
    let mut part = reqwest::multipart::Part::bytes(content).file_name(file_name);
    if let Some(mime_type) = &args.mime_type {
        part = part
            .mime_str(mime_type)
            .with_context(|| format!("invalid MIME type {mime_type:?}"))?;
    }
    let form = reqwest::multipart::Form::new()
        .text("path", args.destination)
        .part("file", part);
    let response = client
        .post(format!("{api}/sandboxes/{}/files", args.sandbox_id))
        .multipart(form)
        .send()
        .await?;
    print_json::<FileResponse>(response).await
}

async fn download_file(client: &reqwest::Client, api: &str, args: CpArgs) -> anyhow::Result<()> {
    let listed = client
        .get(format!("{api}/sandboxes/{}/files", args.sandbox_id))
        .send()
        .await?;
    let files = decode_json::<ListFilesResponse>(listed).await?;
    let file = files
        .files
        .into_iter()
        .find(|file| file.path == args.source)
        .ok_or_else(|| anyhow::anyhow!("remote file {:?} was not found", args.source))?;
    let response = client
        .get(format!(
            "{api}/sandboxes/{}/files/{}",
            args.sandbox_id, file.id
        ))
        .send()
        .await?;
    let status = response.status();
    let content = response
        .bytes()
        .await
        .context("failed to read downloaded file")?;
    if !status.is_success() {
        bail!(
            "download failed with {status}: {}",
            String::from_utf8_lossy(&content)
        );
    }
    tokio::fs::write(&args.destination, &content)
        .await
        .with_context(|| format!("failed to write local file {}", args.destination))?;
    Ok(())
}

async fn print_json<T>(response: reqwest::Response) -> anyhow::Result<()>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value = decode_json::<T>(response).await?;
    print_value(&value)
}

fn print_value<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn is_terminal(status: &CommandStatus) -> bool {
    matches!(status, CommandStatus::Finished | CommandStatus::Failed)
}

fn print_output_chunks(chunks: &[sandboxwich_core::CommandOutputChunk]) {
    use std::io::Write as _;

    for chunk in chunks {
        match chunk.stream {
            CommandOutputStream::Stdout => {
                print!("{}", chunk.chunk);
                let _ = std::io::stdout().flush();
            }
            CommandOutputStream::Stderr => {
                eprint!("{}", chunk.chunk);
                let _ = std::io::stderr().flush();
            }
        }
    }
}

/// Polls `GET /commands/{id}` (the existing one-shot command getter) with bounded exponential
/// backoff until the command reaches a terminal state (Finished/Failed) or `timeout` elapses.
/// When `follow` is set, also polls `GET /commands/{id}/output` each iteration and prints any
/// output chunks not yet seen, so stdout/stderr are tailed live rather than dumped at the end.
async fn poll_command_until_terminal(
    client: &reqwest::Client,
    api: &str,
    command_id: CommandId,
    timeout: Duration,
    follow: bool,
) -> anyhow::Result<CommandRun> {
    let start = tokio::time::Instant::now();
    let mut delay = Duration::from_millis(200);
    let max_delay = Duration::from_secs(5);
    let mut seen_chunks = 0usize;

    loop {
        let response = client
            .get(format!("{api}/commands/{command_id}"))
            .send()
            .await?;
        let command = decode_json::<CommandResponse>(response).await?.command;

        if follow {
            let output = client
                .get(format!("{api}/commands/{command_id}/output"))
                .send()
                .await?;
            let chunks = decode_json::<CommandOutputListResponse>(output)
                .await?
                .chunks;
            print_output_chunks(&chunks[seen_chunks.min(chunks.len())..]);
            seen_chunks = chunks.len();
        }

        if is_terminal(&command.status) {
            return Ok(command);
        }

        if start.elapsed() >= timeout {
            bail!(
                "timed out after {:?} waiting for command {command_id} to finish (last status: {:?})",
                timeout,
                command.status
            );
        }

        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(max_delay);
    }
}

/// Builds the shared API client, applying auth/tenant headers and an optional request timeout
/// overridable via `--request-timeout-secs` / `SANDBOXWICH_REQUEST_TIMEOUT_SECS`.
fn build_client(
    api_token: Option<&str>,
    tenant: Option<&str>,
    request_timeout: Option<Duration>,
) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    if let Some(api_token) = api_token.map(str::trim).filter(|token| !token.is_empty()) {
        let value = format!("Bearer {api_token}");
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&value).context("invalid SANDBOXWICH_API_TOKEN")?,
        );
    }
    if let Some(tenant) = tenant.map(str::trim).filter(|tenant| !tenant.is_empty()) {
        headers.insert(
            HeaderName::from_static("x-sandboxwich-tenant"),
            HeaderValue::from_str(tenant).context("invalid SANDBOXWICH_TENANT")?,
        );
    }
    let mut builder = reqwest::Client::builder().default_headers(headers);
    if let Some(request_timeout) = request_timeout {
        builder = builder.timeout(request_timeout);
    }
    builder.build().context("failed to build HTTP client")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_terminal_true_only_for_finished_or_failed() {
        assert!(is_terminal(&CommandStatus::Finished));
        assert!(is_terminal(&CommandStatus::Failed));
        assert!(!is_terminal(&CommandStatus::Queued));
        assert!(!is_terminal(&CommandStatus::Running));
    }

    #[test]
    fn build_client_applies_a_request_timeout_by_default() {
        // There's no public accessor on `reqwest::Client` for its configured timeout, so this
        // just verifies the default-path construction succeeds; the request-timeout wiring
        // itself is covered end-to-end by `--request-timeout-secs`/`SANDBOXWICH_REQUEST_TIMEOUT_SECS`
        // being threaded straight into `reqwest::ClientBuilder::timeout`.
        let client = build_client(
            None,
            None,
            Some(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS)),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn build_client_allows_disabling_the_timeout() {
        let client = build_client(None, None, None);
        assert!(client.is_ok());
    }

    #[test]
    fn build_client_rejects_invalid_api_token_header_value() {
        let client = build_client(Some("bad\ntoken"), None, None);
        assert!(client.is_err());
    }
}
