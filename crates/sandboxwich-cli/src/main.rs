use std::{collections::BTreeSet, process::Stdio, sync::OnceLock, time::Duration};

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
    NetworkAllowRule, NetworkAllowRuleKind, NetworkEgress, QueueCommandResponse,
    RequestSshKeyRequest, RuntimeResourceListResponse, SandboxListResponse, SandboxResponse,
    SandboxState, SnapshotCleanupResponse, SnapshotListResponse, SnapshotResponse,
    SshAccessRequest, SshAccessResponse, SshKeyListResponse, SshKeyResponse, SshKeyStatus,
    UpdateDesktopSessionRequest, UpdateGuestHealthRequest, UpdateSshKeyStatusRequest,
    WorkerListResponse, WorkspaceMode,
};
use uuid::Uuid;

/// Default `reqwest` request timeout applied to every CLI call; overridable via
/// `--request-timeout-secs` / `SANDBOXWICH_REQUEST_TIMEOUT_SECS`. A value of `0` disables it.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Default ceiling on how long `--wait`/`--follow` (and `logs --follow`) poll for completion.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 300;

/// Header name the API's idempotency middleware looks for on mutating `/v1`
/// requests (see `sandboxwich-api`'s `enforce_idempotency`). Every mutating CLI
/// command attaches one.
///
/// Honesty note on what the key buys you: by default the key is freshly
/// generated per CLI invocation, which only makes the single request this
/// process sends replayable *server-side* -- it cannot protect against the
/// common retry, a user or script re-running the whole CLI command after a
/// timeout, because that new process generates a new key. To make a scripted
/// retry actually replay the original response instead of executing the
/// mutation twice, pass the same key explicitly via
/// `--idempotency-key`/`SANDBOXWICH_IDEMPOTENCY_KEY` on every attempt (e.g.
/// generate one `uuidgen` per logical operation in the script and reuse it
/// across retries).
///
/// File uploads deliberately do not get a key: the API buffers idempotent
/// request bodies up to its normal 1 MiB limit, so attaching one to a large
/// multipart upload would turn an otherwise-fine upload into a
/// `413 idempotency_payload_too_large`.
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Resolves the `Idempotency-Key` value used for this invocation's mutating
/// request: the explicitly supplied key when given (so retries of the same
/// logical operation can replay), otherwise a fresh UUIDv7. A blank explicit
/// value is treated as unset rather than sent as an (invalid) empty key.
fn resolve_idempotency_key(explicit: Option<String>) -> String {
    match explicit {
        Some(key) if !key.trim().is_empty() => key.trim().to_string(),
        _ => Uuid::now_v7().to_string(),
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Jsonl,
}

#[derive(Clone, Copy, Debug)]
struct OutputOptions {
    format: OutputFormat,
    quiet: bool,
}

static OUTPUT_OPTIONS: OnceLock<OutputOptions> = OnceLock::new();

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

    /// Idempotency-Key sent on this invocation's mutating request. Pass the
    /// same key when retrying a failed/timed-out invocation of the same
    /// logical operation and the API replays the original response instead of
    /// executing the mutation twice. When omitted, a fresh key is generated
    /// per invocation -- which does NOT protect a re-run of the CLI, only a
    /// server-side replay of this one request.
    #[arg(long, env = "SANDBOXWICH_IDEMPOTENCY_KEY")]
    idempotency_key: Option<String>,

    /// Output format for structured responses.
    #[arg(long, short = 'o', value_enum, default_value_t = OutputFormat::Json)]
    output: OutputFormat,

    /// Suppress structured success output.
    #[arg(long, short = 'q')]
    quiet: bool,

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
    Scp(ScpArgs),
    Cp(CpArgs),
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

    #[arg(long, value_enum, default_value_t = WorkspaceModeArg::Persistent)]
    workspace_mode: WorkspaceModeArg,

    #[arg(long)]
    ttl_seconds: Option<u64>,

    /// Wait until the sandbox reaches Ready or Error.
    #[arg(long)]
    wait: bool,

    #[arg(long, default_value_t = DEFAULT_WAIT_TIMEOUT_SECS)]
    wait_timeout_secs: u64,

    #[arg(long, value_enum, default_value_t = NetworkEgressArg::DenyAll)]
    network_egress: NetworkEgressArg,

    /// CIDR allowed when --network-egress=allowlist. May be repeated.
    #[arg(long = "allow-cidr")]
    allow_cidrs: Vec<String>,
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

    /// Print access metadata instead of opening an interactive SSH session.
    #[arg(long)]
    print_command: bool,
}

#[derive(Debug, Args)]
struct ScpArgs {
    sandbox_id: Uuid,
    source: String,
    destination: String,

    #[arg(long)]
    download: bool,

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

    /// Maximum time the command itself may run before the executor kills it
    /// and reports a timeout failure. Unset falls back to the server's
    /// `DEFAULT_COMMAND_TIMEOUT_SECS`. Distinct from --wait-timeout-secs,
    /// which only bounds how long this CLI invocation polls for a result.
    #[arg(long)]
    command_timeout_secs: Option<u64>,

    #[arg(long)]
    cwd: Option<String>,

    /// Environment entry formatted as KEY=VALUE. May be repeated.
    #[arg(long = "env", value_parser = parse_key_value)]
    env: Vec<(String, String)>,

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

#[derive(Clone, Debug, ValueEnum)]
enum WorkspaceModeArg {
    Ephemeral,
    GenericEphemeral,
    Persistent,
}

#[derive(Clone, Debug, ValueEnum)]
enum NetworkEgressArg {
    DenyAll,
    Allowlist,
    AllowAll,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let _ = OUTPUT_OPTIONS.set(OutputOptions {
        format: cli.output,
        quiet: cli.quiet,
    });
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
    // One key per invocation is safe because every subcommand sends at most one
    // idempotency-keyed mutating request; see IDEMPOTENCY_KEY_HEADER for what an
    // explicit key buys over the generated default.
    let idempotency_key = resolve_idempotency_key(cli.idempotency_key.clone());

    match cli.command {
        Command::New(args) => {
            let network_egress = network_egress_from_args(&args)?;
            let wait = args.wait;
            let wait_timeout = Duration::from_secs(args.wait_timeout_secs);
            let response = client
                .post(format!("{api}/sandboxes"))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .json(&CreateSandboxRequest {
                    name: args.name,
                    template: args.template,
                    memory_limit: args.memory_limit.map(Into::into),
                    network_egress: Some(network_egress),
                    workspace_mode: Some(args.workspace_mode.into()),
                    runtime_profile: None,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            let created = decode_json::<SandboxResponse>(response).await?;
            if wait {
                let sandbox =
                    poll_sandbox_until_ready(&client, api, created.sandbox.id.0, wait_timeout)
                        .await?;
                print_value(&SandboxResponse {
                    ok: true,
                    sandbox,
                    operation: None,
                })?;
            } else {
                print_value(&created)?;
            }
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::Resume { sandbox_id } => {
            let response = client
                .post(format!("{api}/sandboxes/{sandbox_id}/resume"))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::Fork(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/fork", args.sandbox_id))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .json(&CreateSandboxRequest {
                    name: args.name,
                    template: None,
                    memory_limit: None,
                    network_egress: None,
                    workspace_mode: None,
                    runtime_profile: None,
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<SandboxResponse>(response).await?;
        }
        Command::CreateSnapshot(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/snapshots", args.sandbox_id))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .json(&DesktopAccessRequest {
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            print_json::<DesktopAccessResponse>(response).await?;
        }
        Command::Ssh(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/ssh-access", args.sandbox_id))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .json(&SshAccessRequest {
                    principal: args.principal.clone(),
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            let access = decode_json::<SshAccessResponse>(response).await?;
            if args.print_command {
                print_value(&access)?;
            } else {
                run_ssh(access).await?;
            }
        }
        Command::Scp(args) => {
            let response = client
                .post(format!("{api}/sandboxes/{}/ssh-access", args.sandbox_id))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .json(&SshAccessRequest {
                    principal: args.principal.clone(),
                    ttl_seconds: args.ttl_seconds,
                })
                .send()
                .await?;
            let access = decode_json::<SshAccessResponse>(response).await?;
            run_scp(access, args).await?;
        }
        Command::Cp(args) => {
            if args.download {
                download_file(&client, api, args).await?;
            } else {
                upload_file(&client, api, args).await?;
            }
        }
        Command::Exec(args) => {
            let follow = args.follow;
            let wait = args.wait || follow;
            let response = client
                .post(format!("{api}/sandboxes/{}/commands", args.sandbox_id))
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
                .json(&CommandRequest {
                    argv: args.argv,
                    cwd: args.cwd,
                    env: args.env.into_iter().collect(),
                    stdin: None,
                    timeout_secs: args.command_timeout_secs,
                })
                .send()
                .await?;
            let queued = decode_json::<QueueCommandResponse>(response).await?;
            if wait {
                let command = poll_command_until_terminal(
                    &client,
                    api,
                    queued.command.id,
                    Duration::from_secs(args.wait_timeout_secs),
                    follow,
                )
                .await?;
                print_value(&CommandResponse {
                    ok: true,
                    command: command.clone(),
                })?;
                exit_with_command_result(&command);
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
            let follow = args.follow;
            print_value(&CommandResponse {
                ok: true,
                command: command.clone(),
            })?;
            // Only `--follow` implies waiting for a terminal state; a plain one-shot
            // `logs` should keep reflecting whatever status the command happens to be
            // in right now without forcing a process exit code on it.
            if follow {
                exit_with_command_result(&command);
            }
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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
                .header(IDEMPOTENCY_KEY_HEADER, &idempotency_key)
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

impl From<WorkspaceModeArg> for WorkspaceMode {
    fn from(value: WorkspaceModeArg) -> Self {
        match value {
            WorkspaceModeArg::Ephemeral => Self::Ephemeral,
            WorkspaceModeArg::GenericEphemeral => Self::GenericEphemeral,
            WorkspaceModeArg::Persistent => Self::Persistent,
        }
    }
}

fn parse_key_value(value: &str) -> Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "environment values must use KEY=VALUE".to_string())?;
    if key.is_empty()
        || !key.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || (byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit()))
        })
    {
        return Err("environment key must be a valid POSIX-style identifier".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}

fn network_egress_from_args(args: &NewArgs) -> anyhow::Result<NetworkEgress> {
    match args.network_egress {
        NetworkEgressArg::DenyAll if args.allow_cidrs.is_empty() => Ok(NetworkEgress::DenyAll),
        NetworkEgressArg::AllowAll if args.allow_cidrs.is_empty() => Ok(NetworkEgress::AllowAll),
        NetworkEgressArg::Allowlist => {
            if args.allow_cidrs.is_empty() {
                bail!("--network-egress=allowlist requires at least one --allow-cidr");
            }
            Ok(NetworkEgress::Allowlist {
                rules: args
                    .allow_cidrs
                    .iter()
                    .map(|value| NetworkAllowRule {
                        kind: NetworkAllowRuleKind::Cidr,
                        value: value.clone(),
                    })
                    .collect(),
            })
        }
        NetworkEgressArg::DenyAll | NetworkEgressArg::AllowAll => {
            bail!("--allow-cidr is only valid with --network-egress=allowlist")
        }
    }
}

async fn poll_sandbox_until_ready(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: Uuid,
    timeout: Duration,
) -> anyhow::Result<sandboxwich_core::Sandbox> {
    let start = tokio::time::Instant::now();
    let mut delay = Duration::from_millis(200);
    loop {
        let response = client
            .get(format!("{api}/sandboxes/{sandbox_id}"))
            .send()
            .await?;
        let sandbox = decode_json::<SandboxResponse>(response).await?.sandbox;
        match sandbox.state {
            SandboxState::Ready => return Ok(sandbox),
            SandboxState::Error => bail!("sandbox {sandbox_id} entered the error state"),
            SandboxState::Archived => {
                bail!("sandbox {sandbox_id} was archived before it became ready")
            }
            _ if start.elapsed() >= timeout => {
                bail!(
                    "timed out after {timeout:?} waiting for sandbox {sandbox_id} (last state: {:?})",
                    sandbox.state
                )
            }
            _ => {}
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(3));
    }
}

async fn run_ssh(access: SshAccessResponse) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("ssh")
        .arg("-p")
        .arg(access.ssh_access.port.to_string())
        .arg(format!(
            "{}@{}",
            access.ssh_access.username, access.ssh_access.host
        ))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("failed to launch ssh; install an OpenSSH client or use --print-command")?;
    if !status.success() {
        bail!("ssh exited with {status}");
    }
    Ok(())
}

async fn run_scp(access: SshAccessResponse, args: ScpArgs) -> anyhow::Result<()> {
    let remote = |path: &str| {
        format!(
            "{}@{}:{path}",
            access.ssh_access.username, access.ssh_access.host
        )
    };
    let (source, destination) = if args.download {
        (remote(&args.source), args.destination)
    } else {
        (args.source, remote(&args.destination))
    };
    let status = tokio::process::Command::new("scp")
        .arg("-P")
        .arg(access.ssh_access.port.to_string())
        .arg(source)
        .arg(destination)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("failed to launch scp; install an OpenSSH client")?;
    if !status.success() {
        bail!("scp exited with {status}");
    }
    Ok(())
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
    let options = OUTPUT_OPTIONS.get().copied().unwrap_or(OutputOptions {
        format: OutputFormat::Json,
        quiet: false,
    });
    if options.quiet {
        return Ok(());
    }
    let value = serde_json::to_value(value)?;
    match options.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => print_jsonl(&value)?,
        OutputFormat::Table => print_table(&value),
    }
    Ok(())
}

fn primary_rows(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    match value {
        serde_json::Value::Array(rows) => rows.iter().collect(),
        serde_json::Value::Object(object) => {
            let arrays = object
                .iter()
                .filter(|(key, _)| *key != "ok" && *key != "next_cursor")
                .filter_map(|(_, value)| value.as_array())
                .collect::<Vec<_>>();
            if let [rows] = arrays.as_slice() {
                rows.iter().collect()
            } else {
                // A response with several arrays has no unambiguous primary row set.
                // Keep the complete object so table and JSONL output cannot drop fields.
                vec![value]
            }
        }
        _ => vec![value],
    }
}

fn print_jsonl(value: &serde_json::Value) -> anyhow::Result<()> {
    for row in primary_rows(value) {
        println!("{}", serde_json::to_string(row)?);
    }
    Ok(())
}

fn display_cell(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => "-".to_string(),
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(value @ (serde_json::Value::Bool(_) | serde_json::Value::Number(_))) => {
            value.to_string()
        }
        Some(value) => serde_json::to_string(value).unwrap_or_else(|_| "<invalid>".to_string()),
    }
}

fn print_table(value: &serde_json::Value) {
    let rows = primary_rows(value);
    if rows.is_empty() {
        println!("No results.");
        return;
    }
    if !rows.iter().all(|row| row.is_object()) {
        for row in rows {
            println!("{}", display_cell(Some(row)));
        }
        return;
    }

    let headers: Vec<String> = rows
        .iter()
        .filter_map(|row| row.as_object())
        .flat_map(|row| row.keys().cloned())
        .filter(|key| key != "ok" && key != "next_cursor")
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let object = row.as_object().expect("rows were checked as objects");
            headers
                .iter()
                .map(|header| display_cell(object.get(header)))
                .collect()
        })
        .collect();
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            cells
                .iter()
                .map(|row| row[index].chars().count())
                .max()
                .unwrap_or_default()
                .max(header.chars().count())
                .min(60)
        })
        .collect();
    let render = |row: &[String]| {
        row.iter()
            .enumerate()
            .map(|(index, value)| {
                let clipped: String = value.chars().take(widths[index]).collect();
                format!("{clipped:<width$}", width = widths[index])
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    println!("{}", render(&headers));
    println!(
        "{}",
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for row in cells {
        println!("{}", render(&row));
    }
}

fn is_terminal(status: &CommandStatus) -> bool {
    matches!(status, CommandStatus::Finished | CommandStatus::Failed)
}

/// The process exit code that should be reported for a terminal `command`, or
/// `None` if it hasn't reached a terminal state yet (nothing to report). A
/// `Failed` command with no exit code at all (e.g. killed by a timeout) maps
/// to `1`, since "no exit code" is not success.
fn command_exit_code(command: &CommandRun) -> Option<i32> {
    if !is_terminal(&command.status) {
        return None;
    }
    Some(match command.status {
        CommandStatus::Failed => command.exit_code.filter(|&code| code != 0).unwrap_or(1),
        _ => command.exit_code.unwrap_or(0),
    })
}

/// Exits the process with `command`'s own exit code once it has reached a
/// terminal state, mirroring how `sandboxwich-agent`'s own `exec` reflects a
/// command's exit code in its process exit code. Without this, `sandboxwich
/// exec --wait`/`logs --follow` always exited 0 after printing the terminal
/// `CommandRun` -- even a `Failed` one -- so CI pipelines could not gate on
/// command failure without parsing the printed JSON themselves.
fn exit_with_command_result(command: &CommandRun) {
    if let Some(code) = command_exit_code(command)
        && code != 0
    {
        std::process::exit(code);
    }
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
    fn resolve_idempotency_key_uses_an_explicit_key_verbatim() {
        // The whole point of --idempotency-key/SANDBOXWICH_IDEMPOTENCY_KEY: a
        // scripted retry passes the same key on every attempt so the API
        // replays the first response instead of executing the mutation twice.
        assert_eq!(
            resolve_idempotency_key(Some("retry-key-1".to_string())),
            "retry-key-1"
        );
        assert_eq!(
            resolve_idempotency_key(Some("  padded-key  ".to_string())),
            "padded-key"
        );
    }

    #[test]
    fn resolve_idempotency_key_generates_a_fresh_key_when_unset_or_blank() {
        let generated = resolve_idempotency_key(None);
        assert!(
            Uuid::parse_str(&generated).is_ok(),
            "generated key should be a UUID, got: {generated}"
        );
        // Fresh per resolution, never a fixed value.
        assert_ne!(resolve_idempotency_key(None), generated);
        // A blank explicit value would be rejected by the API as an invalid
        // (empty) key; treat it as unset instead.
        let from_blank = resolve_idempotency_key(Some("   ".to_string()));
        assert!(Uuid::parse_str(&from_blank).is_ok());
    }

    fn command_run(status: CommandStatus, exit_code: Option<i32>) -> CommandRun {
        let now = chrono::Utc::now();
        CommandRun {
            id: CommandId(Uuid::now_v7()),
            sandbox_id: sandboxwich_core::SandboxId(Uuid::now_v7()),
            status,
            argv: vec!["echo".to_string()],
            cwd: None,
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
            created_at: now,
            finished_at: Some(now),
        }
    }

    #[test]
    fn command_exit_code_is_none_for_non_terminal_commands() {
        assert_eq!(
            command_exit_code(&command_run(CommandStatus::Queued, None)),
            None
        );
        assert_eq!(
            command_exit_code(&command_run(CommandStatus::Running, None)),
            None
        );
    }

    #[test]
    fn command_exit_code_reflects_a_finished_commands_own_exit_code() {
        assert_eq!(
            command_exit_code(&command_run(CommandStatus::Finished, Some(0))),
            Some(0)
        );
    }

    #[test]
    fn command_exit_code_is_non_zero_for_a_failed_command_with_a_non_zero_exit_code() {
        // Regression test: `sandboxwich exec --wait` used to print a Failed
        // CommandRun and still exit 0, so CI could not gate on it.
        assert_eq!(
            command_exit_code(&command_run(CommandStatus::Failed, Some(7))),
            Some(7)
        );
    }

    #[test]
    fn command_exit_code_falls_back_to_one_for_a_failed_command_with_no_exit_code() {
        // e.g. a command killed by a timeout never reports its own exit code;
        // "no exit code" must still not be treated as success.
        assert_eq!(
            command_exit_code(&command_run(CommandStatus::Failed, None)),
            Some(1)
        );
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

    #[test]
    fn environment_parser_accepts_values_with_equals_and_rejects_invalid_keys() {
        assert_eq!(
            parse_key_value("TOKEN=a=b").unwrap(),
            ("TOKEN".to_string(), "a=b".to_string())
        );
        assert!(parse_key_value("1TOKEN=value").is_err());
        assert!(parse_key_value("missing-delimiter").is_err());
    }

    #[test]
    fn allowlist_requires_explicit_cidrs() {
        let args = NewArgs {
            workspace_mode: WorkspaceModeArg::Persistent,
            name: None,
            template: None,
            memory_limit: None,
            ttl_seconds: None,
            wait: false,
            wait_timeout_secs: DEFAULT_WAIT_TIMEOUT_SECS,
            network_egress: NetworkEgressArg::Allowlist,
            allow_cidrs: Vec::new(),
        };
        assert!(network_egress_from_args(&args).is_err());
    }

    #[test]
    fn cli_exposes_machine_readable_output_and_exec_environment() {
        let cli = Cli::try_parse_from([
            "sandboxwich",
            "--output",
            "jsonl",
            "exec",
            "00000000-0000-0000-0000-000000000001",
            "--cwd",
            "/workspace",
            "--env",
            "MODE=test",
            "--",
            "true",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn row_projection_preserves_multi_array_responses() {
        let response = serde_json::json!({
            "ok": true,
            "expired": [{"id": 1}],
            "runtime_resources_deleted": [{"id": 2}],
        });

        assert_eq!(primary_rows(&response), vec![&response]);
    }
}
